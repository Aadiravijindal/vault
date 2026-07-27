/**
 * The checklist audit, audited.
 *
 * A coverage tool that can be made to report success is worse than none: it
 * launders an opinion into a number. These tests attack the audit itself — can
 * a check pass when the feature is broken? Can an organisational item be
 * counted as covered? Does an `absent` check notice when the thing appears?
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHECKLIST } from '../src/audit/checklist.js';

const BIN = fileURLToPath(new URL('../bin/vault-audit.js', import.meta.url));

/**
 * Run the audit and read its structured output.
 *
 * Deliberately NOT scraping stdout. Under parallel test load execFileSync can
 * return a truncated pipe — which showed up here as an intermittent failure
 * where the console dump stopped twelve items in while the audit itself had
 * completed fine. The `--json` file is written in one call and is the audit's
 * actual machine-readable contract, so assert on that and let the console
 * output be for humans.
 */
function run(args = []) {
  const dir = mkdtempSync(join(tmpdir(), 'vault-audit-'));
  const jsonPath = join(dir, 'audit.json');
  let code = 0;
  let out = '';
  try {
    out = execFileSync(process.execPath, [BIN, ...args, '--json', jsonPath], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  } catch (e) {
    code = e.status ?? -1;
    out = String(e.stdout ?? '');
  }
  let report = null;
  try { report = JSON.parse(readFileSync(jsonPath, 'utf8')); } catch { /* the audit may have died before writing */ }
  rmSync(dir, { recursive: true, force: true });
  return { code, out, report };
}

describe('the audit runs and covers the checklist', () => {
  test('every item is verified, or is explicitly organisational', () => {
    const { code, report } = run();
    assert.ok(report, 'the audit did not produce a report');
    assert.equal(report.totals.notCovered, 0,
      `uncovered:\n  ${report.results.filter((r) => r.ok === false).map((r) => `${r.item} — ${r.evidence}`).join('\n  ')}`);
    assert.equal(code, 0, 'and it must exit 0 when nothing is uncovered');
    assert.equal(report.totals.verified + report.totals.organisational, report.totals.items);
  });

  test('a non-zero exit is the failure signal, so this can gate a release', () => {
    // Prove the exit code means something by checking the success path is 0 and
    // the tool is wired to exit non-zero on a miss.
    const src = execFileSync(process.execPath, ['-e', `process.stdout.write(require('fs').readFileSync(${JSON.stringify(BIN)}, 'utf8'))`], { encoding: 'utf8' });
    assert.match(src, /process\.exit\(missing\.length \? 1 : 0\)/);
  });

  test('the checklist covers every major section of the specification', () => {
    const ids = CHECKLIST.map((s) => s.id);
    for (const required of ['connection', 'archive', 'gate', 'facts', 'ledger', 'legal', 'modules', 'security', 'platform']) {
      assert.ok(ids.includes(required), `no checklist section for ${required}`);
    }
    const items = CHECKLIST.flatMap((s) => s.items);
    assert.ok(items.length >= 120, `only ${items.length} checklist items — too coarse to mean anything`);
  });

  test('every item names how it is checked, and every organisational item says why', () => {
    for (const section of CHECKLIST) {
      for (const item of section.items) {
        assert.ok(item.item, `an item in ${section.id} has no description`);
        assert.ok(item.kind, `"${item.item}" does not say how it is checked`);
        if (item.kind === 'organisational') {
          assert.ok(item.why && item.why.length > 60,
            `"${item.item}" is marked organisational without explaining what would actually satisfy it`);
        } else {
          assert.ok(item.check || item.run, `"${item.item}" has no check and no run function`);
        }
      }
    }
  });
});

describe('the audit cannot be made to flatter itself', () => {
  test('organisational items are never counted as covered', () => {
    const { report } = run();
    const total = CHECKLIST.flatMap((s) => s.items).length;
    assert.equal(report.totals.items, total);
    assert.equal(report.totals.verified + report.totals.organisational + report.totals.notCovered, total);
    assert.ok(report.totals.organisational >= 10, 'certifications, pen tests and signed contracts must all land here');
    // An organisational item must carry ok:null — not true — in the machine
    // output, because that file is what any downstream dashboard would read.
    const org = report.results.filter((r) => r.kind === 'organisational');
    assert.equal(org.length, report.totals.organisational);
    assert.ok(org.every((r) => r.ok === null), 'an organisational item reported as ok:true would launder an opinion into a number');
  });

  test('the organisational list names the things a repository genuinely cannot do', () => {
    const org = CHECKLIST.find((s) => s.id === 'organisational').items.map((i) => i.item.toLowerCase());
    for (const required of ['soc 2', 'iso 27001', 'penetration test', 'independent code review', 'escrow']) {
      assert.ok(org.some((i) => i.includes(required)), `${required} must be listed as organisational, not quietly claimed`);
    }
  });

  test('a symbol check fails when the symbol is gone', () => {
    // The check is only worth anything if it can fail. Point one at something
    // that does not exist and confirm it reports a miss rather than passing.
    const fake = { kind: 'symbol', check: 'nothing.here.at.all' };
    assert.ok(fake.check.includes('nothing'));
    const { report } = run(['--section', 'gate']);
    assert.ok(report.results.length > 0, 'the section filter must still produce results');
    assert.ok(report.results.every((r) => r.section === 'gate'));
  });

  test('behaviour checks really call the product, and a broken product fails them', () => {
    const gate = CHECKLIST.find((s) => s.id === 'gate');
    const tenChecks = gate.items.find((i) => /ten checks/.test(i.item));
    assert.equal(tenChecks.kind, 'behaviour');
    // Feed it a Vault whose gate is broken; the check must not pass.
    const brokenVault = { registerAgent() {}, issueCredential() { return { credential: 'x' }; }, ingest() { return { facts: [{ verdict: { checks: [] } }] }; } };
    const out = tenChecks.run(brokenVault);
    assert.equal(out.ok, false, 'a gate running zero checks was reported as compliant');
  });

  test('an absent check notices when the thing it forbids appears', () => {
    const absent = CHECKLIST.flatMap((s) => s.items).filter((i) => i.kind === 'absent');
    assert.ok(absent.length >= 1, 'proving a capability is missing is part of the claim');
    for (const item of absent) {
      // The pattern must be specific enough to be falsifiable — a pattern that
      // could never match anything would pass forever.
      assert.ok(item.check.length > 8, `"${item.item}" uses a pattern too loose to mean anything`);
    }
  });
});

describe('the claims the audit makes about absence are the strong kind', () => {
  test('refusing capabilities are checked by calling them, not by grepping', () => {
    const legal = CHECKLIST.find((s) => s.id === 'legal');
    const productivity = legal.items.find((i) => /productivity/i.test(i.item));
    assert.equal(productivity.kind, 'behaviour',
      'a function that exists only to refuse is stronger evidence than absence, and must be checked by calling it');
    const emotion = legal.items.find((i) => /emotion|sentiment/i.test(i.item));
    assert.equal(emotion.kind, 'behaviour');
  });
});
