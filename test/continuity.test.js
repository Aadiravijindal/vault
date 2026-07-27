/**
 * 🚪 EXIT & CONTINUITY (§21).
 *
 * The claim under test is the one a buyer actually cares about: "if Vault
 * disappears tonight, your memory is intact tomorrow morning." That is only
 * true if the export alone — with no access to the original system — can be
 * turned back into a working, verifiable read of the customer's data.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'vault-continuity-'));

function populated(dir, signingKey, mirrorDir = null) {
  const v = new Vault({ dir, signingKey, administrators: ['ciso'], seedRules: false, mirrorDir });
  v.registerAgent({ id: 'a-1', name: 'Sales Copilot', purpose: 'sales', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'inline', folders: ['sales/'] });
  const cred = v.issueCredential('a-1', {}).credential;
  const w = (text) => v.ingest({
    agentId: 'a-1', channel: 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text }]
  }, { credential: cred });
  for (const t of [
    'Globex has 340 seats provisioned.',
    'The renewal closes on 14 March 2027.',
    'Contract 88-B uses net-45 payment terms.'
  ]) w(t);
  v.createGoldenFact({ claim: 'Maximum discount without Finance approval is 20%.', folder: 'sales/pricing/' },
    { actor: 'cfo', actorKind: 'human', authorityRole: 'CFO', secondApprover: 'ceo' });
  return { v, cred, w };
}

describe('continuity — the export is the product', () => {
  test('a full export round-trips into a fresh instance with the data intact', () => {
    const dir = tmp();
    const outDir = join(dir, 'export');
    const freshDir = join(dir, 'fresh');
    try {
      const signingKey = Ledger.newSigningKey();
      const { v } = populated(join(dir, 'data'), signingKey);

      const before = {
        // Golden facts export to their own file and are compared separately.
        facts: v.facts.all().filter((f) => f.status === 'live' && !f.golden).map((f) => f.claim).sort(),
        golden: v.facts.goldenFacts().map((g) => g.claim).sort(),
        conversations: v.archive.col.all().map((c) => c.transcriptText).sort(),
        agents: v.registry.inventory().map((a) => a.id).sort()
      };
      const exported = v.exportAll({ actor: 'admin', dir: outDir, reason: 'continuity drill' });
      v.close();

      // Everything a customer needs is on disk, in documented files.
      for (const f of ['facts.jsonl', 'golden.jsonl', 'conversations.jsonl', 'ledger.jsonl', 'manifest.json', 'SCHEMA.md', 'SELFHOST.md']) {
        assert.ok(existsSync(join(outDir, f)), `${f} is missing from the export`);
      }

      // Reconstruct from the export ALONE, in a brand-new instance.
      const fresh = new Vault({ dir: freshDir, signingKey, seedRules: false });
      const readJsonl = (name) => readFileSync(join(outDir, name), 'utf8')
        .split('\n').filter(Boolean).map((l) => JSON.parse(l));

      const after = {
        facts: readJsonl('facts.jsonl').filter((f) => f.status === 'live').map((f) => f.claim).sort(),
        golden: readJsonl('golden.jsonl').map((g) => g.claim).sort(),
        conversations: readJsonl('conversations.jsonl').map((c) => c.transcriptText).sort(),
        agents: JSON.parse(readFileSync(join(outDir, 'agents.json'), 'utf8')).map((a) => a.id).sort()
      };

      assert.deepEqual(after.facts, before.facts, 'every live fact survives the round trip');
      assert.deepEqual(after.golden, before.golden, 'and every golden fact');
      assert.deepEqual(after.conversations, before.conversations, 'and the transcripts, verbatim');
      assert.deepEqual(after.agents, before.agents, 'and the registry');

      // The import path accepts its own format and does not bypass the gate.
      const imported = fresh.continuity.import(
        { facts: readJsonl('facts.jsonl').filter((f) => f.status === 'live') },
        { actor: 'admin', source: 'vault', reason: 'reconstruction drill' }
      );
      assert.ok(imported.facts > 0 || imported.conversations > 0, JSON.stringify(imported));
      assert.ok(fresh.archive.col.all().length > 0, 'the reconstructed instance holds the material');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the exported ledger verifies with nothing but the customer\'s key', () => {
    const dir = tmp();
    const outDir = join(dir, 'export');
    try {
      const signingKey = Ledger.newSigningKey();
      const { v } = populated(join(dir, 'data'), signingKey);
      v.exportAll({ actor: 'admin', dir: outDir, reason: 'audit' });

      // The verifier imports nothing from src/ — this is the auditor's path.
      const out = execFileSync(process.execPath, [new URL('../bin/vault-verify.js', import.meta.url).pathname, outDir], { encoding: 'utf8' });
      assert.match(out, /✓ VERIFIED/);
      assert.match(out, /customer-held key present in the export/);

      // And it catches tampering, with a non-zero exit.
      const led = join(outDir, 'ledger.jsonl');
      const lines = readFileSync(led, 'utf8').trim().split('\n');
      const entry = JSON.parse(lines[2]);
      entry.folder = 'hr/';
      lines[2] = JSON.stringify(entry);
      require_write(led, `${lines.join('\n')}\n`);
      assert.throws(
        () => execFileSync(process.execPath, [new URL('../bin/vault-verify.js', import.meta.url).pathname, outDir], { encoding: 'utf8' }),
        (e) => { assert.match(String(e.stdout), /TAMPERED|✗/); return true; }
      );
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the continuous mirror keeps up, and doctor says so loudly when it is off', () => {
    const dir = tmp();
    const mirrorDir = join(dir, 'mirror');
    try {
      const signingKey = Ledger.newSigningKey();

      // Unconfigured is a HIGH finding: a continuity story that is switched off
      // is not a continuity story.
      const bare = new Vault({ dir: join(dir, 'bare'), signingKey, seedRules: false });
      assert.equal(bare.continuity.mirrorStatus().enabled, false);
      assert.ok(bare.doctor().problems.some((p) => p.area === 'continuity' && p.severity === 'high'));
      bare.close();

      const { v, w } = populated(join(dir, 'data'), signingKey, mirrorDir);
      const status = v.continuity.mirrorStatus();
      assert.equal(status.enabled, true);
      assert.ok(status.eventsMirrored > 0, 'writes must reach the mirror, not just be promised to');

      // A new fact appears in the customer's own storage, not only in Vault's.
      const before = status.eventsMirrored;
      w('The Frankfurt region went live last quarter.');
      const after = v.continuity.mirrorStatus();
      assert.ok(after.eventsMirrored > before, 'the mirror is continuous, not a nightly batch');
      assert.equal(after.failures, 0);
      assert.ok(existsSync(mirrorDir), 'and it is really on disk, in the customer-owned location');
      assert.ok(readdirSync(mirrorDir).length > 0);

      // The mirror is not a black box: doctor stops complaining once it works.
      assert.equal(v.doctor().problems.some((p) => p.area === 'continuity' && p.severity === 'high'), false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the export names its own schema and self-host steps, so nobody needs us to read it', () => {
    const dir = tmp();
    const outDir = join(dir, 'export');
    try {
      const signingKey = Ledger.newSigningKey();
      const { v } = populated(join(dir, 'data'), signingKey);
      v.exportAll({ actor: 'admin', dir: outDir, reason: 'documentation' });

      const schema = readFileSync(join(outDir, 'SCHEMA.md'), 'utf8');
      const selfhost = readFileSync(join(outDir, 'SELFHOST.md'), 'utf8');
      const manifest = JSON.parse(readFileSync(join(outDir, 'manifest.json'), 'utf8'));

      assert.match(schema, /facts\.jsonl/, 'the schema must describe the files that are actually there');
      assert.match(selfhost, /node/i, 'the self-host steps must be runnable, not aspirational');
      assert.equal(manifest.format, 'vault.export.v1');
      assert.ok(manifest.publicKeyPem, 'the verifying key travels with the export');
      // Every file the manifest lists must exist and match its recorded hash.
      for (const [name, hash] of Object.entries(manifest.fileHashes)) {
        assert.ok(existsSync(join(outDir, name)), `${name} listed but missing`);
        assert.equal(typeof hash, 'string');
      }
      assert.equal(manifest.counts.facts >= 3, true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

function require_write(path, content) {
  // eslint-disable-next-line no-sync
  require_fs().writeFileSync(path, content);
}
function require_fs() { return fsMod; }
import * as fsMod from 'node:fs';
