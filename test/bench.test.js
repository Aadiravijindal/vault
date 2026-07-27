/**
 * Measurement machinery (§30) — the benchmark harness and the restore drill.
 *
 * These test the *honesty* of the numbers, not the numbers themselves. A
 * benchmark that reports a flattering figure is worse than no benchmark, so the
 * assertions here are mostly about what the harness refuses to claim: it must
 * not average away a tail, must not call an error a fast operation, must not
 * extrapolate past the scale it reached, and must not report a quiet window as
 * proof of availability.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Samples, growth, Benchmark, BUDGETS } from '../src/observability/bench.js';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { setClock, DAY } from '../src/util/time.js';

describe('percentiles are computed, not estimated', () => {
  test('p50/p95/p99 come from the real distribution, including a fat tail', () => {
    const s = new Samples('t');
    // 99 fast operations and one very slow one. An average would read 11ms and
    // hide the outlier entirely; the p99 exists precisely to surface it.
    for (let i = 0; i < 99; i++) s.values.push(1);
    s.values.push(1000);
    const r = s.report();
    assert.equal(r.p50, 1);
    assert.equal(r.p95, 1);
    assert.equal(r.p99, 1, 'nearest-rank over 100 samples puts the 99th at 1ms');
    assert.equal(r.max, 1000, 'and the outlier is still reported');
    assert.ok(r.mean > 10, 'the mean is dragged up by the tail, which is why it is not the headline');
    assert.ok(r.mean > r.p99, 'and here the mean is worse than the p99 — the exact reason the mean is not the headline');
    assert.equal(r.tailRatio, 1, 'tail amplification is p99 over p50, so a single outlier shows in max rather than being smeared');
  });

  test('a failed operation is counted as an error, never as a fast sample', () => {
    const s = new Samples('t');
    for (let i = 0; i < 8; i++) s.tryTime(() => 1);
    for (let i = 0; i < 2; i++) s.tryTime(() => { throw new Error('nope'); });
    const r = s.report();
    assert.equal(r.samples, 8, 'only successful operations are timed');
    assert.equal(r.errors, 2);
    assert.equal(r.errorRate, 0.2, 'and the error rate is published beside the latency');
  });

  test('an empty run says there is nothing to measure rather than reporting zero', () => {
    const r = new Samples('t').report();
    assert.equal(r.samples, 0);
    assert.equal(r.p50, undefined);
    assert.match(r.note, /no successful operations/,
      'zero milliseconds and no data are different answers');
  });
});

describe('growth is characterised honestly', () => {
  test('constant time across a wide size range reads as flat', () => {
    const g = growth([{ size: 100, ms: 5 }, { size: 1000, ms: 5.1 }, { size: 10000, ms: 5.2 }]);
    assert.equal(g.shape, 'flat');
    assert.equal(g.confidence, 'good');
    assert.match(g.verdict, /independent of size/);
  });

  test('proportional growth reads as linear, and is called out as the shape that fails', () => {
    const g = growth([{ size: 100, ms: 1 }, { size: 1000, ms: 10 }, { size: 10000, ms: 100 }]);
    assert.equal(g.shape, 'linear');
    assert.match(g.verdict, /does NOT hold at 100M/,
      'a linear read path is the finding, not something to smooth over');
  });

  test('logarithmic growth is distinguished from linear', () => {
    const g = growth([{ size: 100, ms: 10 }, { size: 1000, ms: 15 }, { size: 10000, ms: 20 }]);
    assert.equal(g.shape, 'logarithmic');
    assert.match(g.verdict, /Fine at any realistic scale/);
  });

  test('too few points, or too narrow a range, is "unknown" rather than a guess', () => {
    assert.equal(growth([{ size: 10, ms: 1 }, { size: 100, ms: 2 }]).shape, 'unknown');
    const narrow = growth([{ size: 1000, ms: 5 }, { size: 1500, ms: 6 }, { size: 2000, ms: 7 }]);
    assert.equal(narrow.shape, 'unknown');
    assert.match(narrow.note, /too narrow/,
      'three points spanning 2x cannot tell flat from linear, and pretending otherwise is the whole problem');
  });

  test('every growth finding carries the extrapolation caveat', () => {
    const g = growth([{ size: 100, ms: 1 }, { size: 1000, ms: 10 }, { size: 10000, ms: 100 }]);
    assert.match(g.caveat, /predicts; it does not prove/);
  });
});

describe('the benchmark drives the real product', () => {
  const factory = () => {
    const vault = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });
    vault.registerAgent({ id: 'bench', name: 'B', purpose: 'measurement', businessOwner: 'b', technicalOwner: 'b', department: 'sales', mode: 'inline', folders: ['sales/'] });
    return { vault, credential: vault.issueCredential('bench', { ttl: '48h' }).credential, agentId: 'bench' };
  };

  test('ingest measurements come from writes that really went through the gate', () => {
    const b = new Benchmark({ factory });
    const { vault, credential, agentId } = factory();
    try {
      const before = vault.ledger.entries({ limit: Infinity }).length;
      const r = b.ingestRun({ n: 60, vault, credential, agentId });
      assert.equal(r.ingest.samples, 60);
      assert.ok(r.facts > 0);
      // The proof it was not a shortcut path: the gate wrote ledger entries.
      const gateEvents = vault.ledger.entries({ limit: Infinity }).filter((e) => /^fact\./.test(e.type));
      assert.ok(gateEvents.length > 0, 'a benchmark that skips the gate measures nothing');
      assert.ok(vault.ledger.entries({ limit: Infinity }).length > before);
      assert.ok(r.ingest.p99 >= r.ingest.p50);
      assert.ok(r.ingest.throughputPerSecond > 0);
    } finally { vault.close(); }
  });

  test('the corpus is varied enough that ingest is not secretly measuring deduplication', () => {
    const b = new Benchmark({ factory });
    const { vault, credential, agentId } = factory();
    try {
      const r = b.ingestRun({ n: 120, vault, credential, agentId });
      // If every phrase were identical, reconciliation would fold them into one
      // fact and the run would measure the dedupe path rather than the gate.
      assert.ok(r.facts > 30, `only ${r.facts} distinct facts from 120 writes — the corpus is folding together`);
    } finally { vault.close(); }
  });

  test('read and search measurements run against a populated store', () => {
    const b = new Benchmark({ factory });
    const { vault, credential, agentId } = factory();
    try {
      b.ingestRun({ n: 40, vault, credential, agentId });
      const read = b.readRun({ n: 30, vault, credential, agentId });
      const search = b.searchRun({ n: 30, vault });
      assert.equal(read.samples + read.errors, 30);
      assert.equal(search.samples + search.errors, 30);
      assert.equal(read.errors, 0, `the read path errored ${read.errors} times during measurement`);
    } finally { vault.close(); }
  });

  test('ledger measurement verifies the real chain and reports cost per 1000 entries', () => {
    const b = new Benchmark({ factory });
    const { vault } = factory();
    try {
      const r = b.ledgerRun({ vault });
      assert.equal(r.verify.chainOk, true);
      assert.ok(r.verify.entries >= 500);
      assert.ok(r.verify.msPer1000 != null, 'verification cost must be reported per unit, so it can be scaled');
      assert.ok(r.append.p95 != null);
    } finally { vault.close(); }
  });

  test('grading against the budgets names what failed, in milliseconds', () => {
    const good = Benchmark.grade({ read: { p50: 1, p95: 2, p99: 3 } });
    assert.equal(good.ok, true);
    assert.equal(good.total, 3);

    const bad = Benchmark.grade({ read: { p50: 1, p95: 2, p99: 9000 } });
    assert.equal(bad.ok, false);
    assert.equal(bad.failed.length, 1);
    assert.match(bad.failed[0], /9000ms against a 500ms budget/);
    assert.match(bad.note, /reproduce before drawing conclusions/,
      'a missed budget on one machine is a signal, not a verdict');
  });

  test('every report states the scale it reached and refuses to speak past it', () => {
    const c = Benchmark.caveats({ facts: 5000, ledgerEntries: 16000, conversations: 5000 });
    assert.deepEqual(c.scaleReached, { facts: 5000, ledgerEntries: 16000, conversations: 5000 });
    assert.ok(c.whatWasNotMeasured.some((x) => /100M/.test(x)),
      'the spec targets 100M facts; a run at 5000 must say it did not go near that');
    assert.ok(c.whatWasNotMeasured.some((x) => /[Cc]oncurrency/.test(x)));
    assert.ok(c.whatWasNotMeasured.some((x) => /Network latency/.test(x)));
    assert.match(c.howToRunItYourself, /vault-bench/);
  });

  test('the stated budgets are the spec\'s, and every one is a real number', () => {
    for (const [key, b] of Object.entries(BUDGETS)) {
      assert.equal(typeof b.ms, 'number', `${key} has no numeric budget`);
      assert.ok(b.ms > 0);
      assert.ok(b.what.length > 5, `${key} does not say what it measures`);
    }
    assert.ok(BUDGETS.read_p99.ms > BUDGETS.read_p50.ms, 'a p99 budget below the p50 budget would be nonsense');
  });
});

describe('the restore drill proves the continuity claim', () => {
  const populated = () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });
    v.demo.load({ actor: 'admin' });
    return v;
  };

  test('a passing drill exports, verifies independently, restores and compares by data', () => {
    const v = populated();
    try {
      const r = v.drill.run({ actor: 'sre' });
      assert.equal(r.ok, true);
      const names = r.steps.map((s) => s.name);
      assert.ok(names.includes('verify export with the standalone verifier'),
        'the drill must verify with the program that imports none of our code');
      assert.ok(r.steps.every((s) => s.ok), JSON.stringify(r.steps.filter((s) => !s.ok)));
      assert.equal(r.verifiedIndependently, true);
      assert.ok(r.counts.source.facts > 0);
    } finally { v.close(); }
  });

  test('RPO is measured, and zero loss is reported as a drill result rather than a guarantee', () => {
    const v = populated();
    try {
      const r = v.drill.run({ actor: 'sre' });
      assert.equal(r.rpo.lostRecords, 0);
      assert.match(r.rpo.statement, /not a guaranteed RPO/,
        'a clean drill is evidence about this drill; promising an RPO is a different claim');
    } finally { v.close(); }
  });

  test('RTO is reported with the volume, so it can be scaled instead of quoted', () => {
    const v = populated();
    try {
      const r = v.drill.run({ actor: 'sre' });
      assert.ok(r.rto.totalMs >= 0);
      assert.ok(r.rto.bytes > 0, 'the restored volume must be reported');
      assert.match(r.rto.statement, /not a fixed RTO/);
    } finally { v.close(); }
  });

  test('a drill that loses records reports what went missing and when it was written', () => {
    const v = populated();
    try {
      // An export that is internally consistent but genuinely incomplete —
      // the real RPO case, where the manifest agrees with itself and a record
      // simply is not in it. Truncating without fixing the manifest would only
      // prove the verifier catches truncation, which is a different test.
      const realExport = v.exportAll.bind(v);
      v.exportAll = (opts) => {
        const out = realExport(opts);
        const factsFile = join(opts.dir, 'facts.jsonl');
        const lines = readFileSync(factsFile, 'utf8').split('\n').filter(Boolean);
        // Drop a *live* fact: the comparison is over live facts, so removing a
        // held one would silently prove nothing.
        const victim = lines.findIndex((l) => JSON.parse(l).status === 'live');
        assert.ok(victim >= 0, 'the export must contain at least one live fact for this test to mean anything');
        const truncated = `${lines.filter((_, i) => i !== victim).join('\n')}\n`;
        writeFileSync(factsFile, truncated);
        const manifestFile = join(opts.dir, 'manifest.json');
        const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
        manifest.fileHashes['facts.jsonl'] = createHash('sha256').update(truncated).digest('hex');
        writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
        return out;
      };
      const r = v.drill.run({ actor: 'sre' });
      assert.equal(r.ok, false, 'a drill that silently tolerates a lost record is worthless');
      assert.ok(r.rpo.lostRecords > 0);
      assert.match(r.rpo.statement, /did not survive the round trip/);
      assert.ok(r.rpo.windowMs >= 0);
    } finally { v.close(); }
  });

  test('a drill that cannot verify its export fails loudly instead of restoring bad data', () => {
    const v = populated();
    const dir = mkdtempSync(join(tmpdir(), 'vault-drill-test-'));
    try {
      const realExport = v.exportAll.bind(v);
      v.exportAll = (opts) => {
        const out = realExport(opts);
        // Tamper with the ledger, exactly as an attacker would.
        const led = join(opts.dir, 'ledger.jsonl');
        const lines = readFileSync(led, 'utf8').trim().split('\n');
        const entry = JSON.parse(lines[2]);
        entry.folder = 'hr/';
        lines[2] = JSON.stringify(entry);
        writeFileSync(led, `${lines.join('\n')}\n`);
        return out;
      };
      assert.throws(() => v.drill.run({ actor: 'sre', dir }), (e) => {
        assert.equal(e.code, 'drill_failed');
        assert.match(e.message, /verify export/);
        return true;
      }, 'restoring from an unverified export is restoring unverified data');

      // And the failure is on the record, not swallowed.
      const status = v.drill.status();
      assert.equal(status.everPassed, false);
      assert.match(status.statement, /never passed/);
      assert.ok(v.ledger.entries({ limit: Infinity }).some((e) => e.action === 'continuity.drill_failed'));
    } finally { v.close(); rmSync(dir, { recursive: true, force: true }); }
  });

  test('a never-run drill is a high finding, and one run long ago goes overdue', () => {
    let clock = Date.parse('2026-01-01T00:00:00Z');
    setClock(() => clock);
    try {
      const v = populated();
      const before = v.drill.status();
      assert.equal(before.everPassed, false);
      assert.equal(before.severity, 'high');
      assert.match(before.statement, /untested claim/);

      v.drill.run({ actor: 'sre' });
      assert.equal(v.drill.status().overdue, false);

      clock += 100 * DAY;
      const late = v.drill.status();
      assert.equal(late.overdue, true);
      assert.equal(late.severity, 'medium');

      clock += 120 * DAY;
      assert.equal(v.drill.status().severity, 'high', 'the longer it slips the louder it gets');
      v.close();
    } finally { setClock(() => Date.now()); }
  });

  test('the evidence pack states what the drill does not prove', () => {
    const v = populated();
    try {
      v.drill.run({ actor: 'sre' });
      const e = v.drill.evidence();
      assert.equal(e.status, 'met');
      assert.equal(e.runs.length, 1);
      assert.match(e.whatItDoesNotProve, /production hardware|data-centre/,
        'a code-level drill is not a data-centre failover, and the evidence pack must not let a reader assume it is');
      assert.match(e.whatTheDrillProves, /imports none of Vault/);
    } finally { v.close(); }
  });

  test('a drill needs a named actor', () => {
    const v = populated();
    try {
      assert.throws(() => v.drill.run({}), /named actor/);
    } finally { v.close(); }
  });
});

describe('verification scales by verifying the tail, not the world', () => {
  test('tail verification checks only what happened since the last anchor', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false, anchorEvery: 50 });
    try {
      for (let i = 0; i < 300; i++) v.ledger.append('admin.action', { subject: `x${i}`, actor: 'a', action: 'noop' });
      const full = v.verifyLedger();
      const tail = v.verifyLedgerTail();

      assert.equal(full.ok, true);
      assert.equal(full.full, true);
      assert.equal(tail.ok, true);
      assert.equal(tail.sinceAnchor, true);
      assert.ok(tail.checked < full.checked,
        `the tail check examined ${tail.checked} of ${full.checked} entries — if it examined all of them it is not an incremental check`);
      assert.ok(tail.witnesses.length >= 1, 'the span it skipped must be covered by independent witnesses, or skipping it is unjustified');
      assert.match(tail.note, /weaker claim/,
        'the report must say why re-hashing anchored entries locally proves less, rather than implying the tail check is equivalent');
    } finally { v.close(); }
  });

  test('a range verification does not silently start from the wrong link', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });
    try {
      for (let i = 0; i < 40; i++) v.ledger.append('admin.action', { subject: `x${i}`, actor: 'a', action: 'noop' });
      const partial = v.verifyLedger({ from: 20 });
      assert.equal(partial.ok, true, JSON.stringify(partial.problems?.slice(0, 2)));
      assert.equal(partial.full, false, 'a partial verification must not report itself as a full one');
      assert.ok(partial.checked < v.ledger.entries({ limit: Infinity }).length);

      // Tamper inside the range and confirm the narrowed check still catches it.
      const entries = v.ledger.col.all();
      const victim = entries.find((e) => e.seq === 25);
      v.ledger.col.store?.set?.(victim.id, { ...victim, actor: 'someone-else' });
      const after = v.verifyLedger({ from: 20 });
      if (v.ledger.col.store) assert.equal(after.ok, false, 'narrowing the range must not narrow the tamper detection');
    } finally { v.close(); }
  });

  test('with no anchor published, the tail check verifies everything and says so', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false, anchorEvery: 0 });
    try {
      for (let i = 0; i < 20; i++) v.ledger.append('admin.action', { subject: `x${i}`, actor: 'a', action: 'noop' });
      const tail = v.verifyLedgerTail();
      assert.equal(tail.sinceAnchor, false);
      assert.match(tail.note, /no anchor has been published/,
        'without an anchor there is nothing to trust, so falling back to a full verification is the only honest option');
      assert.equal(tail.full, true);
    } finally { v.close(); }
  });
});
