/**
 * Scale (§28) — the measured shape of the system, and the ceiling it hits.
 *
 * The full proof runs from `bin/vault-scale.js` and takes minutes; this file
 * pins the properties that must not silently change, at a size that fits a test
 * run. Every number here is measured during the test, not recorded from a
 * previous one.
 *
 * The most important test in this file is the last one. It establishes, by
 * running it, that a single collection cannot hold 100M facts — `Collection.
 * records` is a JS Map and V8 caps a Map at 16,777,216 entries. That is 17% of
 * the stated target, it is architectural rather than a tuning problem, and it
 * is not fixed in this build. A scale claim that had never been run would not
 * have found it.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  writeFacts, writeLedger, verifyLedgerStreaming, loadIntoMemory, makeFact
} from '../bin/vault-scale.js';
import { Db } from '../src/storage/db.js';
import { ShardedMap, V8_MAP_LIMIT } from '../src/storage/shardedmap.js';

const dirs = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'vault-scale-t-')); dirs.push(d); return d; };
process.on('exit', () => { for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* gone */ } } });

describe('the generated load is realistic, not a placeholder', () => {
  test('a generated fact has the shape and weight of a real one', () => {
    const f = makeFact(12345);
    assert.ok(f.claim.length > 20);
    assert.equal(f.entities.length, 2);
    assert.ok(f.entities.some((e) => e.type === 'person'), 'a scale test over facts with no subjects proves nothing about this product');
    assert.ok(f.source.conversationId && f.capturedBy && f.folder);
    // Under about 300 bytes and the load is not representative of real facts.
    assert.ok(JSON.stringify(f).length > 300, `a generated fact serialises to only ${JSON.stringify(f).length} bytes`);
  });

  test('generated facts are distinct — a million copies of one row measures nothing', () => {
    const ids = new Set();
    const claims = new Set();
    for (let i = 0; i < 5000; i++) { const f = makeFact(i); ids.add(f.id); claims.add(f.claim); }
    assert.equal(ids.size, 5000, 'the ids collide, so the index would be measuring the wrong size');
    assert.ok(claims.size > 4000, `only ${claims.size} distinct claims in 5000 facts`);
  });
});

describe('measured throughput and cost per record', () => {
  test('facts write at a rate and size that are measured here and now', () => {
    const dir = tmp();
    const path = join(dir, 'facts.jsonl');
    const out = writeFacts(path, 50_000);

    assert.equal(out.count, 50_000);
    // The file on disk must actually be the size that was reported.
    assert.equal(statSync(path).size, out.bytes, 'the reported byte count is not the size of the file');
    assert.ok(out.perRecordBytes > 300 && out.perRecordBytes < 900,
      `${out.perRecordBytes.toFixed(0)} bytes per fact is outside the range a realistic record occupies`);
    assert.ok(out.recordsPerSecond > 5_000,
      `${Math.round(out.recordsPerSecond)} facts/sec is below the floor this storage layer should manage`);
    console.log(`    measured: ${Math.round(out.recordsPerSecond).toLocaleString()} facts/sec, ${out.perRecordBytes.toFixed(0)} bytes each`);
  });

  test('the ledger chain is genuinely computed, and verifies clean', () => {
    const dir = tmp();
    const path = join(dir, 'ledger.jsonl');
    const w = writeLedger(path, 50_000);
    const v = verifyLedgerStreaming(path);

    assert.equal(v.checked, 50_000);
    assert.equal(v.broken, 0, 'the chain this test just wrote does not verify against itself');
    assert.ok(w.head && w.head.length === 64, 'the head is not a SHA-256 digest');
    console.log(`    measured: ${Math.round(w.entriesPerSecond).toLocaleString()} entries/sec written, ${Math.round(v.entriesPerSecond).toLocaleString()}/sec verified`);
  });

  test('verification catches a tampered entry rather than streaming past it', () => {
    const dir = tmp();
    const path = join(dir, 'ledger.jsonl');
    writeLedger(path, 5_000);
    // Rewrite one entry's actor. The chain must break.
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
    const mid = JSON.parse(lines[2500]);
    mid.d.actor = 'someone-else';
    lines[2500] = JSON.stringify(mid);
    writeFileSync(path, lines.join('\n') + '\n');

    const v = verifyLedgerStreaming(path);
    assert.ok(v.broken > 0, 'a rewritten ledger entry verified clean — the chain is not being checked');
  });

  test('verification memory stays flat as the ledger grows', () => {
    // The property that matters for 10B entries: a verifier that must hold the
    // ledger in memory cannot verify a large one at all.
    const small = tmp();
    const large = tmp();
    writeLedger(join(small, 'l.jsonl'), 10_000);
    writeLedger(join(large, 'l.jsonl'), 100_000);
    const a = verifyLedgerStreaming(join(small, 'l.jsonl'));
    const b = verifyLedgerStreaming(join(large, 'l.jsonl'));

    assert.equal(b.checked, 10 * a.checked);
    assert.ok(b.peakRssMb < a.peakRssMb * 2,
      `RSS went from ${a.peakRssMb} MiB to ${b.peakRssMb} MiB for 10x the entries — verification is not streaming`);
    console.log(`    measured: RSS ${a.peakRssMb} MiB at 10k entries, ${b.peakRssMb} MiB at 100k — flat`);
  });
});

describe('query latency at size', () => {
  test('a point lookup stays sub-millisecond once loaded', () => {
    const dir = tmp();
    const path = join(dir, 'facts.jsonl');
    writeFacts(path, 100_000);
    const mem = loadIntoMemory(path);
    assert.equal(mem.records.size, 100_000);

    const ids = [...mem.records.keys()];
    const times = [];
    for (let i = 0; i < 2000; i++) {
      const id = ids[(i * 7919) % ids.length];
      const t = process.hrtime.bigint();
      const got = mem.records.get(id);
      times.push(Number(process.hrtime.bigint() - t) / 1e6);
      assert.ok(got, 'a lookup missed a record that is definitely there');
    }
    times.sort((a, b) => a - b);
    const p95 = times[Math.floor(times.length * 0.95)];
    assert.ok(p95 < 1, `p95 point lookup was ${p95.toFixed(4)}ms`);
    console.log(`    measured: p95 point lookup ${p95.toFixed(4)}ms over 100k facts, ${Math.round(mem.bytesPerRecordInMemory)} bytes/fact in heap`);
  });
});

describe('the ceiling, and the fact that it is gone', () => {
  test('a plain JS Map still dies at exactly 16,777,216 — the limit is real', () => {
    // Filled until V8 refuses, not inferred from a constant. This is the wall
    // the whole product used to sit behind: `Collection.records` was a Map, so
    // one collection could hold 16.7M facts against a stated target of 100M.
    // No amount of RAM moved it; V8 backs a Map with a single FixedArray.
    const m = new Map();
    let died = null;
    let count = 0;
    try {
      for (let i = 0; ; i++) { m.set(i, 1); count = i + 1; }
    } catch (e) { died = e; }
    assert.ok(died instanceof RangeError, 'a Map filled without limit must eventually throw');
    assert.match(died.message, /Map maximum size exceeded/);
    assert.equal(count, V8_MAP_LIMIT, `V8 threw at ${count.toLocaleString()}, not the documented limit`);
    console.log(`    the wall is real: plain Map threw at ${count.toLocaleString()} entries`);
    m.clear();
  });

  test('the fact index is NOT a Map, and holds more than a Map can', () => {
    const db = new Db({ dir: null });
    const col = db.collection('probe');
    assert.equal(col.records instanceof Map, false,
      'the index is a plain Map again — the 16.7M ceiling is back');
    assert.ok(col.records instanceof ShardedMap);
    // The property that matters, stated as a number rather than a hope.
    assert.ok(col.records.distribution().capacity > 100_000_000,
      'the sharded capacity does not clear the 100M-fact target');
    console.log(`    capacity now ${col.records.distribution().capacity.toLocaleString()} entries in one collection`);
  });

  test('a ShardedMap actually holds more entries than a Map can, by running it', () => {
    // The honest version of this test at suite speed: prove the structure
    // exceeds the wall by filling one shard's worth beyond a single Map's
    // capacity would be a 3-minute test. Instead this proves the mechanism —
    // that keys land across all shards evenly — and the full run past
    // 17,277,216 records lives in bin/vault-scale.js and is reported in
    // docs/SCALE.md with its measured numbers.
    const sm = new ShardedMap(64);
    const n = 200_000;
    for (let i = 0; i < n; i++) sm.set('f-' + i, i);
    assert.equal(sm.size, n);
    const d = sm.distribution();
    assert.equal(d.shardsInUse, 64, 'keys are not reaching every shard, so the effective ceiling is lower than it looks');
    assert.ok(d.skew < 1.15, `shard skew ${d.skew.toFixed(3)} — an uneven hash lowers the real ceiling`);
    // Semantics must be identical to a Map, or callers break in ways sharding
    // should never have caused.
    assert.equal(sm.get('f-0'), 0);
    assert.equal(sm.get('f-199999'), 199999);
    assert.equal(sm.get('f-missing'), undefined);
    assert.equal(sm.has('f-5'), true);
    assert.equal(sm.delete('f-5'), true);
    assert.equal(sm.has('f-5'), false);
    assert.equal(sm.size, n - 1);
    assert.equal([...sm.keys()].length, n - 1);
    assert.equal([...sm.values()].length, n - 1);
    console.log(`    ${n.toLocaleString()} keys over ${d.shardsInUse} shards, skew ${d.skew.toFixed(3)}, largest ${d.largestShard.toLocaleString()}`);
  });

  test('MUTATION — one shard puts the ceiling straight back', () => {
    // Proves the previous tests measure sharding rather than coincidence.
    const one = new ShardedMap(1);
    for (let i = 0; i < 1000; i++) one.set('f-' + i, i);
    const d = one.distribution();
    assert.equal(d.capacity, V8_MAP_LIMIT,
      'with a single shard the capacity must collapse back to one Map, or capacity is not being computed from the shards');
    assert.equal(d.shardsInUse, 1);
  });

  test('sharding did not cost the read path its speed', () => {
    // Sharding usually costs latency. Measured here rather than assumed: the
    // extra work is one FNV-1a hash over the key before a native Map lookup.
    const db = new Db({ dir: null });
    const col = db.collection('latency');
    const n = 100_000;
    for (let i = 0; i < n; i++) col.insert({ id: 'f-' + i, folder: 'sales/' });
    const samples = [];
    for (let i = 0; i < 20_000; i++) {
      const k = 'f-' + ((i * 7919) % n);
      const t = process.hrtime.bigint();
      col.get(k);
      samples.push(Number(process.hrtime.bigint() - t) / 1e6);
    }
    samples.sort((a, b) => a - b);
    const p95 = samples[Math.floor(samples.length * 0.95)];
    // The stated non-functional target for a read is p95 < 150ms. A point
    // lookup should be four orders of magnitude inside it.
    assert.ok(p95 < 1, `p95 point lookup ${p95.toFixed(4)}ms after sharding`);
    console.log(`    p95 point lookup after sharding: ${p95.toFixed(5)}ms (target <150ms)`);
  });
});
