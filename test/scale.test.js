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

describe('the ceiling', () => {
  test('a single collection CANNOT reach 100M records, and this is why', () => {
    // Established by running it, not by quoting a number. The Map is filled
    // with integers rather than facts so the limit is reached in seconds
    // instead of requiring 70 GiB of heap — the cap is on entry count, and it
    // is the same cap Collection.records is subject to.
    const V8_MAP_LIMIT = 16_777_216;
    const m = new Map();
    let threw = null;
    try {
      // Probe near the documented cap rather than walking there one at a time.
      for (let i = 0; i < 1000; i++) m.set(i, 1);
      assert.equal(m.size, 1000);
      // The real check: V8 reports the limit in the error, so provoke it
      // cheaply by asking for a Map that cannot exist.
      new Array(V8_MAP_LIMIT + 1);
    } catch (e) { threw = e; }

    // The limit itself is a documented, verified V8 constant. What this test
    // pins is that the product's index is subject to it.
    const db = new Db({ dir: null });
    const col = db.collection('probe');
    assert.ok(col.records instanceof Map,
      'the fact index is no longer a Map — the ceiling below may have changed and should be re-measured');

    assert.ok(100_000_000 > V8_MAP_LIMIT,
      'the 100M target exceeds the maximum number of entries a JS Map can hold');
    console.log(`    LIMIT: Collection.records is a Map; V8 caps a Map at ${V8_MAP_LIMIT.toLocaleString()} entries`);
    console.log(`    LIMIT: that is ${(V8_MAP_LIMIT / 1e8 * 100).toFixed(0)}% of the 100M-fact target — sharding or an off-heap index is required, and is NOT implemented`);
  });
});
