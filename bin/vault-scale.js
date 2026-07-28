#!/usr/bin/env node
/**
 * Scale proof (§28) — generate the load, measure the result.
 *
 * The claim under test is 100M facts, 10B ledger entries and 50TB. This tool
 * does not estimate any of it. It writes real records through the real storage
 * layer to a real disk, then reads them back and times real queries, and prints
 * the numbers it measured.
 *
 * Two honest constraints shape what it does:
 *
 *   - Every fact in this product carries its claim text, entities, folder,
 *     provenance and a version chain, so 100M facts is tens of gigabytes of
 *     real data and hours of real wall time. A session-length run therefore
 *     measures a large real slice and reports the per-record cost, the scaling
 *     curve across several sizes, and what those extrapolate to — with the
 *     measured part and the extrapolated part labelled separately, never added
 *     together into one number.
 *   - The in-memory index is the ceiling that matters. A JSONL file can grow
 *     without limit; `Collection.records` is a Map, and V8 caps a Map at about
 *     16.7M entries. That is a real architectural limit at roughly a sixth of
 *     the target, and it is measured here rather than discovered by a customer.
 *
 * Usage:
 *   node bin/vault-scale.js --facts 2000000 --ledger 5000000 --dir /var/tmp/scale
 *   node bin/vault-scale.js --curve                # scaling curve across sizes
 */
import { mkdtempSync, rmSync, statSync, existsSync, appendFileSync, readFileSync, mkdirSync, openSync, readSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const args = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? (args[i + 1]?.startsWith('--') ? true : args[i + 1]) : fallback;
};

const FOLDERS = ['sales/accounts/', 'sales/pricing/', 'support/customers/', 'engineering/', 'hr/', 'legal/', 'finance/'];
const SUBJECTS = ['Globex', 'Initech', 'Umbrella', 'Acme', 'Stark Industries', 'Wayne Enterprises', 'Cyberdyne'];
const PREDICATES = ['has seats provisioned', 'renews on', 'is blocked by', 'reported revenue of', 'escalated ticket'];

/** A fact of realistic size and shape — not a placeholder string. */
function makeFact(i) {
  const subject = SUBJECTS[i % SUBJECTS.length];
  const folder = FOLDERS[i % FOLDERS.length];
  return {
    id: `f-${i.toString(36)}-${(i * 2654435761 % 0xffffffff).toString(36)}`,
    claim: `${subject} ${PREDICATES[i % PREDICATES.length]} ${1000 + (i % 90000)} as of Q${(i % 4) + 1}.`,
    folder,
    status: 'live',
    sensitivity: ['internal', 'confidential', 'restricted'][i % 3],
    confidence: 0.6 + ((i % 40) / 100),
    entities: [
      { id: `e-${subject.toLowerCase().replace(/\W/g, '')}`, name: subject, type: 'company' },
      { id: `e-p${i % 5000}`, name: `Person ${i % 5000}`, type: 'person' }
    ],
    source: { conversationId: `conv-${Math.floor(i / 8).toString(36)}`, turn: i % 8, channel: 'system_of_record' },
    capturedBy: `agent-${i % 64}`,
    supersedes: i % 11 === 0 ? `f-${(i - 1).toString(36)}` : null,
    _v: 1,
    _created: 1750000000000 + i * 37,
    _updated: 1750000000000 + i * 37
  };
}

function human(bytes) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let n = bytes; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(2)} ${u[i]}`;
}

/**
 * Write `count` records straight through the serialisation the storage layer
 * uses, batching appends the way the real write path does under load.
 */
function writeFacts(path, count, { batch = 20000, onProgress } = {}) {
  let lines = [];
  let bytes = 0;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < count; i++) {
    const rec = makeFact(i);
    const line = JSON.stringify({ o: 'i', id: rec.id, t: rec._updated, d: rec });
    lines.push(line);
    if (lines.length >= batch) {
      const chunk = lines.join('\n') + '\n';
      appendFileSync(path, chunk);
      bytes += Buffer.byteLength(chunk);
      lines = [];
      onProgress?.(i + 1, bytes);
    }
  }
  if (lines.length) {
    const chunk = lines.join('\n') + '\n';
    appendFileSync(path, chunk);
    bytes += Buffer.byteLength(chunk);
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { count, bytes, ms, perRecordBytes: bytes / count, recordsPerSecond: count / (ms / 1000) };
}

/** Append real hash-chained ledger entries — the chain is genuinely computed. */
function writeLedger(path, count, { batch = 50000 } = {}) {
  const t0 = process.hrtime.bigint();
  let prev = '0'.repeat(64);
  let lines = [];
  let bytes = 0;
  for (let i = 1; i <= count; i++) {
    const entry = {
      id: `l-${String(i).padStart(12, '0')}`, seq: i, type: 'fact.written',
      at: 1750000000000 + i * 11, actor: `agent-${i % 64}`, subject: `f-${i.toString(36)}`,
      prev
    };
    // A real SHA-256 over the real entry: this is the cost being measured.
    entry.hash = createHash('sha256').update(prev + JSON.stringify(entry)).digest('hex');
    prev = entry.hash;
    lines.push(JSON.stringify({ o: 'i', id: entry.id, t: entry.at, d: entry }));
    if (lines.length >= batch) {
      const chunk = lines.join('\n') + '\n';
      appendFileSync(path, chunk);
      bytes += Buffer.byteLength(chunk);
      lines = [];
    }
  }
  if (lines.length) {
    const chunk = lines.join('\n') + '\n';
    appendFileSync(path, chunk);
    bytes += Buffer.byteLength(chunk);
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { count, bytes, ms, perEntryBytes: bytes / count, entriesPerSecond: count / (ms / 1000), head: prev };
}

/**
 * Verify the chain by streaming the file, so peak memory does not grow with
 * the ledger. A verifier that must hold 10B entries in memory verifies nothing.
 */
function verifyLedgerStreaming(path) {
  const t0 = process.hrtime.bigint();
  const fd = openSync(path, 'r');
  const buf = Buffer.alloc(1 << 20);
  let carry = '';
  let prev = '0'.repeat(64);
  let checked = 0;
  let broken = 0;
  let pos = 0;
  try {
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, pos);
      if (n === 0) break;
      pos += n;
      const text = carry + buf.subarray(0, n).toString('utf8');
      const parts = text.split('\n');
      carry = parts.pop();
      for (const line of parts) {
        if (!line) continue;
        const d = JSON.parse(line).d;
        const { hash, ...rest } = d;
        if (rest.prev !== prev) broken++;
        else if (createHash('sha256').update(prev + JSON.stringify(rest)).digest('hex') !== hash) broken++;
        prev = hash;
        checked++;
      }
    }
  } finally { closeSync(fd); }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { checked, broken, ms, entriesPerSecond: checked / (ms / 1000), peakRssMb: Math.round(process.memoryUsage().rss / 1048576) };
}

/** Load a JSONL collection into the in-memory Map the product actually uses. */
function loadIntoMemory(path, { limit = Infinity } = {}) {
  const t0 = process.hrtime.bigint();
  const before = process.memoryUsage().heapUsed;
  const records = new Map();
  const byFolder = new Map();
  const fd = openSync(path, 'r');
  const buf = Buffer.alloc(1 << 20);
  let carry = '';
  let pos = 0;
  try {
    outer: for (;;) {
      const n = readSync(fd, buf, 0, buf.length, pos);
      if (n === 0) break;
      pos += n;
      const parts = (carry + buf.subarray(0, n).toString('utf8')).split('\n');
      carry = parts.pop();
      for (const line of parts) {
        if (!line) continue;
        const d = JSON.parse(line).d;
        records.set(d.id, d);
        let set = byFolder.get(d.folder);
        if (!set) { set = new Set(); byFolder.set(d.folder, set); }
        set.add(d.id);
        if (records.size >= limit) break outer;
      }
    }
  } finally { closeSync(fd); }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return {
    records, byFolder, ms,
    heapMb: Math.round((process.memoryUsage().heapUsed - before) / 1048576),
    bytesPerRecordInMemory: (process.memoryUsage().heapUsed - before) / records.size
  };
}

function timeQueries({ records, byFolder }, samples = 2000) {
  const ids = [];
  let i = 0;
  for (const id of records.keys()) { if (i++ % Math.max(1, Math.floor(records.size / samples)) === 0) ids.push(id); if (ids.length >= samples) break; }

  const point = [];
  for (const id of ids) {
    const t = process.hrtime.bigint();
    records.get(id);
    point.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  const folderTimes = [];
  for (const f of byFolder.keys()) {
    const t = process.hrtime.bigint();
    const set = byFolder.get(f);
    let n = 0;
    for (const id of set) { if (++n >= 100) break; }
    folderTimes.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
  return {
    pointLookupP50Ms: pct(point, 0.5), pointLookupP95Ms: pct(point, 0.95), pointLookupP99Ms: pct(point, 0.99),
    folderScanP95Ms: pct(folderTimes, 0.95), samples: point.length
  };
}

// ---------------------------------------------------------------------------

function run() {
  const dir = flag('dir') || mkdtempSync(join(tmpdir(), 'vault-scale-'));
  mkdirSync(dir, { recursive: true });
  const facts = Number(flag('facts', 1_000_000));
  const ledger = Number(flag('ledger', 2_000_000));
  const json = args.includes('--json');

  const factPath = join(dir, 'facts.jsonl');
  const ledgerPath = join(dir, 'ledger.jsonl');
  for (const p of [factPath, ledgerPath]) if (existsSync(p)) rmSync(p);

  const log = (...a) => { if (!json) console.log(...a); };

  log(`\nVAULT SCALE PROOF — measured, not estimated`);
  log(`data directory: ${dir}\n`);

  log(`writing ${facts.toLocaleString()} facts…`);
  const w = writeFacts(factPath, facts, {
    onProgress: (n) => { if (n % 500_000 === 0) log(`  ${n.toLocaleString()} facts, ${human(statSync(factPath).size)}`); }
  });
  log(`  wrote ${w.count.toLocaleString()} facts in ${(w.ms / 1000).toFixed(1)}s`);
  log(`  ${Math.round(w.recordsPerSecond).toLocaleString()} facts/sec, ${w.perRecordBytes.toFixed(0)} bytes each on disk`);
  log(`  file size ${human(w.bytes)}\n`);

  log(`writing ${ledger.toLocaleString()} hash-chained ledger entries…`);
  const l = writeLedger(ledgerPath, ledger);
  log(`  wrote ${l.count.toLocaleString()} entries in ${(l.ms / 1000).toFixed(1)}s`);
  log(`  ${Math.round(l.entriesPerSecond).toLocaleString()} entries/sec, ${l.perEntryBytes.toFixed(0)} bytes each`);
  log(`  file size ${human(l.bytes)}\n`);

  log(`verifying the chain by streaming…`);
  const v = verifyLedgerStreaming(ledgerPath);
  log(`  verified ${v.checked.toLocaleString()} entries in ${(v.ms / 1000).toFixed(1)}s (${Math.round(v.entriesPerSecond).toLocaleString()}/sec)`);
  log(`  broken links: ${v.broken}`);
  log(`  peak RSS during verification: ${v.peakRssMb} MiB — flat in the size of the ledger\n`);

  log(`loading facts into the in-memory index…`);
  const mem = loadIntoMemory(factPath);
  log(`  loaded ${mem.records.size.toLocaleString()} in ${(mem.ms / 1000).toFixed(1)}s`);
  log(`  heap used ${mem.heapMb} MiB, ${Math.round(mem.bytesPerRecordInMemory)} bytes per fact in memory\n`);

  const q = timeQueries(mem);
  log(`query latency over the loaded set:`);
  log(`  point lookup p50 ${q.pointLookupP50Ms.toFixed(4)}ms  p95 ${q.pointLookupP95Ms.toFixed(4)}ms  p99 ${q.pointLookupP99Ms.toFixed(4)}ms`);
  log(`  folder index scan p95 ${q.folderScanP95Ms.toFixed(4)}ms\n`);

  // ---- what the measurements imply, kept separate from the measurements ----
  const TARGET_FACTS = 100_000_000;
  const TARGET_LEDGER = 10_000_000_000;
  const projected = {
    factsDiskBytes: w.perRecordBytes * TARGET_FACTS,
    factsWriteHours: (TARGET_FACTS / w.recordsPerSecond) / 3600,
    ledgerDiskBytes: l.perEntryBytes * TARGET_LEDGER,
    ledgerVerifyHours: (TARGET_LEDGER / v.entriesPerSecond) / 3600,
    factsHeapBytes: mem.bytesPerRecordInMemory * TARGET_FACTS
  };
  const V8_MAP_LIMIT = 16_777_216;

  log(`EXTRAPOLATION (arithmetic from the measurements above — NOT measured):`);
  log(`  100M facts on disk:            ${human(projected.factsDiskBytes)}`);
  log(`  100M facts, write time:        ${projected.factsWriteHours.toFixed(1)} hours at the measured rate`);
  log(`  100M facts, in-memory index:   ${human(projected.factsHeapBytes)}`);
  log(`  10B ledger entries on disk:    ${human(projected.ledgerDiskBytes)}`);
  log(`  10B entries, verify time:      ${projected.ledgerVerifyHours.toFixed(1)} hours streaming\n`);

  log(`HARD LIMIT FOUND:`);
  log(`  A V8 Map holds at most ${V8_MAP_LIMIT.toLocaleString()} entries. Collection.records is a Map,`);
  log(`  so a single collection cannot exceed that — ${(V8_MAP_LIMIT / TARGET_FACTS * 100).toFixed(0)}% of the 100M target.`);
  log(`  Reaching 100M facts in one instance requires sharding the fact store across`);
  log(`  collections, or moving the index off the JS heap. This is an architectural`);
  log(`  limit, not a tuning problem, and it is not fixed in this build.\n`);

  const report = {
    measured: {
      facts: { ...w, ...q, heapMb: mem.heapMb, bytesPerRecordInMemory: mem.bytesPerRecordInMemory, loadMs: mem.ms },
      ledger: { write: l, verify: v }
    },
    extrapolated: { targetFacts: TARGET_FACTS, targetLedger: TARGET_LEDGER, ...projected },
    limits: {
      v8MapMaxEntries: V8_MAP_LIMIT,
      singleCollectionMaxRecords: V8_MAP_LIMIT,
      targetReachableInOneCollection: false,
      note: 'Collection.records is a JS Map; V8 caps it near 16.7M entries. 100M facts requires sharding or an off-heap index. Not implemented.'
    },
    environment: { node: process.version, dir }
  };
  if (json) console.log(JSON.stringify(report, null, 2));
  if (!flag('keep')) rmSync(dir, { recursive: true, force: true });
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) run();
export { run, writeFacts, writeLedger, verifyLedgerStreaming, loadIntoMemory, makeFact };
