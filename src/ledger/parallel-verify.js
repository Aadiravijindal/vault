/**
 * Full-corpus chain verification, in parallel.
 *
 * Measured single-threaded rate on this hardware is ~163,000 entries/sec. At
 * the stated 10B-entry target that is 17 hours, against a stated target of
 * "full-corpus chain verification under one hour". That is a miss, and no
 * amount of tuning the inner loop closes a 17× gap.
 *
 * The way it closes is parallelism, and a hash chain admits it despite looking
 * strictly sequential. The trick is that verifying a chain is two independent
 * claims:
 *
 *   1. every entry's content hash matches its body        — per-entry, local
 *   2. every entry's prevHash matches the previous hash   — pairwise, local
 *
 * Neither needs the whole prefix. A worker handed lines [a,b) can check both
 * claims for every pair inside its own range, and report the two facts the
 * parent needs to stitch ranges together: the prevHash of its first entry and
 * the hash of its last. The parent then checks that worker[i].firstPrevHash
 * equals worker[i-1].lastHash. If every range is internally sound and every
 * seam matches, the whole chain is sound — the same argument as verifying a
 * linked list by checking every link exactly once, just with the links
 * distributed.
 *
 * This is exact, not a sample. Every entry is hashed, every link compared. The
 * only thing that changes is which core does it.
 *
 * Splitting is by byte offset, then advanced to the next newline, so a worker
 * never sees a torn line. Ranges are contiguous and cover the file exactly.
 */
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { createReadStream, statSync, openSync, readSync, closeSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { availableParallelism } from 'node:os';
import { fileURLToPath } from 'node:url';

/**
 * Imported, deliberately, rather than reimplemented.
 *
 * The first version of this file reimplemented `canonical`, `hashObject` and
 * `chainHash` locally so it would have no dependencies. The canonicaliser came
 * out byte-identical; `chainHash` did not — it joined with `|` where the real
 * one joins with a newline. Every entry then failed verification, which at
 * least failed loudly. A divergence in the other direction — a verifier that
 * accepts what the writer produces AND accepts something else — is the one that
 * matters, and reimplementing a hash is how you get it. There is exactly one
 * definition of the chain in this codebase and this reads it.
 *
 * `bin/vault-verify.js` is the separate case: it must run with no Vault code at
 * all, so it carries its own copy on purpose, and its round-trip against a real
 * export is what keeps that copy honest.
 */
import { hashObject, chainHash } from '../util/crypto.js';

/**
 * Move `offset` forward to just after the next newline, so a range always
 * begins at a line boundary. Returns the file size if none remains.
 */
function alignToLine(path, offset, size) {
  if (offset <= 0) return 0;
  if (offset >= size) return size;
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(64 * 1024);
    let at = offset;
    while (at < size) {
      const read = readSync(fd, buf, 0, Math.min(buf.length, size - at), at);
      if (read <= 0) return size;
      const nl = buf.subarray(0, read).indexOf(0x0a);
      if (nl !== -1) return at + nl + 1;
      at += read;
    }
    return size;
  } finally { closeSync(fd); }
}

/** Verify one byte range. Runs in a worker; exported for the single-threaded path. */
export async function verifyRange(path, start, end, { maxProblems = 100 } = {}) {
  const problems = [];
  let problemCount = 0;
  // Bounded. A corrupted file can make every line a problem, and a verifier
  // that dies of its own findings reports nothing at all — the count is what
  // matters for the verdict, the first few are what matter for the diagnosis.
  const note = (p) => { problemCount++; if (problems.length < maxProblems) problems.push(p); };
  let checked = 0;
  let firstPrevHash = null;
  let firstSeq = null;
  let lastHash = null;
  let lastSeq = null;

  const stream = createReadStream(path, { start, end: end - 1, encoding: 'utf8' });
  const lines = createInterface({ input: stream, crlfDelay: Infinity });

  for await (const line of lines) {
    if (!line.trim()) continue;
    let e;
    try { e = JSON.parse(line); } catch { note({ problem: 'unparseable_line', at: checked }); continue; }
    checked++;

    const { id, contentHash, prevHash, hash, signature, _v, _created, _updated, ...body } = e;
    if (hashObject(body) !== contentHash) {
      note({ seq: e.seq, problem: 'content_hash_mismatch' });
    }
    if (chainHash(prevHash, contentHash) !== hash) {
      note({ seq: e.seq, problem: 'chain_hash_mismatch' });
    }
    if (lastHash !== null && prevHash !== lastHash) {
      note({ seq: e.seq, problem: 'broken_link', expectedPrev: lastHash, actualPrev: prevHash });
    }
    if (firstPrevHash === null) { firstPrevHash = prevHash; firstSeq = e.seq; }
    lastHash = hash;
    lastSeq = e.seq;
  }
  return { checked, problems, problemCount, firstPrevHash, firstSeq, lastHash, lastSeq };
}

/**
 * Verify the whole file across `workers` threads.
 *
 * @param {string} path a JSONL ledger export, one entry per line, in seq order
 * @param {{workers?:number, genesis?:string}} [opts]
 */
export async function verifyParallel(path, { workers = availableParallelism(), genesis = 'GENESIS' } = {}) {
  const started = Date.now();
  const size = statSync(path).size;
  if (size === 0) return { ok: true, checked: 0, problems: [], workers: 0, ms: 0 };

  const n = Math.max(1, Math.min(workers, Math.ceil(size / (1024 * 1024))));
  const bounds = [0];
  for (let i = 1; i < n; i++) bounds.push(alignToLine(path, Math.floor((size * i) / n), size));
  bounds.push(size);
  // Aligning can collapse two boundaries onto each other on a small file.
  const ranges = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    if (bounds[i + 1] > bounds[i]) ranges.push([bounds[i], bounds[i + 1]]);
  }

  const self = fileURLToPath(import.meta.url);
  const results = await Promise.all(ranges.map(([start, end], i) =>
    (n === 1
      ? verifyRange(path, start, end)
      : new Promise((resolve, reject) => {
        const w = new Worker(self, { workerData: { path, start, end, index: i } });
        w.once('message', resolve);
        w.once('error', reject);
      }))
  ));

  const problems = [];
  let problemCount = 0;
  let checked = 0;
  for (const r of results) {
    checked += r.checked;
    problemCount += r.problemCount ?? r.problems.length;
    for (const p of r.problems) if (problems.length < 100) problems.push(p);
  }

  // Stitch the seams. This is the only part that is inherently sequential, and
  // it is O(number of workers), not O(entries).
  const nonEmpty = results.filter((r) => r.checked > 0);
  for (let i = 0; i < nonEmpty.length; i++) {
    const expected = i === 0 ? genesis : nonEmpty[i - 1].lastHash;
    if (nonEmpty[i].firstPrevHash !== expected) {
      problemCount++;
      problems.push({
        seq: nonEmpty[i].firstSeq,
        problem: i === 0 ? 'chain_does_not_start_at_genesis' : 'broken_link_at_range_seam',
        expectedPrev: expected,
        actualPrev: nonEmpty[i].firstPrevHash
      });
    }
  }

  const ms = Date.now() - started;
  return {
    ok: problemCount === 0,
    checked,
    problems,
    problemCount,
    workers: ranges.length,
    ms,
    entriesPerSecond: ms > 0 ? Math.round((checked / ms) * 1000) : checked
  };
}

// Worker entry point.
if (!isMainThread && workerData?.path) {
  verifyRange(workerData.path, workerData.start, workerData.end)
    .then((r) => parentPort.postMessage(r))
    .catch((e) => parentPort.postMessage({ checked: 0, problems: [{ problem: 'worker_error', error: e.message }], problemCount: 1, firstPrevHash: null, lastHash: null }));
}
