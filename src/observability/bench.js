/**
 * Latency and scale measurement (§30 non-functionals).
 *
 * The spec states targets: p50/p95/p99 on the read path, ingest throughput, and
 * behaviour at 100M facts / 10B ledger entries / 50TB. I do not have a machine
 * that can hold 100M facts, and I am not going to pretend otherwise. What I can
 * build — and what is actually more useful — is a harness that measures the
 * real thing at whatever scale it is pointed at, reports the scale it actually
 * reached, and refuses to extrapolate beyond it.
 *
 * Three rules, all of them about not lying with numbers:
 *
 * 1. **Percentiles come from every sample, not a running average.** An average
 *    latency hides exactly the tail the p99 target exists to catch.
 * 2. **The measured ceiling is reported as the measured ceiling.** If the run
 *    reached 50,000 facts, the report says 50,000 — it does not say "scales to
 *    100M" because the curve looked flat.
 * 3. **Growth is characterised, not assumed.** The harness measures latency at
 *    several sizes and fits the observed shape (flat / logarithmic / linear /
 *    worse). If it looks linear, that is a finding, not something to smooth
 *    over — linear read latency is what makes a system fall over at scale.
 */
import { now, iso } from '../util/time.js';

/**
 * A latency sample set that keeps every observation.
 *
 * Reservoir sampling or a t-digest would use less memory, but both introduce
 * error precisely in the tail. For benchmark runs the memory is affordable and
 * the exactness is the point.
 */
export class Samples {
  constructor(name) {
    this.name = name;
    /** @type {number[]} */
    this.values = [];
    this.errors = 0;
    this.startedAt = null;
    this.endedAt = null;
  }

  /** Time one operation. Failures are counted, never silently dropped. */
  time(fn) {
    const t0 = process.hrtime.bigint();
    try {
      const out = fn();
      this.values.push(Number(process.hrtime.bigint() - t0) / 1e6);
      return out;
    } catch (e) {
      // A failed operation is not a fast operation. Counting it as a sample
      // would make an error storm look like a performance improvement.
      this.errors++;
      throw e;
    }
  }

  /** Same, but a throw is recorded and swallowed — for adversarial sweeps. */
  tryTime(fn) {
    try { return { ok: true, value: this.time(fn) }; } catch (e) { return { ok: false, error: e.message }; }
  }

  percentile(p) {
    if (!this.values.length) return null;
    const sorted = [...this.values].sort((a, b) => a - b);
    // Nearest-rank. For p99 over 100 samples this picks the 99th, which is the
    // conservative reading — no interpolation flattering the tail.
    const rank = Math.ceil((p / 100) * sorted.length);
    return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
  }

  report() {
    const n = this.values.length;
    if (!n) return { name: this.name, samples: 0, errors: this.errors, note: 'no successful operations to measure' };
    const sorted = [...this.values].sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    const wall = this.startedAt && this.endedAt ? this.endedAt - this.startedAt : null;
    return {
      name: this.name,
      samples: n,
      errors: this.errors,
      // Errors matter to how a number should be read: 100 fast operations of
      // which 40 threw is not a p99 anybody should quote.
      errorRate: this.errors ? Number((this.errors / (n + this.errors)).toFixed(4)) : 0,
      min: round(sorted[0]),
      p50: round(this.percentile(50)),
      p95: round(this.percentile(95)),
      p99: round(this.percentile(99)),
      max: round(sorted[n - 1]),
      mean: round(sum / n),
      // Tail amplification, the standard reading: how much worse the 99th
      // percentile is than the median. Reported next to the mean precisely so
      // nobody quotes the mean alone.
      tailRatio: round(this.percentile(99) / this.percentile(50)),
      throughputPerSecond: wall ? Math.round((n / wall) * 1000) : null,
      wallClockMs: wall ? round(wall) : null
    };
  }
}

const round = (n) => (n == null ? null : Number(n.toFixed(3)));

/** The spec's stated budgets, so a run says pass/fail rather than leaving it to the reader. */
export const BUDGETS = {
  read_p50: { ms: 50, what: 'read path, median' },
  read_p95: { ms: 200, what: 'read path, 95th percentile' },
  read_p99: { ms: 500, what: 'read path, 99th percentile' },
  gate_p50: { ms: 100, what: 'gate decision, median' },
  gate_p95: { ms: 400, what: 'gate decision, 95th percentile' },
  gate_p99: { ms: 1000, what: 'gate decision, 99th percentile' },
  search_p95: { ms: 300, what: 'search query, 95th percentile' },
  ledger_append_p95: { ms: 20, what: 'ledger append, 95th percentile' },
  ledger_verify_per_1k: { ms: 500, what: 'ledger verification, per 1000 entries' }
};

/**
 * Characterise how a measurement grows with size.
 *
 * Given [{size, ms}] at increasing sizes, decide whether the relationship looks
 * flat, logarithmic, linear or worse. This is the number that actually predicts
 * behaviour at 100M — far more honestly than running at 100M once and quoting
 * the result.
 */
export function growth(points) {
  const usable = points.filter((p) => p.size > 0 && p.ms != null && p.ms > 0);
  if (usable.length < 3) {
    return { shape: 'unknown', confidence: 'none', note: `need at least 3 size points, have ${usable.length}` };
  }
  const first = usable[0];
  const last = usable[usable.length - 1];
  const sizeRatio = last.size / first.size;
  const timeRatio = last.ms / first.ms;
  if (sizeRatio < 4) {
    return { shape: 'unknown', confidence: 'none', sizeRatio: round(sizeRatio), note: 'the size range is too narrow to tell the shapes apart — re-run with a wider spread' };
  }

  // Compare the observed time ratio against what each shape predicts.
  const predictions = {
    flat: 1,
    logarithmic: Math.log(last.size) / Math.log(first.size),
    linear: sizeRatio,
    quadratic: sizeRatio ** 2
  };
  let best = 'flat';
  let bestError = Infinity;
  for (const [shape, predicted] of Object.entries(predictions)) {
    const error = Math.abs(Math.log(timeRatio / predicted));
    if (error < bestError) { bestError = error; best = shape; }
  }

  return {
    shape: best,
    sizeRatio: round(sizeRatio),
    timeRatio: round(timeRatio),
    confidence: bestError < 0.35 ? 'good' : bestError < 0.8 ? 'weak' : 'poor',
    points: usable.map((p) => ({ size: p.size, ms: round(p.ms) })),
    verdict: {
      flat: 'Latency is independent of size. This is what an indexed lookup should look like.',
      logarithmic: 'Latency grows with the logarithm of size. Fine at any realistic scale.',
      linear: 'Latency grows in proportion to size. This does NOT hold at 100M — it is the shape that falls over.',
      quadratic: 'Latency grows faster than size. This is a defect, not a scaling characteristic.'
    }[best],
    // The honest caveat, stated every time.
    caveat: 'Extrapolation from a measured range predicts; it does not prove. The only proof at 100M facts is a run at 100M facts.'
  };
}

/**
 * The benchmark suite.
 *
 * Everything here drives the real product through its public API. There are no
 * shortcut paths, no pre-warmed caches and no writes that skip the gate,
 * because a benchmark that avoids the expensive part measures nothing.
 */
export class Benchmark {
  /**
   * @param {object} o
   * @param {() => {vault: import('../index.js').Vault, credential: string, agentId: string}} o.factory
   */
  constructor({ factory, onProgress = () => {} }) {
    this.factory = factory;
    this.onProgress = onProgress;
    this.env = {
      node: process.version,
      platform: `${process.platform}/${process.arch}`,
      cpus: (() => { try { return require('node:os').cpus().length; } catch { return null; } })(),
      startedAt: iso()
    };
  }

  /**
   * Write `n` conversations through the real gate, measuring each.
   * @returns {{ingest: object, facts: number, held: number, blocked: number}}
   */
  ingestRun({ n = 1000, vault, credential, agentId, folder = 'sales/accounts/' } = {}) {
    const s = new Samples('ingest');
    s.startedAt = now();
    let blocked = 0;
    for (let i = 0; i < n; i++) {
      const text = phrase(i);
      const r = s.tryTime(() => vault.ingest({
        agentId, channel: 'system_of_record',
        participants: [{ name: 'Dana Whitfield', kind: 'employee', internal: true }],
        turns: [{ speaker: 'Dana Whitfield', text }]
      }, { credential, folderHint: folder, sampleRoll: 0 }));
      if (!r.ok) blocked++;
      if (i % 250 === 0) this.onProgress({ phase: 'ingest', done: i, total: n });
    }
    s.endedAt = now();
    const all = vault.facts.all();
    return {
      ingest: s.report(),
      facts: all.length,
      live: all.filter((f) => f.status === 'live').length,
      held: all.filter((f) => f.status === 'held').length,
      rejected: all.filter((f) => f.status === 'rejected').length,
      ingestErrors: blocked
    };
  }

  /** Measure the read path against whatever is currently in the store. */
  readRun({ n = 500, vault, credential, agentId, queries = null } = {}) {
    const s = new Samples('read');
    const pool = queries || ['renewal', 'seats', 'contract', 'region', 'payment terms', 'procurement', 'ticket'];
    s.startedAt = now();
    for (let i = 0; i < n; i++) {
      s.tryTime(() => vault.read(pool[i % pool.length], {
        agentId, credential, actor: agentId, clearance: 'internal', purpose: 'memory_governance'
      }));
      if (i % 250 === 0) this.onProgress({ phase: 'read', done: i, total: n });
    }
    s.endedAt = now();
    return s.report();
  }

  searchRun({ n = 300, vault, terms = null } = {}) {
    const s = new Samples('search');
    const pool = terms || ['renewal', 'seats', 'Globex', 'net-45', 'Frankfurt'];
    s.startedAt = now();
    for (let i = 0; i < n; i++) {
      s.tryTime(() => vault.search.search(pool[i % pool.length], { actor: 'bench', clearance: 'internal', role: 'security' }));
    }
    s.endedAt = now();
    return s.report();
  }

  ledgerRun({ vault } = {}) {
    const append = new Samples('ledger_append');
    append.startedAt = now();
    for (let i = 0; i < 500; i++) {
      append.tryTime(() => vault.ledger.append('admin.action', { subject: `bench-${i}`, actor: 'bench', action: 'bench.noop' }));
    }
    append.endedAt = now();

    const verify = new Samples('ledger_verify');
    verify.startedAt = now();
    const result = verify.tryTime(() => vault.verifyLedger());
    verify.endedAt = now();
    const entries = vault.ledger.entries({ limit: Infinity }).length;

    return {
      append: append.report(),
      verify: {
        ...verify.report(),
        entries,
        msPer1000: entries ? round((verify.values[0] ?? 0) / (entries / 1000)) : null,
        chainOk: result.ok ? result.value.ok : false
      }
    };
  }

  /**
   * The scaling run: measure the same operations at increasing store sizes and
   * characterise the growth.
   */
  scaleRun({ sizes = [500, 2000, 8000], readsPerSize = 200 } = {}) {
    const points = { read: [], search: [], verify: [], ingest: [] };
    const stages = [];
    const { vault, credential, agentId } = this.factory();
    try {
      let written = 0;
      for (const target of sizes) {
        const batch = target - written;
        const ing = this.ingestRun({ n: batch, vault, credential, agentId });
        written = target;

        const read = this.readRun({ n: readsPerSize, vault, credential, agentId });
        const search = this.searchRun({ n: Math.min(readsPerSize, 200), vault });
        const verify = new Samples('verify');
        verify.tryTime(() => vault.verifyLedger());

        const size = vault.facts.all().length;
        points.read.push({ size, ms: read.p95 });
        points.search.push({ size, ms: search.p95 });
        points.verify.push({ size, ms: verify.percentile(50) });
        points.ingest.push({ size, ms: ing.ingest.p95 });
        stages.push({ conversationsWritten: target, facts: size, read, search, ingest: ing.ingest });
        this.onProgress({ phase: 'scale', done: target, total: sizes[sizes.length - 1] });
      }

      return {
        stages,
        growth: {
          read: growth(points.read),
          search: growth(points.search),
          ledgerVerify: growth(points.verify),
          ingest: growth(points.ingest)
        },
        // The number that must never be inflated.
        measuredCeiling: {
          facts: vault.facts.all().length,
          ledgerEntries: vault.ledger.entries({ limit: Infinity }).length,
          conversations: vault.archive.col.all().length
        }
      };
    } finally { vault.close?.(); }
  }

  /** Compare a report against the stated budgets. */
  static grade(reports) {
    const checks = [];
    const push = (key, measured) => {
      const budget = BUDGETS[key];
      if (!budget || measured == null) return;
      checks.push({
        budget: key, what: budget.what, targetMs: budget.ms, measuredMs: round(measured),
        pass: measured <= budget.ms,
        headroom: round(budget.ms - measured)
      });
    };
    if (reports.read) { push('read_p50', reports.read.p50); push('read_p95', reports.read.p95); push('read_p99', reports.read.p99); }
    if (reports.ingest) { push('gate_p50', reports.ingest.p50); push('gate_p95', reports.ingest.p95); push('gate_p99', reports.ingest.p99); }
    if (reports.search) push('search_p95', reports.search.p95);
    if (reports.ledger?.append) push('ledger_append_p95', reports.ledger.append.p95);
    if (reports.ledger?.verify?.msPer1000 != null) push('ledger_verify_per_1k', reports.ledger.verify.msPer1000);

    const failed = checks.filter((c) => !c.pass);
    return {
      checks,
      passed: checks.length - failed.length,
      total: checks.length,
      ok: failed.length === 0,
      failed: failed.map((f) => `${f.what}: ${f.measuredMs}ms against a ${f.targetMs}ms budget`),
      note: failed.length
        ? 'Budgets were missed. These are measurements on this machine, under this load — reproduce before drawing conclusions.'
        : 'Every stated budget was met on this machine at the measured scale.'
    };
  }

  /**
   * The honesty section, attached to every report.
   *
   * This is the part that stops a benchmark becoming a marketing document.
   */
  static caveats(measuredCeiling) {
    return {
      whatWasMeasured: `A real instance driven through its public API: every write went through the gate, every read through the wall checks and every ledger append through the hash chain. Nothing was stubbed and no cache was pre-warmed.`,
      scaleReached: measuredCeiling,
      whatWasNotMeasured: [
        'The spec\'s 100M-fact / 10B-ledger-entry / 50TB targets. This harness ran at the scale reported above and nowhere near those numbers.',
        'Concurrency. These are single-process, sequential measurements; they say nothing about contention, lock waits or connection-pool behaviour under parallel load.',
        'Network latency to a customer bucket or cloud KMS. Those are round trips this run did not make.',
        'Sustained load over hours, so nothing here speaks to memory growth, GC pauses or index degradation over time.',
        'Cold-start behaviour on a large on-disk store, since the run builds its store in-process.'
      ],
      howToReadIt: 'Use the growth shape, not the absolute numbers, to predict behaviour at your scale. A flat or logarithmic shape holds; a linear one does not. Absolute figures are specific to this machine and will differ on yours.',
      howToRunItYourself: 'node bin/vault-bench.js --sizes 10000,50000,250000 --dir /fast/disk — the same harness, at whatever scale your hardware allows.'
    };
  }
}

// Deliberately varied, so reconciliation does not fold every write into one
// fact and turn an ingest benchmark into a deduplication benchmark.
const SUBJECTS = ['Globex', 'Initech', 'Umbrella', 'Soylent', 'Hooli', 'Massive Dynamic', 'Vehement Capital', 'Wonka Industries'];
const SHAPES = [
  (s, i) => `${s} has ${300 + (i % 700)} seats provisioned on the enterprise plan.`,
  (s, i) => `The ${s} renewal closes on ${1 + (i % 28)} March 2027.`,
  (s, i) => `Contract ${i % 900}-B with ${s} uses net-${15 + (i % 4) * 15} payment terms.`,
  (s, i) => `Support ticket ${4000 + i} for ${s} was resolved by restarting the ingest worker.`,
  (s, i) => `${s} moved procurement to a new lead in ${['January', 'April', 'June', 'October'][i % 4]}.`,
  (s, i) => `The ${s} account added ${1 + (i % 40)} seats in the Dublin office.`
];
function phrase(i) {
  return SHAPES[i % SHAPES.length](SUBJECTS[(i * 7) % SUBJECTS.length], i);
}
