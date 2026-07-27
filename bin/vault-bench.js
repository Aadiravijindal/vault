#!/usr/bin/env node
/**
 * Measure this build's latency and scaling characteristics.
 *
 *   node bin/vault-bench.js                          quick run, in memory
 *   node bin/vault-bench.js --sizes 5000,25000,100000  a real scaling run
 *   node bin/vault-bench.js --dir /fast/disk         on-disk, which is the honest test
 *   node bin/vault-bench.js --json report.json       machine-readable output
 *
 * The report always states what it did NOT measure. A benchmark without that
 * section is a marketing document.
 */
import { writeFileSync } from 'node:fs';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { Benchmark, growth } from '../src/observability/bench.js';

const flags = {};
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i].startsWith('--')) {
    const k = process.argv[i].slice(2);
    flags[k] = process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[++i] : true;
  }
}

const B = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const H = (s) => `\n${B(s)}\n${'─'.repeat(Math.min(78, s.length + 24))}`;

const sizes = String(flags.sizes || '500,2000,8000').split(',').map((n) => Number(n.trim())).filter(Boolean);
const reads = Number(flags.reads || 300);
const signingKey = Ledger.newSigningKey();

let created = 0;
function factory() {
  const dir = flags.dir ? `${flags.dir}/bench-${created++}` : null;
  const vault = new Vault({ dir, signingKey, administrators: ['bench-a', 'bench-b'], seedRules: false });
  vault.registerAgent({
    id: 'bench', name: 'Benchmark agent', purpose: 'measurement',
    businessOwner: 'bench', technicalOwner: 'bench', department: 'sales',
    mode: 'inline', folders: ['sales/']
  });
  const credential = vault.issueCredential('bench', { ttl: '48h' }).credential;
  return { vault, credential, agentId: 'bench' };
}

let lastPhase = '';
const bench = new Benchmark({
  factory,
  onProgress: ({ phase, done, total }) => {
    if (process.stdout.isTTY) {
      if (phase !== lastPhase) { process.stdout.write(`\n  ${phase}: `); lastPhase = phase; }
      process.stdout.write(`${done}/${total} `);
    }
  }
});

console.log(B('\nVAULT — latency and scaling measurement'));
console.log(dim(`  node ${process.version} · ${process.platform}/${process.arch} · sizes: ${sizes.join(', ')} · storage: ${flags.dir || 'in-memory'}`));

// ---- single-instance latency, at the largest requested size ----------------
console.log(H('Latency'));
const { vault, credential, agentId } = factory();
const warm = bench.ingestRun({ n: Math.min(sizes[sizes.length - 1], 2000), vault, credential, agentId });
const read = bench.readRun({ n: reads, vault, credential, agentId });
const search = bench.searchRun({ n: Math.min(reads, 200), vault });
const ledger = bench.ledgerRun({ vault });
if (process.stdout.isTTY) process.stdout.write('\n');

const table = (r) => `  ${r.name.padEnd(16)} n=${String(r.samples).padStart(6)}  p50 ${String(r.p50).padStart(8)}ms  p95 ${String(r.p95).padStart(8)}ms  p99 ${String(r.p99).padStart(8)}ms  max ${String(r.max).padStart(8)}ms${r.errors ? red(`  errors ${r.errors}`) : ''}`;
console.log(table(warm.ingest));
console.log(table(read));
console.log(table(search));
console.log(table(ledger.append));
console.log(dim(`  ledger verify: ${ledger.verify.entries} entries, ${ledger.verify.msPer1000}ms per 1000, chain ${ledger.verify.chainOk ? green('ok') : red('BROKEN')}`));
console.log(dim(`  store: ${warm.facts} facts (${warm.live} live, ${warm.held} held, ${warm.rejected} rejected)`));

const grade = Benchmark.grade({ read, ingest: warm.ingest, search, ledger });
console.log(H('Against the stated budgets'));
for (const c of grade.checks) {
  const mark = c.pass ? green('✓') : red('✗');
  console.log(`  ${mark} ${c.what.padEnd(38)} ${String(c.measuredMs).padStart(8)}ms / ${c.targetMs}ms`);
}
console.log(`  ${grade.ok ? green(grade.note) : yellow(grade.note)}`);
vault.close?.();

// ---- scaling ---------------------------------------------------------------
console.log(H('How it scales'));
const scale = bench.scaleRun({ sizes, readsPerSize: Math.min(reads, 200) });
if (process.stdout.isTTY) process.stdout.write('\n');
for (const [op, g] of Object.entries(scale.growth)) {
  const colour = g.shape === 'linear' || g.shape === 'quadratic' ? red : g.shape === 'unknown' ? dim : green;
  console.log(`  ${op.padEnd(14)} ${colour(g.shape.padEnd(12))} ${dim(`(${g.confidence} confidence)`)} ${g.verdict || g.note}`);
}
console.log(dim(`\n  measured ceiling: ${scale.measuredCeiling.facts} facts · ${scale.measuredCeiling.ledgerEntries} ledger entries · ${scale.measuredCeiling.conversations} conversations`));

// ---- the part that keeps this honest ---------------------------------------
const caveats = Benchmark.caveats(scale.measuredCeiling);
console.log(H('What this did NOT measure'));
for (const c of caveats.whatWasNotMeasured) console.log(`  · ${c}`);
console.log(`\n  ${dim(caveats.howToReadIt)}`);
console.log(`  ${dim(caveats.howToRunItYourself)}\n`);

const report = {
  environment: bench.env,
  latency: { ingest: warm.ingest, read, search, ledger },
  store: { facts: warm.facts, live: warm.live, held: warm.held, rejected: warm.rejected },
  budgets: grade,
  scaling: scale,
  caveats,
  generatedAt: new Date().toISOString()
};

if (flags.json) {
  writeFileSync(typeof flags.json === 'string' ? flags.json : 'bench-report.json', `${JSON.stringify(report, null, 2)}\n`);
  console.log(dim(`  wrote ${typeof flags.json === 'string' ? flags.json : 'bench-report.json'}\n`));
}

// A missed budget is a non-zero exit, so this can gate a release.
process.exit(grade.ok ? 0 : 1);
