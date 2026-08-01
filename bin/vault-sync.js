#!/usr/bin/env node
/**
 * Continuous sync — pull every connected connector's new events through the
 * gate, on a schedule, without anyone calling vault_remember by hand.
 *
 *   node bin/vault-sync.js [--data ./data] [--watch] [--interval 300000] [--json]
 *
 * One pass by default. --watch runs forever (Ctrl-C to stop), polling every
 * --interval ms (default 5 minutes).
 *
 * This does not invent a vendor response shape. Only connectors whose shape is
 * confirmed elsewhere in the codebase (the same three the contract test checks
 * against a published OpenAPI spec) are actually polled here; every other
 * connected connector is reported skipped, by name, with why — see
 * src/connectors/sync.js for the reasoning.
 */
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { SyncScheduler, syncCoverage } from '../src/connectors/sync.js';

const args = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
};

const DATA = resolve(String(flag('data', './data')));
const KEYFILE = join(DATA, 'signing-key.json');
const json = args.includes('--json');
const watch = args.includes('--watch');
const intervalMs = Number(flag('interval', 5 * 60 * 1000));

let signingKey;
if (existsSync(KEYFILE)) {
  signingKey = JSON.parse(readFileSync(KEYFILE, 'utf8'));
} else {
  signingKey = Ledger.newSigningKey();
  mkdirSync(DATA, { recursive: true });
  writeFileSync(KEYFILE, JSON.stringify(signingKey, null, 2), { mode: 0o600 });
}
const vault = new Vault({ dir: DATA, signingKey, administrators: [process.env.VAULT_ADMIN || 'admin'] });

function render(report) {
  if (json) { console.log(JSON.stringify(report, null, 2)); return; }
  console.log(`CONTINUOUS SYNC — pass at ${new Date(report.at).toISOString()}`);
  console.log('='.repeat(78));
  for (const r of report.synced) {
    console.log(`  OK   ${r.name.padEnd(28)} polled ${r.polled} · ingested ${r.ingested} · held ${r.held} · blocked ${r.blocked} · dup ${r.duplicates}`);
  }
  for (const r of report.errored) console.log(`  FAIL ${r.name.padEnd(28)} ${r.error}`);
  for (const r of report.skipped) console.log(`  SKIP ${(r.name ?? r.id).padEnd(28)} ${r.reason}`);
  console.log('');
  console.log('-'.repeat(78));
  console.log(report.statement);
}

const scheduler = new SyncScheduler({ connectors: vault.connectors, intervalMs, onReport: render });

if (!json) {
  const cov = syncCoverage();
  console.log(cov.statement);
  console.log('');
}

if (watch) {
  console.log(`watching — polling every ${intervalMs}ms, Ctrl-C to stop\n`);
  scheduler.start();
  process.on('SIGINT', () => { scheduler.stop(); process.exit(0); });
} else {
  await scheduler.runOnce();
}
