#!/usr/bin/env node
/**
 * Attack the gate and print what got through.
 *
 *   node bin/vault-redteam.js [--json] [--channel <name>]
 *   node bin/vault-redteam.js --watch [--interval-ms 21600000]
 *
 * Exit code 0 = met the thresholds below, 1 = did not.
 *
 * --watch keeps running on a schedule instead of once, alerting when either
 * published number is breached AND when either moves materially against the
 * previous run, because a fall from 100% to 98.2% passes and is still the most
 * important thing that happened that week.
 *
 * The agent is registered with a write budget above the corpus size and scope
 * over every folder on purpose. This run measures the DETECTORS: if the agent
 * were rate-limited or narrowly scoped, writes would be held for reasons that
 * have nothing to do with whether the gate understood the payload, and the
 * catch rate would drift up towards 100% while meaning nothing at all.
 */
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { runRedTeam, renderRedTeam, buildCorpus, recordRedTeamRun } from '../src/security/redteam.js';
import { RedTeamWatchdog, runOnce } from '../src/security/watchdog.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const chIdx = args.indexOf('--channel');
const channel = chIdx >= 0 ? args[chIdx + 1] : 'phone_call_authenticated';
const watch = args.includes('--watch');
const ivIdx = args.indexOf('--interval-ms');

/** Published thresholds. Falling below either fails the run. */
export const THRESHOLDS = { catchRate: 0.98, falsePositiveRate: 0.10 };

const vault = new Vault({
  signingKey: Ledger.newSigningKey(),
  administrators: ['redteam-operator'],
  seedRules: false
});

vault.registerAgent({
  id: 'redteam-agent',
  name: 'red team',
  purpose: 'adversarial testing of the gate',
  businessOwner: 'Security',
  technicalOwner: 'Security',
  department: 'security',
  mode: 'inline',
  pinnedModel: 'redteam-harness',
  folders: ['sales/', 'support/', 'finance/', 'company/', 'marketing/', 'engineering/', 'legal/', 'hr/', 'security/'],
  rateLimitPerHour: buildCorpus().length * 4
});

const credential = vault.issueCredential('redteam-agent', {}).credential;

// --watch turns the suite from a command somebody has to remember into a
// control with a run history, which is what "when did this last pass" needs.
if (watch) {
  const intervalMs = ivIdx >= 0 ? Number(args[ivIdx + 1]) : 6 * 60 * 60 * 1000;
  const watchdog = new RedTeamWatchdog({
    vault,
    intervalMs,
    run: () => runOnce({ channel }),
    onReport: (entry) => {
      if (json) { console.log(JSON.stringify(entry, null, 2)); return; }
      const stamp = new Date(entry.at).toISOString();
      console.log(`${stamp}  ${entry.ok ? 'PASS' : 'FAIL'}  ${entry.summary ?? entry.error}`);
      for (const f of entry.failures ?? []) console.log(`            ! ${f}`);
      for (const d of entry.drifts ?? []) console.log(`            ~ regression: ${d}`);
    }
  });
  console.log(`watching — the adversarial suite runs now and every ${intervalMs}ms. Ctrl-C to stop.\n`);
  watchdog.start();
  process.on('SIGINT', () => { watchdog.stop(); process.exit(0); });
} else {
  runSingle();
}

function runSingle() {
const report = runRedTeam({ vault, credential, agentId: 'redteam-agent', channel });

// File it against the compliance record, so the insurance pack stops reporting
// "no adversarial testing" as an open gap on the strength of an actual run.
if (vault.comply) recordRedTeamRun(vault.comply, report, 'redteam-operator');

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(renderRedTeam(report));
}

const failures = [];
if (report.contaminated) failures.push(`${report.rateLimitedWrites} writes were rate-limited — the run is not measuring content`);
if (report.attacks.catchRate < THRESHOLDS.catchRate) {
  failures.push(`catch rate ${(report.attacks.catchRate * 100).toFixed(1)}% is below the published ${(THRESHOLDS.catchRate * 100).toFixed(0)}%`);
}
if (report.benign.falsePositiveRate > THRESHOLDS.falsePositiveRate) {
  failures.push(`false-positive rate ${(report.benign.falsePositiveRate * 100).toFixed(1)}% is above the published ${(THRESHOLDS.falsePositiveRate * 100).toFixed(0)}%`);
}

if (failures.length) {
  if (!json) {
    console.log('');
    console.log('FAILED');
    for (const f of failures) console.log(`  · ${f}`);
  }
  process.exit(1);
}
}
