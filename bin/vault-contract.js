#!/usr/bin/env node
/**
 * Check Vault's endpoints against each vendor's own published OpenAPI spec.
 *
 *   node bin/vault-contract.js [--json] [--offline]
 *
 * Exit 0 = every checkable connector matches its vendor's contract.
 */
import { runContractChecks } from '../src/connectors/specs.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const report = await runContractChecks({ allowNetwork: !args.includes('--offline') });

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log('PROVIDER CONTRACT CHECK');
  console.log('='.repeat(78));
  for (const r of report.results) {
    console.log(`  ${r.ok ? 'OK  ' : 'FAIL'} ${r.vendor.padEnd(10)} ${r.checked} endpoint(s) · spec from ${r.specFrom}`);
    for (const e of r.endpoints) console.log(`         ${e.found ? '✓' : '✗'} ${e.key} → ${e.path}`);
    for (const p of r.problems) console.log(`         ! ${p.check}: ${p.detail}`);
  }
  for (const s of report.skipped) console.log(`  SKIP ${s.vendor.padEnd(10)} ${s.reason}`);
  console.log('');
  console.log('-'.repeat(78));
  console.log(report.statement);
}
process.exit(report.contractFailed ? 1 : 0);
