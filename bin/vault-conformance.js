#!/usr/bin/env node
/**
 * Check every connector builds a request a vendor would accept.
 *
 *   node bin/vault-conformance.js [--json]
 *
 * Exit code 0 = all conform, 1 = at least one does not.
 *
 * This is not a live test and does not change the live-verified count. It
 * rules out a malformed request; only a credential rules out a vendor whose
 * API differs from its own documentation.
 */
import { generateKeyPairSync } from 'node:crypto';
import { runConformance } from '../src/connectors/conformance.js';

const json = process.argv.includes('--json');
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const report = await runConformance({ privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) });

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log('CONNECTOR CONFORMANCE');
  console.log('='.repeat(78));
  console.log(`  ${report.passed}/${report.total} conform · ${report.httpConnectors} speak HTTP · ${report.liveVerified} verified against a real vendor API`);
  if (report.failures.length) {
    console.log('');
    console.log('FAILING');
    console.log('-'.repeat(78));
    for (const f of report.failures) {
      console.log(`  ${f.id}`);
      for (const p of f.problems) console.log(`      ${p.check}: ${p.detail}`);
    }
  }
  console.log('');
  console.log('-'.repeat(78));
  console.log(report.statement);
}

process.exit(report.failed ? 1 : 0);
