#!/usr/bin/env node
/**
 * Is a model configured, is it actually there, and what does it cost you?
 *
 *   node bin/vault-model.js              status, and setup steps if not configured
 *   node bin/vault-model.js --probe      actually call it, and time it
 *   node bin/vault-model.js --json
 *
 * The default is deliberately not a probe. `available` only says the
 * configuration is complete; for a local model that is a much weaker claim
 * than it sounds, because `ollama serve` may not be running and the weights may
 * never have been pulled. --probe is the question that costs a round trip, so
 * it is the one you have to ask for.
 */
import { ModelProvider, PROVIDERS, SETUP } from '../src/ai/provider.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const doProbe = args.includes('--probe');

const provider = new ModelProvider();
const status = provider.status();

if (json && !doProbe) {
  console.log(JSON.stringify(status, null, 2));
  process.exit(status.available ? 0 : 1);
}

if (!json) {
  console.log('');
  console.log('  MODEL');
  console.log('  ─────');
  if (!status.available) {
    console.log(`  not configured — ${status.reason}`);
    console.log('');
    console.log('  Nothing is broken. Filing runs on deterministic rules and answers are');
    console.log('  composed from retrieved facts, which is a complete answer rather than a');
    console.log('  degraded one. A model makes filing understand meaning instead of keywords.');
    console.log('');
    console.log('  To run one on THIS machine — no API key, no per-token bill, and no claim');
    console.log('  leaving the building to be classified:');
    console.log('');
    for (const line of SETUP.ollama) console.log(`    ${line}`);
    console.log('');
    console.log('  Or point it at a hosted model instead:');
    console.log('');
    for (const name of Object.keys(PROVIDERS).filter((p) => !PROVIDERS[p].local)) {
      console.log(`    ${SETUP[name].join('  &&  ')}`);
    }
    console.log('');
  } else {
    console.log(`  provider   ${status.provider}${status.local ? '  (on this machine)' : '  (hosted — third party)'}`);
    console.log(`  model      ${status.model}`);
    console.log(`  endpoint   ${status.url}`);
    console.log(`  timeout    ${status.timeoutMs}ms`);
    console.log(`  calls      ${status.calls}${status.failures ? `  (${status.failures} failed)` : ''}`);
    if (status.averageMs) console.log(`  average    ${status.averageMs}ms`);
    if (status.lastError) console.log(`  lastError  ${status.lastError}`);
    console.log('');
    console.log(wrap(status.note, 74, '  '));
    console.log('');
    if (!doProbe) console.log('  Run with --probe to check the model is actually reachable.\n');
  }
}

if (doProbe) {
  if (!json) console.log('  probing…\n');
  const result = await provider.probe();
  if (json) {
    console.log(JSON.stringify({ status, probe: result }, null, 2));
  } else if (result.ok) {
    console.log(`  ✓ reachable — ${result.ms}ms for a one-word reply`);
    console.log('');
    console.log(wrap(result.note, 74, '  '));
    console.log('');
  } else {
    console.log(`  ✗ not reachable — ${result.reason}`);
    console.log('');
    if (result.setup) {
      console.log('  Try:');
      for (const line of result.setup) console.log(`    ${line}`);
      console.log('');
    }
  }
  process.exit(result.ok ? 0 : 1);
}

process.exit(status.available ? 0 : 1);

function wrap(text, width, indent = '') {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) { lines.push(line.trim()); line = w; }
    else line += ' ' + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => indent + l).join('\n');
}
