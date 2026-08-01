#!/usr/bin/env node
/**
 * Scaffold and validate a new connector before it is added to the catalog.
 *
 *   node bin/vault-add-connector.js <spec.json> [--json]
 *
 * spec.json carries the facts that are specific to the new vendor — see
 * src/connectors/scaffold.js for the full field list and an example below.
 * Exit 0 and the two ready-to-paste snippets if it validates; exit 1 and the
 * named problems if it doesn't. Nothing is written to catalog.js or
 * clients.js — this only generates and checks.
 *
 * Example spec.json:
 * {
 *   "id": "acme-copilot", "name": "Acme Copilot", "vendor": "Acme",
 *   "category": "chat", "auth": "bearer", "modes": ["watch", "inline"],
 *   "pulls": ["conversations", "attachments"],
 *   "cannotPull": ["conversations from before the retention window"],
 *   "setupMinutes": 30, "scopes": ["conversations:read"], "rateLimit": "60 req/min",
 *   "channel": "customer_chat", "baseUrl": "https://api.acme.com/v1",
 *   "endpoints": { "conversations": "/conversations" },
 *   "credential": "an Acme API key from the admin console"
 * }
 */
import { readFileSync } from 'node:fs';
import { validateScaffold } from '../src/connectors/scaffold.js';

const args = process.argv.slice(2);
const json = args.includes('--json');
const file = args.find((a) => !a.startsWith('--'));

if (!file) {
  console.error('usage: node bin/vault-add-connector.js <spec.json> [--json]');
  process.exit(2);
}

const spec = JSON.parse(readFileSync(file, 'utf8'));
const r = validateScaffold(spec);

if (json) {
  console.log(JSON.stringify(r, null, 2));
} else {
  console.log(`NEW CONNECTOR: ${spec.id ?? '(no id)'}`);
  console.log('='.repeat(78));
  console.log(`  checks run: ${r.checks.join(', ')}`);
  if (r.problems.length) {
    console.log('');
    console.log('PROBLEMS');
    console.log('-'.repeat(78));
    for (const p of r.problems) console.log(`  ✗ ${p}`);
  }
  if (r.ok) {
    console.log('');
    console.log('PASTE INTO src/connectors/catalog.js — CONNECTORS array');
    console.log('-'.repeat(78));
    console.log(r.catalogSnippet);
    console.log('');
    console.log('PASTE INTO src/connectors/clients.js — CLIENTS array');
    console.log('-'.repeat(78));
    console.log(r.clientSnippet);
    console.log('');
    console.log('-'.repeat(78));
    console.log('This validates the request shape offline, the same class of check conformance.js runs.');
    console.log('It does not verify against the vendor\'s real API — run vault conformance after pasting,');
    console.log('and vault contract if the vendor publishes a machine-readable OpenAPI spec.');
  }
}

process.exit(r.ok ? 0 : 1);
