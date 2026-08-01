/**
 * Provider-contract checks, and the OWASP mapping.
 *
 * These tests must run offline, so they use a spec fixture rather than the
 * network. The network path is exercised by bin/vault-contract.js, which caches
 * to disk; a CI box with no egress still gets a real answer from the cache and
 * an honest "skipped" when there is none.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { verifyAgainstSpec, serversOf, SPEC_SOURCES, runContractChecks } from '../src/connectors/specs.js';
import { CLIENTS } from '../src/connectors/clients.js';
import { OWASP_AGENTIC_2026, ATTACK_FAMILIES } from '../src/security/redteam.js';

/** A spec shaped like GitHub's, covering exactly what the connector calls. */
const githubish = {
  openapi: '3.0.3',
  info: { version: 'fixture' },
  servers: [{ url: 'https://api.github.com' }],
  paths: {
    '/app/installations': { get: {} },
    '/installation/repositories': { get: {} },
    '/repos/{owner}/{repo}/events': { get: {} }
  }
};

describe('endpoints are checked against the vendor contract', () => {
  test('a connector whose paths all exist passes', () => {
    const r = verifyAgainstSpec('copilot-agent', githubish);
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.equal(r.checked, 3);
    assert.ok(r.endpoints.every((e) => e.found));
  });

  test('an invented path fails', () => {
    const spec = { ...githubish, paths: { '/app/installations': { get: {} } } };
    const r = verifyAgainstSpec('copilot-agent', spec);
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => p.check === 'endpoint_exists'));
  });

  test('a host the vendor does not declare fails', () => {
    const spec = { ...githubish, servers: [{ url: 'https://api.example.invalid' }] };
    const r = verifyAgainstSpec('copilot-agent', spec);
    assert.ok(r.problems.some((p) => p.check === 'server_declared'));
  });

  test('placeholder NAMES are ours; only the path shape is the contract', () => {
    // Twilio's spec says {AccountSid}; Vault says {accountSid}. Same path.
    const spec = {
      openapi: '3.0.1',
      servers: [{ url: 'https://api.twilio.com' }],
      paths: {
        '/2010-04-01/Accounts/{AccountSid}/Calls.json': { get: {} },
        '/2010-04-01/Accounts/{AccountSid}/Recordings.json': { get: {} }
      }
    };
    const r = verifyAgainstSpec('twilio', spec);
    assert.equal(r.ok, true, JSON.stringify(r.problems));
  });

  test('Swagger 2 host/basePath is read as a server', () => {
    assert.deepEqual(serversOf({ host: 'slack.com', basePath: '/api', schemes: ['https'] }),
      ['https://slack.com/api']);
  });

  test('every registered spec source names a real connector', () => {
    for (const id of Object.keys(SPEC_SOURCES)) {
      assert.ok(CLIENTS[id], `${id} has a spec source but no client`);
    }
  });

  test('an unreachable spec is skipped, never counted as a pass', async () => {
    const dead = async () => { throw new Error('network disabled'); };
    const r = await runContractChecks({ fetchImpl: dead, allowNetwork: true });
    // With no cache the run skips; with a warm cache it passes. Either way the
    // two must add up, and a skip must never inflate contractPassed.
    assert.equal(r.contractChecked + r.skipped.length, Object.keys(SPEC_SOURCES).length);
    assert.ok(r.contractPassed <= r.contractChecked);
  });

  test('the statement never lets a contract check pass for a live one', async () => {
    const r = await runContractChecks({ allowNetwork: false });
    assert.match(r.statement, /still not a live test/);
    assert.ok(r.liveVerified <= r.totalConnectors);
  });
});

describe('the OWASP Top 10 for Agentic Applications mapping', () => {
  test('all ten risks are present', () => {
    const ids = Object.keys(OWASP_AGENTIC_2026);
    assert.equal(ids.length, 10);
    for (let i = 1; i <= 10; i++) {
      assert.ok(ids.includes(`ASI${String(i).padStart(2, '0')}`), `ASI${i} missing`);
    }
  });

  test('every family maps to a risk that exists', () => {
    for (const f of ATTACK_FAMILIES) {
      assert.ok(Array.isArray(f.owasp) && f.owasp.length, `${f.id} has no OWASP mapping`);
      for (const id of f.owasp) assert.ok(OWASP_AGENTIC_2026[id], `${f.id} maps to unknown ${id}`);
    }
  });

  test('a risk Vault does not address says so instead of claiming coverage', () => {
    // ASI05 is code execution. Memory governance does not address it, and a
    // coverage table that implied otherwise would be the overclaim this
    // product exists to prevent.
    assert.equal(OWASP_AGENTIC_2026.ASI05.inScope, false);
    const claiming = ATTACK_FAMILIES.filter((f) => f.owasp.includes('ASI05'));
    assert.equal(claiming.length, 0, 'no family may claim to exercise an out-of-scope risk');
  });

  test('in-scope risks are actually exercised by the corpus', () => {
    const exercised = new Set(ATTACK_FAMILIES.flatMap((f) => f.owasp));
    const unexercised = Object.entries(OWASP_AGENTIC_2026)
      .filter(([id, m]) => m.inScope === true && !exercised.has(id))
      .map(([id]) => id);
    assert.deepEqual(unexercised, [],
      `in-scope risks with no attacks: ${unexercised.join(', ')}`);
  });
});
