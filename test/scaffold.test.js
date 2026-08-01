/**
 * Adding a new connector — the scaffold has to catch the same defects
 * conformance.js catches on the 74 already shipped, before either the catalog
 * entry or the client definition is written.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { scaffoldConnector, validateScaffold } from '../src/connectors/scaffold.js';

const GOOD = {
  id: 'acme-copilot', name: 'Acme Copilot', vendor: 'Acme', category: 'chat',
  auth: 'bearer', modes: ['watch', 'inline'],
  pulls: ['conversations'], cannotPull: ['conversations from before the retention window'],
  setupMinutes: 30, scopes: ['conversations:read'], rateLimit: '60 req/min',
  channel: 'customer_chat', baseUrl: 'https://api.acme.com/v1',
  endpoints: { conversations: '/conversations' },
  credential: 'an Acme API key from the admin console'
};

describe('scaffolding a connector generates paste-ready code and validates it offline', () => {
  test('a well-formed spec produces both snippets with no problems', () => {
    const r = validateScaffold(GOOD);
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.match(r.catalogSnippet, /"acme-copilot"/);
    assert.match(r.clientSnippet, /D\("acme-copilot"/);
  });

  test('a missing required field is named, not silently defaulted', () => {
    const { rateLimit, ...missing } = GOOD;
    const r = validateScaffold(missing);
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => p.includes('rateLimit')));
  });

  test('an empty cannotPull is refused — every connector has a blind spot', () => {
    const r = validateScaffold({ ...GOOD, cannotPull: [] });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /cannotPull is empty/.test(p)));
  });

  test('an unknown auth scheme is refused by name', () => {
    const r = validateScaffold({ ...GOOD, auth: 'made_up_scheme' });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /made_up_scheme/.test(p)));
  });

  test('an unknown mode is refused', () => {
    const r = validateScaffold({ ...GOOD, modes: ['watch', 'teleport'] });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /teleport/.test(p)));
  });

  test('http baseUrl is rejected — a credential must never cross plaintext', () => {
    const r = validateScaffold({ ...GOOD, baseUrl: 'http://api.acme.com/v1' });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /plaintext/.test(p)));
  });

  test('an endpoint that is not a rooted path is rejected', () => {
    const r = validateScaffold({ ...GOOD, endpoints: { conversations: 'conversations' } });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /must start with \//.test(p)));
  });

  test('an oauth scheme with no tokenUrl is rejected — the assertion has nowhere to go', () => {
    const r = validateScaffold({ ...GOOD, auth: 'oauth2_client_credentials' });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /tokenUrl/.test(p)));
  });

  test('an oauth scheme with a tokenUrl passes that check', () => {
    const r = validateScaffold({ ...GOOD, auth: 'oauth2_client_credentials', tokenUrl: 'https://api.acme.com/oauth/token' });
    assert.equal(r.ok, true, JSON.stringify(r.problems));
  });

  test('a webhook with no signature scheme is rejected', () => {
    const r = validateScaffold({ ...GOOD, webhook: { header: 'x-signature' } });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => /signature scheme/.test(p)));
  });

  test('an in-process connector (no baseUrl) skips the HTTP checks entirely', () => {
    const r = validateScaffold({ ...GOOD, auth: 'in_process', baseUrl: null, endpoints: {} });
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.ok(r.checks.includes('in_process_or_webhook_only'));
  });

  test('scaffoldConnector alone never throws on a garbage spec — the CLI reports problems, not a stack trace', () => {
    assert.doesNotThrow(() => scaffoldConnector({}));
  });
});
