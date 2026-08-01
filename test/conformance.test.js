/**
 * Connector conformance — the part of "verified" that does not need a tenant.
 *
 * Four connectors have been run against a real vendor API. These tests do not
 * change that number and must never be quoted as if they did. What they close
 * is the class of defect that a live run would have caught on its first
 * request: a credential attached under the wrong header, a placeholder left
 * unsubstituted, a base URL that is not a URL, a webhook verifier that accepts
 * a forged signature.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { runConformance, checkConnector, syntheticVendor, placeholdersOf } from '../src/connectors/conformance.js';
import { CLIENTS, VendorClient } from '../src/connectors/clients.js';
import { CONNECTORS } from '../src/connectors/catalog.js';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });

describe('every connector builds a request a vendor would accept', () => {
  test('all of them pass conformance', async () => {
    const r = await runConformance({ privateKeyPem: PEM });
    assert.equal(r.failed, 0,
      `failing: ${JSON.stringify(r.failures.map((f) => ({ id: f.id, problems: f.problems })), null, 1)}`);
    assert.equal(r.total, CONNECTORS.length, 'every catalogued connector must have a client');
  });

  test('the statement never inflates conformance into live verification', async () => {
    const r = await runConformance({ privateKeyPem: PEM });
    assert.match(r.statement, /conformance test, not a live one/);
    assert.match(r.statement, /written from published documentation/);
    assert.equal(r.liveVerified, Object.values(CLIENTS).filter((c) => c.status === 'live').length);
    assert.ok(r.liveVerified < r.total, 'if this ever equals total, the claim must be re-earned, not assumed');
  });
});

describe('the defects conformance found', () => {
  test('a placeholder holding a whole origin is not percent-encoded', async () => {
    // Salesforce and n8n both put the operator's origin in the base URL.
    // Encoding it produced https%3A%2F%2F… and neither could have worked.
    const { fetchImpl, requests } = syntheticVendor();
    const c = new VendorClient('n8n', {
      credentials: { token: 'k' },
      vars: { instanceUrl: 'https://n8n.acme.internal' },
      fetchImpl
    });
    await c.request('executions');
    const sent = requests[requests.length - 1];
    assert.equal(sent.url, 'https://n8n.acme.internal/api/v1/executions');
    assert.ok(!sent.url.includes('%3A%2F%2F'), 'the scheme was percent-encoded into the path');
  });

  test('a token exchange that returns an origin still overrides the configured one', async () => {
    // Salesforce tells you which host to call; ignoring that would send every
    // request to the login endpoint.
    const { fetchImpl, requests } = syntheticVendor();
    const c = new VendorClient('salesforce', {
      credentials: {
        clientId: 'x', clientSecret: 'y', privateKey: PEM, privateKeyPem: PEM,
        clientEmail: 'svc@example.invalid', subject: 'runas@example.invalid'
      },
      vars: { instanceUrl: 'https://login.example.invalid' },
      fetchImpl
    });
    await c.request('query');
    const sent = requests[requests.length - 1];
    assert.ok(sent.url.startsWith('https://synthetic.example.invalid/services/data/'),
      `expected the instance_url from the token response, got ${sent.url}`);
  });

  test('an identifier dropped into a path segment IS still encoded', () => {
    // The fix must not turn every placeholder into a path-traversal hole.
    const { fetchImpl, requests } = syntheticVendor();
    const c = new VendorClient('copilot', {
      credentials: { clientId: 'x', clientSecret: 'y' },
      vars: { tenantId: 'a/../../etc', userId: 'user one' },
      fetchImpl
    });
    return c.request('interactions').then(() => {
      const sent = requests[requests.length - 1];
      assert.ok(!sent.url.includes('/../'), `path traversal survived encoding: ${sent.url}`);
      assert.ok(sent.url.includes('user%20one'), 'a space in an id must be encoded');
    });
  });

  test('a jwt_bearer connector declares where the assertion is exchanged', async () => {
    // gemini-enterprise had no tokenUrl, so it could never have authenticated.
    for (const [id, def] of Object.entries(CLIENTS)) {
      if (['oauth2_authorization_code', 'oauth2_client_credentials', 'jwt_bearer'].includes(def.auth)) {
        assert.ok(def.tokenUrl, `${id} uses ${def.auth} with no tokenUrl`);
      }
    }
  });
});

describe('conformance catches what it claims to catch', () => {
  test('a missing auth header fails', async () => {
    const r = await checkConnector('claude-enterprise', { privateKeyPem: PEM });
    assert.ok(r.checks.includes('request_authenticated'));
    assert.ok(r.checks.includes('vendor_auth_header'));
    assert.equal(r.ok, true);
  });

  test('a vendor-specific header is asserted by name, not assumed', async () => {
    // Anthropic reads x-api-key; a Bearer fallback would look fine and 401.
    const { fetchImpl, requests } = syntheticVendor();
    const c = new VendorClient('claude-enterprise', { credentials: { token: 't' }, fetchImpl });
    await c.request('models');
    const sent = requests[requests.length - 1];
    assert.equal(sent.headers['x-api-key'], 't');
    assert.equal(sent.headers['anthropic-version'], '2023-06-01');
  });

  test('every signed-webhook connector rejects a forged signature', async () => {
    const signed = Object.entries(CLIENTS).filter(([, d]) => d.webhook);
    assert.ok(signed.length > 0);
    for (const [id] of signed) {
      const c = new VendorClient(id, { credentials: { signingSecret: 'secret', token: 't' } });
      const forged = c.verifyWebhook('{"a":1}', { 'x-hub-signature-256': `sha256=${'0'.repeat(64)}` });
      assert.equal(forged.valid, false, `${id} accepted a forged signature`);
    }
  });

  test('placeholders are discovered from every URL a connector uses', () => {
    assert.deepEqual(placeholdersOf({
      baseUrl: 'https://{host}/v1', tokenUrl: 'https://{host}/oauth/{tenant}',
      endpoints: { a: '/x/{id}' }
    }).sort(), ['host', 'id', 'tenant']);
  });
});
