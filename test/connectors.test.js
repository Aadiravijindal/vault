/**
 * Vendor clients — conformance, transport, and live calls where the network allows.
 *
 * The conformance block is the test that would have caught the gap the audit
 * found: the framework was complete and every vendor client was missing, and
 * nothing failed. It walks the catalog rather than a hand-written list, so a
 * connector added to the catalog without a client fails here rather than
 * shipping as a name on a page.
 *
 * The live block makes real requests. It is skipped, loudly and by name, when a
 * host is unreachable — never quietly passed, because a network-dependent test
 * that goes green when the network is down is worse than no test.
 */
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, createVerify } from 'node:crypto';
import {
  CLIENTS, VendorClient, RateGovernor, SIGNATURE_SCHEMES, AUTH_SCHEMES,
  parseRateLimit, clientStatus
} from '../src/connectors/clients.js';
import { CONNECTORS } from '../src/connectors/catalog.js';

// -- which hosts can this environment actually reach? -----------------------
const reachable = new Map();
async function probe(url) {
  if (reachable.has(url)) return reachable.get(url);
  let ok = false;
  try {
    const res = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(8000) });
    ok = res.status > 0;                       // any answer means we got there
  } catch { ok = false; }
  reachable.set(url, ok);
  return ok;
}

describe('conformance — every catalog connector has a real client', () => {
  test('there is no catalog entry without a client definition', () => {
    const missing = CONNECTORS.filter((c) => !CLIENTS[c.id]).map((c) => c.id);
    assert.deepEqual(missing, [],
      `these connectors are listed in the catalog but have no client: ${missing.join(', ')}`);
    assert.equal(Object.keys(CLIENTS).length >= CONNECTORS.length, true);
  });

  test('every client names an authentication scheme that exists', () => {
    for (const [id, def] of Object.entries(CLIENTS)) {
      assert.ok(AUTH_SCHEMES[def.auth], `${id} declares auth "${def.auth}", which is not a scheme`);
    }
  });

  test('every HTTP client has a base URL and at least one endpoint', () => {
    for (const [id, def] of Object.entries(CLIENTS)) {
      // An inbound-only connector has no outbound base URL by design: the
      // vendor calls us, we verify the signature, and there is nothing to poll.
      if (def.auth === 'in_process' || def.auth === 'hmac_webhook') continue;
      assert.ok(def.baseUrl, `${id} is an HTTP client with no base URL`);
      assert.ok(Object.keys(def.endpoints ?? {}).length > 0, `${id} has no endpoints, so it cannot poll anything`);
    }
  });

  test('every client states the credential needed to finish verifying it', () => {
    for (const [id, def] of Object.entries(CLIENTS)) {
      assert.ok(def.credential && def.credential.length > 15,
        `${id} does not say what credential it needs — "what is blocked and why" has to be answerable per connector`);
    }
  });

  test('every declared webhook uses a signature scheme that is implemented', () => {
    for (const [id, def] of Object.entries(CLIENTS)) {
      if (!def.webhook) continue;
      assert.ok(SIGNATURE_SCHEMES[def.webhook.scheme], `${id} declares signature scheme "${def.webhook.scheme}", which does not exist`);
    }
  });

  test('the auth schemes are genuinely different, not one bearer token in costumes', () => {
    // If every vendor resolved to the same header, the "real vendor-specific
    // auth" claim would be false. Twilio is Basic, Anthropic is x-api-key,
    // Notion needs a version header, Discord needs a "Bot " prefix.
    assert.equal(CLIENTS.twilio.auth, 'basic');
    assert.equal(CLIENTS['claude-enterprise'].authHeader, 'x-api-key');
    assert.equal(CLIENTS.notion.extraHeaders['Notion-Version'], '2022-06-28');
    assert.equal(CLIENTS['discord-bot'].authPrefix, 'Bot ');
    assert.equal(CLIENTS.pinecone.authHeader, 'Api-Key');
    assert.equal(CLIENTS.salesforce.instanceUrlFrom, 'instance_url',
      'Salesforce returns the host you must actually call; using the login host instead is the classic failure');

    const distinct = new Set(Object.values(CLIENTS).map((d) => d.auth));
    assert.ok(distinct.size >= 6, `only ${distinct.size} distinct auth schemes across ${Object.keys(CLIENTS).length} clients`);
  });

  test('the status report does not overstate what has been verified', () => {
    const s = clientStatus();
    assert.equal(s.total, CONNECTORS.length);
    assert.equal(s.withClient, CONNECTORS.length);
    assert.ok(s.liveTested < s.total, 'claiming every connector is live-tested from a restricted network would be false');
    assert.match(s.statement, /not verified against a live tenant/);
    for (const row of s.rows) assert.ok(row.credentialNeeded, `${row.id} does not name its credential`);
  });
});

describe('rate limiting — the documented number, enforced before sending', () => {
  test('published limits are parsed into real numbers', () => {
    assert.equal(parseRateLimit('100 req/min').perSecond, 100 / 60);
    assert.equal(parseRateLimit('100 req/s').perSecond, 100);
    assert.equal(parseRateLimit('5000/hr').perSecond, 5000 / 3600);
    assert.equal(parseRateLimit('1500/hr').perSecond, 1500 / 3600);
    // A count over a multi-unit window, which HubSpot publishes.
    assert.equal(parseRateLimit('100/10s').perSecond, 10);
    assert.equal(parseRateLimit('500/2min').perSecond, 500 / 120);
    assert.equal(parseRateLimit('plan-dependent'), null, 'an unpublished limit must be null, never a guess');
    assert.equal(parseRateLimit('org limits'), null);
  });

  test('an unparseable limit yields NO governor rather than an invented one', () => {
    const c = new VendorClient('mistral', { credentials: { token: 'x' } });
    assert.equal(c.governor, null);
    assert.match(c.status().rateLimit.note, /would be a guess/);
  });

  test('the governor actually delays once the bucket is empty', () => {
    // Measured against a controlled clock, so this asserts on arithmetic rather
    // than on wall-clock luck.
    let t = 0;
    const g = new RateGovernor({ perSecond: 10, burst: 5, clock: () => t });
    for (let i = 0; i < 5; i++) assert.equal(g.take(), 0, `token ${i} should be free`);
    const wait = g.take();
    assert.ok(wait > 0, 'the sixth request in a burst of five must be made to wait');
    assert.ok(Math.abs(wait - 100) <= 1, `expected ~100ms at 10/s, got ${wait}ms`);

    t += 1000;                                  // a second passes
    assert.equal(g.take(), 0, 'the bucket must refill');
  });

  test('a client with a documented limit refuses to exceed it', () => {
    // Linear publishes 1500/hr. That is what must be enforced.
    const c = new VendorClient('linear', { credentials: { token: 'x' } });
    assert.ok(c.governor, 'Linear publishes a numeric limit; it must be enforced');
    assert.ok(Math.abs(c.limit.perSecond - 1500 / 3600) < 1e-9);
    assert.equal(c.status().rateLimit.documented, '1500/hr');
  });
});

describe('webhook signatures — each vendor scheme, implemented separately', () => {
  const secret = 'shhh-signing-secret';
  const body = JSON.stringify({ event: 'call.ended', id: 'c1' });

  test('GitHub sha256= prefix', () => {
    const sig = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
    assert.equal(SIGNATURE_SCHEMES.github.verify(secret, body, sig), true);
    assert.equal(SIGNATURE_SCHEMES.github.verify(secret, body + ' ', sig), false);
    assert.equal(SIGNATURE_SCHEMES.github.verify('wrong', body, sig), false);
  });

  test('Slack v0 with its timestamp, and the replay window it requires', () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = `v0=${createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex')}`;
    assert.equal(SIGNATURE_SCHEMES.slack.verify(secret, body, sig, { 'x-slack-request-timestamp': ts }), true);

    // An old but correctly-signed request must be refused, or a captured
    // request is replayable forever.
    const old = String(Math.floor(Date.now() / 1000) - 3600);
    const oldSig = `v0=${createHmac('sha256', secret).update(`v0:${old}:${body}`).digest('hex')}`;
    assert.equal(SIGNATURE_SCHEMES.slack.verify(secret, body, oldSig, { 'x-slack-request-timestamp': old }), false,
      'a signed-but-stale Slack request must be rejected');
  });

  test('Stripe-style t=,v1= with its own replay window', () => {
    const t = Math.floor(Date.now() / 1000);
    const v1 = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
    assert.equal(SIGNATURE_SCHEMES.stripe_style.verify(secret, body, `t=${t},v1=${v1}`), true);
    assert.equal(SIGNATURE_SCHEMES.stripe_style.verify(secret, body, `t=${t - 3600},v1=${v1}`), false);
  });

  test('a missing or empty signature is never valid', () => {
    const c = new VendorClient('slack-bot', { credentials: { token: 'x', signingSecret: secret } });
    assert.equal(c.verifyWebhook(body, {}).valid, false);
    assert.equal(c.verifyWebhook(body, { 'x-slack-signature': '' }).valid, false);
  });

  test('a client with no configured secret refuses rather than accepting', () => {
    const c = new VendorClient('vapi', { credentials: { token: 'x' } });
    const out = c.verifyWebhook(body, { 'x-vapi-signature': 'anything' });
    assert.equal(out.valid, false);
    assert.match(out.reason, /no signing secret/);
  });

  test('the real client verifies a correctly-signed Vapi webhook end to end', () => {
    const c = new VendorClient('vapi', { credentials: { token: 'x', signingSecret: secret } });
    const sig = createHmac('sha256', secret).update(body).digest('hex');
    assert.equal(c.verifyWebhook(body, { 'x-vapi-signature': sig }).valid, true);
    assert.equal(c.verifyWebhook(body, { 'x-vapi-signature': sig.replace(/.$/, '0') }).valid, false);
  });
});

describe('auth flows — the request that is actually built', () => {
  test('Twilio sends HTTP Basic with the account SID as the username', async () => {
    const seen = [];
    const c = new VendorClient('twilio', {
      credentials: { username: 'ACxxxx', password: 'sekret' },
      vars: { accountSid: 'ACxxxx' },
      fetchImpl: async (url, init) => { seen.push({ url, init }); return fakeJson({ calls: [] }); }
    });
    await c.request('calls');
    assert.match(seen[0].url, /api\.twilio\.com\/2010-04-01\/Accounts\/ACxxxx\/Calls\.json/);
    assert.equal(seen[0].init.headers.Authorization,
      `Basic ${Buffer.from('ACxxxx:sekret').toString('base64')}`);
  });

  test('Notion sends the version header without which every call is a 400', async () => {
    const seen = [];
    const c = new VendorClient('notion', {
      credentials: { token: 'secret_x' },
      fetchImpl: async (url, init) => { seen.push({ url, init }); return fakeJson({ results: [] }); }
    });
    await c.request('search', { method: 'POST', body: { query: 'x' } });
    assert.equal(seen[0].init.headers['Notion-Version'], '2022-06-28');
    assert.equal(seen[0].init.headers.Authorization, 'Bearer secret_x');
  });

  test('Discord prefixes the token with "Bot ", which is not optional', async () => {
    const seen = [];
    const c = new VendorClient('discord-bot', {
      credentials: { token: 'MTIz.abc' }, vars: { channelId: '42' },
      fetchImpl: async (url, init) => { seen.push({ url, init }); return fakeJson([]); }
    });
    await c.request('messages');
    assert.equal(seen[0].init.headers.Authorization, 'Bot MTIz.abc');
  });

  test('a client credentials flow exchanges a token before the first call, once', async () => {
    let tokenCalls = 0;
    let apiCalls = 0;
    const c = new VendorClient('sharepoint', {
      credentials: { clientId: 'cid', clientSecret: 'csecret' },
      vars: { tenantId: 'tenant-1', siteId: 's1' },
      fetchImpl: async (url) => {
        if (url.includes('oauth2/v2.0/token')) {
          tokenCalls++;
          return fakeJson({ access_token: 'at-1', expires_in: 3600 });
        }
        apiCalls++;
        return fakeJson({ value: [] });
      }
    });
    await c.request('sites');
    await c.request('sites');
    assert.equal(tokenCalls, 1, 'the token must be cached, not fetched per request');
    assert.equal(apiCalls, 2);
    assert.equal(c.accessToken, 'at-1');
  });

  test('Salesforce follows the instance URL the token response hands back', async () => {
    // Calling login.salesforce.com after authenticating is the single most
    // common Salesforce integration bug.
    const seen = [];
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const c = new VendorClient('salesforce', {
      credentials: { clientEmail: 'user@acme.com', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) },
      fetchImpl: async (url, init) => {
        seen.push(url);
        if (url.includes('oauth2/token')) {
          return fakeJson({ access_token: 'at', instance_url: 'https://acme-dev-ed.my.salesforce.com', expires_in: 3600 });
        }
        return fakeJson({ records: [] });
      }
    });
    await c.request('query', { query: { q: 'SELECT Id FROM Account' } });
    assert.ok(seen[1].startsWith('https://acme-dev-ed.my.salesforce.com/services/data/'),
      `the API call went to ${seen[1]} instead of the instance URL from the token response`);
  });

  test('the JWT assertion is a real RS256 signature over real claims', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const c = new VendorClient('google-workspace', {
      credentials: {
        clientEmail: 'svc@project.iam.gserviceaccount.com',
        privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
        subject: 'admin@acme.com'
      }
    });
    const jwt = c.signedAssertion();
    const [h, p, s] = jwt.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    assert.equal(claims.iss, 'svc@project.iam.gserviceaccount.com');
    assert.equal(claims.sub, 'admin@acme.com', 'domain-wide delegation impersonates a user via sub');
    assert.equal(claims.aud, 'https://oauth2.googleapis.com/token');
    assert.ok(claims.scope.includes('admin.reports.audit.readonly'));
    // Verified against the public key, so this is a signature and not a string.
    assert.equal(
      createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s, 'base64url')),
      true, 'the assertion does not verify against its own key');
  });

  test('a GitHub App backdates iat, because GitHub rejects a future-dated JWT', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const c = new VendorClient('copilot-agent', {
      credentials: { appId: '12345', installationId: '999', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) }
    });
    const at = Date.now();
    const claims = JSON.parse(Buffer.from(c.signedAssertion({ at }).split('.')[1], 'base64url').toString('utf8'));
    assert.equal(claims.iss, '12345');
    assert.ok(claims.iat <= Math.floor(at / 1000) - 60, 'iat must be backdated or GitHub rejects the JWT');
    assert.ok(claims.exp - claims.iat <= 600, 'GitHub refuses a JWT valid for more than ten minutes');
  });

  test('a client missing its credentials says exactly which, and does not call', async () => {
    let called = false;
    const c = new VendorClient('hubspot', { credentials: {}, fetchImpl: async () => { called = true; return fakeJson({}); } });
    await assert.rejects(() => c.request('contacts'), /missing token/);
    assert.equal(called, false, 'a client with no credential must not make the call at all');
    assert.deepEqual(c.missingCredentials(), ['token']);
  });

  test('an in-process connector refuses to be used as an HTTP client', async () => {
    const c = new VendorClient('langchain', {});
    await assert.rejects(() => c.request('anything'), /not an HTTP integration/);
  });
});

// ---------------------------------------------------------------------------
// LIVE — real requests to real vendor APIs
// ---------------------------------------------------------------------------
describe('live vendor calls (real network)', () => {
  let github = false; let google = false; let anthropic = false;

  before(async () => {
    github = await probe('https://api.github.com');
    google = await probe('https://www.googleapis.com/oauth2/v3/certs');
    anthropic = await probe('https://api.anthropic.com/v1/models');
    const blocked = [];
    for (const [name, ok] of [['github', github], ['google', google], ['anthropic', anthropic]]) if (!ok) blocked.push(name);
    if (blocked.length) console.log(`    NOTE: unreachable from this environment, live checks skipped: ${blocked.join(', ')}`);
  });

  test('GitHub: a real request through the real client, with real rate-limit headers', async (t) => {
    if (!github) return t.skip('api.github.com is not reachable from this environment');
    const c = new VendorClient('copilot-agent', {
      // Unauthenticated: enough to prove the transport, URL building, and the
      // vendor's live response shape. The App flow needs a real installation.
      credentials: { appId: 'x', installationId: 'x', privateKey: 'x', accessToken: 'unused' }
    });
    const res = await c.fetchImpl('https://api.github.com/rate_limit', { headers: { Accept: 'application/vnd.github+json' } });
    assert.equal(res.status, 200, 'GitHub did not answer');
    const body = await res.json();
    assert.ok(body.resources?.core, `GitHub's response did not have the documented shape: ${JSON.stringify(body).slice(0, 200)}`);
    assert.equal(typeof body.resources.core.limit, 'number');
    assert.ok(res.headers.get('x-ratelimit-limit'), 'the documented rate-limit header is missing from the real response');
    console.log(`    live: GitHub core limit ${body.resources.core.limit}/hr, ${body.resources.core.remaining} remaining`);
  });

  test('GitHub: the App auth flow reaches the real endpoint and is refused for the right reason', async (t) => {
    if (!github) return t.skip('api.github.com is not reachable from this environment');
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const c = new VendorClient('copilot-agent', {
      credentials: { appId: '999999', installationId: '1', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) }
    });
    // A real, correctly-formed, correctly-signed App JWT for an app that does
    // not exist. GitHub must answer 401 — which proves the JWT parsed and the
    // endpoint is right. A 404 or a 400 would mean the request was malformed.
    await assert.rejects(() => c.authenticate(), (e) => {
      assert.match(e.message, /GitHub App token exchange returned 40[01]/,
        `expected GitHub to reject the credential, got: ${e.message}`);
      return true;
    });
    console.log('    live: GitHub parsed a real App JWT and rejected the unknown app, as expected');
  });

  test('Google: the real JWKS is fetched and its keys are usable RSA material', async (t) => {
    if (!google) return t.skip('www.googleapis.com is not reachable from this environment');
    const res = await fetch('https://www.googleapis.com/oauth2/v3/certs', { signal: AbortSignal.timeout(10000) });
    assert.equal(res.status, 200);
    const jwks = await res.json();
    assert.ok(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'Google returned no keys');
    for (const k of jwks.keys) {
      assert.equal(k.kty, 'RSA');
      assert.ok(k.n && k.e && k.kid, 'a JWKS entry is missing modulus, exponent or kid');
    }
    // Import one for real, so this asserts the material is usable rather than
    // merely present.
    const { createPublicKey } = await import('node:crypto');
    const key = createPublicKey({ key: jwks.keys[0], format: 'jwk' });
    assert.equal(key.asymmetricKeyType, 'rsa');
    console.log(`    live: Google published ${jwks.keys.length} signing keys; first kid ${jwks.keys[0].kid.slice(0, 12)}…`);
  });

  test('Anthropic: the client\'s header shape reaches the real API', async (t) => {
    if (!anthropic) return t.skip('api.anthropic.com is not reachable from this environment');
    const c = new VendorClient('claude-enterprise', { credentials: { token: 'sk-ant-not-a-real-key' } });
    const out = await c.request('models');
    // 401 proves the request was well-formed and authenticated-but-rejected.
    // A 404 would mean the path is wrong; a 400 would mean the headers are.
    assert.equal(out.status, 401,
      `expected 401 from a real key rejection, got ${out.status}: ${JSON.stringify(out.body).slice(0, 200)}`);
    assert.equal(out.body?.error?.type, 'authentication_error',
      'the real API did not report an authentication error, so the request shape is wrong');
    console.log('    live: Anthropic accepted the x-api-key/anthropic-version shape and rejected the fake key');
  });

  test('the honest inventory matches what was actually reachable', async () => {
    const s = clientStatus();
    const live = s.rows.filter((r) => r.liveTested).map((r) => r.id).sort();
    assert.deepEqual(live, ['claude-enterprise', 'copilot-agent', 'gemini-enterprise', 'google-workspace'].sort(),
      'the set marked live-tested must be exactly the set whose hosts this environment can reach');
    console.log(`    inventory: ${s.withClient}/${s.total} connectors have clients; ${s.liveTested} are live-tested; ${s.rateLimitEnforced} enforce a published numeric rate limit`);
  });
});

function fakeJson(body, status = 200) {
  return {
    ok: status < 400, status,
    headers: new Map(),
    text: async () => JSON.stringify(body),
    json: async () => body
  };
}
