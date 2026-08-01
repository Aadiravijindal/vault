/**
 * CONNECTOR CONFORMANCE — what can be verified without a vendor tenant.
 *
 * 74 connectors ship. Four have been exercised against the vendor's real API;
 * the other 70 are written from published documentation, and the coverage map
 * says so per connector rather than averaging it away.
 *
 * This file exists because "not verified against a live tenant" was being used
 * to mean "not verified at all", and those are different. Most of what breaks
 * on first contact with a real tenant is not the vendor behaving unexpectedly
 * — it is the client sending a malformed request: the auth header under the
 * wrong name, an unsubstituted {placeholder} in the path, a credential the
 * scheme needs but the definition never declares, a webhook verifier that
 * accepts a forged signature.
 *
 * Every one of those is decidable here, offline, against a synthetic vendor
 * that answers the way the documentation says the real one does. So it is
 * decided here, for all 74.
 *
 * What this does NOT prove, stated plainly so nobody quotes it as if it did:
 *
 *   · that the vendor's real API matches its own documentation
 *   · that undocumented required headers, tenant quirks or auth edge cases
 *     do not exist
 *   · that the response shapes parsed here are the shapes really returned
 *
 * Those need a credential. `status: 'live'` in clients.js still means what it
 * has always meant, and passing conformance does not grant it.
 */
import { CLIENTS, AUTH_SCHEMES, VendorClient } from './clients.js';
import { CONNECTORS } from './catalog.js';

/** Credentials good enough to build a request with, and obviously fake. */
const FAKE = {
  token: 'test-token-not-a-real-credential',
  username: 'test-user',
  password: 'test-password',
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  refreshToken: 'test-refresh-token',
  signingSecret: 'test-signing-secret',
  installationId: '12345678',
  appId: '1234',
  accountSid: 'ACtest',
  // A real RSA key is needed to sign a JWT assertion, so conformance generates
  // one per run rather than committing one to the repository.
  privateKey: null,
  privateKeyPem: null,
  clientEmail: 'conformance@example.invalid',
  subject: 'conformance@example.invalid',
  tenantId: 'test-tenant',
  workspaceId: 'test-workspace',
  siteId: 'test-site',
  userId: 'test-user-id',
  owner: 'test-owner',
  repo: 'test-repo',
  matterId: 'test-matter',
  instanceUrl: 'https://test.example.invalid'
};

/**
 * A vendor that behaves the way the documentation says it does.
 *
 * Records every request so the caller can assert on what was actually sent,
 * which is the entire point: the assertion is about the request Vault builds,
 * not about the response it gets back.
 */
export function syntheticVendor({ onRequest = () => {} } = {}) {
  const requests = [];
  const fetchImpl = async (url, init = {}) => {
    const record = {
      url,
      method: init.method ?? 'GET',
      headers: Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
      body: init.body ?? null
    };
    requests.push(record);
    onRequest(record);

    // Token exchanges come back looking like a token exchange.
    if (/token|oauth|access_tokens/i.test(url) && record.method === 'POST') {
      const body = JSON.stringify({
        access_token: 'synthetic-access-token',
        token: 'synthetic-installation-token',
        expires_in: 3600,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        instance_url: 'https://synthetic.example.invalid'
      });
      return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ data: [], items: [], value: [], results: [] }),
      { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { fetchImpl, requests };
}

/**
 * A plausible value for a placeholder, by what it clearly is.
 *
 * Several vendors are self-hosted or per-tenant, so the operator supplies the
 * whole origin rather than an id — "{clusterUrl}/v1", "https://{host}/ccx".
 * Feeding those a bare word would fail conformance for a reason that says
 * nothing about the connector.
 */
export function placeholderValue(name, template = '') {
  if (FAKE[name] !== undefined && FAKE[name] !== null) return FAKE[name];
  // Whether {host} means "acme.workday.com" or "https://chroma.internal:8000"
  // depends on whether the template already supplies the scheme.
  const schemeAlreadyThere = new RegExp(`https?://[^{]*\\{${name}\\}`).test(template);
  if (/url$/i.test(name) || /^(host|domain|endpoint|cluster)$/i.test(name)) {
    return schemeAlreadyThere ? 'tenant.example.invalid' : 'https://tenant.example.invalid';
  }
  if (/^(subdomain|handle|zone|instance|region|workspace|account|org)$/i.test(name)) return 'tenant';
  if (/^(path|service)$/i.test(name)) return '/v1/records';
  return `test-${name}`;
}

/** Every placeholder a definition's URLs require. */
export function placeholdersOf(def) {
  const out = new Set();
  const scan = (s) => {
    for (const m of String(s ?? '').matchAll(/\{(\w+)\}/g)) out.add(m[1]);
  };
  scan(def.baseUrl);
  scan(def.tokenUrl);
  for (const p of Object.values(def.endpoints ?? {})) scan(p);
  return [...out];
}

/**
 * Check one connector, offline.
 * @returns {{id:string, ok:boolean, transport:string, problems:object[], checks:string[]}}
 */
export async function checkConnector(id, { privateKeyPem = null } = {}) {
  const def = CLIENTS[id];
  const problems = [];
  const checks = [];
  const fail = (check, detail) => problems.push({ check, detail });

  if (!def) return { id, ok: false, transport: 'unknown', checks, problems: [{ check: 'defined', detail: 'no client definition' }] };

  // ---- the catalog and the client must agree -----------------------------
  const cat = CONNECTORS.find((c) => c.id === id);
  if (!cat) fail('catalogued', 'the client has no catalog entry, so it is invisible on the coverage map');
  checks.push('catalogued');

  // ---- the auth scheme must exist and declare what it needs --------------
  const scheme = AUTH_SCHEMES[def.auth];
  if (!scheme) {
    fail('auth_scheme_known', `unknown auth scheme "${def.auth}"`);
    return { id, ok: false, transport: def.transport ?? 'http', checks, problems };
  }
  checks.push('auth_scheme_known');

  if (!def.credential || def.credential.length < 10) {
    fail('credential_documented', 'no plain-language description of the credential an operator must obtain');
  }
  checks.push('credential_documented');

  // Non-HTTP integrations stop here: there is no request to build.
  const transport = def.baseUrl === null ? (def.transport ?? 'in_process') : 'http';
  if (transport !== 'http') {
    return { id, ok: problems.length === 0, transport, checks, problems };
  }

  // ---- the base URL must be a real, secure, absolute URL -----------------
  const probeUrl = String(def.baseUrl).replace(/\{(\w+)\}/g, (m, k) => placeholderValue(k, def.baseUrl));
  let parsed;
  try { parsed = new URL(probeUrl); } catch { fail('base_url_valid', `baseUrl is not a URL: ${def.baseUrl}`); }
  if (parsed) {
    if (parsed.protocol !== 'https:') fail('base_url_https', `baseUrl is ${parsed.protocol}, and a credential must never cross plaintext`);
    if (!parsed.hostname.includes('.')) fail('base_url_valid', `baseUrl host "${parsed.hostname}" is not a domain`);
  }
  checks.push('base_url_valid', 'base_url_https');

  // ---- every endpoint must be a rooted path -----------------------------
  for (const [key, path] of Object.entries(def.endpoints ?? {})) {
    // A path that is nothing but a placeholder is supplied whole by the
    // operator — the generic REST and webhook connectors work that way — and
    // is rooted at call time, not in the template.
    if (/^\{\w+\}$/.test(String(path))) continue;
    if (!String(path).startsWith('/')) fail('endpoint_rooted', `endpoint "${key}" is "${path}" — a path must start with /`);
  }
  checks.push('endpoint_rooted');

  // ---- a token-exchange scheme must say where the token comes from ------
  if (['oauth2_authorization_code', 'oauth2_client_credentials', 'jwt_bearer'].includes(def.auth) && !def.tokenUrl) {
    fail('token_url_present', `${def.auth} needs a tokenUrl and none is defined`);
  }
  checks.push('token_url_present');

  // ---- build a real request against a synthetic vendor ------------------
  const { fetchImpl, requests } = syntheticVendor();
  const template = `${def.baseUrl ?? ''} ${def.tokenUrl ?? ''}`;
  const vars = Object.fromEntries(placeholdersOf(def).map((p) => [p, placeholderValue(p, template)]));
  // Schemes differ on what they call the signing key; supply every spelling.
  const credentials = { ...FAKE, privateKeyPem, privateKey: privateKeyPem };

  const client = new VendorClient(id, { credentials, fetchImpl, vars });

  // Everything the scheme says it needs must be satisfiable.
  const missing = client.missingCredentials();
  if (missing.length) {
    fail('credentials_satisfiable', `scheme needs ${missing.join(', ')}, which the conformance credentials do not cover`);
  }
  checks.push('credentials_satisfiable');

  const endpointKey = Object.keys(def.endpoints ?? {})[0];
  if (endpointKey) {
    try {
      await client.request(endpointKey);
      const sent = requests[requests.length - 1];

      // The request must be addressed somewhere real, with nothing left unfilled.
      if (/\{[a-z]+\}/i.test(sent.url)) fail('url_fully_substituted', `unsubstituted placeholder in ${sent.url}`);
      if (!sent.url.startsWith('https://')) fail('request_https', `request went to ${sent.url}`);
      checks.push('url_fully_substituted', 'request_https');

      // The credential must actually be attached, under the name this vendor
      // reads. A request that authenticates with nothing is the failure mode
      // that looks like success until a real tenant returns 401.
      const authHeaderName = (def.authHeader ?? 'authorization').toLowerCase();
      const carriesAuth = sent.headers[authHeaderName] !== undefined
        || sent.headers.authorization !== undefined;
      if (!carriesAuth) {
        fail('request_authenticated', `no credential on the request; expected header "${authHeaderName}", got ${Object.keys(sent.headers).join(', ')}`);
      }
      checks.push('request_authenticated');

      // A vendor-specific header must not silently fall back to Authorization.
      if (def.authHeader && sent.headers[def.authHeader.toLowerCase()] === undefined) {
        fail('vendor_auth_header', `${id} documents header "${def.authHeader}" but the request did not carry it`);
      }
      checks.push('vendor_auth_header');

      for (const [k, v] of Object.entries(def.extraHeaders ?? {})) {
        if (sent.headers[k.toLowerCase()] !== v) fail('extra_headers_sent', `required header ${k}: ${v} was not sent`);
      }
      checks.push('extra_headers_sent');
    } catch (err) {
      fail('request_builds', `${err.code ?? 'error'}: ${err.message}`);
    }
  }

  // ---- a signed webhook must reject a forged signature ------------------
  if (def.webhook) {
    const body = JSON.stringify({ event: 'conformance' });
    const forged = client.verifyWebhook(body, { [def.webhook.header ?? 'x-signature']: 'sha256=' + '0'.repeat(64) });
    if (forged.valid) fail('webhook_rejects_forgery', 'a forged signature was accepted');
    const unsigned = client.verifyWebhook(body, {});
    if (unsigned.valid) fail('webhook_requires_signature', 'an unsigned body was accepted');
    checks.push('webhook_rejects_forgery', 'webhook_requires_signature');
  }

  return { id, ok: problems.length === 0, transport, checks, problems };
}

/** Check all of them. */
export async function runConformance({ privateKeyPem = null } = {}) {
  const ids = Object.keys(CLIENTS);
  const results = [];
  for (const id of ids) results.push(await checkConnector(id, { privateKeyPem }));

  const failed = results.filter((r) => !r.ok);
  const http = results.filter((r) => r.transport === 'http');
  const live = ids.filter((id) => CLIENTS[id].status === 'live');

  return {
    total: results.length,
    httpConnectors: http.length,
    passed: results.length - failed.length,
    failed: failed.length,
    liveVerified: live.length,
    results,
    failures: failed,
    statement: `${results.length - failed.length} of ${results.length} connectors build a well-formed, authenticated `
      + `request against a synthetic vendor and reject forged webhook signatures. That is a conformance test, not a `
      + `live one: ${live.length} of ${results.length} have been exercised against the vendor's real API, and the `
      + `remaining ${results.length - live.length} are still written from published documentation. Conformance rules `
      + `out a malformed request; only a credential rules out a vendor whose API differs from its own docs.`
  };
}
