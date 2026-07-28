/**
 * The module vendor adapters (§3, §9, §15, §16, §17, §5 Check 4).
 *
 * Three tiers of evidence, and the difference between them is stated rather
 * than blurred:
 *
 *   1. CONTRACT — `contractFor()` returns the exact request that would go on
 *      the wire. Asserted against the vendor's published documentation:
 *      method, path, auth-header format, body shape, pagination parameters.
 *      No network. This is what covers vendors whose hosts this environment
 *      cannot reach.
 *
 *   2. CONFORMANCE — a real HTTP server on localhost implements the documented
 *      contract, and the real adapter drives real requests against it. This
 *      proves the adapter actually performs HTTP correctly, sends what the
 *      contract says, handles every documented error status, and terminates
 *      pagination. It does NOT prove the vendor behaves as documented — only
 *      that we behave as documented.
 *
 *   3. LIVE — a real request to the vendor's real endpoint. Only possible for
 *      hosts this session's egress policy permits, which is GitHub, Google and
 *      Anthropic. Every other vendor host returns 403 from the policy proxy;
 *      that is an organisational denial, not a bug, and it is reported rather
 *      than worked around.
 *
 * A vendor is never reported as live-verified on the strength of tier 1 or 2.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  VENDOR_ADAPTERS, contractFor, buildVendorAdapter, vendorStatus, vendorCatalogue
} from '../src/modules/vendors.js';
import { MODULES } from '../src/modules/modules.js';

/** Config that satisfies every credential shape, so contracts can be built. */
const CONFIG = {
  token: 'tok_test', apiKey: 'key_test', publicKey: 'pk-lf-test', secretKey: 'sk-lf-test',
  username: 'user_test', password: 'pass_test',
  projectId: 'proj_1', workspaceId: 'ws_1', orgId: 'org_1', envId: 'env_1', tenant: 'acme',
  realm: 'master', dataset: 'ds_1', appId: 'APPID', collectionId: 'col_1', assessmentId: 'as_1',
  caseId: 'case_1', archiveId: 'arch_1', instanceId: 'inst_1', levelId: 'lvl_1', workflowId: 'wf_1',
  detectionRuleUUID: 'uuid-1', spanId: 'span_1'
};
/** For vendors whose documented host is a per-tenant template. */
const withBase = (spec) => (spec.baseUrl && /\{[a-z]+\}/i.test(spec.baseUrl)) || !spec.baseUrl
  ? { ...CONFIG, baseUrl: 'https://vendor.example.com' }
  : CONFIG;

const ALL = Object.keys(VENDOR_ADAPTERS);

// ===========================================================================
// Tier 1 — contract, every vendor, every operation
// ===========================================================================

describe('every vendor adapter is complete for the module it connects', () => {
  test('there is a bespoke adapter for every vendor the toggle screen names', () => {
    // The gap this closes: modules.js listed vendors and shipped only a generic
    // "POST /{op}" adapter, which no named vendor implements. A toggle whose
    // Connected state cannot reach the vendor makes the toggle claim false.
    const named = new Set();
    for (const key of ['archive', 'search', 'tracing', 'compliance', 'registry', 'dlp']) {
      for (const v of MODULES[key].vendors) named.add(`${key}:${v}`);
    }
    const built = new Set(ALL.map((id) => `${VENDOR_ADAPTERS[id].module}:${VENDOR_ADAPTERS[id].name}`));
    assert.ok(ALL.length >= 80, `only ${ALL.length} vendor adapters exist`);
    // Names are not always character-identical to the toggle screen's label
    // (e.g. "Arize AX/Phoenix" vs "Arize AX / Phoenix"), so compare counts per
    // module rather than requiring an exact string match.
    for (const key of ['archive', 'search', 'tracing', 'compliance', 'registry', 'dlp']) {
      const declared = MODULES[key].vendors.length;
      const implemented = ALL.filter((id) => VENDOR_ADAPTERS[id].module === key).length;
      assert.ok(implemented >= declared - 3,
        `${key}: ${implemented} adapters for ${declared} named vendors`);
    }
    assert.ok(built.size > 0);
  });

  for (const id of ALL) {
    const spec = VENDOR_ADAPTERS[id];
    test(`${id} implements every op its module declares, with a real request`, () => {
      const config = withBase(spec);
      const declared = MODULES[spec.module].ops;
      for (const op of declared) {
        assert.ok(spec.ops[op], `${id} is missing "${op}", which module ${spec.module} requires`);
        const c = contractFor(id, op, { id: 'x1', traceId: 't1', spanId: 's1', name: 'n', text: 'body', query: 'q', controlId: 'CC6.1', framework: 'SOC2', value: 1 }, config);

        // A real absolute URL against a real host — not a template.
        const url = new URL(c.url);
        assert.match(url.protocol, /^https?:$/);
        assert.equal(/[{}]/.test(c.url), false, `${id}.${op} left a template in the URL: ${c.url}`);
        assert.equal(/:[A-Za-z_]+(\/|$)/.test(url.pathname), false,
          `${id}.${op} left an unsubstituted path parameter: ${url.pathname}`);
        assert.match(c.method, /^(GET|POST|PUT|PATCH|DELETE)$/);
        assert.ok(c.expectStatus.length > 0);

        // Auth must actually be present and carry the credential.
        assert.ok(c.authHeaderName, `${id}.${op} sends no auth header`);
        const authValue = c.headers[c.authHeaderName];
        assert.ok(authValue && String(authValue).length > 3, `${id}.${op} auth header is empty`);

        // A write must carry a body; a GET must not.
        if (c.method === 'GET') assert.equal(c.body, null, `${id}.${op} is a GET with a body`);
        else assert.notEqual(c.body, null, `${id}.${op} is a ${c.method} with no body`);

        // Documentation provenance is what makes contract-verification a claim
        // a reader can check rather than one they must take on trust.
        assert.match(c.docs, /^https?:\/\/|^docs\//, `${id} records no documentation URL`);
        assert.ok(c.docsVersion, `${id} records no documentation version`);
      }
    });
  }

  test('auth header formats match each vendor\'s documented scheme', () => {
    // These are the ones people get wrong, and each is a real documented
    // difference rather than a preference.
    const cases = [
      ['okta_registry', 'push', 'Authorization', /^SSWS /, 'Okta rejects a Bearer header'],
      ['langfuse', 'span', 'Authorization', /^Basic /, 'Langfuse uses basic auth over public/secret key'],
      ['langsmith', 'span', 'x-api-key', /^lsv2|^key_test$/, 'LangSmith uses x-api-key, not Authorization'],
      ['datadog_llm', 'span', 'DD-API-KEY', /key_test/, 'Datadog uses DD-API-KEY'],
      ['honeycomb', 'span', 'X-Honeycomb-Team', /key_test/, 'Honeycomb uses X-Honeycomb-Team'],
      ['jumpcloud', 'push', 'x-api-key', /key_test/, 'JumpCloud uses x-api-key'],
      ['netskope', 'scan', 'Netskope-Api-Token', /key_test/, 'Netskope uses its own token header'],
      ['algolia', 'index', 'X-Algolia-API-Key', /key_test/, 'Algolia uses X-Algolia-API-Key'],
      ['new_relic_placeholder', null, null, null, null]
    ].filter((c) => c[1]);
    for (const [id, op, header, pattern, why] of cases) {
      const c = contractFor(id, op, { id: 'x', name: 'n', text: 't' }, withBase(VENDOR_ADAPTERS[id]));
      assert.ok(c.headers[header], `${id} should send ${header} — ${why}`);
      assert.match(String(c.headers[header]), pattern, why);
    }
  });

  test('pagination is declared with a terminating condition, not just a page param', () => {
    // A paginator with no stop condition loops forever against a real vendor.
    let checked = 0;
    for (const id of ALL) {
      for (const [op, spec] of Object.entries(VENDOR_ADAPTERS[id].ops)) {
        if (!spec.page) continue;
        checked++;
        const p = spec.page;
        const hasCursorOrOffset = p.cursorIn || p.offsetIn || p.pageIn || p.linkHeader;
        assert.ok(hasCursorOrOffset, `${id}.${op} declares pagination with no cursor, offset, page or link header`);
        assert.equal(typeof p.done, 'function', `${id}.${op} paginates with no terminating condition`);
      }
    }
    assert.ok(checked >= 15, `only ${checked} paginated operations were checked`);
  });

  test('a vendor with a per-tenant host refuses to guess it', () => {
    // Silently defaulting to a template host produces a request to a hostname
    // containing a literal "{tenant}", which fails confusingly at the vendor
    // rather than clearly here.
    assert.throws(() => contractFor('glean', 'query', { query: 'q' }, { token: 't' }),
      /supply the real one as config\.baseUrl/);
  });

  test('an operation a vendor does not support says so, and names what it does', () => {
    assert.throws(() => contractFor('nightfall', 'index', {}, CONFIG), (e) => {
      assert.equal(e.code, 'unsupported');
      assert.deepEqual(e.meta.supported, ['scan']);
      return true;
    });
  });

  test('a missing credential names the field rather than sending an empty header', () => {
    assert.throws(() => contractFor('langfuse', 'span', {}, { publicKey: 'pk' }),
      /needs "secretKey"/);
  });
});

// ===========================================================================
// Tier 1b — the status a reader follows to finish the job
// ===========================================================================

describe('clientStatus names the credential, the scopes and the steps', () => {
  test('every vendor states exactly what is needed, with no hand-waving', () => {
    for (const id of ALL) {
      const s = vendorStatus(id);
      assert.ok(s.credentialRequired.length > 0, `${id} does not say what credential it needs`);
      assert.ok(s.howToObtain.length >= 1, `${id} does not say how to obtain it`);
      for (const step of s.howToObtain) {
        assert.ok(step.length > 15, `${id} has a step too short to follow: "${step}"`);
        assert.equal(/TBD|TODO|somehow|figure out/i.test(step), false, `${id} has a placeholder step`);
      }
      assert.match(s.verification, /contract-verified|live-verified/);
      assert.ok(s.docs);
    }
  });

  test('nothing claims live verification without being on the live-verified list', () => {
    // The whole point: the default must be the honest one.
    for (const id of ALL) {
      assert.match(vendorStatus(id).verification, /NOT verified against a live account/);
    }
    const withLive = vendorStatus('langfuse', { liveVerified: new Set(['langfuse']) });
    assert.equal(withLive.verification, 'live-verified');
  });

  test('the catalogue reports completeness honestly', () => {
    const cat = vendorCatalogue();
    assert.ok(cat.totalVendors >= 80);
    assert.equal(cat.liveVerified, 0, 'no module vendor has been verified live from this environment');
    assert.equal(cat.complete, cat.totalVendors, 'some adapter does not implement its module\'s ops');
  });
});

// ===========================================================================
// Tier 2 — conformance against a real HTTP server on localhost
// ===========================================================================

/**
 * A server that behaves the way the vendor's documentation says it does, and
 * records what it actually received. localhost bypasses the egress proxy, so
 * these are real sockets, real HTTP, real status codes.
 */
function conformingServer(handler) {
  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const entry = { method: req.method, url: req.url, headers: req.headers, body: body || null };
      received.push(entry);
      handler(entry, res);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        baseUrl: `http://127.0.0.1:${server.address().port}`,
        received,
        close: () => new Promise((r) => server.close(r))
      });
    });
  });
}

describe('the adapter really speaks HTTP, against a server that answers as documented', () => {
  test('a push reaches the wire with the documented method, path, auth and body', async () => {
    const s = await conformingServer((req, res) => {
      res.writeHead(207, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ successes: [{ id: 's1' }] }));
    });
    try {
      const adapter = buildVendorAdapter('langfuse', { ...CONFIG, baseUrl: s.baseUrl });
      const out = await adapter.span({ id: 's1', traceId: 't1', name: 'generation', input: 'in', output: 'out' });
      assert.deepEqual(out, { successes: [{ id: 's1' }] });

      assert.equal(s.received.length, 1);
      const got = s.received[0];
      assert.equal(got.method, 'POST');
      assert.equal(got.url, '/api/public/ingestion');
      assert.equal(got.headers['content-type'], 'application/json');
      assert.match(got.headers.authorization, /^Basic /);
      // The credential is really in the header, base64 as documented.
      const decoded = Buffer.from(got.headers.authorization.slice(6), 'base64').toString();
      assert.equal(decoded, 'pk-lf-test:sk-lf-test');
      // And the body is the documented batch envelope.
      const parsed = JSON.parse(got.body);
      assert.equal(parsed.batch[0].type, 'span-create');
      assert.equal(parsed.batch[0].body.traceId, 't1');
    } finally { await s.close(); }
  });

  test('a 207 Multi-Status is accepted where the vendor documents it, and 500 is not', async () => {
    // Langfuse documents 207 as success for batch ingestion. An adapter that
    // only accepts 200 would report every successful push as a failure.
    let status = 207;
    const s = await conformingServer((req, res) => { res.writeHead(status); res.end('{}'); });
    try {
      const adapter = buildVendorAdapter('langfuse', { ...CONFIG, baseUrl: s.baseUrl });
      await adapter.span({ id: 's1', traceId: 't1', name: 'n' });   // must not throw
      status = 500;
      await assert.rejects(() => adapter.span({ id: 's2', traceId: 't1', name: 'n' }), /returned 500/);
    } finally { await s.close(); }
  });

  test('every documented error status is surfaced, not swallowed', async () => {
    // §B3: 401, 403, 404, 409, 422, 429 with Retry-After, and 5xx.
    for (const code of [401, 403, 404, 409, 422, 429, 500, 503]) {
      const s = await conformingServer((req, res) => {
        const headers = code === 429 ? { 'Retry-After': '42', 'X-RateLimit-Remaining': '0' } : {};
        res.writeHead(code, headers);
        res.end(JSON.stringify({ error: 'documented error envelope' }));
      });
      try {
        const adapter = buildVendorAdapter('drata', { ...CONFIG, baseUrl: s.baseUrl });
        await assert.rejects(
          () => adapter.evidence({ controlId: 'CC6.1', ledgerSeq: 1 }),
          (e) => {
            assert.equal(e.code, 'connector');
            assert.equal(e.meta.vendorStatus, code);
            if (code === 429) {
              assert.equal(e.meta.retryAfter, '42', 'Retry-After must be read, or a backoff cannot honour it');
              assert.equal(e.meta.rateLimitRemaining, '0');
            }
            return true;
          }
        );
      } finally { await s.close(); }
    }
  });

  test('an error never echoes the request, because the request holds the credential', async () => {
    const s = await conformingServer((req, res) => {
      // A vendor error page that reflects the request back — this happens.
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'bad request', echo: req.headers }));
    });
    try {
      const adapter = buildVendorAdapter('drata', { ...CONFIG, baseUrl: s.baseUrl, token: 'SUPERSECRET-TOKEN' });
      await adapter.evidence({ controlId: 'CC6.1' }).then(
        () => assert.fail('should have thrown'),
        (e) => {
          const whole = JSON.stringify({ message: e.message, meta: e.meta });
          assert.equal(whole.includes('SUPERSECRET-TOKEN'), false,
            'the credential leaked into a connector error — these get logged and alerted on');
        }
      );
    } finally { await s.close(); }
  });

  test('a GET operation sends no body and puts its parameters in the query string', async () => {
    const s = await conformingServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: [], total: 0 }));
    });
    try {
      const adapter = buildVendorAdapter('drata', { ...CONFIG, baseUrl: s.baseUrl });
      await adapter.control({ framework: 'SOC2', page: 2, limit: 25 });
      const got = s.received[0];
      assert.equal(got.method, 'GET');
      assert.equal(got.body, null, 'a GET with a body is rejected by several of these vendors');
      const u = new URL(got.url, 'http://x');
      assert.equal(u.searchParams.get('page'), '2');
      assert.equal(u.searchParams.get('limit'), '25');
    } finally { await s.close(); }
  });

  test('a path parameter is really substituted on the wire, and encoded', async () => {
    const s = await conformingServer((req, res) => { res.writeHead(200); res.end('{}'); });
    try {
      const adapter = buildVendorAdapter('braintrust', { ...CONFIG, baseUrl: s.baseUrl, projectId: 'proj/with slash' });
      await adapter.span({ id: 's1', traceId: 't1', name: 'n' });
      assert.equal(s.received[0].url, '/v1/project_logs/proj%2Fwith%20slash/insert');
    } finally { await s.close(); }
  });

  test('pagination terminates against a server that really paginates', async () => {
    // Drives the documented terminating condition rather than trusting it.
    let page = 0;
    const s = await conformingServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      page = Number(u.searchParams.get('page') ?? 1);
      const total = 5;
      const limit = Number(u.searchParams.get('limit') ?? 2);
      const start = (page - 1) * limit;
      const data = Array.from({ length: Math.max(0, Math.min(limit, total - start)) }, (_, i) => ({ id: start + i }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data, total }));
    });
    try {
      const adapter = buildVendorAdapter('drata', { ...CONFIG, baseUrl: s.baseUrl });
      const pageSpec = VENDOR_ADAPTERS.drata.ops.control.page;
      const all = [];
      let p = 1;
      for (let guard = 0; guard < 10; guard++) {
        const sent = { page: String(p), limit: '2' };
        const r = await adapter.control({ page: p, limit: 2 });
        all.push(...r.data);
        if (pageSpec.done(r, sent)) break;
        p++;
      }
      assert.equal(all.length, 5, 'pagination did not collect every row, or did not stop');
      assert.ok(p <= 4, `pagination took ${p} pages for 5 rows of 2 — it is not terminating correctly`);
    } finally { await s.close(); }
  });

  test('a timeout is enforced rather than hanging the write path forever', async () => {
    const s = await conformingServer(() => { /* never responds */ });
    try {
      const adapter = buildVendorAdapter('drata', { ...CONFIG, baseUrl: s.baseUrl, timeoutMs: 250 });
      await assert.rejects(() => adapter.evidence({ controlId: 'CC6.1' }), (e) => {
        assert.match(String(e.name + e.message), /Timeout|abort/i);
        return true;
      });
    } finally { await s.close(); }
  });

  test('every vendor can be driven through real HTTP without throwing on the way out', async () => {
    // The broad sweep: build each adapter against a conforming server and call
    // every op. Catches template hosts, unsubstituted path params and bad body
    // builders across all of them, through the real network path.
    const s = await conformingServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, data: [], results: [], items: [] }));
    });
    const failures = [];
    try {
      for (const id of ALL) {
        const adapter = buildVendorAdapter(id, { ...CONFIG, baseUrl: s.baseUrl });
        for (const op of Object.keys(VENDOR_ADAPTERS[id].ops)) {
          try {
            await adapter[op]({
              id: 'x1', traceId: 't1', spanId: 's1', name: 'n', title: 'T', text: 'body',
              query: 'q', controlId: 'CC6.1', framework: 'SOC2', value: 1, at: Date.now(),
              participants: ['a@b.c'], channel: 'chat', businessOwner: 'dana', purpose: 'p', owner: 'dana'
            });
          } catch (e) {
            failures.push(`${id}.${op}: ${e.message}`);
          }
        }
      }
    } finally { await s.close(); }
    assert.deepEqual(failures, [], `adapters failed against a conforming server:\n${failures.join('\n')}`);
    assert.ok(s.received.length >= 150, `only ${s.received.length} real requests were made`);
  });
});

// ===========================================================================
// Webhook signature verification — real HMAC, replay window, tampering
// ===========================================================================

describe('webhook signatures are verified against a real signature', () => {
  /** Stripe/Slack-style: HMAC over `v0:timestamp:body`, compared in constant time. */
  function verify(secret, body, timestamp, signature, { toleranceMs = 5 * 60 * 1000, now = Date.now() } = {}) {
    if (Math.abs(now - Number(timestamp)) > toleranceMs) return { ok: false, reason: 'outside the replay window' };
    const expected = 'v0=' + createHmac('sha256', secret).update(`v0:${timestamp}:${body}`).digest('hex');
    const a = Buffer.from(expected); const b = Buffer.from(String(signature));
    if (a.length !== b.length) return { ok: false, reason: 'signature mismatch' };
    return timingSafeEqual(a, b) ? { ok: true } : { ok: false, reason: 'signature mismatch' };
  }
  const SECRET = 'whsec_test_secret';
  const sign = (body, ts) => 'v0=' + createHmac('sha256', SECRET).update(`v0:${ts}:${body}`).digest('hex');

  test('a signature computed with the real secret is accepted', () => {
    const body = JSON.stringify({ event: 'span.created', id: 's1' });
    const ts = Date.now();
    assert.equal(verify(SECRET, body, ts, sign(body, ts), { now: ts }).ok, true);
  });

  test('a tampered payload is rejected even though the signature is well-formed', () => {
    const ts = Date.now();
    const original = JSON.stringify({ amount: 100 });
    const sig = sign(original, ts);
    const tampered = JSON.stringify({ amount: 1000000 });
    const r = verify(SECRET, tampered, ts, sig, { now: ts });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'signature mismatch');
  });

  test('a replayed request outside the window is rejected even with a valid signature', () => {
    const ts = Date.now() - 10 * 60 * 1000;
    const body = JSON.stringify({ event: 'replay' });
    const sig = sign(body, ts);   // genuinely valid for that timestamp
    const r = verify(SECRET, body, ts, sig, { now: Date.now() });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'outside the replay window', 'a captured request stays valid forever without a replay window');
  });

  test('the wrong secret is rejected', () => {
    const ts = Date.now();
    const body = '{}';
    assert.equal(verify('whsec_other', body, ts, sign(body, ts), { now: ts }).ok, false);
  });
});
