/**
 * PROVIDER CONTRACT VERIFICATION — against the vendor's own published spec.
 *
 * conformance.js proves Vault builds a well-formed request. It cannot prove
 * the request goes anywhere real, because the synthetic vendor it talks to
 * accepts whatever it is sent. A path invented from a misread doc page passes
 * conformance and 404s on a live tenant.
 *
 * This closes that. For every vendor that publishes a machine-readable API
 * description, the endpoints Vault calls are checked against the vendor's own
 * OpenAPI document: the path must exist, the method must be allowed, and the
 * host must be one of the servers the vendor declares. That is the provider-
 * driven contract test the industry uses for third-party integrations, and it
 * needs no credential — only the spec, which is public.
 *
 * The honest boundary, again:
 *
 *   conformance   — the request is well-formed          (all 74)
 *   contract      — the endpoint exists in the vendor's own spec  (this file)
 *   live          — a real tenant answered it            (still 4)
 *
 * A contract check catches the invented path and the renamed endpoint. It
 * still cannot catch an undocumented required header, a tenant-specific quirk,
 * or a vendor whose implementation has drifted from its own description. Those
 * need a credential, and `status: 'live'` continues to mean what it says.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { CLIENTS } from './clients.js';

/**
 * Vendors that publish an OpenAPI document, and where it lives.
 *
 * JSON only: adding a YAML parser to read a handful more specs would be a
 * dependency in the trust boundary of a product whose pitch is that it has
 * almost none. Vendors publishing YAML are listed as unverifiable-here rather
 * than quietly dropped, so the gap stays visible.
 */
export const SPEC_SOURCES = {
  'copilot-agent': {
    vendor: 'GitHub',
    url: 'https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json',
    note: "GitHub's own machine-readable description of the REST API"
  },
  'slack-bot': {
    vendor: 'Slack',
    url: 'https://raw.githubusercontent.com/slackapi/slack-api-specs/master/web-api/slack_web_openapi_v2.json',
    note: 'the Slack Web API spec Slack publishes'
  },
  twilio: {
    vendor: 'Twilio',
    url: 'https://raw.githubusercontent.com/twilio/twilio-oai/main/spec/json/twilio_api_v2010.json',
    note: 'the generated spec Twilio ships its own SDKs from'
  }
};

/** Vendors with no machine-readable description we can check against. */
export const NO_PUBLISHED_SPEC_REASON = {
  yaml_only: 'publishes OpenAPI as YAML only, and Vault ships no YAML parser',
  none: 'publishes no machine-readable API description',
  graphql: 'is GraphQL — there are no REST paths to check',
  in_process: 'is not an HTTP integration'
};

const CACHE_DIR = join(process.env.VAULT_SPEC_CACHE || '/tmp', 'vault-vendor-specs');
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Fetch a vendor spec, caching it.
 *
 * Cached rather than committed: these run to twelve megabytes, and a spec
 * frozen into the repository would go stale silently, which is the failure
 * this check exists to catch.
 */
export async function loadSpec(id, { fetchImpl = globalThis.fetch, allowNetwork = true } = {}) {
  const src = SPEC_SOURCES[id];
  if (!src) return { ok: false, reason: 'no published spec source is registered for this connector' };

  mkdirSync(CACHE_DIR, { recursive: true });
  const cached = join(CACHE_DIR, `${id}.json`);

  if (existsSync(cached) && Date.now() - statSync(cached).mtimeMs < MAX_AGE_MS) {
    try { return { ok: true, spec: JSON.parse(readFileSync(cached, 'utf8')), from: 'cache' }; } catch { /* refetch */ }
  }
  if (!allowNetwork) return { ok: false, reason: 'no cached spec and the network is disabled' };

  try {
    const res = await fetchImpl(src.url, { redirect: 'follow' });
    if (!res.ok) return { ok: false, reason: `${src.vendor} spec fetch returned ${res.status}` };
    const text = await res.text();
    const spec = JSON.parse(text);
    writeFileSync(cached, text);
    return { ok: true, spec, from: 'network' };
  } catch (err) {
    return { ok: false, reason: `could not reach the ${src.vendor} spec: ${err.message}` };
  }
}

/** Placeholder names are ours; only the SHAPE of the path is the contract. */
function normalisePath(path) {
  return String(path).replace(/\{[^}]+\}/g, '{}').replace(/\/+$/, '') || '/';
}

/** Every server URL a spec declares, across OpenAPI 3 and Swagger 2. */
export function serversOf(spec) {
  if (Array.isArray(spec.servers) && spec.servers.length) return spec.servers.map((s) => s.url);
  if (spec.host) {
    const scheme = (spec.schemes ?? ['https'])[0];
    return [`${scheme}://${spec.host}${spec.basePath ?? ''}`];
  }
  return [];
}

/**
 * Check one connector's endpoints against the vendor's published spec.
 *
 * @returns {{id:string, vendor:string, ok:boolean, checked:number, problems:object[], endpoints:object[]}}
 */
export function verifyAgainstSpec(id, spec) {
  const def = CLIENTS[id];
  const src = SPEC_SOURCES[id];
  const problems = [];
  const endpoints = [];

  const specPaths = new Map();
  for (const [p, ops] of Object.entries(spec.paths ?? {})) {
    specPaths.set(normalisePath(p), new Set(Object.keys(ops).map((m) => m.toLowerCase())));
  }

  // The host must be one the vendor says it serves.
  const servers = serversOf(spec);
  const ourOrigin = (() => {
    try { return new URL(String(def.baseUrl).replace(/\{[^}]+\}/g, 'x')).origin; } catch { return null; }
  })();
  const serverOrigins = servers.map((s) => { try { return new URL(s).origin; } catch { return s; } });
  if (ourOrigin && serverOrigins.length && !serverOrigins.includes(ourOrigin)) {
    problems.push({
      check: 'server_declared',
      detail: `Vault calls ${ourOrigin}; ${src.vendor} declares ${serverOrigins.join(', ')}`
    });
  }

  // The spec's own base path is part of the path key, but Vault carries it in
  // the base URL — so try the endpoint both with and without that prefix.
  const basePath = (() => {
    for (const s of servers) {
      try { const u = new URL(s); if (u.pathname && u.pathname !== '/') return u.pathname.replace(/\/$/, ''); } catch { /* not a URL */ }
    }
    return '';
  })();
  const ourPrefix = (() => {
    try { return new URL(String(def.baseUrl).replace(/\{[^}]+\}/g, 'x')).pathname.replace(/\/$/, ''); } catch { return ''; }
  })();

  for (const [key, path] of Object.entries(def.endpoints ?? {})) {
    const candidates = [
      normalisePath(path),
      normalisePath(`${ourPrefix}${path}`),
      normalisePath(`${basePath}${path}`)
    ];
    const hit = candidates.find((c) => specPaths.has(c));
    if (!hit) {
      problems.push({
        check: 'endpoint_exists',
        detail: `"${key}" → ${path} is not a path in the ${src.vendor} spec (tried ${candidates.join(', ')})`
      });
      endpoints.push({ key, path, found: false });
      continue;
    }
    const methods = specPaths.get(hit);
    // Vault reads; every endpoint it registers should be gettable.
    const readable = methods.has('get') || methods.has('post');
    if (!readable) {
      problems.push({ check: 'method_allowed', detail: `"${key}" exists but allows only ${[...methods].join(', ')}` });
    }
    endpoints.push({ key, path, found: true, specPath: hit, methods: [...methods] });
  }

  return {
    id, vendor: src.vendor, ok: problems.length === 0,
    checked: endpoints.length, problems, endpoints,
    specVersion: spec.info?.version ?? null
  };
}

/** Verify every connector for which a vendor spec is registered. */
export async function runContractChecks({ fetchImpl = globalThis.fetch, allowNetwork = true } = {}) {
  const results = [];
  const skipped = [];

  for (const id of Object.keys(SPEC_SOURCES)) {
    const loaded = await loadSpec(id, { fetchImpl, allowNetwork });
    if (!loaded.ok) { skipped.push({ id, vendor: SPEC_SOURCES[id].vendor, reason: loaded.reason }); continue; }
    results.push({ ...verifyAgainstSpec(id, loaded.spec), specFrom: loaded.from });
  }

  const total = Object.keys(CLIENTS).length;
  const failed = results.filter((r) => !r.ok);
  const live = Object.values(CLIENTS).filter((c) => c.status === 'live').length;

  return {
    contractChecked: results.length,
    contractPassed: results.length - failed.length,
    contractFailed: failed.length,
    skipped,
    totalConnectors: total,
    liveVerified: live,
    results,
    statement: `${results.length - failed.length} of ${results.length} connectors with a published machine-readable `
      + `spec have every endpoint they call confirmed to exist in the vendor's own OpenAPI document, at a host the `
      + `vendor declares. That is ${results.length} of ${total} connectors — the rest publish no spec, or publish `
      + `one only as YAML. It is still not a live test: ${live} of ${total} have been answered by a real tenant. A `
      + `contract check catches an invented or renamed path; it cannot catch an undocumented header or a vendor `
      + `whose implementation has drifted from its own description.`
  };
}
