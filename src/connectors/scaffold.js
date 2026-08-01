/**
 * ADDING A NEW AI TOOL — the guided path, not tribal knowledge.
 *
 * Every one of the 74 connectors in the catalog carries the same seven facts
 * (auth method, modes supported, what it pulls, what it CANNOT pull, setup
 * time, scopes required, rate-limit profile) and a client shape conformance.js
 * knows how to check. Onboarding a 75th by hand means an engineer reconstructing
 * all of that from memory and finding out what was missed only when
 * conformance runs — or worse, only when it fails at a real tenant.
 *
 * scaffoldConnector() takes the handful of facts that are actually specific to
 * a new vendor and returns the catalog entry and client definition, ready to
 * paste into catalog.js and clients.js. validateScaffold() runs the same class
 * of checks conformance.js runs — auth scheme known, base URL is absolute
 * HTTPS, every endpoint is a rooted path, a token-exchange scheme names where
 * the token comes from, the auth scheme can actually build a header — BEFORE
 * either file is touched, so a new connector fails here, offline, in seconds,
 * rather than shipping broken.
 *
 * What this does not and cannot do: decide the vendor's actual auth scheme,
 * endpoints, or rate limit for you. Those come from the vendor's own
 * documentation, same as every existing client. Getting cannotPull right is
 * also on the person filling this in — the tool only refuses to let it be
 * silently empty, on the theory that a blank blind-spot list is worse than
 * requiring someone to say "we don't know yet".
 */
import { AUTH_SCHEMES } from './clients.js';
import { placeholderValue } from './conformance.js';
import { MODES } from './catalog.js';

const REQUIRED = ['id', 'name', 'vendor', 'category', 'auth', 'modes', 'pulls', 'cannotPull', 'setupMinutes', 'scopes', 'rateLimit', 'channel'];

const AUTH_DESCRIPTIONS = {
  bearer: 'Bearer token', api_key_header: 'API key (vendor-specific header)', basic: 'HTTP Basic',
  oauth2_authorization_code: 'OAuth 2.0 authorization code', oauth2_client_credentials: 'OAuth 2.0 client credentials',
  jwt_bearer: 'Signed JWT bearer assertion', github_app: 'GitHub App installation token',
  hmac_webhook: 'Inbound HMAC-signed webhook', in_process: 'in-process / SDK — no HTTP credential'
};

/**
 * Build the catalog entry and client definition for a new connector.
 * Does not touch catalog.js or clients.js — this only generates and validates.
 *
 * @param {object} spec
 * @param {string} spec.id            lowercase-kebab, must be unique in the catalog
 * @param {string} spec.name          display name
 * @param {string} spec.vendor        the company that makes it
 * @param {string} spec.category      e.g. 'chat', 'voice', 'coding', 'memory'
 * @param {keyof AUTH_SCHEMES} spec.auth
 * @param {('watch'|'inline'|'gateway')[]} spec.modes
 * @param {string[]} spec.pulls       what Vault can see, named
 * @param {string[]} spec.cannotPull  the honest blind spots — required, never empty by default
 * @param {number} spec.setupMinutes
 * @param {string[]} spec.scopes      least-privilege scopes this connector requests
 * @param {string} spec.rateLimit     the vendor's documented limit, or 'undocumented'
 * @param {string} spec.channel       trust classification, e.g. 'customer_chat'
 * @param {string|null} [spec.baseUrl]
 * @param {object} [spec.endpoints]   { key: '/path/{placeholder}' }
 * @param {string} [spec.credential]  plain-language description of what an operator must obtain
 * @param {string} [spec.tokenUrl]    required for the oauth2 and jwt_bearer schemes
 * @param {object} [spec.webhook]     { scheme, header } if the vendor signs inbound webhooks
 * @param {string} [spec.authHeader]  vendor-specific header name, if not Authorization
 */
export function scaffoldConnector(spec) {
  const problems = [];
  for (const f of REQUIRED) {
    if (spec[f] === undefined || spec[f] === null) problems.push(`missing required field "${f}"`);
  }
  if (Array.isArray(spec.cannotPull) && spec.cannotPull.length === 0) {
    problems.push('cannotPull is empty — every connector has a blind spot; if it is not known yet, say so rather than implying there is none');
  }
  if (spec.auth && !AUTH_SCHEMES[spec.auth]) {
    problems.push(`auth scheme "${spec.auth}" is not one of: ${Object.keys(AUTH_SCHEMES).join(', ')}`);
  }
  if (Array.isArray(spec.modes)) {
    const bad = spec.modes.filter((m) => !MODES[m]);
    if (bad.length) problems.push(`unknown mode(s): ${bad.join(', ')} — must be watch, inline or gateway`);
  }
  if (Array.isArray(spec.scopes) && spec.scopes.length === 0) {
    problems.push('scopes is empty — least-privilege means naming exactly what is requested, even if that is one scope');
  }

  const catalogEntry = {
    id: spec.id, name: spec.name, category: spec.category, vendor: spec.vendor,
    auth: AUTH_DESCRIPTIONS[spec.auth] ?? spec.auth, modes: spec.modes ?? [],
    pulls: spec.pulls ?? [], cannotPull: spec.cannotPull ?? [],
    setupMinutes: spec.setupMinutes ?? null, scopes: spec.scopes ?? [],
    rateLimit: spec.rateLimit ?? 'undocumented', channel: spec.channel ?? 'unknown'
  };

  const clientDef = {
    id: spec.id, auth: spec.auth, status: 'docs',
    baseUrl: spec.baseUrl ?? null,
    endpoints: spec.endpoints ?? {},
    credential: spec.credential ?? `credentials for ${spec.vendor ?? 'this vendor'} — fill this in before shipping`,
    ...(spec.tokenUrl ? { tokenUrl: spec.tokenUrl } : {}),
    ...(spec.webhook ? { webhook: spec.webhook } : {}),
    ...(spec.authHeader ? { authHeader: spec.authHeader } : {}),
    ...(spec.extraHeaders ? { extraHeaders: spec.extraHeaders } : {})
  };

  return { problems, catalogEntry, clientDef, catalogSnippet: renderCatalogEntry(catalogEntry), clientSnippet: renderClientDef(clientDef) };
}

/**
 * Validate a scaffolded connector the way conformance.js validates a shipped
 * one — offline, no vendor tenant needed — before it is added to the catalog.
 *
 * @param {object} spec same shape scaffoldConnector() takes
 * @returns {{ok:boolean, problems:string[], checks:string[], catalogEntry:object, clientDef:object}}
 */
export function validateScaffold(spec) {
  const { problems, catalogEntry, clientDef, catalogSnippet, clientSnippet } = scaffoldConnector(spec);
  const checks = [];

  if (clientDef.baseUrl === null) {
    checks.push('in_process_or_webhook_only');
    return { ok: problems.length === 0, problems, checks, catalogEntry, clientDef, catalogSnippet, clientSnippet };
  }

  const template = `${clientDef.baseUrl} ${clientDef.tokenUrl ?? ''}`;
  const fill = (s) => String(s).replace(/\{(\w+)\}/g, (m, k) => {
    const v = String(placeholderValue(k, template));
    return (/^https?:\/\//i.test(v) || v.startsWith('/')) ? v : encodeURIComponent(v);
  });

  let parsed = null;
  try { parsed = new URL(fill(clientDef.baseUrl)); } catch { problems.push(`baseUrl does not resolve to a URL once placeholders are filled: ${clientDef.baseUrl}`); }
  if (parsed && parsed.protocol !== 'https:') problems.push(`baseUrl is ${parsed.protocol} — a credential must never cross plaintext`);
  checks.push('base_url_valid_https');

  for (const [key, path] of Object.entries(clientDef.endpoints ?? {})) {
    if (/^\{\w+\}$/.test(String(path))) continue; // whole path supplied by the operator at call time
    if (!String(path).startsWith('/')) problems.push(`endpoint "${key}" (${path}) must start with /`);
  }
  if (Object.keys(clientDef.endpoints ?? {}).length === 0) problems.push('no endpoints defined — nothing to poll or call');
  checks.push('endpoints_rooted');

  if (['oauth2_authorization_code', 'oauth2_client_credentials', 'jwt_bearer'].includes(clientDef.auth) && !clientDef.tokenUrl) {
    problems.push(`${clientDef.auth} exchanges a token but no tokenUrl is defined — the assertion would have nowhere to go`);
  }
  checks.push('token_url_present');

  const scheme = AUTH_SCHEMES[clientDef.auth];
  if (scheme) {
    const fake = { token: 'x', username: 'x', password: 'x', accessToken: 'x' };
    let headers = null;
    try { headers = scheme.headers({ ...fake, header: clientDef.authHeader, prefix: '' }); }
    catch (e) { problems.push(`auth scheme "${clientDef.auth}" could not build a header: ${e.message}`); }
    if (headers && scheme.needs.length && Object.keys(headers).length === 0) {
      problems.push(`auth scheme "${clientDef.auth}" produced no header at all`);
    }
    if (clientDef.authHeader && headers && !(clientDef.authHeader in headers)) {
      problems.push(`authHeader "${clientDef.authHeader}" was declared but the scheme did not use it`);
    }
    checks.push('auth_headers_buildable');
  }

  if (clientDef.webhook && !clientDef.webhook.scheme) problems.push('webhook is declared but names no signature scheme');
  if (clientDef.webhook) checks.push('webhook_scheme_named');

  return { ok: problems.length === 0, problems, checks, catalogEntry, clientDef, catalogSnippet, clientSnippet };
}

function renderCatalogEntry(e) {
  const j = (v) => JSON.stringify(v);
  return `  { id: ${j(e.id)}, name: ${j(e.name)}, category: ${j(e.category)}, vendor: ${j(e.vendor)}, `
    + `auth: ${j(e.auth)}, modes: ${j(e.modes)}, pulls: ${j(e.pulls)}, cannotPull: ${j(e.cannotPull)}, `
    + `setupMinutes: ${e.setupMinutes ?? 'null'}, scopes: ${j(e.scopes)}, rateLimit: ${j(e.rateLimit)}, channel: ${j(e.channel)} },`;
}

function renderClientDef(d) {
  const j = (v) => JSON.stringify(v);
  const parts = [
    `auth: ${j(d.auth)}`, `status: ${j(d.status)}`,
    `baseUrl: ${d.baseUrl === null ? 'null' : j(d.baseUrl)}`,
    `endpoints: ${j(d.endpoints)}`, `credential: ${j(d.credential)}`
  ];
  if (d.tokenUrl) parts.push(`tokenUrl: ${j(d.tokenUrl)}`);
  if (d.webhook) parts.push(`webhook: ${j(d.webhook)}`);
  if (d.authHeader) parts.push(`authHeader: ${j(d.authHeader)}`);
  if (d.extraHeaders) parts.push(`extraHeaders: ${j(d.extraHeaders)}`);
  return `  D(${j(d.id)}, { ${parts.join(', ')} }),`;
}
