/**
 * Real vendor clients (§2).
 *
 * The connector framework already handled the parts that are the same for
 * everyone: idempotency, cursors, gap detection, kill switches, cost. What it
 * did not have was anything that actually talks to a vendor. `receive()` took
 * events someone else had already fetched, and `backfill()` required the caller
 * to supply the fetcher. That is a framework, not an integration.
 *
 * This is the layer that makes the call. For each connector it declares, from
 * the vendor's published documentation:
 *
 *   - the authentication scheme, in the vendor's own shape — Twilio wants HTTP
 *     Basic with the account SID as the username, Notion wants a bearer plus a
 *     dated `Notion-Version` header, Salesforce wants an OAuth instance URL that
 *     is not the same host you authenticated against, Google wants a signed JWT
 *     assertion exchanged for a token with domain-wide delegation. A generic
 *     "Authorization: Bearer ${token}" works for perhaps a third of them and
 *     silently 401s for the rest.
 *   - the vendor's DOCUMENTED rate limit, as a number this code enforces
 *     before sending, rather than a generic backoff that discovers the limit by
 *     being throttled. Being throttled is a signal you already broke something.
 *   - the endpoints that are polled, the webhook registration call, and the
 *     signature scheme used to verify what arrives.
 *
 * ── WHAT IS AND IS NOT VERIFIED ────────────────────────────────────────────
 *
 * This environment's egress is restricted. Of the hosts these clients target,
 * four answer: api.github.com, www.googleapis.com, api.anthropic.com and
 * api.datadoghq.com. Everything else fails to connect, so no live credential
 * exchange is possible for them here.
 *
 * Accordingly:
 *   - GitHub, Google and Anthropic are exercised against the REAL API in the
 *     live block of test/connectors.test.js — real requests, real responses,
 *     real rate-limit headers, real JWKS material. Those tests SKIP by name
 *     when a host is unreachable rather than passing quietly, because a
 *     network test that goes green with the network down is worse than none.
 *   - Every other client is written against published documentation and is
 *     covered by conformance and transport tests, but has NOT been run against
 *     a live tenant. `clientStatus()` reports exactly that, per connector, and
 *     names the credential each one still needs. Nothing here is marked
 *     verified on the strength of the code existing.
 */
import { createHmac, createSign, timingSafeEqual, randomBytes, createHash } from 'node:crypto';
import { now } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { CONNECTORS } from './catalog.js';

// ---------------------------------------------------------------------------
// Authentication schemes, as the vendors actually implement them
// ---------------------------------------------------------------------------
export const AUTH_SCHEMES = {
  /** Authorization: Bearer <token> */
  bearer: {
    headers: ({ token }) => ({ Authorization: `Bearer ${token}` }),
    needs: ['token']
  },
  /** A vendor-specific header name. Anthropic uses x-api-key, not Bearer. */
  api_key_header: {
    headers: ({ token, header = 'X-API-Key', prefix = '' }) => ({ [header]: `${prefix}${token}` }),
    needs: ['token']
  },
  /** HTTP Basic. Twilio: username = Account SID, password = auth token. */
  basic: {
    headers: ({ username, password }) => ({
      Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
    }),
    needs: ['username', 'password']
  },
  /** OAuth 2.0 authorization code, with the token refreshed when it expires. */
  oauth2_authorization_code: {
    headers: ({ accessToken }) => ({ Authorization: `Bearer ${accessToken}` }),
    needs: ['clientId', 'clientSecret', 'refreshToken']
  },
  /** OAuth 2.0 client credentials — machine to machine, no user. */
  oauth2_client_credentials: {
    headers: ({ accessToken }) => ({ Authorization: `Bearer ${accessToken}` }),
    needs: ['clientId', 'clientSecret']
  },
  /**
   * Signed JWT assertion (RFC 7523). Google service accounts with domain-wide
   * delegation, and Salesforce's JWT bearer flow, both use this: you sign an
   * assertion with a private key and exchange it for an access token. There is
   * no client secret anywhere in the flow.
   */
  jwt_bearer: {
    headers: ({ accessToken }) => ({ Authorization: `Bearer ${accessToken}` }),
    needs: ['clientEmail', 'privateKey']
  },
  /** A GitHub App: sign a short JWT with the app key, swap it for an installation token. */
  github_app: {
    headers: ({ accessToken }) => ({ Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' }),
    needs: ['appId', 'privateKey', 'installationId']
  },
  /** Inbound only: the vendor signs, we verify. No outbound credential. */
  hmac_webhook: { headers: () => ({}), needs: ['signingSecret'] },
  /** No HTTP at all — the integration is a library hook or an MCP server. */
  in_process: { headers: () => ({}), needs: [] }
};

/**
 * Webhook signature schemes.
 *
 * Every one of these is a different shape, and getting one wrong means either
 * rejecting real traffic or accepting forged traffic. They are implemented
 * individually rather than approximated by one HMAC.
 */
export const SIGNATURE_SCHEMES = {
  /** GitHub: `X-Hub-Signature-256: sha256=<hex>` over the raw body. */
  github: {
    header: 'x-hub-signature-256',
    verify: (secret, raw, header) =>
      safeEq(`sha256=${createHmac('sha256', secret).update(raw).digest('hex')}`, header)
  },
  /** Slack: `v0:<timestamp>:<body>`, with a 5-minute replay window. */
  slack: {
    header: 'x-slack-signature',
    verify: (secret, raw, header, headers = {}) => {
      const ts = headers['x-slack-request-timestamp'];
      if (!ts) return false;
      // Slack's own guidance: refuse anything older than five minutes, or a
      // captured request is replayable forever.
      if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
      return safeEq(`v0=${createHmac('sha256', secret).update(`v0:${ts}:${raw}`).digest('hex')}`, header);
    }
  },
  /** Stripe-style `t=<ts>,v1=<hex>`, used by several vendors. */
  stripe_style: {
    header: 'stripe-signature',
    verify: (secret, raw, header) => {
      const parts = Object.fromEntries(String(header).split(',').map((p) => p.split('=')));
      if (!parts.t || !parts.v1) return false;
      if (Math.abs(Date.now() / 1000 - Number(parts.t)) > 300) return false;
      return safeEq(createHmac('sha256', secret).update(`${parts.t}.${raw}`).digest('hex'), parts.v1);
    }
  },
  /** Plain hex HMAC-SHA256 of the body — Vapi, Retell, Intercom and others. */
  hmac_sha256_hex: {
    header: 'x-signature',
    verify: (secret, raw, header) => safeEq(createHmac('sha256', secret).update(raw).digest('hex'), header)
  },
  /** Base64 HMAC-SHA1 — Twilio signs the URL plus sorted POST parameters. */
  twilio: {
    header: 'x-twilio-signature',
    verify: (secret, raw, header, headers = {}) => {
      const url = headers['x-original-url'] ?? '';
      let data = url;
      try {
        const params = JSON.parse(raw);
        for (const k of Object.keys(params).sort()) data += k + params[k];
      } catch { data = url + raw; }
      return safeEq(createHmac('sha1', secret).update(data).digest('base64'), header);
    }
  }
};

function safeEq(a, b) {
  const ba = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * Parse a documented rate limit into requests per second.
 *
 * Deliberately returns null for "plan-dependent" and friends rather than
 * inventing a number: a made-up limit is worse than none, because it reads as
 * knowledge in the operator's console.
 */
export function parseRateLimit(text) {
  const s = String(text ?? '').toLowerCase().trim();
  const UNIT = { s: 1, sec: 1, second: 1, min: 60, minute: 60, hr: 3600, hour: 3600, day: 86400 };
  // "100/10s" — a count over a multi-unit window — is a shape several vendors
  // publish, and reading it as "10 per second" by finding the "10s" later in
  // the string would be right by accident and wrong on "500/2min".
  const win = /^(\d[\d,]*)\s*(?:req(?:uests)?)?\s*\/\s*(\d+)\s*(s|sec|second|min|minute|hr|hour|day)\b/.exec(s);
  if (win) {
    const n = Number(win[1].replace(/,/g, ''));
    const seconds = Number(win[2]) * UNIT[win[3]];
    return { perSecond: n / seconds, documented: text, burst: Math.max(1, n) };
  }
  const m = /^(\d[\d,]*)\s*(?:req(?:uests)?)?\s*\/?\s*(?:per\s*)?(s|sec|second|min|minute|hr|hour|day)\b/.exec(s);
  if (!m) return null;
  const n = Number(m[1].replace(/,/g, ''));
  const per = UNIT[m[2]];
  return { perSecond: n / per, documented: text, burst: Math.max(1, Math.ceil(n / per)) };
}

/**
 * A token bucket that refuses to exceed the vendor's published limit.
 *
 * Enforced BEFORE sending, not after being throttled. A 429 means the limit was
 * already crossed, the vendor has already recorded it, and on several of these
 * platforms repeated 429s degrade the whole tenant, not just this client.
 */
export class RateGovernor {
  constructor({ perSecond, burst = null, clock = now }) {
    this.perSecond = perSecond;
    this.capacity = burst ?? Math.max(1, Math.ceil(perSecond));
    this.tokens = this.capacity;
    this.clock = clock;
    this.last = clock();
    this.waited = 0;
    this.grants = 0;
  }

  /** @returns {number} milliseconds the caller must wait before sending */
  take(n = 1) {
    const t = this.clock();
    this.tokens = Math.min(this.capacity, this.tokens + ((t - this.last) / 1000) * this.perSecond);
    this.last = t;
    if (this.tokens >= n) {
      this.tokens -= n;
      this.grants++;
      return 0;
    }
    const deficit = n - this.tokens;
    const waitMs = Math.ceil((deficit / this.perSecond) * 1000);
    this.waited += waitMs;
    return waitMs;
  }
}

// ---------------------------------------------------------------------------
// Per-vendor definitions, from published documentation
// ---------------------------------------------------------------------------

const D = (id, def) => [id, { id, ...def }];

/**
 * `live` marks a client whose host is reachable from this environment and which
 * is therefore exercised against the real API in the live test. Everything else
 * is `docs`: written from the vendor's documentation, transport-tested, and not
 * yet run against a tenant.
 */
export const CLIENTS = Object.fromEntries([
  // ---- voice --------------------------------------------------------------
  D('vapi', {
    baseUrl: 'https://api.vapi.ai', auth: 'bearer', status: 'docs',
    endpoints: { calls: '/call', call: '/call/{id}' },
    webhook: { register: 'POST /webhook', scheme: 'hmac_sha256_hex', header: 'x-vapi-signature' },
    credential: 'a Vapi private API key and the webhook signing secret from the dashboard'
  }),
  D('bland', {
    baseUrl: 'https://api.bland.ai/v1', auth: 'api_key_header', authHeader: 'Authorization', status: 'docs',
    endpoints: { calls: '/calls', transcript: '/calls/{id}' },
    credential: 'a Bland AI API key from the dashboard (Authorization header, no Bearer prefix)'
  }),
  D('retell', {
    baseUrl: 'https://api.retellai.com', auth: 'bearer', status: 'docs',
    endpoints: { calls: '/v2/list-calls', call: '/v2/get-call/{id}' },
    webhook: { scheme: 'hmac_sha256_hex', header: 'x-retell-signature' },
    credential: 'a Retell AI API key and the webhook signing secret from the dashboard'
  }),
  D('twilio', {
    // Basic auth with the account SID as the username — not a bearer token.
    baseUrl: 'https://api.twilio.com/2010-04-01', auth: 'basic', status: 'docs',
    endpoints: { calls: '/Accounts/{accountSid}/Calls.json', recordings: '/Accounts/{accountSid}/Recordings.json' },
    webhook: { scheme: 'twilio', header: 'x-twilio-signature' },
    credential: 'a Twilio Account SID and auth token (or an API key SID/secret pair)'
  }),
  D('elevenlabs', {
    baseUrl: 'https://api.elevenlabs.io/v1', auth: 'api_key_header', authHeader: 'xi-api-key', status: 'docs',
    endpoints: { history: '/history', conversations: '/convai/conversations' },
    credential: 'an ElevenLabs API key with history and Conversational AI read access'
  }),
  D('synthflow', {
    baseUrl: 'https://api.synthflow.ai/v2', auth: 'bearer', status: 'docs',
    endpoints: { calls: '/calls' }, credential: 'a Synthflow workspace API key with call-log read access'
  }),
  D('sip', {
    baseUrl: null, auth: 'in_process', status: 'docs',
    endpoints: {}, credential: 'SIP trunk credentials and an RTP mirror port; this is not an HTTP integration'
  }),

  // ---- chat / LLM platforms ----------------------------------------------
  D('chatgpt-enterprise', {
    baseUrl: 'https://api.chatgpt.com/v1', auth: 'bearer', status: 'docs',
    endpoints: { conversations: '/compliance/workspaces/{workspaceId}/conversations', users: '/compliance/workspaces/{workspaceId}/users' },
    credential: 'an OpenAI Compliance API key, available only on the Enterprise tier, plus the workspace id'
  }),
  D('claude-enterprise', {
    baseUrl: 'https://api.anthropic.com/v1', auth: 'api_key_header', authHeader: 'x-api-key',
    extraHeaders: { 'anthropic-version': '2023-06-01' }, status: 'live',
    endpoints: { models: '/models', organizations: '/organizations/users' },
    credential: 'an Anthropic Admin API key (sk-ant-admin…) for the Organizations endpoints'
  }),
  D('gemini-enterprise', {
    // The assertion had nowhere to go: jwt_bearer without a tokenUrl cannot
    // complete a token exchange, so every authenticated call would have failed
    // on first contact. The "live" status came from the JWKS endpoint, which
    // needs no credential — which is precisely the kind of overclaim the
    // coverage map exists to prevent. Conformance now fails the build for it.
    baseUrl: 'https://www.googleapis.com', auth: 'jwt_bearer', status: 'live',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    endpoints: { jwks: '/oauth2/v3/certs', vault: '/apps/vault/v1/matters', activity: '/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps' },
    scopes: ['https://www.googleapis.com/auth/ediscovery', 'https://www.googleapis.com/auth/admin.reports.audit.readonly'],
    credential: 'a Google Cloud service account key with domain-wide delegation authorised for the Vault and Admin Reports scopes'
  }),
  D('copilot', {
    baseUrl: 'https://graph.microsoft.com/v1.0', auth: 'oauth2_client_credentials', status: 'docs',
    tokenUrl: 'https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token',
    endpoints: { interactions: '/copilot/users/{userId}/interactionHistory/getAllEnterpriseInteractions' },
    scopes: ['https://graph.microsoft.com/.default'],
    credential: 'an Entra app registration with AiEnterpriseInteraction.Read.All application permission and admin consent'
  }),
  D('perplexity', {
    baseUrl: 'https://api.perplexity.ai', auth: 'bearer', status: 'docs',
    endpoints: { chat: '/chat/completions' }, credential: 'a Perplexity Enterprise Pro API key, issued by the workspace admin'
  }),
  D('mistral', {
    baseUrl: 'https://api.mistral.ai/v1', auth: 'bearer', status: 'docs',
    endpoints: { models: '/models', chat: '/chat/completions' }, credential: 'a Mistral La Plateforme API key'
  }),
  D('cohere', {
    baseUrl: 'https://api.cohere.com/v1', auth: 'bearer', status: 'docs',
    endpoints: { models: '/models', chat: '/chat' }, credential: 'a Cohere production API key (a trial key is rate-limited too aggressively to poll)'
  }),

  // ---- coding agents ------------------------------------------------------
  D('copilot-agent', {
    baseUrl: 'https://api.github.com', auth: 'github_app', status: 'live',
    endpoints: { installation: '/app/installations', repos: '/installation/repositories', events: '/repos/{owner}/{repo}/events' },
    webhook: { scheme: 'github', header: 'x-hub-signature-256' },
    credential: 'a GitHub App id, its PEM private key, and the installation id for the org'
  }),
  ...['claude-code', 'cursor', 'windsurf', 'aider', 'cline', 'continue', 'jetbrains-ai'].map((id) =>
    D(id, {
      baseUrl: null, auth: 'in_process', status: 'docs', endpoints: {},
      transport: 'mcp',
      credential: 'none — this integrates as an MCP server the tool connects to, so the credential is the MCP transport itself'
    })),
  D('devin', {
    baseUrl: 'https://api.devin.ai/v1', auth: 'bearer', status: 'docs',
    endpoints: { sessions: '/sessions' }, credential: 'a Devin API key from the organisation settings page'
  }),
  D('emergent', {
    baseUrl: 'https://api.emergent.sh/v1', auth: 'bearer', status: 'docs',
    endpoints: { sessions: '/sessions' }, credential: 'an Emergent API key from the workspace settings page'
  }),
  D('codex', {
    baseUrl: 'https://api.openai.com/v1', auth: 'bearer', status: 'docs',
    endpoints: { responses: '/responses' }, credential: 'an OpenAI API key with access to the Responses API'
  }),

  // ---- customer-facing bots ----------------------------------------------
  D('intercom-fin', {
    baseUrl: 'https://api.intercom.io', auth: 'oauth2_authorization_code', status: 'docs',
    tokenUrl: 'https://api.intercom.io/auth/eagle/token',
    extraHeaders: { 'Intercom-Version': '2.11' },
    endpoints: { conversations: '/conversations', me: '/me' },
    webhook: { scheme: 'hmac_sha256_hex', header: 'x-hub-signature' },
    credential: 'an Intercom OAuth app client id/secret and an installed workspace'
  }),
  D('zendesk-ai', {
    baseUrl: 'https://{subdomain}.zendesk.com/api/v2', auth: 'basic', status: 'docs',
    endpoints: { tickets: '/tickets.json', comments: '/tickets/{id}/comments.json' },
    credential: 'a Zendesk subdomain plus an email/API-token pair used as HTTP Basic (email/token:apitoken)'
  }),
  D('agentforce', {
    baseUrl: '{instanceUrl}/services/data/v60.0', auth: 'oauth2_client_credentials', status: 'docs',
    tokenUrl: 'https://login.salesforce.com/services/oauth2/token',
    // Salesforce returns the instance host in the token response; calling the
    // login host afterwards fails, and it is the single most common mistake.
    instanceUrlFrom: 'instance_url',
    endpoints: { query: '/query', einsteinLogs: '/sobjects/AIAgentSession' },
    credential: 'a Salesforce Connected App with client credentials flow enabled and a run-as user'
  }),
  D('drift', {
    baseUrl: 'https://driftapi.com', auth: 'oauth2_authorization_code', status: 'docs',
    tokenUrl: 'https://driftapi.com/oauth2/token',
    endpoints: { conversations: '/conversations/list' }, credential: 'a Drift OAuth application client id and secret, plus an installed org'
  }),
  D('ada', {
    baseUrl: 'https://{handle}.ada.support/api/v2', auth: 'bearer', status: 'docs',
    endpoints: { conversations: '/conversations' }, credential: 'an Ada bot handle (the subdomain) and a platform API key'
  }),
  D('forethought', {
    baseUrl: 'https://api.forethought.ai/v1', auth: 'bearer', status: 'docs',
    endpoints: { workflows: '/workflows' }, credential: 'a Forethought API key with workflow read access'
  }),

  // ---- internal bots ------------------------------------------------------
  D('slack-bot', {
    baseUrl: 'https://slack.com/api', auth: 'bearer', status: 'docs',
    endpoints: { test: '/auth.test', history: '/conversations.history', replies: '/conversations.replies' },
    webhook: { scheme: 'slack', header: 'x-slack-signature' },
    scopes: ['channels:history', 'groups:history', 'im:history', 'users:read'],
    credential: 'a Slack bot token (xoxb-…) and the app signing secret'
  }),
  D('teams-bot', {
    baseUrl: 'https://graph.microsoft.com/v1.0', auth: 'oauth2_client_credentials', status: 'docs',
    tokenUrl: 'https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token',
    endpoints: { messages: '/teams/{teamId}/channels/{channelId}/messages' },
    scopes: ['https://graph.microsoft.com/.default'],
    credential: 'an Entra app registration with ChannelMessage.Read.All and admin consent'
  }),
  D('discord-bot', {
    baseUrl: 'https://discord.com/api/v10', auth: 'api_key_header', authHeader: 'Authorization', authPrefix: 'Bot ',
    status: 'docs', endpoints: { messages: '/channels/{channelId}/messages' },
    credential: 'a Discord bot token, with the bot invited to the guild and message-content intent enabled'
  }),

  // ---- orchestration frameworks ------------------------------------------
  ...['langgraph', 'langchain', 'crewai', 'autogen', 'semantic-kernel', 'pydantic-ai', 'openai-agents', 'dspy', 'langmem'].map((id) =>
    D(id, {
      baseUrl: null, auth: 'in_process', status: 'docs', endpoints: {}, transport: 'sdk',
      credential: 'none — this is an in-process callback registered in the customer\'s own code'
    })),
  D('letta', {
    baseUrl: 'https://api.letta.com/v1', auth: 'bearer', status: 'docs',
    endpoints: { agents: '/agents', messages: '/agents/{id}/messages' }, credential: 'a Letta Cloud API key, or a self-hosted server URL and token'
  }),
  D('n8n', {
    baseUrl: '{instanceUrl}/api/v1', auth: 'api_key_header', authHeader: 'X-N8N-API-KEY', status: 'docs',
    endpoints: { executions: '/executions', workflows: '/workflows' },
    webhook: { scheme: 'hmac_sha256_hex', header: 'x-n8n-signature' },
    credential: 'an n8n instance URL and an owner-issued API key'
  }),
  D('zapier', {
    baseUrl: 'https://api.zapier.com/v1', auth: 'bearer', status: 'docs',
    endpoints: { zaps: '/zaps' }, webhook: { scheme: 'hmac_sha256_hex', header: 'x-hook-signature' },
    credential: 'a Zapier OAuth token or a private webhook signing secret'
  }),
  D('make', {
    baseUrl: 'https://{zone}.make.com/api/v2', auth: 'api_key_header', authHeader: 'Authorization', authPrefix: 'Token ',
    status: 'docs', endpoints: { scenarios: '/scenarios' },
    credential: 'a Make API token and the zone hostname for the account'
  }),

  // ---- memory layers ------------------------------------------------------
  D('mem0', {
    baseUrl: 'https://api.mem0.ai/v1', auth: 'api_key_header', authHeader: 'Authorization', authPrefix: 'Token ',
    status: 'docs', endpoints: { memories: '/memories', search: '/memories/search' }, credential: 'a Mem0 platform API key for the target organisation'
  }),
  D('zep', {
    baseUrl: 'https://api.getzep.com/api/v2', auth: 'api_key_header', authHeader: 'Authorization', authPrefix: 'Api-Key ',
    status: 'docs', endpoints: { memory: '/sessions/{sessionId}/memory', graph: '/graph/search' }, credential: 'a Zep Cloud project API key'
  }),
  D('cognee', {
    baseUrl: 'https://api.cognee.ai/v1', auth: 'bearer', status: 'docs',
    endpoints: { search: '/search' }, credential: 'a Cognee API key from the platform dashboard'
  }),
  D('supermemory', {
    baseUrl: 'https://api.supermemory.ai/v3', auth: 'bearer', status: 'docs',
    endpoints: { memories: '/memories', search: '/search' }, credential: 'a Supermemory API key from the developer console'
  }),
  D('pinecone', {
    baseUrl: 'https://api.pinecone.io', auth: 'api_key_header', authHeader: 'Api-Key', status: 'docs',
    extraHeaders: { 'X-Pinecone-API-Version': '2024-07' },
    endpoints: { indexes: '/indexes' }, credential: 'a Pinecone API key for the target project and environment'
  }),
  D('weaviate', {
    baseUrl: '{clusterUrl}/v1', auth: 'bearer', status: 'docs',
    endpoints: { schema: '/schema', objects: '/objects' }, credential: 'a Weaviate cluster URL and API key'
  }),
  D('qdrant', {
    baseUrl: '{clusterUrl}', auth: 'api_key_header', authHeader: 'api-key', status: 'docs',
    endpoints: { collections: '/collections' }, credential: 'a Qdrant cluster URL and API key'
  }),
  D('chroma', {
    baseUrl: '{host}/api/v1', auth: 'api_key_header', authHeader: 'X-Chroma-Token', status: 'docs',
    endpoints: { collections: '/collections' }, credential: 'a Chroma host, and a token if the deployment enables auth'
  }),

  // ---- systems of record --------------------------------------------------
  D('salesforce', {
    baseUrl: '{instanceUrl}/services/data/v60.0', auth: 'jwt_bearer', status: 'docs',
    tokenUrl: 'https://login.salesforce.com/services/oauth2/token', instanceUrlFrom: 'instance_url',
    endpoints: { query: '/query', sobjects: '/sobjects' },
    credential: 'a Salesforce Connected App with a certificate for the JWT bearer flow, and a pre-authorised run-as user'
  }),
  D('hubspot', {
    baseUrl: 'https://api.hubapi.com', auth: 'bearer', status: 'docs',
    endpoints: { contacts: '/crm/v3/objects/contacts', notes: '/crm/v3/objects/notes' },
    credential: 'a HubSpot private app access token with the crm.objects scopes'
  }),
  D('jira', {
    baseUrl: 'https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3', auth: 'oauth2_authorization_code', status: 'docs',
    tokenUrl: 'https://auth.atlassian.com/oauth/token',
    // Atlassian Cloud requires resolving a cloud id before any API call.
    discovery: 'https://api.atlassian.com/oauth/token/accessible-resources',
    endpoints: { search: '/search', issue: '/issue/{key}' },
    scopes: ['read:jira-work', 'offline_access'],
    credential: 'an Atlassian OAuth 2.0 (3LO) app, or a site URL plus email/API-token for Basic'
  }),
  D('linear', {
    baseUrl: 'https://api.linear.app', auth: 'api_key_header', authHeader: 'Authorization', status: 'docs',
    graphql: '/graphql',
    endpoints: { graphql: '/graphql' },
    webhook: { scheme: 'hmac_sha256_hex', header: 'linear-signature' },
    credential: 'a Linear personal API key or OAuth token'
  }),
  D('servicenow', {
    baseUrl: 'https://{instance}.service-now.com/api/now', auth: 'oauth2_client_credentials', status: 'docs',
    tokenUrl: 'https://{instance}.service-now.com/oauth_token.do',
    endpoints: { table: '/table/{table}' },
    credential: 'a ServiceNow instance, an OAuth application registry entry, and a service account'
  }),
  D('workday', {
    baseUrl: 'https://{host}/ccx/api/v1/{tenant}', auth: 'oauth2_client_credentials', status: 'docs',
    tokenUrl: 'https://{host}/ccx/oauth2/{tenant}/token',
    endpoints: { workers: '/workers' },
    credential: 'a Workday Integration System User (ISU) and a registered API client with a refresh token'
  }),
  D('sap', {
    baseUrl: 'https://{host}/sap/opu/odata/sap', auth: 'basic', status: 'docs',
    endpoints: { service: '/{service}' },
    credential: 'an SAP technical user with OData service authorisations'
  }),
  D('netsuite', {
    baseUrl: 'https://{accountId}.suitetalk.api.netsuite.com/services/rest/record/v1', auth: 'oauth2_client_credentials',
    status: 'docs', tokenUrl: 'https://{accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token',
    endpoints: { records: '/{recordType}' },
    credential: 'a NetSuite account id and an integration record with OAuth 2.0 client credentials (M2M) enabled'
  }),
  D('notion', {
    baseUrl: 'https://api.notion.com/v1', auth: 'bearer', status: 'docs',
    // The version header is required; omitting it is a 400 on every call.
    extraHeaders: { 'Notion-Version': '2022-06-28' },
    endpoints: { search: '/search', page: '/pages/{id}', blocks: '/blocks/{id}/children' },
    credential: 'a Notion internal integration token, with the pages shared to the integration'
  }),
  D('confluence', {
    baseUrl: 'https://api.atlassian.com/ex/confluence/{cloudId}/wiki/api/v2', auth: 'oauth2_authorization_code',
    status: 'docs', tokenUrl: 'https://auth.atlassian.com/oauth/token',
    endpoints: { pages: '/pages', page: '/pages/{id}' },
    scopes: ['read:page:confluence', 'offline_access'],
    credential: 'an Atlassian OAuth 2.0 (3LO) app with Confluence scopes'
  }),
  D('sharepoint', {
    baseUrl: 'https://graph.microsoft.com/v1.0', auth: 'oauth2_client_credentials', status: 'docs',
    tokenUrl: 'https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token',
    endpoints: { sites: '/sites', drive: '/sites/{siteId}/drive/root/children' },
    scopes: ['https://graph.microsoft.com/.default'],
    credential: 'an Entra app registration with Sites.Read.All and admin consent'
  }),
  D('google-workspace', {
    baseUrl: 'https://www.googleapis.com', auth: 'jwt_bearer', status: 'live',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    endpoints: { jwks: '/oauth2/v3/certs', drive: '/drive/v3/files', reports: '/admin/reports/v1/activity/users/all/applications/drive' },
    scopes: ['https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/admin.reports.audit.readonly'],
    credential: 'a Google Cloud service account key with domain-wide delegation authorised in the Admin console'
  }),

  // ---- generic ------------------------------------------------------------
  D('webhook', {
    baseUrl: null, auth: 'hmac_webhook', status: 'docs', endpoints: {},
    webhook: { scheme: 'hmac_sha256_hex', header: 'x-vault-signature' },
    credential: 'a shared signing secret, generated by Vault at connector creation'
  }),
  D('rest', { baseUrl: '{baseUrl}', auth: 'bearer', status: 'docs', endpoints: { poll: '{path}' }, credential: 'whatever bearer token the endpoint expects' }),
  D('mcp', { baseUrl: null, auth: 'in_process', status: 'docs', endpoints: {}, transport: 'mcp', credential: 'none — the MCP transport is the trust boundary' }),
  D('kafka', { baseUrl: null, auth: 'in_process', status: 'docs', endpoints: {}, transport: 'kafka', credential: 'SASL/SCRAM credentials or an IAM role for MSK' }),
  D('sftp', { baseUrl: null, auth: 'in_process', status: 'docs', endpoints: {}, transport: 'sftp', credential: 'an SSH key pair and the host key fingerprint' }),
  D('otel', { baseUrl: '{endpoint}', auth: 'bearer', status: 'docs', endpoints: { traces: '/v1/traces' }, credential: 'an OTLP endpoint and its bearer token' }),
  D('bulk', { baseUrl: null, auth: 'in_process', status: 'docs', endpoints: {}, transport: 'upload', credential: 'an authenticated upload session, created through the API' })
]);

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

export class VendorClient {
  /**
   * @param {string} id catalog connector id
   * @param {object} o
   * @param {object} o.credentials scheme-dependent
   * @param {typeof globalThis.fetch} [o.fetchImpl]
   */
  constructor(id, { credentials = {}, fetchImpl = globalThis.fetch, vars = {}, clock = now, onEvent = null } = {}) {
    const def = CLIENTS[id];
    if (!def) throw new VaultError('not_found', `no vendor client for connector "${id}"`, { id });
    const catalogEntry = CONNECTORS.find((c) => c.id === id);
    this.def = def;
    this.catalog = catalogEntry ?? null;
    this.credentials = credentials;
    this.fetchImpl = fetchImpl;
    this.vars = vars;
    this.onEvent = onEvent;
    const limit = parseRateLimit(catalogEntry?.rateLimit);
    this.limit = limit;
    // No documented number means no governor, and `status()` says so rather
    // than pretending a made-up limit is being respected.
    this.governor = limit ? new RateGovernor({ perSecond: limit.perSecond, burst: limit.burst, clock }) : null;
    this.calls = 0;
    this.throttled = 0;
    this.accessToken = credentials.accessToken ?? null;
    this.tokenExpiresAt = credentials.expiresAt ?? 0;
    this.instanceUrl = credentials.instanceUrl ?? null;
  }

  /** Which credentials this scheme requires but does not have. */
  missingCredentials() {
    const scheme = AUTH_SCHEMES[this.def.auth];
    if (!scheme) return [];
    return scheme.needs.filter((k) => !this.credentials[k]);
  }

  _url(path) {
    const base = this.def.instanceUrlFrom && this.instanceUrl
      ? this.def.baseUrl.replace('{instanceUrl}', this.instanceUrl)
      : this.def.baseUrl;
    if (!base) throw new VaultError('unsupported', `${this.def.id} is not an HTTP integration`, { transport: this.def.transport });
    const filled = (s) => String(s).replace(/\{(\w+)\}/g, (m, k) => {
      const v = this.vars[k] ?? this.credentials[k];
      if (v === undefined) throw new VaultError('config', `${this.def.id} needs "${k}" to build its URL`, { variable: k });
      const str = String(v);
      // Percent-encoding is right for an identifier dropped into a path segment
      // and catastrophic for a placeholder that IS the origin or the path.
      // Salesforce learns its instanceUrl from its own token exchange, so
      // encoding it turned every request into https%3A%2F%2F… and the connector
      // could not have worked against a real tenant. An absolute URL or a
      // rooted path is never a single segment, so it goes in verbatim.
      if (/^https?:\/\//i.test(str) || str.startsWith('/')) return str.replace(/\/$/, '');
      return encodeURIComponent(str);
    });
    return filled(base) + (path ? filled(path) : '');
  }

  async _headers() {
    const scheme = AUTH_SCHEMES[this.def.auth];
    const missing = this.missingCredentials();
    if (missing.length) {
      throw forbidden(`${this.def.id} cannot authenticate: missing ${missing.join(', ')} — ${this.def.credential}`, { missing });
    }
    if (['oauth2_authorization_code', 'oauth2_client_credentials', 'jwt_bearer', 'github_app'].includes(this.def.auth)) {
      await this._ensureToken();
    }
    return {
      ...scheme.headers({
        ...this.credentials,
        accessToken: this.accessToken,
        header: this.def.authHeader,
        prefix: this.def.authPrefix ?? ''
      }),
      ...(this.def.extraHeaders ?? {}),
      Accept: 'application/json'
    };
  }

  /** Refresh when it is gone or within a minute of expiry. */
  async _ensureToken() {
    if (this.accessToken && now() < this.tokenExpiresAt - 60_000) return this.accessToken;
    const tokens = await this.authenticate();
    return tokens.access_token;
  }

  /**
   * Perform the vendor's token exchange.
   *
   * Split out so it is the one place the credential leaves this process, and
   * so a test can replace exactly that and leave everything else real.
   */
  async authenticate() {
    const def = this.def;
    let body;
    if (def.auth === 'oauth2_client_credentials') {
      body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.credentials.clientId,
        client_secret: this.credentials.clientSecret,
        ...(def.scopes ? { scope: def.scopes.join(' ') } : {})
      });
    } else if (def.auth === 'oauth2_authorization_code') {
      body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.credentials.refreshToken,
        client_id: this.credentials.clientId,
        client_secret: this.credentials.clientSecret
      });
    } else if (def.auth === 'jwt_bearer') {
      body = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: this.signedAssertion()
      });
    } else if (def.auth === 'github_app') {
      // A GitHub App swaps an app-signed JWT for a short-lived installation
      // token at a different endpoint, with no form body at all.
      const jwt = this.signedAssertion();
      const res = await this.fetchImpl(`https://api.github.com/app/installations/${this.credentials.installationId}/access_tokens`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${jwt}`, Accept: 'application/vnd.github+json' }
      });
      if (!res.ok) throw forbidden(`GitHub App token exchange returned ${res.status}`);
      const json = await res.json();
      this.accessToken = json.token;
      this.tokenExpiresAt = Date.parse(json.expires_at);
      return { access_token: json.token, expires_in: (this.tokenExpiresAt - now()) / 1000 };
    } else {
      throw new VaultError('unsupported', `${def.id} does not use a token exchange`, { auth: def.auth });
    }

    const tokenUrl = String(def.tokenUrl).replace(/\{(\w+)\}/g, (m, k) => this.vars[k] ?? this.credentials[k] ?? m);
    const res = await this.fetchImpl(tokenUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString()
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw forbidden(`${def.id} token endpoint returned ${res.status}`, { status: res.status, detail: detail.slice(0, 200) });
    }
    const json = await res.json();
    this.accessToken = json.access_token;
    this.tokenExpiresAt = now() + (Number(json.expires_in ?? 3600) * 1000);
    // Salesforce and others hand back the host you must actually call.
    if (def.instanceUrlFrom && json[def.instanceUrlFrom]) this.instanceUrl = json[def.instanceUrlFrom];
    return json;
  }

  /** RFC 7523 assertion, signed with the customer's private key. */
  signedAssertion({ at = now() } = {}) {
    const def = this.def;
    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const iat = Math.floor(at / 1000);
    const isGithub = def.auth === 'github_app';
    const header = b64u({ alg: 'RS256', typ: 'JWT', ...(this.credentials.keyId ? { kid: this.credentials.keyId } : {}) });
    const claims = isGithub
      // GitHub backdates iat by 60s because it rejects a JWT whose iat is even
      // slightly in the future relative to its own clock.
      ? { iat: iat - 60, exp: iat + 540, iss: this.credentials.appId }
      : {
        iss: this.credentials.clientEmail,
        scope: (def.scopes ?? []).join(' '),
        aud: def.tokenUrl,
        iat, exp: iat + 3600,
        ...(this.credentials.subject ? { sub: this.credentials.subject } : {})
      };
    const payload = b64u(claims);
    const sig = createSign('RSA-SHA256').update(`${header}.${payload}`).sign(this.credentials.privateKey, 'base64url');
    return `${header}.${payload}.${sig}`;
  }

  /**
   * One request, rate-limited before it is sent.
   *
   * @returns {Promise<{status:number, body:any, headers:object, waitedMs:number}>}
   */
  async request(pathOrKey, { method = 'GET', query = null, body = null, raw = false } = {}) {
    const path = this.def.endpoints[pathOrKey] ?? pathOrKey;
    const waitMs = this.governor ? this.governor.take() : 0;
    if (waitMs > 0) {
      this.throttled++;
      // Waiting is the correct behaviour: a 429 means the vendor has already
      // recorded the breach, and on several platforms repeated 429s degrade
      // the whole tenant rather than just this client.
      await new Promise((r) => setTimeout(r, waitMs));
      this.governor.take();
    }
    // Headers FIRST. For Salesforce and NetSuite the token response is what
    // reveals the host to call, so building the URL before authenticating
    // would send every request to the login endpoint.
    const headers = await this._headers();
    let url = this._url(path);
    if (query) url += (url.includes('?') ? '&' : '?') + new URLSearchParams(query).toString();
    const res = await this.fetchImpl(url, {
      method, headers: { ...headers, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {})
    });
    this.calls++;
    const text = await res.text();
    let parsed = text;
    if (!raw) { try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; } }
    const out = {
      status: res.status, ok: res.ok, body: parsed, waitedMs: waitMs,
      headers: Object.fromEntries(res.headers.entries())
    };
    this.onEvent?.({ connector: this.def.id, url, status: res.status, waitedMs: waitMs });
    return out;
  }

  /** Verify an inbound webhook using this vendor's own scheme. */
  verifyWebhook(rawBody, headers = {}) {
    const spec = this.def.webhook;
    if (!spec) return { valid: false, reason: `${this.def.id} does not deliver signed webhooks` };
    const scheme = SIGNATURE_SCHEMES[spec.scheme];
    if (!scheme) return { valid: false, reason: `unknown signature scheme ${spec.scheme}` };
    const secret = this.credentials.signingSecret;
    if (!secret) return { valid: false, reason: 'no signing secret is configured for this connector' };
    const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    const header = lower[(spec.header ?? scheme.header).toLowerCase()];
    if (!header) return { valid: false, reason: `the request carried no ${spec.header ?? scheme.header} header` };
    const valid = scheme.verify(secret, rawBody, header, lower);
    return valid ? { valid: true, scheme: spec.scheme } : { valid: false, reason: 'the signature does not match the body' };
  }

  status() {
    return {
      id: this.def.id,
      auth: this.def.auth,
      verified: this.def.status === 'live' ? 'reachable from this environment and exercised against the real API'
        : 'written from published documentation; NOT run against a live tenant',
      liveTested: this.def.status === 'live',
      rateLimit: this.limit
        ? { documented: this.limit.documented, enforcedPerSecond: this.limit.perSecond }
        : { documented: this.catalog?.rateLimit ?? null, enforcedPerSecond: null, note: 'no numeric limit is published; a governor would be a guess, so none is applied' },
      webhookScheme: this.def.webhook?.scheme ?? null,
      credentialNeeded: this.def.credential,
      missingCredentials: this.missingCredentials(),
      calls: this.calls, throttled: this.throttled
    };
  }
}

/**
 * The honest inventory: every catalog connector, its client, and whether it has
 * ever been run against the vendor.
 */
export function clientStatus() {
  const rows = CONNECTORS.map((c) => {
    const def = CLIENTS[c.id];
    return {
      id: c.id, name: c.name, category: c.category,
      hasClient: Boolean(def),
      transport: def?.transport ?? (def?.baseUrl ? 'http' : 'none'),
      auth: def?.auth ?? null,
      liveTested: def?.status === 'live',
      rateLimitEnforced: Boolean(parseRateLimit(c.rateLimit)),
      credentialNeeded: def?.credential ?? null
    };
  });
  return {
    total: rows.length,
    withClient: rows.filter((r) => r.hasClient).length,
    liveTested: rows.filter((r) => r.liveTested).length,
    httpClients: rows.filter((r) => r.transport === 'http').length,
    inProcess: rows.filter((r) => r.auth === 'in_process').length,
    rateLimitEnforced: rows.filter((r) => r.rateLimitEnforced).length,
    rows,
    statement: `${rows.filter((r) => r.liveTested).length} of ${rows.length} connectors have been exercised against the vendor's real API from this environment. The rest are implemented from published documentation and are not verified against a live tenant; each row names the credential required to finish that verification.`
  };
}
