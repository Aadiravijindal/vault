/**
 * INBOUND WEBHOOKS — capture at the moment it is typed, not at the next poll.
 *
 * sync.js polls, which is the only option for a vendor that offers nothing
 * else, and it means a message written at 14:00 is governed at 14:05. For a
 * Watch-mode connector that is forensics either way. For anything where the
 * point is to catch a thing as it happens, five minutes is the difference
 * between governing a fact and reading about one.
 *
 * Where a vendor pushes, this receives the push. The credential story is
 * inverted from every other route in the API: the vendor has no bearer token
 * and never will, so the HMAC signature over the raw body IS the
 * authentication. That makes exactly one thing load-bearing —
 *
 *   the signature is checked BEFORE the payload is parsed, read, or ingested,
 *   and a failure returns without the body ever reaching the gate.
 *
 * — which is why this is a separate file with its own tests rather than a few
 * lines inside a route handler. `verifyWebhook` in clients.js implements each
 * vendor's scheme; conformance.js already proves every one of them rejects a
 * forged signature and an unsigned body.
 *
 * The raw body matters. Re-serialising JSON changes bytes — key order,
 * whitespace, unicode escapes — and the HMAC is over the bytes the vendor
 * sent, so a re-serialised body fails verification even when the payload is
 * genuine. The route hands the raw string through untouched.
 *
 * After verification the event goes through `receive()`, exactly like a polled
 * one: same idempotency, same cursor, same gate. A pushed fact is not a
 * privileged fact.
 */
import { VendorClient } from './clients.js';
import { SYNC_SOURCES } from './sync.js';
import { VaultError, notFound } from '../util/errors.js';

/**
 * How to turn each vendor's PUSH payload into events.
 *
 * A push payload is not the same shape as a poll response — Slack's Events API
 * sends one message envelope, `conversations.history` sends a page of them —
 * so a normalizer here is genuinely different code from the one in sync.js,
 * and only vendors whose push shape is confirmed get one. Everything else is
 * reported unsupported by name rather than guessed at.
 */
export const PUSH_SOURCES = {
  'slack-bot': {
    vendor: 'Slack',
    scheme: 'slack',
    // https://api.slack.com/apis/connections/events-api
    normalize(payload) {
      // The URL-verification handshake is not an event; Slack expects the
      // challenge echoed back before it will deliver anything else.
      if (payload?.type === 'url_verification') return { challenge: payload.challenge, events: [] };
      const e = payload?.event;
      if (!e || e.type !== 'message' || typeof e.text !== 'string' || !e.text) return { events: [] };
      // A bot echoing its own message back is not a new fact.
      if (e.bot_id && e.subtype === 'bot_message' && !e.user) return { events: [] };
      return {
        events: [{
          externalId: `${e.channel ?? 'unknown'}:${e.ts}`,
          cursor: e.ts,
          turns: [{ speaker: e.user || e.bot_id || 'unknown', text: e.text }],
          participants: [{ name: e.user || e.bot_id || 'unknown', kind: e.bot_id ? 'agent' : 'employee' }]
        }]
      };
    }
  },
  vapi: {
    vendor: 'Vapi',
    scheme: 'hmac_sha256_hex',
    // https://docs.vapi.ai/server-url — end-of-call-report carries the transcript
    normalize(payload) {
      const m = payload?.message;
      if (!m || m.type !== 'end-of-call-report') return { events: [] };
      const turns = (m.artifact?.messages ?? [])
        .filter((x) => typeof x.message === 'string' && x.message && x.role !== 'system')
        .map((x) => ({ speaker: x.role === 'user' ? 'caller' : 'assistant', text: x.message }));
      if (!turns.length) return { events: [] };
      return {
        events: [{
          externalId: m.call?.id ?? m.timestamp,
          cursor: m.call?.id ?? null,
          turns,
          participants: [
            { name: m.call?.customer?.number ?? 'caller', kind: 'customer' },
            { name: m.assistant?.name ?? 'assistant', kind: 'agent' }
          ]
        }]
      };
    }
  }
};

/** Vendors that sign a push but whose payload shape is not yet confirmed here. */
export function pushCoverage() {
  const wired = Object.entries(PUSH_SOURCES).map(([id, s]) => ({ id, vendor: s.vendor, scheme: s.scheme }));
  return {
    wired,
    count: wired.length,
    statement: `${wired.length} connector(s) accept a signed real-time push today: ${wired.map((w) => w.vendor).join(', ')}. `
      + 'Those capture at the moment the message is sent. Every other connector is polled by the sync scheduler, so it '
      + 'captures at the next poll rather than instantly — which is a property of what the vendor offers, not a setting. '
      + 'A vendor that publishes no push API cannot be made instant by us, and saying otherwise would be the overclaim '
      + 'this product exists to prevent.'
  };
}

/**
 * Receive one pushed event: verify the signature, then ingest.
 *
 * @param {object} o
 * @param {import('./connectors.js').ConnectorManager} o.connectors
 * @param {string} o.connectorId
 * @param {string} o.rawBody the bytes as sent — never a re-serialised object
 * @param {object} o.headers
 * @returns {{ok:boolean, status:number, body:object}}
 */
export function receiveWebhook({ connectors, connectorId, rawBody, headers = {} }) {
  const c = connectors.get(connectorId);
  if (!c) throw notFound('connector', connectorId);

  const source = PUSH_SOURCES[c.catalogId];
  if (!source) {
    return {
      ok: false, status: 400,
      body: { error: 'unsupported_push', message: `${c.name} has no confirmed push payload shape — it is polled instead` }
    };
  }

  const credential = connectors.credentialFor(connectorId);
  if (!credential?.signingSecret) {
    return {
      ok: false, status: 400,
      body: { error: 'no_signing_secret', message: 'this connector has no webhook signing secret on file, so a push cannot be verified' }
    };
  }

  // ---- the load-bearing step -------------------------------------------
  // Verification happens before the payload is parsed. An unverified body is
  // never read, never normalised, and never reaches the gate.
  let client;
  try {
    client = new VendorClient(c.catalogId, { credentials: credential });
  } catch (err) {
    throw new VaultError('config', `cannot build a client for ${c.catalogId}: ${err.message}`);
  }
  const verified = client.verifyWebhook(rawBody, headers);
  if (!verified.valid) {
    connectors.alerts?.raise({
      severity: 'high', kind: 'webhook_signature_failed', subject: connectorId,
      detail: `a push to ${c.name} failed signature verification: ${verified.reason}`
    });
    return { ok: false, status: 401, body: { error: 'bad_signature', message: verified.reason } };
  }

  let payload;
  try { payload = JSON.parse(rawBody); } catch {
    return { ok: false, status: 400, body: { error: 'bad_payload', message: 'the signed body is not JSON' } };
  }

  const { events, challenge } = source.normalize(payload);
  // Slack will not deliver a single event until the challenge is echoed.
  if (challenge) return { ok: true, status: 200, body: { challenge } };

  const results = [];
  for (const event of events) {
    try { results.push(connectors.receive(connectorId, event)); }
    catch (err) { results.push({ error: err.message }); }
  }

  const ingested = results.filter((r) => r.ingested).length;
  const duplicates = results.filter((r) => r.duplicate).length;
  const held = results.flatMap((r) => r.facts ?? []).filter((f) => f.outcome === 'hold' || f.outcome === 'escalate').length;
  const blocked = results.flatMap((r) => r.facts ?? []).filter((f) => f.outcome === 'block').length;

  return {
    ok: true, status: 200,
    body: { received: events.length, ingested, duplicates, held, blocked, verifiedWith: verified.scheme }
  };
}
