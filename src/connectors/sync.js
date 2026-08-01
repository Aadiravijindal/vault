/**
 * CONTINUOUS SYNC — the loop that closes the gap between "connected" and
 * "ingested", without anyone calling vault_remember by hand.
 *
 * connectors.js already has everything a poll loop needs downstream:
 * idempotency, cursors, schema-drift detection, gap alarms, the kill switch,
 * the cost meter — receive(id, event) does all of it, and every event it
 * receives goes through the SAME gate as an inline write (filing, sensitivity,
 * department walls, instruction detection, the lot). What it never had was
 * anything upstream that actually calls the vendor on a schedule and hands it
 * events. `backfill()` required the caller to supply a fetcher; this is that
 * fetcher, wired to run continuously and to the real client in clients.js.
 *
 * The honest limit, stated the same way conformance.js and specs.js state
 * theirs: a vendor's LIST/HISTORY response has a shape, and turning that shape
 * into `{ turns, participants }` is vendor-specific code that has to be
 * written against real documentation, not guessed. Writing one for a vendor
 * whose shape has not been confirmed would be exactly the overclaim this
 * project exists to refuse. So this ships normalizers only for the vendors
 * whose response shape is already pinned down elsewhere in the codebase —
 * the same three with a contract test against a published OpenAPI spec
 * (specs.js) — and reports every other connected connector as "no
 * normalizer registered" rather than silently doing nothing. That is a
 * fourth, narrower meaning of "verified", alongside conformance/contract/live:
 *
 *   conformance   — the request is well-formed                    (all 74)
 *   contract      — the endpoint exists in the vendor's own spec   (3 of 74)
 *   sync          — continuous polling is wired to a real shape    (3 of 74, today)
 *   live          — a real tenant answered it                      (4 of 74)
 *
 * `syncCoverage()` reports that count so it can sit on the same coverage map
 * as the other three, instead of being a private implementation detail nobody
 * can audit.
 */
import { VendorClient } from './clients.js';
import { now } from '../util/time.js';

/**
 * How to ask each wired vendor for "what's new since last time", and how to
 * turn its answer into the `{ turns, participants }` shape receive() expects.
 *
 * Both live on the same catalog id so adding a vendor means adding one entry
 * here, not touching the scheduler.
 */
export const SYNC_SOURCES = {
  'slack-bot': {
    vendor: 'Slack',
    endpoint: 'history',
    query: (cursor) => (cursor ? { cursor, limit: '200' } : { limit: '200' }),
    // https://api.slack.com/methods/conversations.history
    normalize(body) {
      if (!body || body.ok === false || !Array.isArray(body.messages)) return { events: [], cursor: null };
      const events = body.messages
        .filter((m) => m.type === 'message' && typeof m.text === 'string' && m.text.length)
        .map((m) => ({
          externalId: m.ts,
          cursor: m.ts,
          turns: [{ speaker: m.user || m.bot_id || 'unknown', text: m.text }],
          participants: [{ name: m.user || m.bot_id || 'unknown', kind: m.bot_id ? 'agent' : 'employee' }]
        }));
      return { events, cursor: body.response_metadata?.next_cursor || events[0]?.cursor || null };
    }
  },
  'copilot-agent': {
    vendor: 'GitHub',
    endpoint: 'events',
    query: () => ({}),
    // https://docs.github.com/en/rest/activity/events — newest first, no cursor param;
    // dedup on externalId (receive() is idempotent) is what makes repolling the same page safe.
    normalize(body) {
      const list = Array.isArray(body) ? body : [];
      const events = list
        .filter((e) => e.type === 'IssueCommentEvent' && e.payload?.comment?.body)
        .map((e) => ({
          externalId: String(e.id),
          cursor: String(e.id),
          turns: [{ speaker: e.actor?.login || 'unknown', text: e.payload.comment.body }],
          participants: [{ name: e.actor?.login || 'unknown', kind: 'agent' }]
        }));
      return { events, cursor: events[0]?.cursor || null };
    }
  },
  twilio: {
    vendor: 'Twilio',
    endpoint: 'calls',
    query: (cursor) => (cursor ? { PageToken: cursor } : {}),
    // https://www.twilio.com/docs/voice/api/call-resource — call metadata only;
    // the transcript itself is a separate resource (Transcriptions) not mapped
    // here, so this normalizer states plainly what it does and does not carry.
    normalize(body) {
      const list = body?.calls ?? [];
      const events = list.map((c) => ({
        externalId: c.sid,
        cursor: c.sid,
        turns: [{ speaker: 'system', text: `call ${c.status}: ${c.from} -> ${c.to}, ${c.duration ?? '0'}s (metadata only — no transcript resource mapped)` }],
        participants: [
          { name: c.from ?? 'unknown', kind: 'customer' },
          { name: c.to ?? 'unknown', kind: 'agent' }
        ]
      }));
      return { events, cursor: list[0]?.sid || null };
    }
  }
};

/**
 * Pulls and ingests new events for every connector wired above, on a
 * schedule. Everything else — dedup, the gate, health, cost — is
 * connectors.js; this only supplies the "go ask the vendor" step.
 */
export class SyncScheduler {
  /**
   * @param {object} deps
   * @param {import('./connectors.js').ConnectorManager} deps.connectors
   * @param {typeof globalThis.fetch} [deps.fetchImpl]
   * @param {number} [deps.intervalMs]
   * @param {(report:object)=>void} [deps.onReport]
   */
  constructor({ connectors, fetchImpl = globalThis.fetch, intervalMs = 5 * 60 * 1000, onReport = () => {} }) {
    this.connectors = connectors;
    this.fetchImpl = fetchImpl;
    this.intervalMs = intervalMs;
    this.onReport = onReport;
    this._timer = null;
  }

  /** One pull-and-ingest pass for a single connector. Never throws. */
  async syncOne(id) {
    const c = this.connectors.get(id);
    if (!c) return { id, skipped: true, reason: 'no such connector' };
    if (c.killed) return { id, name: c.name, skipped: true, reason: 'kill switch engaged' };
    if (c.status !== 'connected') return { id, name: c.name, skipped: true, reason: 'disconnected' };

    const source = SYNC_SOURCES[c.catalogId];
    if (!source) {
      return { id, name: c.name, skipped: true, reason: `no response-shape normalizer registered for ${c.vendor} — still webhook push or manual backfill only` };
    }

    const credential = this.connectors.credentialFor(id);
    if (!credential) return { id, name: c.name, skipped: true, reason: 'no credential on file for this connector' };

    let client;
    try {
      client = new VendorClient(c.catalogId, { credentials: credential, fetchImpl: this.fetchImpl });
    } catch (err) {
      return { id, name: c.name, error: err.message, polled: 0, ingested: 0 };
    }

    let res;
    try {
      res = await client.request(source.endpoint, { query: source.query(c.cursor) });
    } catch (err) {
      return { id, name: c.name, error: err.message, polled: 0, ingested: 0 };
    }
    if (!res.ok) return { id, name: c.name, error: `${source.vendor} returned ${res.status}`, polled: 0, ingested: 0 };

    const { events, cursor } = source.normalize(res.body);
    let ingested = 0;
    let duplicates = 0;
    let held = 0;
    let blocked = 0;
    for (const event of events) {
      let r;
      try {
        r = this.connectors.receive(id, event);
      } catch {
        continue; // one bad event never stops the pass
      }
      if (r.duplicate) { duplicates++; continue; }
      if (r.ingested) {
        ingested++;
        for (const f of r.facts ?? []) {
          if (f.outcome === 'hold' || f.outcome === 'escalate') held++;
          if (f.outcome === 'block') blocked++;
        }
      }
    }

    return { id, name: c.name, vendor: source.vendor, polled: events.length, ingested, duplicates, held, blocked, cursor: cursor ?? c.cursor };
  }

  /** One pass across every active connector. */
  async runOnce() {
    const results = [];
    for (const c of this.connectors.active()) results.push(await this.syncOne(c.id));

    const synced = results.filter((r) => !r.skipped && !r.error);
    const skipped = results.filter((r) => r.skipped);
    const errored = results.filter((r) => r.error);
    const report = {
      at: now(),
      total: results.length,
      synced, skipped, errored,
      ingested: synced.reduce((a, r) => a + r.ingested, 0),
      held: synced.reduce((a, r) => a + r.held, 0),
      blocked: synced.reduce((a, r) => a + r.blocked, 0),
      statement: `${synced.length} of ${results.length} connected connectors were polled and ingested this pass. `
        + `${synced.reduce((a, r) => a + r.ingested, 0)} new fact(s) went through the gate; `
        + `${synced.reduce((a, r) => a + r.held, 0)} held for a human, ${synced.reduce((a, r) => a + r.blocked, 0)} blocked outright. `
        + `${skipped.length} connector(s) were skipped, named, with why.`
    };
    this.onReport(report);
    return report;
  }

  /** Run forever on intervalMs, starting now. Idempotent — calling twice is a no-op. */
  start() {
    if (this._timer) return this;
    const tick = () => { this.runOnce().catch(() => {}); };
    tick();
    this._timer = setInterval(tick, this.intervalMs);
    this._timer.unref?.();
    return this;
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    return this;
  }
}

/** Where continuous sync stands today, for the coverage map. */
export function syncCoverage() {
  const wired = Object.entries(SYNC_SOURCES).map(([id, s]) => ({ id, vendor: s.vendor }));
  return {
    wired,
    count: wired.length,
    statement: `${wired.length} connector(s) have continuous polling wired to a confirmed response shape today: `
      + `${wired.map((w) => w.vendor).join(', ')} — the same vendors covered by the contract test, because that is `
      + `where the response shape is actually pinned down rather than guessed. Every other connector still relies `
      + `on webhook push (where the vendor delivers one) or a manually supplied backfill fetcher. That is not sync `
      + `being unimportant for them — it is a normalizer against an unconfirmed shape being exactly the overclaim `
      + `this map exists to prevent. Each one gets wired the same way once its real response shape is confirmed.`
  };
}
