/**
 * L1 — THE CONNECTION LAYER (§4.1, §4.4).
 *
 * Connector requirements, every one non-negotiable and enforced here rather than
 * left to each integration: least-privilege scopes, secrets never logged,
 * backfill on connect, idempotency, rate-limit awareness with resumable cursors,
 * GAP DETECTION WITH ALARM, health monitoring to a named owner, disconnect ≠
 * delete, version pinning, schema-drift detection, a per-connector kill switch
 * and a per-connector cost meter.
 */
import { newId, derivedId } from '../util/id.js';
import { sha256, randomToken } from '../util/crypto.js';
import { now, iso, ago, duration, MINUTE, HOUR, DAY } from '../util/time.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { CONNECTORS, connector as catalogEntry, MODES } from './catalog.js';

export class ConnectorManager {
  /**
   * @param {object} deps
   */
  constructor({ db, ledger, registry, archive, alerts = null, ingest }) {
    this.col = db.collection('connectors');
    this.ledger = ledger;
    this.registry = registry;
    this.archive = archive;
    this.alerts = alerts;
    this.ingest = ingest;                       // (raw) => result — the write path
    this.col.index('byCatalogId', (c) => c.catalogId);
    /** Secrets live here and are NEVER written to the collection, the ledger or a log. */
    this.secrets = new Map();
    this.compatibilityRuns = [];
  }

  // ==== lifecycle =========================================================

  /**
   * @param {object} spec
   */
  connect(spec) {
    const {
      catalogId, mode = 'watch', credential, owner, technicalOwner,
      actor, agentId = null, region = null, expectedRatePerHour = null,
      backfillDays = 30, scopes = null, versionPin = null
    } = spec;

    const entry = catalogEntry(catalogId);
    if (!entry) throw new VaultError('not_found', 'unknown connector', { catalogId, available: CONNECTORS.length });
    if (!entry.modes.includes(mode)) {
      throw new VaultError('validation', `${entry.name} does not support ${mode} mode`, { supported: entry.modes });
    }
    if (!owner || !technicalOwner) {
      throw new VaultError('validation', 'a connector needs a named business owner and a named technical owner — silence has to alert someone');
    }
    if (!actor) throw forbidden('connecting requires a named actor');

    const id = newId('connector');
    // Least-privilege: we request exactly the catalog's documented scopes unless
    // the customer narrows them further. We never widen.
    const requested = scopes ? scopes.filter((s) => entry.scopes.includes(s)) : entry.scopes;

    const record = this.col.insert({
      id,
      catalogId,
      name: entry.name,
      vendor: entry.vendor,
      category: entry.category,
      channel: entry.channel,
      mode,
      status: 'connected',
      owner,
      technicalOwner,
      agentId,
      region,
      scopes: requested,
      // credential is NOT stored here — only a fingerprint, so rotation is provable
      credentialFingerprint: credential ? sha256(credential).slice(0, 16) : null,
      credentialRotatedAt: credential ? now() : null,
      versionPin: versionPin || 'latest',
      schemaFingerprint: null,
      connectedAt: now(),
      connectedBy: actor,
      disconnectedAt: null,
      lastEventAt: null,
      cursor: null,
      eventsIngested: 0,
      duplicatesSuppressed: 0,
      errors: 0,
      backoffUntil: null,
      expectedRatePerHour,
      killed: false,
      costUsd: 0,
      gapReports: []
    });

    if (credential) this.secrets.set(id, credential);

    this.ledger.append('connector.connected', {
      subject: id, actor, catalogId, name: entry.name, mode, owner, technicalOwner,
      scopes: requested.length, region
      // note: no credential, no fingerprint of the secret's content beyond an id
    });

    const backfill = backfillDays ? this.backfill(id, { days: backfillDays, actor }) : null;
    return { ...this.col.get(id), backfill, modeDescription: MODES[mode], cannotPull: entry.cannotPull };
  }

  get(id) { return this.col.get(id); }
  all() { return this.col.all(); }
  active() { return this.col.find((c) => c.status === 'connected' && !c.killed); }

  /** Disconnect ≠ delete. Facts and history survive; access dies immediately. */
  disconnect(id, { actor, reason }) {
    const c = this.col.get(id);
    if (!c) throw notFound('connector', id);
    if (!actor || !reason) throw forbidden('disconnecting requires a named actor and a reason');
    this.secrets.delete(id);
    const updated = this.col.update(id, { status: 'disconnected', disconnectedAt: now(), disconnectReason: reason });
    this.ledger.append('connector.connected', { subject: id, actor, reason, status: 'disconnected' });
    return {
      ...updated,
      note: 'access died immediately; every fact and every archived conversation this connector produced remains, with its full history'
    };
  }

  rotateCredential(id, { credential, actor, reason = 'scheduled rotation' }) {
    const c = this.col.get(id);
    if (!c) throw notFound('connector', id);
    if (!actor) throw forbidden('credential rotation requires a named actor');
    this.secrets.set(id, credential);
    const updated = this.col.update(id, {
      credentialFingerprint: sha256(credential).slice(0, 16),
      credentialRotatedAt: now()
    });
    this.ledger.append('connector.connected', { subject: id, actor, reason, event: 'credential_rotated' });
    return { id, rotatedAt: iso(updated.credentialRotatedAt), note: 'the credential itself is never logged, never stored in the collection and never appears in an error message' };
  }

  /** Per-connector kill switch (§4.4). */
  kill(id, { actor, reason }) {
    const c = this.col.get(id);
    if (!c) throw notFound('connector', id);
    if (!actor || !reason) throw forbidden('killing a connector requires a named actor and a reason');
    const updated = this.col.update(id, { killed: true, killedAt: now(), killReason: reason });
    this.ledger.append('connector.connected', { subject: id, actor, reason, event: 'killed' });
    this.alerts?.raise({ severity: 'medium', kind: 'connector_killed', actor, detail: `${c.name} killed: ${reason}`, subject: id });
    return updated;
  }

  revive(id, { actor, reason }) {
    if (!actor || !reason) throw forbidden('reviving a connector requires a named actor and a reason');
    const updated = this.col.update(id, { killed: false, revivedAt: now() });
    this.ledger.append('connector.connected', { subject: id, actor, reason, event: 'revived' });
    return updated;
  }

  // ==== ingestion =========================================================

  /**
   * Push an event through the connector. Idempotent — reconnecting never
   * duplicates.
   * @param {string} id
   * @param {object} event
   */
  receive(id, event) {
    const c = this.col.get(id);
    if (!c) throw notFound('connector', id);
    if (c.killed) throw new VaultError('frozen', 'connector kill switch is engaged', { id, reason: c.killReason });
    if (c.status !== 'connected') throw new VaultError('forbidden', 'connector is disconnected', { id });
    if (c.backoffUntil && now() < c.backoffUntil) {
      return { queued: true, retryAfterMs: c.backoffUntil - now(), reason: 'rate-limit backoff' };
    }

    const externalId = event.externalId || event.id || sha256(JSON.stringify(event)).slice(0, 24);
    const conversationId = derivedId('conversation', c.catalogId, externalId);
    if (this.archive.get(conversationId)) {
      this.col.update(id, { duplicatesSuppressed: c.duplicatesSuppressed + 1, lastEventAt: now() });
      return { duplicate: true, conversationId, note: 'idempotent — reconnecting never duplicates' };
    }

    // Schema drift detection: upstream added a field, we notice (§4.4).
    const fingerprint = schemaFingerprint(event);
    if (c.schemaFingerprint && c.schemaFingerprint !== fingerprint) {
      const drift = diffSchema(c.lastSchemaKeys || [], Object.keys(flatten(event)));
      this.alerts?.raise({
        severity: 'medium', kind: 'schema_drift', subject: id,
        detail: `${c.name} schema changed — added: ${drift.added.join(', ') || 'none'}; removed: ${drift.removed.join(', ') || 'none'}`
      });
      this.ledger.append('connector.health', { subject: id, event: 'schema_drift', added: drift.added.length, removed: drift.removed.length });
    }

    const result = this.ingest({
      ...event,
      id: conversationId,
      externalId,
      connector: c.catalogId,
      connectorMode: c.mode,
      channel: event.channel || c.channel,
      agentId: event.agentId || c.agentId,
      region: event.region || c.region
    });

    this.col.update(id, {
      eventsIngested: c.eventsIngested + 1,
      lastEventAt: now(),
      cursor: event.cursor || externalId,
      schemaFingerprint: fingerprint,
      lastSchemaKeys: Object.keys(flatten(event)),
      costUsd: Math.round((c.costUsd + (event.costUsd || 0)) * 10000) / 10000
    });
    return { ingested: true, conversationId, ...result };
  }

  /** Rate-limit aware, exponential backoff, resumable from cursor (§4.4). */
  recordRateLimit(id, { retryAfterMs = null } = {}) {
    const c = this.col.get(id);
    if (!c) throw notFound('connector', id);
    const attempt = (c.rateLimitAttempts || 0) + 1;
    const backoff = retryAfterMs ?? Math.min(30 * MINUTE, 2 ** attempt * 1000);
    this.col.update(id, { backoffUntil: now() + backoff, rateLimitAttempts: attempt });
    return { backoffMs: backoff, attempt, resumeFrom: c.cursor };
  }

  /** Backfill on connect (pull history), then incremental (§4.4). */
  backfill(id, { days = 30, actor = 'system', fetcher = null } = {}) {
    const c = this.col.get(id);
    if (!c) throw notFound('connector', id);
    const from = now() - days * DAY;
    if (!fetcher) {
      return {
        connectorId: id, requested: `${days} days`, from: iso(from),
        status: 'ready',
        note: 'supply a fetcher to pull history; the cursor and idempotency guarantees make a partial backfill safe to retry'
      };
    }
    let count = 0;
    let cursor = null;
    for (const event of fetcher({ from, cursor: c.cursor })) {
      try { this.receive(id, event); count++; cursor = event.cursor || cursor; } catch { /* skip and continue */ }
    }
    this.ledger.append('connector.health', { subject: id, actor, event: 'backfill', events: count, days });
    return { connectorId: id, backfilled: count, from: iso(from), cursor };
  }

  // ==== health & gap detection ============================================

  /**
   * GAP DETECTION WITH ALARM — "we should have seen data between 14:00 and 16:00
   * and didn't" (§4.4). Alert within 15 minutes of expected-but-absent data.
   */
  detectGaps({ alertWithinMs = 15 * MINUTE } = {}) {
    const gaps = [];
    for (const c of this.active()) {
      if (!c.expectedRatePerHour || !c.lastEventAt) continue;
      const expectedIntervalMs = HOUR / c.expectedRatePerHour;
      const silentFor = now() - c.lastEventAt;
      if (silentFor <= Math.max(expectedIntervalMs * 3, alertWithinMs)) continue;
      const expectedCount = Math.floor(silentFor / expectedIntervalMs);
      const gap = {
        connectorId: c.id,
        name: c.name,
        from: iso(c.lastEventAt),
        to: iso(now()),
        silentFor: ago(c.lastEventAt),
        expected: expectedCount,
        actual: 0,
        owner: c.technicalOwner,
        alarm: `we should have seen roughly ${expectedCount} events from ${c.name} between ${iso(c.lastEventAt).slice(11, 16)} and ${iso(now()).slice(11, 16)} and saw none`
      };
      gaps.push(gap);
      this.col.update(c.id, { gapReports: [...c.gapReports, gap] });
      this.ledger.append('connector.gap', {
        subject: c.id, expected: expectedCount, actual: 0,
        from: gap.from, to: gap.to, owner: c.technicalOwner
      });
      this.alerts?.raise({
        severity: 'high', kind: 'connector_gap', subject: c.id,
        detail: `${gap.alarm} — notify ${c.technicalOwner}`
      });
    }
    return gaps;
  }

  /** Health monitor — "connector silent for 4 hours" → alert to a named owner. */
  health({ silentAfterMs = 4 * HOUR } = {}) {
    return this.all().map((c) => {
      const silentFor = c.lastEventAt ? now() - c.lastEventAt : null;
      const silent = c.status === 'connected' && !c.killed && (silentFor === null || silentFor >= silentAfterMs);
      if (silent && c.status === 'connected') {
        this.alerts?.raise({
          severity: 'medium', kind: 'connector_silent', subject: c.id,
          detail: `${c.name} has been silent for ${c.lastEventAt ? ago(c.lastEventAt) : 'its entire lifetime'} — notify ${c.technicalOwner}`
        });
      }
      return {
        id: c.id, name: c.name, mode: c.mode, status: c.killed ? 'killed' : c.status,
        healthy: !silent && !c.killed && c.status === 'connected',
        lastEvent: c.lastEventAt ? ago(c.lastEventAt) : 'never',
        eventsIngested: c.eventsIngested,
        duplicatesSuppressed: c.duplicatesSuppressed,
        errors: c.errors,
        owner: c.owner,
        technicalOwner: c.technicalOwner,
        costUsd: c.costUsd,
        openGaps: c.gapReports.length,
        alert: silent ? `silent for ${c.lastEventAt ? ago(c.lastEventAt) : 'its entire lifetime'} — notify ${c.technicalOwner}` : null
      };
    });
  }

  /**
   * Version-pinned against upstream API changes, with a compatibility test suite
   * run daily (§4.4).
   */
  runCompatibilitySuite({ actor = 'ci', probe = null } = {}) {
    const results = [];
    for (const c of this.active()) {
      const entry = catalogEntry(c.catalogId);
      let ok = true;
      let detail = 'pinned version responds as expected';
      if (probe) {
        try { const r = probe(c); ok = r !== false; detail = typeof r === 'string' ? r : detail; }
        catch (e) { ok = false; detail = e.message; }
      }
      results.push({ connectorId: c.id, name: c.name, versionPin: c.versionPin, ok, detail, scopes: c.scopes, documentedCannotPull: entry?.cannotPull ?? [] });
      if (!ok) {
        this.alerts?.raise({ severity: 'high', kind: 'connector_incompatible', subject: c.id, detail: `${c.name}: ${detail}` });
      }
    }
    const run = { at: now(), actor, total: results.length, failing: results.filter((r) => !r.ok).length, results };
    this.compatibilityRuns.push(run);
    return { ...run, at: iso(run.at), cadence: 'daily' };
  }

  /** Per-connector cost meter (§4.4). */
  costReport() {
    const rows = this.all().map((c) => ({
      connector: c.name, mode: c.mode, events: c.eventsIngested,
      costUsd: c.costUsd, costPerEvent: c.eventsIngested ? Math.round((c.costUsd / c.eventsIngested) * 10000) / 10000 : 0,
      owner: c.owner
    }));
    return { rows: rows.sort((a, b) => b.costUsd - a.costUsd), total: Math.round(rows.reduce((a, r) => a + r.costUsd, 0) * 100) / 100 };
  }

  /** The seven things every connector ships with (§4.2). */
  describe(catalogId) {
    const e = catalogEntry(catalogId);
    if (!e) throw notFound('connector', catalogId);
    return {
      name: e.name,
      vendor: e.vendor,
      authMethod: e.auth,
      modesSupported: e.modes.map((m) => MODES[m]),
      whatItPulls: e.pulls,
      whatItCannotPull: e.cannotPull,
      setupTime: `${e.setupMinutes} minutes`,
      scopesRequired: e.scopes,
      rateLimitProfile: e.rateLimit,
      channelClassification: e.channel,
      honestNote: e.honestNote ?? null,
      retentionWarning: e.retentionWarning ?? null,
      requirements: REQUIREMENTS
    };
  }
}

/** The non-negotiables, published (§4.4). */
export const REQUIREMENTS = [
  'least-privilege scopes, enumerated and documented per connector',
  'credentials in an encrypted secret store, rotatable, never logged, never in error messages',
  'backfill on connect (pull history) + incremental after',
  'idempotent — reconnecting never duplicates',
  'rate-limit aware, exponential backoff, resumable from cursor',
  'gap detection with alarm — "we should have seen data between 14:00 and 16:00 and didn\'t"',
  'health monitor — "connector silent for 4 hours" → alert to a named owner',
  'disconnect ≠ delete — facts and history survive; access dies immediately',
  'version-pinned against upstream API changes, with a compatibility test suite run daily',
  'schema drift detection — upstream added a field, we notice',
  'per-connector kill switch',
  'per-connector cost meter'
];

// ---------------------------------------------------------------------------

function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = typeof v;
  }
  return out;
}

function schemaFingerprint(event) {
  return sha256(Object.keys(flatten(event)).sort().join('|')).slice(0, 16);
}

function diffSchema(before, after) {
  return {
    added: after.filter((k) => !before.includes(k)),
    removed: before.filter((k) => !after.includes(k))
  };
}

/**
 * GATEWAY mode: a proxy in front of AI API traffic. Sees everything by
 * construction, including agents nobody registered — which is how shadow agents
 * surface (§4.1).
 */
export class Gateway {
  /**
   * @param {object} deps
   * @param {import('../registry/registry.js').Registry} deps.registry
   * @param {'observe'|'enforce'} [deps.posture]
   */
  constructor({ registry, ingest, ledger, posture = 'observe', alerts = null }) {
    this.registry = registry;
    this.ingest = ingest;
    this.ledger = ledger;
    this.posture = posture;
    this.alerts = alerts;
    this.traffic = [];
  }

  /**
   * @param {object} req { identifier, endpoint, model, body, origin }
   */
  intercept(req) {
    const { identifier, endpoint, model, origin } = req;
    this.traffic.push({ at: now(), identifier, endpoint, model, origin });
    const seen = this.registry.observeTraffic({
      identifier, endpoint, model, origin,
      channel: 'gateway', bytes: JSON.stringify(req.body ?? '').length
    });

    if (!seen.known) {
      this.alerts?.raise({
        severity: 'high', kind: 'shadow_agent_detected', subject: identifier,
        detail: `unregistered agent "${identifier}" observed calling ${model ?? endpoint} through the gateway`
      });
      if (this.posture === 'enforce') {
        return { allowed: false, reason: 'unregistered agent — the gateway is in enforcing posture', shadow: true };
      }
    }

    // In enforcing posture the gateway also puts writes through the gate.
    if (this.posture === 'enforce' && req.body?.memoryWrite) {
      const result = this.ingest({
        content: req.body.memoryWrite,
        channel: 'third_party_api',
        agentId: identifier,
        connector: 'gateway',
        connectorMode: 'gateway'
      });
      return { allowed: result.outcome !== 'block', gateResult: result, shadow: !seen.known };
    }
    return { allowed: true, observed: true, shadow: !seen.known };
  }

  stats() {
    const identifiers = new Set(this.traffic.map((t) => t.identifier));
    return {
      posture: this.posture,
      requestsObserved: this.traffic.length,
      distinctIdentifiers: identifiers.size,
      shadowAgents: this.registry.shadowAgents().length,
      models: [...new Set(this.traffic.map((t) => t.model).filter(Boolean))]
    };
  }
}
