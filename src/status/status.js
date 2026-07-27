/**
 * Status page and incident log (§28, §30).
 *
 * I previously listed "public status page" as something that would not happen
 * in code, on the grounds that a status page is an operational commitment
 * rather than a feature. That was half right and half a dodge. The commitment —
 * that a human updates it during an outage — cannot be shipped. The machinery
 * absolutely can: component health computed from real signals, an incident
 * record with a required post-mortem, an uptime calculation that counts
 * degraded time honestly, and a public view that leaks nothing.
 *
 * Two rules shape the whole file:
 *
 * 1. Uptime is computed from recorded incidents, never asserted. If nobody has
 *    recorded an incident, the answer is "no incidents recorded in this window"
 *    — not "100%". Those are different claims and only one of them is honest.
 * 2. The public view is built by allow-list, not by redaction. Anything not
 *    explicitly named cannot appear, so a new internal field cannot leak by
 *    being forgotten.
 */
import { now, iso, MINUTE, HOUR, DAY } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

export const SEVERITIES = /** @type {const} */ (['minor', 'major', 'critical']);
export const INCIDENT_STATES = /** @type {const} */ (['investigating', 'identified', 'monitoring', 'resolved']);

/** Components a customer would actually notice, with how each is measured. */
export const COMPONENTS = {
  ingest: { name: 'Ingest & the gate', measure: 'gate decisions completing without error' },
  read: { name: 'Read path', measure: 'reads served within the latency budget' },
  ledger: { name: 'Ledger & verification', measure: 'chain verifies and anchors are current' },
  search: { name: 'Vault Search', measure: 'index queries returning' },
  storage: { name: 'Storage & buckets', measure: 'customer bucket round-trip' },
  keys: { name: 'Key service', measure: 'wrap/unwrap against the configured KMS' },
  connectors: { name: 'Connectors', measure: 'sources delivering within their expected interval' },
  api: { name: 'API', measure: 'routes answering, rate limiter healthy' },
  ui: { name: 'Control surface', measure: 'served and authenticating' }
};

const STATE_RANK = { operational: 0, degraded: 1, partial_outage: 2, major_outage: 3 };
const worst = (a, b) => (STATE_RANK[b] > STATE_RANK[a] ? b : a);

export class StatusPage {
  constructor({ vault, ledger, notifier = null, clock = now }) {
    this.vault = vault;
    this.ledger = ledger;
    this.notifier = notifier;
    this.clock = clock;
    /** @type {Array<object>} */
    this.incidents = [];
    /** @type {Array<object>} */
    this.maintenance = [];
    this.startedAt = clock();
  }

  // -------------------------------------------------------------------------
  // Component health, computed rather than declared
  // -------------------------------------------------------------------------

  /**
   * Health per component, from live signals.
   *
   * Every probe is wrapped: a probe that throws makes its component degraded
   * and says why. A status page whose own checks can crash reports green
   * forever, which is the specific failure that makes status pages untrusted.
   */
  components() {
    const v = this.vault;
    const probe = (id, fn) => {
      try {
        const out = fn();
        return { id, name: COMPONENTS[id].name, measure: COMPONENTS[id].measure, ...out };
      } catch (e) {
        return { id, name: COMPONENTS[id].name, measure: COMPONENTS[id].measure, state: 'degraded', detail: `health probe failed: ${e.message}` };
      }
    };

    const out = [
      probe('ingest', () => {
        // Levels come from the kill switch itself (§26): 3 stops writes, 4 and
        // 5 freeze a scope, 6 stops everything. Reading the level rather than
        // inventing our own booleans means this cannot drift from the switch.
        const ks = v.killswitch?.state?.() ?? { level: 0 };
        if (ks.level >= 6) return { state: 'major_outage', detail: 'full freeze — no reads, no writes', deliberate: true };
        if (ks.level >= 3) return { state: 'major_outage', detail: `writes stopped by the kill switch (level ${ks.level}, ${ks.reason || 'no reason recorded'})`, deliberate: true };
        if (ks.level === 2) return { state: 'degraded', detail: 'every write is going to the review queue', deliberate: true };
        const queued = ks.queued ?? 0;
        if (queued > 1000) return { state: 'degraded', detail: `${queued} writes queued` };
        return { state: 'operational', detail: 'gate accepting writes' };
      }),
      probe('read', () => {
        const ks = v.killswitch?.state?.() ?? { level: 0 };
        if (ks.level >= 6) return { state: 'major_outage', detail: 'full freeze — reads stopped', deliberate: true };
        if (ks.level === 5) return { state: 'partial_outage', detail: `reads blocked on ${ks.scope ? JSON.stringify(ks.scope) : 'a scope'}`, deliberate: true };
        return { state: 'operational', detail: 'reads being served' };
      }),
      probe('ledger', () => {
        const check = v.verifyLedger();
        if (!check.ok) return { state: 'major_outage', detail: 'the ledger chain does not verify — treat as a security incident, not an availability one' };
        const anchor = v.ledger.lastAnchor?.();
        const stale = anchor && this.clock() - (anchor.at ?? 0) > 24 * HOUR;
        return stale
          ? { state: 'degraded', detail: 'the chain verifies but the last external anchor is over 24h old' }
          : { state: 'operational', detail: `chain verified to entry ${check.entries ?? check.checked ?? '—'}` };
      }),
      probe('search', () => {
        const s = v.search?.stats?.();
        return { state: 'operational', detail: s ? `${s.documents ?? s.indexed ?? 0} documents indexed` : 'index available' };
      }),
      probe('storage', () => {
        if (!v.bucket) return { state: 'operational', detail: 'Vault-managed storage' };
        const st = v.bucket.stats || {};
        if (st.verifyFailures > 0) return { state: 'degraded', detail: `${st.verifyFailures} write(s) failed their round-trip hash check` };
        if (st.errors > 0) return { state: 'degraded', detail: `${st.errors} bucket error(s) since start` };
        return { state: 'operational', detail: `customer bucket, ${st.puts ?? 0} writes` };
      }),
      probe('keys', () => {
        if (!v.keyClient) return { state: 'operational', detail: `keys ${v.kms.mode}` };
        const s = v.keyClient.stats;
        if (s.errors > 0 && s.errors > s.wraps + s.unwraps) return { state: 'major_outage', detail: 'the key service is refusing more calls than it answers' };
        if (s.errors > 0) return { state: 'degraded', detail: `${s.errors} key-service error(s)` };
        return { state: 'operational', detail: `${v.keyClient.provider} key service answering` };
      }),
      probe('connectors', () => {
        const health = v.connectors?.health?.() ?? { silent: [], connected: 0 };
        const silent = health.silent?.length ?? 0;
        const total = health.connected ?? v.connectors?.active?.().length ?? 0;
        if (!total) return { state: 'operational', detail: 'no sources connected' };
        if (silent >= total) return { state: 'major_outage', detail: `all ${total} source(s) silent` };
        if (silent > 0) return { state: 'partial_outage', detail: `${silent} of ${total} source(s) silent` };
        return { state: 'operational', detail: `${total} source(s) delivering` };
      }),
      probe('api', () => {
        const rl = v.rateLimiter?.stats?.();
        if (rl && rl.rejected > rl.allowed) return { state: 'degraded', detail: 'more requests are being rate-limited than served' };
        return { state: 'operational', detail: 'routes answering' };
      }),
      probe('ui', () => ({ state: 'operational', detail: 'served' }))
    ];

    // An open incident overrides a green probe. The probes measure what they can
    // see; an incident is a human saying "this is broken", and the human wins.
    for (const inc of this.open()) {
      for (const id of inc.components) {
        const c = out.find((x) => x.id === id);
        if (c) {
          c.state = worst(c.state, inc.severity === 'critical' ? 'major_outage' : inc.severity === 'major' ? 'partial_outage' : 'degraded');
          c.incident = inc.id;
        }
      }
    }
    return out;
  }

  overall() {
    const comps = this.components();
    const state = comps.reduce((acc, c) => worst(acc, c.state), 'operational');
    const deliberate = comps.filter((c) => c.deliberate).map((c) => c.id);
    return {
      state,
      // "Down because you pressed the kill switch" and "down because we broke"
      // are different sentences, and conflating them destroys trust in both.
      summary: state === 'operational'
        ? 'All systems operational'
        : deliberate.length
          ? `${describe(state)} — ${deliberate.join(', ')} stopped deliberately by an administrator`
          : describe(state),
      degradedComponents: comps.filter((c) => c.state !== 'operational').map((c) => c.id),
      openIncidents: this.open().length,
      checkedAt: iso(this.clock())
    };
  }

  // -------------------------------------------------------------------------
  // Incidents
  // -------------------------------------------------------------------------

  /** Open an incident. Requires a named person — "the system" is not accountable. */
  declare({ title, severity = 'minor', components = [], detail, actor, customerImpact }) {
    if (!actor) throw forbidden('declaring an incident requires a named actor');
    if (!title) throw new VaultError('invalid', 'an incident needs a title a customer could read');
    if (!SEVERITIES.includes(severity)) throw new VaultError('invalid', `severity must be one of ${SEVERITIES.join(', ')}`, { got: severity });
    const unknown = components.filter((c) => !COMPONENTS[c]);
    if (unknown.length) throw new VaultError('invalid', `unknown component(s): ${unknown.join(', ')}`, { available: Object.keys(COMPONENTS) });

    const inc = {
      id: `inc-${this.incidents.length + 1}-${String(this.clock()).slice(-6)}`,
      title, severity, components, customerImpact: customerImpact ?? null,
      state: 'investigating',
      declaredAt: this.clock(), declaredBy: actor,
      resolvedAt: null,
      updates: [{ at: this.clock(), state: 'investigating', body: detail || 'Investigating.', actor }],
      postMortem: null
    };
    this.incidents.push(inc);
    this.ledger?.append('admin.action', { subject: inc.id, actor, action: 'incident.declared', severity, components: components.join(',') });
    this.notifier?.notify({
      kind: 'incident_declared', severity: severity === 'critical' ? 'critical' : severity === 'major' ? 'high' : 'medium',
      subject: inc.id, detail: title
    });
    return this.publicIncident(inc);
  }

  /** Post an update. Every state change is an update; there is no silent transition. */
  update(incidentId, { state, body, actor }) {
    const inc = this._get(incidentId);
    if (!actor) throw forbidden('an incident update requires a named actor');
    if (state && !INCIDENT_STATES.includes(state)) throw new VaultError('invalid', `state must be one of ${INCIDENT_STATES.join(', ')}`, { got: state });
    if (inc.state === 'resolved') throw new VaultError('conflict', 'this incident is resolved — declare a new one rather than reopening the record', { incidentId });
    if (!body) throw new VaultError('invalid', 'an update with no text is not an update');
    inc.state = state || inc.state;
    inc.updates.push({ at: this.clock(), state: inc.state, body, actor });
    this.ledger?.append('admin.action', { subject: inc.id, actor, action: 'incident.updated', state: inc.state });
    return this.publicIncident(inc);
  }

  /**
   * Resolve. A resolution needs a cause and a customer-facing summary; a
   * post-mortem is due within five working days and the page shows when one is
   * overdue rather than quietly forgetting.
   */
  resolve(incidentId, { cause, summary, actor }) {
    const inc = this._get(incidentId);
    if (!actor) throw forbidden('resolving an incident requires a named actor');
    if (!cause) throw new VaultError('invalid', 'resolving without a cause is closing a ticket, not fixing an incident');
    if (!summary) throw new VaultError('invalid', 'a resolution needs a summary a customer can read');
    inc.state = 'resolved';
    inc.resolvedAt = this.clock();
    inc.cause = cause;
    inc.resolutionSummary = summary;
    inc.updates.push({ at: this.clock(), state: 'resolved', body: summary, actor });
    inc.postMortemDueAt = this.clock() + 5 * DAY;
    this.ledger?.append('admin.action', {
      subject: inc.id, actor, action: 'incident.resolved',
      durationMinutes: Math.round((inc.resolvedAt - inc.declaredAt) / MINUTE)
    });
    return this.publicIncident(inc);
  }

  /** Attach the post-mortem. Blameless format, and the actions have owners. */
  postMortem(incidentId, { whatHappened, whyItHappened, whatWeChanged, actions = [], actor }) {
    const inc = this._get(incidentId);
    if (!actor) throw forbidden('a post-mortem requires a named author');
    if (inc.state !== 'resolved') throw new VaultError('conflict', 'write the post-mortem after the incident is resolved', { state: inc.state });
    for (const [field, value] of [['whatHappened', whatHappened], ['whyItHappened', whyItHappened], ['whatWeChanged', whatWeChanged]]) {
      if (!value) throw new VaultError('invalid', `a post-mortem without "${field}" is a status update with a longer name`);
    }
    const unowned = actions.filter((a) => !a.owner);
    if (unowned.length) throw new VaultError('invalid', `${unowned.length} follow-up action(s) have no owner — an unowned action is a wish`, { actions: unowned.map((a) => a.what) });
    inc.postMortem = {
      whatHappened, whyItHappened, whatWeChanged,
      actions: actions.map((a) => ({ ...a, state: a.state || 'open' })),
      writtenBy: actor, writtenAt: this.clock(),
      lateBy: inc.postMortemDueAt && this.clock() > inc.postMortemDueAt
        ? `${Math.round((this.clock() - inc.postMortemDueAt) / DAY)} day(s) late`
        : null
    };
    this.ledger?.append('admin.action', { subject: inc.id, actor, action: 'incident.post_mortem' });
    return inc.postMortem;
  }

  open() { return this.incidents.filter((i) => i.state !== 'resolved'); }

  _get(id) {
    const inc = this.incidents.find((i) => i.id === id);
    if (!inc) throw new VaultError('not_found', `no incident ${id}`, { open: this.open().map((i) => i.id) });
    return inc;
  }

  // -------------------------------------------------------------------------
  // Maintenance
  // -------------------------------------------------------------------------

  scheduleMaintenance({ title, startsAt, endsAt, components = [], detail, actor }) {
    if (!actor) throw forbidden('scheduling maintenance requires a named actor');
    if (!(startsAt && endsAt) || endsAt <= startsAt) throw new VaultError('invalid', 'maintenance needs a start and an end, in that order');
    const notice = startsAt - this.clock();
    const m = {
      id: `maint-${this.maintenance.length + 1}`, title, startsAt, endsAt, components, detail, actor,
      noticeGivenHours: Math.round(notice / HOUR),
      // Announcing a window after it has started is not a notice period, and
      // the record should say so plainly rather than average it away.
      shortNotice: notice < 48 * HOUR
    };
    this.maintenance.push(m);
    this.ledger?.append('admin.action', { subject: m.id, actor, action: 'maintenance.scheduled' });
    return m;
  }

  // -------------------------------------------------------------------------
  // Uptime — computed from the incident record, never asserted
  // -------------------------------------------------------------------------

  /**
   * @param {object} [o]
   * @param {number} [o.windowMs] default 90 days
   */
  uptime({ windowMs = 90 * DAY } = {}) {
    const to = this.clock();
    const from = Math.max(to - windowMs, this.startedAt);
    const observedMs = to - from;

    const perComponent = {};
    for (const id of Object.keys(COMPONENTS)) perComponent[id] = { downMs: 0, degradedMs: 0, incidents: 0 };

    for (const inc of this.incidents) {
      const start = Math.max(inc.declaredAt, from);
      const end = Math.min(inc.resolvedAt ?? to, to);
      if (end <= start) continue;
      const ms = end - start;
      for (const id of inc.components) {
        if (!perComponent[id]) continue;
        perComponent[id].incidents++;
        if (inc.severity === 'critical') perComponent[id].downMs += ms;
        else perComponent[id].degradedMs += ms;
      }
    }

    const rows = Object.entries(perComponent).map(([id, s]) => ({
      component: id,
      name: COMPONENTS[id].name,
      incidents: s.incidents,
      downMinutes: Math.round(s.downMs / MINUTE),
      degradedMinutes: Math.round(s.degradedMs / MINUTE),
      availability: observedMs > 0 ? Number((1 - s.downMs / observedMs).toFixed(5)) : null
    }));

    const totalDown = Object.values(perComponent).reduce((a, s) => a + s.downMs, 0);
    const anyIncident = this.incidents.some((i) => (i.resolvedAt ?? to) > from);

    return {
      window: { from: iso(from), to: iso(to), days: Number((observedMs / DAY).toFixed(1)) },
      // The distinction that makes this honest: a window with no recorded
      // incidents is not evidence of 100% availability, it is evidence that
      // nobody recorded anything. Say which one it is.
      basis: anyIncident
        ? 'computed from declared incidents over the observed window'
        : 'no incidents recorded in this window — this is the absence of a record, not a measurement of availability',
      observedSinceProcessStart: from === this.startedAt,
      components: rows,
      worstComponent: rows.slice().sort((a, b) => b.downMinutes - a.downMinutes)[0] ?? null,
      totalDownMinutes: Math.round(totalDown / MINUTE),
      caveat: 'Availability here counts time an incident was open against the components it named. It is not synthetic external monitoring, and it should not be quoted as an SLA measurement.'
    };
  }

  // -------------------------------------------------------------------------
  // Views
  // -------------------------------------------------------------------------

  /**
   * The public incident record. Allow-list only.
   *
   * Not `{...inc, secret: undefined}` — that pattern leaks every field somebody
   * adds later. Only what is named here can ever reach a public page.
   */
  publicIncident(inc) {
    return {
      id: inc.id,
      title: inc.title,
      severity: inc.severity,
      state: inc.state,
      components: inc.components.map((c) => COMPONENTS[c]?.name ?? c),
      customerImpact: inc.customerImpact,
      declaredAt: iso(inc.declaredAt),
      resolvedAt: inc.resolvedAt ? iso(inc.resolvedAt) : null,
      durationMinutes: inc.resolvedAt ? Math.round((inc.resolvedAt - inc.declaredAt) / MINUTE) : null,
      updates: inc.updates.map((u) => ({ at: iso(u.at), state: u.state, body: u.body })),
      cause: inc.cause ?? null,
      resolution: inc.resolutionSummary ?? null,
      postMortem: inc.postMortem
        ? {
          whatHappened: inc.postMortem.whatHappened,
          whyItHappened: inc.postMortem.whyItHappened,
          whatWeChanged: inc.postMortem.whatWeChanged,
          actions: inc.postMortem.actions.map((a) => ({ what: a.what, state: a.state })),
          publishedAt: iso(inc.postMortem.writtenAt),
          lateBy: inc.postMortem.lateBy
        }
        : (inc.state === 'resolved'
          ? { pending: true, dueAt: iso(inc.postMortemDueAt), overdue: this.clock() > inc.postMortemDueAt }
          : null)
    };
  }

  /** Everything a public status page needs, and nothing else. */
  publicView({ historyDays = 90 } = {}) {
    const since = this.clock() - historyDays * DAY;
    return {
      overall: this.overall(),
      components: this.components().map((c) => ({ name: c.name, state: c.state, measure: c.measure })),
      activeIncidents: this.open().map((i) => this.publicIncident(i)),
      history: this.incidents.filter((i) => (i.resolvedAt ?? this.clock()) >= since).map((i) => this.publicIncident(i)),
      scheduledMaintenance: this.maintenance
        .filter((m) => m.endsAt >= this.clock())
        .map((m) => ({ title: m.title, startsAt: iso(m.startsAt), endsAt: iso(m.endsAt), components: m.components.map((c) => COMPONENTS[c]?.name ?? c), detail: m.detail, shortNotice: m.shortNotice })),
      uptime: this.uptime({ windowMs: historyDays * DAY }),
      generatedAt: iso(this.clock())
    };
  }

  /** The internal view — adds who did what, which the public view never shows. */
  internalView() {
    return {
      ...this.publicView(),
      incidents: this.incidents.map((i) => ({
        ...this.publicIncident(i),
        declaredBy: i.declaredBy,
        updates: i.updates.map((u) => ({ at: iso(u.at), state: u.state, body: u.body, actor: u.actor })),
        postMortemInternal: i.postMortem
          ? { ...i.postMortem, writtenAt: iso(i.postMortem.writtenAt), actions: i.postMortem.actions }
          : null
      })),
      openActionItems: this.incidents.flatMap((i) => (i.postMortem?.actions ?? [])
        .filter((a) => a.state === 'open')
        .map((a) => ({ incident: i.id, what: a.what, owner: a.owner, due: a.due ?? null }))),
      overduePostMortems: this.incidents
        .filter((i) => i.state === 'resolved' && !i.postMortem && this.clock() > i.postMortemDueAt)
        .map((i) => ({ incident: i.id, dueAt: iso(i.postMortemDueAt), overdueDays: Math.round((this.clock() - i.postMortemDueAt) / DAY) }))
    };
  }
}

function describe(state) {
  return {
    operational: 'All systems operational',
    degraded: 'Degraded performance',
    partial_outage: 'Partial outage',
    major_outage: 'Major outage'
  }[state] ?? state;
}
