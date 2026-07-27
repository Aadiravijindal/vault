/**
 * Layer 6 — detection & response (§9.8).
 *
 * Real-time alerting with severity, deduplication and correlation (don't page
 * someone 200 times), case management, and automated response playbooks.
 */
import { newId } from '../util/id.js';
import { now, iso, ago, MINUTE, HOUR } from '../util/time.js';
import { sha256 } from '../util/crypto.js';
import { VaultError } from '../util/errors.js';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Where alerts go. Each sink is a function; the defaults are console-safe. */
export const SINKS = {
  email: (a) => ({ channel: 'email', delivered: true, alert: a.id }),
  slack: (a) => ({ channel: 'slack', delivered: true, alert: a.id }),
  teams: (a) => ({ channel: 'teams', delivered: true, alert: a.id }),
  pagerduty: (a) => ({ channel: 'pagerduty', delivered: true, alert: a.id }),
  siem: (a) => ({ channel: 'siem', delivered: true, alert: a.id })
};

export class AlertManager {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../storage/db.js').Collection} opts.cases
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {Record<string, (a:object)=>any>} [opts.sinks]
   * @param {Record<string, string[]>} [opts.routing] severity → sink names
   */
  constructor({ collection, cases, ledger, sinks = SINKS, routing = null, dedupWindowMs = 15 * MINUTE }) {
    this.col = collection;
    this.cases = cases;
    this.ledger = ledger;
    this.sinks = sinks;
    this.routing = routing || {
      info: [], low: ['siem'], medium: ['slack', 'siem'],
      high: ['slack', 'email', 'siem'], critical: ['pagerduty', 'slack', 'email', 'siem']
    };
    this.dedupWindowMs = dedupWindowMs;
    this.col.index('bySeverity', (a) => a.severity);
    this.col.index('byKind', (a) => a.kind);
    this.col.index('byStatus', (a) => a.status);
    this.playbooks = new Map();
    this.deliveries = [];
    this.subscribers = new Set();
    this.installDefaultPlaybooks();
  }

  subscribe(fn) { this.subscribers.add(fn); return () => this.subscribers.delete(fn); }

  /**
   * @param {{severity?:string, kind:string, actor?:string, detail:string, [k:string]:any}} spec
   */
  raise(spec) {
    const severity = SEVERITIES.includes(spec.severity) ? spec.severity : 'medium';
    const fingerprint = sha256([spec.kind, spec.actor ?? '', spec.folder ?? '', spec.subject ?? ''].join('|')).slice(0, 16);

    // Deduplicate and correlate.
    const recent = this.col.find((a) => a.fingerprint === fingerprint && now() - a.lastSeenAt < this.dedupWindowMs && a.status !== 'closed');
    if (recent.length) {
      const a = recent[0];
      const updated = this.col.update(a.id, {
        count: a.count + 1, lastSeenAt: now(),
        severity: SEV_RANK[severity] > SEV_RANK[a.severity] ? severity : a.severity
      });
      return { ...updated, deduplicated: true };
    }

    const alert = this.col.insert({
      id: newId('alert'),
      at: now(), lastSeenAt: now(), count: 1,
      severity, kind: spec.kind, actor: spec.actor ?? null, subject: spec.subject ?? null,
      detail: spec.detail, context: omit(spec, ['severity', 'kind', 'actor', 'detail', 'subject']),
      fingerprint, status: 'open', caseId: null, acknowledgedBy: null, resolvedAt: null,
      suggestedAction: SUGGESTED_ACTIONS[spec.kind] || 'investigate and decide',
      blastRadius: spec.blastRadius ?? null
    });

    this.ledger.append('security.alert', {
      subject: alert.subject || alert.kind, actor: alert.actor,
      alertId: alert.id, severity, kind: alert.kind
    });

    for (const sink of this.routing[severity] || []) {
      if (this.sinks[sink]) {
        try { this.deliveries.push({ ...this.sinks[sink](alert), at: now(), severity }); } catch { /* a sink must never break detection */ }
      }
    }
    for (const fn of this.subscribers) { try { fn(alert); } catch { /* ignore */ } }

    // Automated response playbooks.
    const playbook = this.playbooks.get(alert.kind);
    if (playbook) {
      try {
        const result = playbook(alert, this);
        this.col.update(alert.id, { playbookRun: playbook.name || alert.kind, playbookResult: result });
      } catch (e) {
        this.col.update(alert.id, { playbookError: e.message });
      }
    }
    return alert;
  }

  acknowledge(alertId, { actor, note }) {
    if (!actor) throw new VaultError('forbidden', 'acknowledging an alert requires a named actor');
    return this.col.update(alertId, { status: 'acknowledged', acknowledgedBy: actor, acknowledgedAt: now(), note });
  }

  resolve(alertId, { actor, resolution }) {
    if (!actor || !resolution) throw new VaultError('forbidden', 'resolving an alert requires a named actor and a resolution');
    const a = this.col.update(alertId, { status: 'closed', resolvedAt: now(), resolvedBy: actor, resolution });
    this.ledger.append('security.alert', { subject: a.subject || a.kind, actor, alertId, status: 'closed', resolution });
    return a;
  }

  open({ severity = null, limit = 100 } = {}) {
    return this.col.find((a) => a.status !== 'closed' && (!severity || a.severity === severity))
      .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.lastSeenAt - a.lastSeenAt)
      .slice(0, limit)
      .map((a) => ({ ...a, age: ago(a.at) }));
  }

  // -- cases ---------------------------------------------------------------

  /** Own case management, or push to their SOAR (§9.8). */
  openCase({ title, alertIds = [], actor, severity = 'high', description = '' }) {
    if (!actor || !title) throw new VaultError('forbidden', 'opening a case requires a title and a named actor');
    const c = this.cases.insert({
      id: newId('case'), title, description, severity, status: 'open',
      openedBy: actor, openedAt: now(), alertIds, timeline: [{ at: now(), actor, event: 'case opened' }],
      closedAt: null, rootCause: null, remediation: null, disclosure: null
    });
    for (const id of alertIds) {
      if (this.col.get(id)) this.col.update(id, { caseId: c.id });
    }
    return c;
  }

  addToCase(caseId, { actor, event, alertId = null }) {
    const c = this.cases.get(caseId);
    if (!c) throw new VaultError('not_found', 'case not found', { caseId });
    const timeline = [...c.timeline, { at: now(), actor, event, alertId }];
    const alertIds = alertId ? [...new Set([...c.alertIds, alertId])] : c.alertIds;
    if (alertId && this.col.get(alertId)) this.col.update(alertId, { caseId });
    return this.cases.update(caseId, { timeline, alertIds });
  }

  closeCase(caseId, { actor, rootCause, remediation, disclosure = null }) {
    if (!actor || !rootCause) throw new VaultError('forbidden', 'closing a case requires a named actor and a root cause');
    const c = this.cases.update(caseId, {
      status: 'closed', closedAt: now(), closedBy: actor, rootCause, remediation, disclosure,
      timeline: [...this.cases.require(caseId).timeline, { at: now(), actor, event: `closed: ${rootCause}` }]
    });
    this.ledger.append('security.detection', { subject: caseId, actor, detection: 'case_closed', rootCause });
    return c;
  }

  // -- playbooks -----------------------------------------------------------

  registerPlaybook(kind, fn) { this.playbooks.set(kind, fn); return this; }

  installDefaultPlaybooks() {
    // "on drip-feed detection → freeze folder, notify owner, open case" (§9.8)
    this.registerPlaybook('drip_feed', (alert, mgr) => {
      const c = mgr.openCase({
        title: `Drip-feed poisoning suspected: ${alert.context?.claimSubject || alert.subject || 'unknown subject'}`,
        alertIds: [alert.id], actor: 'playbook:drip_feed', severity: 'high',
        description: alert.detail
      });
      return { caseId: c.id, actions: ['folder freeze recommended', 'folder owner notified'] };
    });
    this.registerPlaybook('golden_overwrite_attempt', (alert, mgr) => {
      const c = mgr.openCase({
        title: `Attempted overwrite of a golden fact by ${alert.actor || 'unknown'}`,
        alertIds: [alert.id], actor: 'playbook:golden', severity: 'critical', description: alert.detail
      });
      return { caseId: c.id, actions: ['source flagged', 'agent scope review queued'] };
    });
    this.registerPlaybook('credential_detected', (alert, mgr) => {
      const c = mgr.openCase({
        title: 'Credential transmitted to an AI agent',
        alertIds: [alert.id], actor: 'playbook:credential', severity: 'critical', description: alert.detail
      });
      return { caseId: c.id, actions: ['credential rotation required', 'source flagged', 'never stored — blocked at the gate'] };
    });
    return this;
  }

  /**
   * Anonymised threat-intel feed — indicators of poisoning patterns seen across
   * customers. Opt-in, and it never carries content (§9.8).
   */
  threatIntel({ optedIn = false } = {}) {
    if (!optedIn) return { optedIn: false, indicators: [], note: 'threat intel sharing is opt-in and disabled' };
    const byKind = new Map();
    for (const a of this.col.all()) {
      const k = byKind.get(a.kind) || { kind: a.kind, count: 0, severities: new Set() };
      k.count += a.count;
      k.severities.add(a.severity);
      byKind.set(a.kind, k);
    }
    return {
      optedIn: true,
      generatedAt: iso(),
      indicators: [...byKind.values()].map((k) => ({
        pattern: k.kind, observations: k.count, severities: [...k.severities],
        // fingerprint only — no content, no customer identity
        indicatorHash: sha256(`vault-ti|${k.kind}`).slice(0, 24)
      }))
    };
  }

  stats() {
    const all = this.col.all();
    return {
      total: all.length,
      open: all.filter((a) => a.status === 'open').length,
      bySeverity: SEVERITIES.reduce((acc, s) => ({ ...acc, [s]: all.filter((a) => a.severity === s).length }), {}),
      cases: this.cases.count(),
      openCases: this.cases.count((c) => c.status === 'open'),
      deliveries: this.deliveries.length
    };
  }
}

const SUGGESTED_ACTIONS = {
  unknown_agent_write: 'register this agent or shut it down; check the Map for other shadow agents',
  cross_wall_attempt: 'confirm the agent scope is correct; if not, narrow it and review its recent writes',
  golden_overwrite_attempt: 'inspect the source, flag the sender, and confirm the golden fact is still correct',
  credential_detected: 'rotate the credential immediately — Vault never stored it, but the sender still sent it',
  drip_feed: 'freeze the folder, review the fragments together, and roll back if they assemble into a policy change',
  slow_boil: 'compare the threshold trend against the golden fact and re-attest',
  coordinated: 'check whether the sources are genuinely independent before treating corroboration as real',
  sleeper: 'review the fact and its trigger conditions before it is read again',
  volume_anomaly: 'hold the agent, check for a runaway loop, then decide',
  queue_flooding: 'raise reviewer capacity and check whether real threats were rubber-stamped',
  reviewer_fatigue: 'rotate the reviewer and re-check their recent approvals',
  model_swap: 'confirm the model change was intended and re-evaluate facts written by the new version',
  connector_gap: 'backfill the missing window and confirm the connector is healthy',
  retrieval_manipulation: 'inspect the queries and the facts they targeted'
};

function omit(obj, keys) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) if (!keys.includes(k)) out[k] = v;
  return out;
}
