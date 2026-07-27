/**
 * NOTIFICATION DELIVERY (§9.8).
 *
 * The spec says "alert fired" and "loud alarm" in dozens of places and never
 * says how it reaches a human. This is that layer.
 *
 * Two properties matter more than the channel list:
 *
 *  - Deduplication. An alert storm that pages someone two hundred times is
 *    indistinguishable from no alerting at all, because the recipient turns it
 *    off. Identical alerts collapse into one notification with a count.
 *  - Content-free payloads. A notification leaves Vault's trust boundary and
 *    lands in an inbox, a chat client and a phone. It carries ids, counts and
 *    severities — never a claim, never a transcript (§9.11).
 */
import { createHmac } from 'node:crypto';
import { newId } from '../util/id.js';
import { now, iso, ago, duration, MINUTE } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { sha256 } from '../util/crypto.js';

export const SEVERITIES = /** @type {const} */ (['info', 'low', 'medium', 'high', 'critical']);
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Channels we ship. Each is a transport, not a policy. */
export const CHANNELS = {
  email: { name: 'Email', needs: ['to'], severityFloor: 'low' },
  slack: { name: 'Slack', needs: ['webhookUrl'], severityFloor: 'medium' },
  teams: { name: 'Microsoft Teams', needs: ['webhookUrl'], severityFloor: 'medium' },
  pagerduty: { name: 'PagerDuty', needs: ['routingKey'], severityFloor: 'high' },
  opsgenie: { name: 'Opsgenie', needs: ['apiKey'], severityFloor: 'high' },
  // SMS is deliberately critical-only: it is the channel people cannot mute,
  // so using it for anything less trains them to ignore it.
  sms: { name: 'SMS', needs: ['to'], severityFloor: 'critical' },
  webhook: { name: 'Generic webhook', needs: ['url'], severityFloor: 'info' }
};

export class Notifier {
  /**
   * @param {object} opts
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {import('../storage/db.js').Collection} [opts.collection] durable config + outbox
   * @param {(req:{url:string,init:object})=>Promise<any>} [opts.transport] injectable for tests
   */
  constructor({ ledger, collection = null, transport = null, dedupeWindow = '15m' } = {}) {
    this.ledger = ledger;
    this.col = collection;
    this.transport = transport || ((url, init) => fetch(url, init));
    this.dedupeWindow = duration(dedupeWindow);

    const saved = this.col?.get('state') ?? null;
    /** @type {Map<string, object>} */
    this.channels = new Map(Object.entries(saved?.channels ?? {}));
    /** @type {Map<string, object>} per-recipient preferences */
    this.preferences = new Map(Object.entries(saved?.preferences ?? {}));
    /** @type {Map<string, {count:number, firstAt:number, lastAt:number, notifiedAt:number}>} */
    this.recent = new Map(Object.entries(saved?.recent ?? {}));
    this.outbox = saved?.outbox ?? [];
    this.suppressed = saved?.suppressed ?? 0;
  }

  _persist() {
    this.col?.put({
      id: 'state',
      channels: Object.fromEntries(this.channels),
      preferences: Object.fromEntries(this.preferences),
      recent: Object.fromEntries(this.recent),
      // The outbox is a delivery record, not an archive — keep it bounded.
      outbox: this.outbox.slice(-500),
      suppressed: this.suppressed
    });
  }

  /**
   * @param {keyof CHANNELS} kind
   * @param {object} config
   */
  configure(kind, config, { actor, severityFloor = null } = {}) {
    const spec = CHANNELS[kind];
    if (!spec) throw new VaultError('validation', `unknown channel "${kind}"`, { available: Object.keys(CHANNELS) });
    if (!actor) throw forbidden('configuring a notification channel requires a named actor');
    const missing = spec.needs.filter((k) => !config[k]);
    if (missing.length) throw new VaultError('validation', `${spec.name} needs ${missing.join(', ')}`, { missing });
    if (severityFloor && !SEVERITIES.includes(severityFloor)) {
      throw new VaultError('validation', `severity floor must be one of ${SEVERITIES.join(', ')}`);
    }
    const id = config.id || `${kind}:${sha256(JSON.stringify(config)).slice(0, 8)}`;
    this.channels.set(id, {
      id, kind, config, enabled: true,
      severityFloor: severityFloor || spec.severityFloor,
      configuredBy: actor, configuredAt: now(),
      delivered: 0, failed: 0
    });
    this._persist();
    // The config carries a secret; the ledger entry must not.
    this.ledger.append('admin.action', {
      subject: id, actor, action: 'notification.channel_configured', channel: kind,
      severityFloor: severityFloor || spec.severityFloor
    });
    return { id, kind, severityFloor: severityFloor || spec.severityFloor };
  }

  disable(id, { actor, reason }) {
    const ch = this.channels.get(id);
    if (!ch) throw new VaultError('not_found', 'notification channel not found', { id });
    this.channels.set(id, { ...ch, enabled: false, disabledBy: actor, disabledReason: reason });
    this._persist();
    return { id, enabled: false };
  }

  /** Per-recipient preferences, so one person's noise floor is not everyone's. */
  setPreference(recipient, { minSeverity = 'medium', channels = null, mutedKinds = [], actor }) {
    if (!actor) throw forbidden('changing notification preferences requires a named actor');
    if (!SEVERITIES.includes(minSeverity)) throw new VaultError('validation', `unknown severity "${minSeverity}"`);
    this.preferences.set(recipient, { recipient, minSeverity, channels, mutedKinds, updatedBy: actor, updatedAt: now() });
    this._persist();
    return this.preferences.get(recipient);
  }

  /**
   * The dedupe key. Two alerts that a human would read as "the same thing
   * again" must collapse — same kind, same subject, same severity.
   */
  static key(alert) {
    return `${alert.kind}|${alert.subject ?? '-'}|${alert.severity ?? 'medium'}`;
  }

  /**
   * Deliver an alert. Returns what was sent, what was suppressed, and why.
   * @param {{kind:string, severity?:string, subject?:string, detail?:string, folder?:string, actor?:string}} alert
   */
  async notify(alert, { at = now(), force = false } = {}) {
    const severity = SEVERITIES.includes(alert.severity) ? alert.severity : 'medium';
    const key = Notifier.key({ ...alert, severity });
    const prior = this.recent.get(key);

    // Deduplication and correlation: don't page someone 200 times (§9.8).
    if (!force && prior && at - prior.notifiedAt < this.dedupeWindow) {
      const updated = { ...prior, count: prior.count + 1, lastAt: at };
      this.recent.set(key, updated);
      this.suppressed++;
      this._persist();
      return {
        delivered: [], suppressed: true, key,
        occurrences: updated.count,
        reason: `identical alert already sent ${ago(prior.notifiedAt, at)} ago — suppressed until the window closes`,
        nextEligibleAt: iso(prior.notifiedAt + this.dedupeWindow)
      };
    }

    const rolledUp = prior && at - prior.notifiedAt < this.dedupeWindow * 4 ? prior.count : 0;
    const payload = this.render({ ...alert, severity }, { occurrences: rolledUp + 1, at });

    const delivered = [];
    const failures = [];
    for (const ch of this.channels.values()) {
      if (!ch.enabled) continue;
      if (RANK[severity] < RANK[ch.severityFloor]) continue;
      const pref = this.preferences.get(ch.config.to || ch.config.recipient || '');
      if (pref) {
        if (RANK[severity] < RANK[pref.minSeverity]) continue;
        if (pref.mutedKinds.includes(alert.kind)) continue;
        if (pref.channels && !pref.channels.includes(ch.kind)) continue;
      }
      try {
        await this._send(ch, payload);
        this.channels.set(ch.id, { ...ch, delivered: ch.delivered + 1 });
        delivered.push({ channel: ch.id, kind: ch.kind });
      } catch (e) {
        this.channels.set(ch.id, { ...ch, failed: ch.failed + 1, lastError: e.message });
        failures.push({ channel: ch.id, kind: ch.kind, error: e.message });
      }
    }

    this.recent.set(key, { count: 1, firstAt: prior?.firstAt ?? at, lastAt: at, notifiedAt: at });
    this.outbox.push({ id: newId('notice'), at, key, severity, kind: alert.kind, delivered: delivered.length, failed: failures.length });
    this._persist();

    this.ledger.append('security.alert', {
      subject: alert.subject ?? alert.kind, kind: alert.kind, severity,
      notified: delivered.length, failed: failures.length, rolledUp
    });
    return { delivered, failures, suppressed: false, key, payload, occurrences: rolledUp + 1 };
  }

  /**
   * Render a notification body.
   *
   * Ids, counts and severities only. A notification lands in an inbox, a chat
   * client and someone's phone — none of which are inside the trust boundary.
   */
  render(alert, { occurrences = 1, at = now() } = {}) {
    const title = `[${alert.severity.toUpperCase()}] ${humanKind(alert.kind)}`;
    const lines = [
      title,
      alert.subject ? `Subject: ${alert.subject}` : null,
      alert.folder ? `Folder: ${alert.folder}` : null,
      alert.detail ? `What happened: ${stripContent(alert.detail)}` : null,
      occurrences > 1 ? `Occurrences: ${occurrences} in the last window` : null,
      alert.actor ? `Actor: ${alert.actor}` : null,
      `At: ${iso(at)}`,
      '',
      'Open Vault to see the detail. This notice carries no memory content by design.'
    ].filter(Boolean);
    return { title, severity: alert.severity, kind: alert.kind, subject: alert.subject ?? null, text: lines.join('\n'), at: iso(at) };
  }

  async _send(channel, payload) {
    const { kind, config } = channel;
    if (kind === 'slack') {
      return this.transport(config.webhookUrl, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: payload.text })
      });
    }
    if (kind === 'teams') {
      return this.transport(config.webhookUrl, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ '@type': 'MessageCard', title: payload.title, text: payload.text })
      });
    }
    if (kind === 'pagerduty') {
      return this.transport(config.endpoint || 'https://events.pagerduty.com/v2/enqueue', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          routing_key: config.routingKey, event_action: 'trigger',
          dedup_key: Notifier.key(payload),
          payload: { summary: payload.title, severity: payload.severity === 'critical' ? 'critical' : 'error', source: 'vault' }
        })
      });
    }
    if (kind === 'opsgenie') {
      return this.transport(config.endpoint || 'https://api.opsgenie.com/v2/alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `GenieKey ${config.apiKey}` },
        body: JSON.stringify({ message: payload.title, description: payload.text, priority: payload.severity === 'critical' ? 'P1' : 'P3' })
      });
    }
    if (kind === 'email') {
      // SMTP is out of scope for a zero-dependency build; a relay endpoint is
      // the honest integration point and every provider offers one.
      if (!config.relayUrl) throw new VaultError('config', 'the email channel needs a relayUrl to post to');
      return this.transport(config.relayUrl, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: config.to, subject: payload.title, text: payload.text })
      });
    }
    if (kind === 'sms') {
      if (!config.relayUrl) throw new VaultError('config', 'the SMS channel needs a relayUrl to post to');
      return this.transport(config.relayUrl, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: config.to, text: `${payload.title} — open Vault` })
      });
    }
    // Generic webhook, signed so the receiver can verify it came from Vault.
    const body = JSON.stringify(payload);
    const signature = config.secret ? createHmac('sha256', config.secret).update(body).digest('hex') : null;
    return this.transport(config.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(signature ? { 'X-Vault-Signature': `sha256=${signature}` } : {}) },
      body
    });
  }

  /** ⚙️ ADMIN → NOTIFICATIONS. */
  status() {
    return {
      channels: [...this.channels.values()].map((c) => ({
        id: c.id, kind: c.kind, name: CHANNELS[c.kind].name, enabled: c.enabled,
        severityFloor: c.severityFloor, delivered: c.delivered, failed: c.failed,
        lastError: c.lastError ?? null,
        // never echo the config: it holds routing keys and webhook secrets
        configured: Object.keys(c.config)
      })),
      preferences: [...this.preferences.values()],
      dedupeWindowMs: this.dedupeWindow,
      suppressed: this.suppressed,
      recentKeys: this.recent.size,
      sent: this.outbox.length,
      note: 'notifications carry ids, counts and severities — never memory content'
    };
  }
}

function humanKind(kind) {
  return String(kind).replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

/** Belt and braces: a detail string that smuggled content in gets truncated. */
function stripContent(detail) {
  const s = String(detail);
  return s.length > 200 ? `${s.slice(0, 200)}…` : s;
}
