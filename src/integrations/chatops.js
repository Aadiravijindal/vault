/**
 * Slack and Microsoft Teams apps.
 *
 * The reason these are worth building rather than pointing at a webhook: the
 * two moments Vault most needs a human — approving a held fact, and pulling the
 * kill switch — happen when that human is on a phone, not at the console. A
 * review queue nobody looks at is a slower kind of blocked, and a kill switch
 * that needs a laptop at 3am is a kill switch that gets pulled twenty minutes
 * late.
 *
 * Everything here is inbound-authenticated before it is read. A chat platform
 * is an untrusted network: anyone who learns the URL can POST to it, so a
 * handler that acts on an unverified payload is a remote kill switch for
 * whoever finds it. Slack signatures are HMAC-SHA256 over a versioned base
 * string with a replay window; Teams uses HMAC-SHA256 over the raw body with
 * the channel's shared secret. Both are checked in constant time, and both
 * reject before parsing.
 *
 * The second rule is that chat is a *control* surface, never a content one.
 * A held fact's claim can be commercially sensitive or personal; posting it
 * into a Slack channel would move regulated content into a system that has none
 * of Vault's walls. So messages carry ids, counts, reasons and actions — never
 * the claim text — and the deep link sends the reviewer to the real UI.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { now, iso, MINUTE } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

/** Slack replays outside this window are refused even with a valid signature. */
export const REPLAY_WINDOW_MS = 5 * MINUTE;

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  return timingSafeEqual(A, B);
}

// ---------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------

export class SlackApp {
  /**
   * @param {object} o
   * @param {import('../index.js').Vault} o.vault
   * @param {string} o.signingSecret from the Slack app's Basic Information page
   * @param {string} [o.baseUrl] where the Vault UI lives, for deep links
   * @param {Record<string,string>} [o.userMap] slack user id → Vault principal name
   */
  constructor({ vault, signingSecret, baseUrl = 'https://vault.internal', userMap = {}, ledger = null }) {
    if (!signingSecret) throw new VaultError('config', 'the Slack app needs the signing secret — an unverified endpoint is a remote kill switch for whoever finds the URL');
    this.vault = vault;
    this.signingSecret = signingSecret;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.userMap = new Map(Object.entries(userMap));
    this.ledger = ledger ?? vault?.ledger ?? null;
    this.stats = { verified: 0, rejected: 0, commands: 0, actions: 0 };
  }

  /**
   * Verify a request. Returns the reason on failure rather than a bare false,
   * because "signature mismatch" and "timestamp too old" need different fixes.
   *
   * @param {object} o
   * @param {string} o.body the RAW body, before JSON or form parsing
   * @param {Record<string,string>} o.headers
   */
  verify({ body, headers = {}, at = now() }) {
    const ts = headers['x-slack-request-timestamp'] ?? headers['X-Slack-Request-Timestamp'];
    const sig = headers['x-slack-signature'] ?? headers['X-Slack-Signature'];
    if (!ts || !sig) {
      this.stats.rejected++;
      return { ok: false, reason: 'missing X-Slack-Request-Timestamp or X-Slack-Signature' };
    }
    // The timestamp check comes first and is not optional. Without it a valid
    // signature captured once works forever, which for /vault stop is fatal.
    const age = Math.abs(at - Number(ts) * 1000);
    if (!Number.isFinite(age) || age > REPLAY_WINDOW_MS) {
      this.stats.rejected++;
      return { ok: false, reason: `timestamp is ${Math.round(age / 1000)}s away from now — outside the ${REPLAY_WINDOW_MS / 1000}s replay window` };
    }
    const base = `v0:${ts}:${body}`;
    const expected = `v0=${createHmac('sha256', this.signingSecret).update(base).digest('hex')}`;
    if (!safeEqual(expected, sig)) {
      this.stats.rejected++;
      return { ok: false, reason: 'signature mismatch' };
    }
    this.stats.verified++;
    return { ok: true };
  }

  /** Map a Slack user to a Vault principal. Unmapped users get nothing. */
  principal(slackUserId, slackUserName) {
    const name = this.userMap.get(slackUserId);
    if (!name) {
      throw forbidden(
        `Slack user ${slackUserName || slackUserId} is not mapped to a Vault principal`,
        { fix: 'map them explicitly — an unmapped chat identity must never inherit a role by default' }
      );
    }
    return name;
  }

  /**
   * Handle a slash command. `body` must be the raw string; verification runs
   * before anything is parsed.
   */
  async command({ body, headers, at = now() }) {
    const check = this.verify({ body, headers, at });
    if (!check.ok) throw forbidden(`Slack request rejected: ${check.reason}`);
    const form = Object.fromEntries(new URLSearchParams(body));
    this.stats.commands++;

    const [verb, ...rest] = String(form.text || '').trim().split(/\s+/);
    const actor = this.principal(form.user_id, form.user_name);
    this.ledger?.append('admin.action', {
      subject: 'slack', actor, action: 'chatops.command', command: verb || 'help', channel: form.channel_id
    });

    switch ((verb || 'help').toLowerCase()) {
      case 'review': return this._reviewQueue(actor);
      case 'status': return this._status();
      case 'stop': return this._confirmStop(actor, rest.join(' '));
      case 'fact': return this._fact(actor, rest[0]);
      default: return this._help();
    }
  }

  /**
   * Handle an interactive action (a button press). Slack sends these as a
   * form-encoded `payload` field containing JSON.
   */
  async interact({ body, headers, at = now() }) {
    const check = this.verify({ body, headers, at });
    if (!check.ok) throw forbidden(`Slack request rejected: ${check.reason}`);
    const form = Object.fromEntries(new URLSearchParams(body));
    const payload = JSON.parse(form.payload || '{}');
    this.stats.actions++;

    const actor = this.principal(payload.user?.id, payload.user?.name);
    const action = payload.actions?.[0] ?? {};
    const [kind, id] = String(action.value || '').split(':');

    this.ledger?.append('admin.action', { subject: id ?? 'slack', actor, action: `chatops.${kind}` });

    if (kind === 'approve' || kind === 'reject') {
      const decision = kind === 'approve' ? 'approve' : 'reject';
      const out = this.vault.review.decide(id, {
        actor, decision,
        reason: `decided from Slack by ${actor}`
      });
      return {
        replace_original: true,
        blocks: [section(`*${decision === 'approve' ? 'Approved' : 'Rejected'}* \`${id}\` — ${actor}`),
          context([`Recorded in the ledger. ${this.baseUrl}/#review`])],
        // The API result, for callers that want it (and for tests).
        _result: out
      };
    }

    if (kind === 'stop') {
      const level = Number(id) || 3;
      const out = this.vault.killswitch.engage(level, {
        actor, reason: `engaged from Slack by ${actor}`
      });
      return {
        replace_original: true,
        blocks: [section(`:rotating_light: *Kill switch level ${level}* engaged by ${actor}`),
          context([out.effect ?? 'Effective immediately.', `Release it in the Admin screen: ${this.baseUrl}/#admin`])],
        _result: out
      };
    }

    return { text: `Unrecognised action \`${action.value}\`.` };
  }

  _help() {
    return {
      response_type: 'ephemeral',
      blocks: [
        section('*Vault*'),
        section('`/vault review` — what is waiting for a human\n`/vault status` — kill switch, chain, connectors\n`/vault fact <id>` — where a fact came from\n`/vault stop [level]` — engage the kill switch (asks for confirmation)'),
        context(['Claims and transcripts are never posted into chat. Everything here is ids, counts and actions; the content stays behind the walls.'])
      ]
    };
  }

  _reviewQueue(actor) {
    const items = this.vault.review.list({ status: 'open', limit: 5 });
    if (!items.length) {
      return { response_type: 'ephemeral', blocks: [section('Nothing is waiting for review. :white_check_mark:')] };
    }
    const blocks = [section(`*${items.length} item(s) waiting* — showing the ${Math.min(5, items.length)} highest priority`)];
    for (const item of items) {
      // Ids, priority and reasons only. The claim text stays in the UI.
      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: `\`${item.id}\` · *${item.priority ?? 'normal'}* · ${item.folder ?? 'unfiled'}\n_${(item.signals ?? item.reasons ?? []).slice(0, 2).join(', ') || 'held by the gate'}_` },
        accessory: {
          type: 'button', text: { type: 'plain_text', text: 'Open' },
          url: `${this.baseUrl}/#review/${item.id}`
        }
      });
      blocks.push({
        type: 'actions',
        elements: [
          { type: 'button', style: 'primary', text: { type: 'plain_text', text: 'Approve' }, value: `approve:${item.id}`, action_id: `approve_${item.id}` },
          { type: 'button', style: 'danger', text: { type: 'plain_text', text: 'Reject' }, value: `reject:${item.id}`, action_id: `reject_${item.id}` }
        ]
      });
    }
    blocks.push(context([`Requested by ${actor}. Deciding here is the same decision as deciding in the UI, and lands in the same ledger.`]));
    return { response_type: 'ephemeral', blocks };
  }

  _status() {
    const ks = this.vault.killswitch.state();
    const chain = this.vault.verifyLedgerTail();
    const connectors = this.vault.connectors.health();
    const held = this.vault.facts.all().filter((f) => f.status === 'held').length;
    return {
      response_type: 'ephemeral',
      blocks: [
        section(`*Kill switch:* ${ks.level ? `:rotating_light: L${ks.level} — ${ks.reason ?? 'no reason recorded'}` : ':white_check_mark: normal'}`),
        section(`*Ledger:* ${chain.ok ? ':white_check_mark:' : ':x: BROKEN —'} ${chain.checked} entries checked${chain.sinceAnchor ? ' since the last anchor' : ''}`),
        section(`*Connectors:* ${connectors.connected ?? 0} connected, ${connectors.silent?.length ?? 0} silent`),
        section(`*Review queue:* ${held} held`),
        context([`${this.baseUrl}/#map`])
      ]
    };
  }

  _fact(actor, factId) {
    if (!factId) return { response_type: 'ephemeral', blocks: [section('Give me a fact id: `/vault fact f-abc123`')] };
    const f = this.vault.facts.get(factId);
    if (!f) return { response_type: 'ephemeral', blocks: [section(`No fact \`${factId}\`.`)] };
    return {
      response_type: 'ephemeral',
      blocks: [
        // Provenance without content: who said it, through what channel, when,
        // and how it was decided. Not what it says.
        section(`\`${f.id}\` · *${f.status}* · ${f.folder} · ${f.sensitivity}`),
        section(`*Said by:* ${f.saidBy ?? 'unknown'} · *Channel:* ${f.channel} (${f.channelTrust ?? 'unknown'} trust)\n*Gate:* ${f.gateOutcome}\n*Corroborating sources:* ${f.corroboratingSources ?? 1}`),
        context([`The claim itself is not posted to chat. Open it: ${this.baseUrl}/#memory/${f.id}`])
      ]
    };
  }

  /**
   * `/vault stop` never fires directly.
   *
   * A slash command is one keystroke away from a typo, and level 6 stops the
   * business. The confirmation button costs three seconds and removes the
   * entire class of accident.
   */
  _confirmStop(actor, rest) {
    const level = Number(String(rest).trim()) || 3;
    if (level < 1 || level > 6) {
      return { response_type: 'ephemeral', blocks: [section('Level must be 1–6. `3` is read-only, `6` is a full freeze.')] };
    }
    const admins = [...(this.vault.killswitch.administrators ?? [])];
    if (admins.length && !admins.includes(actor)) {
      return {
        response_type: 'ephemeral',
        blocks: [section(`:no_entry: ${actor} is not a named kill-switch administrator.`), context([`Named administrators: ${admins.join(', ')}`])]
      };
    }
    return {
      response_type: 'ephemeral',
      blocks: [
        section(`:warning: *Engage kill switch level ${level}?*`),
        section(LEVEL_EFFECT[level]),
        { type: 'actions', elements: [{ type: 'button', style: 'danger', text: { type: 'plain_text', text: `Yes — engage L${level}` }, value: `stop:${level}`, action_id: `stop_${level}`, confirm: { title: { type: 'plain_text', text: 'Confirm' }, text: { type: 'mrkdwn', text: LEVEL_EFFECT[level] }, confirm: { type: 'plain_text', text: 'Engage' }, deny: { type: 'plain_text', text: 'Cancel' } } }] }
      ]
    };
  }

  /** Outbound: an alert, rendered without content. */
  static alertMessage(alert, baseUrl = '') {
    return {
      blocks: [
        section(`${alert.severity === 'critical' ? ':rotating_light:' : alert.severity === 'high' ? ':warning:' : ':information_source:'} *${alert.kind}* — ${alert.severity}`),
        section(alert.detail ? `_${String(alert.detail).slice(0, 300)}_` : '_no detail_'),
        context([`subject: \`${alert.subject ?? '—'}\` · ${iso(alert.at ?? now())}${baseUrl ? ` · ${baseUrl}/#security` : ''}`])
      ]
    };
  }
}

const LEVEL_EFFECT = {
  1: 'Everything keeps working, everything is flagged.',
  2: 'Every write goes to the review queue. Slow, still working.',
  3: 'No writes accepted. Reads continue — agents keep working, they stop learning.',
  4: 'A scoped freeze: one agent, folder, channel or department.',
  5: 'That scope cannot be read either.',
  6: 'No reads, no writes, anywhere. *The business stops.*'
};

const section = (text) => ({ type: 'section', text: { type: 'mrkdwn', text } });
const context = (items) => ({ type: 'context', elements: items.filter(Boolean).map((t) => ({ type: 'mrkdwn', text: t })) });

// ---------------------------------------------------------------------------
// Microsoft Teams
// ---------------------------------------------------------------------------

/**
 * Teams outgoing webhooks authenticate with HMAC-SHA256 over the raw body,
 * keyed with the base64 security token Teams issues when the connector is
 * created, and present it as `Authorization: HMAC <base64 signature>`.
 */
export class TeamsApp {
  constructor({ vault, securityToken, baseUrl = 'https://vault.internal', userMap = {}, ledger = null }) {
    if (!securityToken) throw new VaultError('config', 'the Teams app needs the security token Teams issued for this connector');
    this.vault = vault;
    this.key = Buffer.from(securityToken, 'base64');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.userMap = new Map(Object.entries(userMap));
    this.ledger = ledger ?? vault?.ledger ?? null;
    this.stats = { verified: 0, rejected: 0, commands: 0 };
  }

  verify({ body, headers = {} }) {
    const auth = headers.authorization ?? headers.Authorization ?? '';
    const provided = String(auth).replace(/^HMAC\s+/i, '');
    if (!provided) { this.stats.rejected++; return { ok: false, reason: 'missing Authorization: HMAC <signature>' }; }
    const expected = createHmac('sha256', this.key).update(Buffer.from(body, 'utf8')).digest('base64');
    if (!safeEqual(expected, provided)) { this.stats.rejected++; return { ok: false, reason: 'signature mismatch' }; }
    this.stats.verified++;
    return { ok: true };
  }

  principal(aadObjectId, name) {
    const mapped = this.userMap.get(aadObjectId);
    if (!mapped) throw forbidden(`Teams user ${name || aadObjectId} is not mapped to a Vault principal`);
    return mapped;
  }

  async command({ body, headers }) {
    const check = this.verify({ body, headers });
    if (!check.ok) throw forbidden(`Teams request rejected: ${check.reason}`);
    const msg = JSON.parse(body);
    this.stats.commands++;
    const actor = this.principal(msg.from?.aadObjectId ?? msg.from?.id, msg.from?.name);
    // Teams prefixes the bot mention into the text; strip it before parsing.
    const text = String(msg.text || '').replace(/<at>.*?<\/at>/g, '').trim();
    const [verb, ...rest] = text.split(/\s+/);

    this.ledger?.append('admin.action', { subject: 'teams', actor, action: 'chatops.command', command: verb || 'help' });

    switch ((verb || 'help').toLowerCase()) {
      case 'review': return this._card('Review queue', this._reviewFacts(), `${this.baseUrl}/#review`);
      case 'status': return this._card('Vault status', this._statusFacts(), `${this.baseUrl}/#map`);
      default:
        return this._card('Vault', [
          { title: 'review', value: 'what is waiting for a human' },
          { title: 'status', value: 'kill switch, chain, connectors' }
        ], `${this.baseUrl}/#map`, 'Claims and transcripts are never posted into chat.');
    }
  }

  _reviewFacts() {
    const items = this.vault.review.list({ status: 'open', limit: 5 });
    if (!items.length) return [{ title: 'Queue', value: 'empty' }];
    return items.map((i) => ({ title: i.id, value: `${i.priority ?? 'normal'} · ${i.folder ?? 'unfiled'} · ${(i.signals ?? i.reasons ?? []).slice(0, 2).join(', ') || 'held by the gate'}` }));
  }

  _statusFacts() {
    const ks = this.vault.killswitch.state();
    const chain = this.vault.verifyLedgerTail();
    const health = this.vault.connectors.health();
    return [
      { title: 'Kill switch', value: ks.level ? `L${ks.level}` : 'normal' },
      { title: 'Ledger', value: `${chain.ok ? 'verified' : 'BROKEN'} (${chain.checked} entries)` },
      { title: 'Connectors', value: `${health.connected ?? 0} connected, ${health.silent?.length ?? 0} silent` },
      { title: 'Held facts', value: String(this.vault.facts.all().filter((f) => f.status === 'held').length) }
    ];
  }

  /** An Adaptive Card. Same rule as Slack: ids and counts, never claims. */
  _card(title, facts, url, note = null) {
    return {
      type: 'message',
      attachments: [{
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard', version: '1.4',
          body: [
            { type: 'TextBlock', text: title, weight: 'Bolder', size: 'Medium', wrap: true },
            { type: 'FactSet', facts },
            ...(note ? [{ type: 'TextBlock', text: note, wrap: true, isSubtle: true, size: 'Small' }] : [])
          ],
          actions: [{ type: 'Action.OpenUrl', title: 'Open Vault', url }]
        }
      }]
    };
  }

  static alertCard(alert, baseUrl = '') {
    return {
      type: 'message',
      attachments: [{
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard', version: '1.4',
          body: [
            { type: 'TextBlock', text: `${alert.kind} — ${alert.severity}`, weight: 'Bolder', wrap: true,
              color: alert.severity === 'critical' ? 'Attention' : alert.severity === 'high' ? 'Warning' : 'Default' },
            { type: 'FactSet', facts: [
              { title: 'Subject', value: String(alert.subject ?? '—') },
              { title: 'At', value: iso(alert.at ?? now()) },
              { title: 'Detail', value: String(alert.detail ?? '').slice(0, 300) || '—' }
            ] }
          ],
          actions: baseUrl ? [{ type: 'Action.OpenUrl', title: 'Open Security', url: `${baseUrl}/#security` }] : []
        }
      }]
    };
  }
}
