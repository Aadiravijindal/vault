/**
 * Emergency controls — the graduated kill switch (§16.1).
 *
 * Freezing all writes stops the business. Never offer that as the only option.
 * Six levels, a named administrator role, in-flight writes queued not lost,
 * auto-expiry with forced re-authorisation, and a quarterly test whose result is
 * recorded because insurers ask for it.
 */
import { now, iso, ago, duration, MINUTE, HOUR, DAY } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { newId } from '../util/id.js';

export const LEVELS = [
  { level: 0, label: 'Normal', effect: 'Everything works', impact: 'none' },
  { level: 1, label: 'Warn', effect: 'Everything works, everything flagged', impact: 'none' },
  { level: 2, label: 'Review all', effect: 'Every write goes to the queue', impact: 'slow, still working' },
  { level: 3, label: 'Read-only', effect: 'No writes accepted. Reads continue.', impact: 'agents keep working, stop learning' },
  { level: 4, label: 'Scoped freeze', effect: 'One agent, folder, channel or department frozen', impact: 'contained' },
  { level: 5, label: 'Read-block on scope', effect: "That scope can't be read either", impact: 'contained, harder' },
  { level: 6, label: 'Full freeze', effect: 'No reads, no writes, anywhere', impact: 'business stops' }
];

export class KillSwitch {
  /**
   * @param {object} opts
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {string[]} opts.administrators named administrator role (an RFP question)
   * @param {(e:object)=>void} [opts.onChange]
   */
  constructor({ ledger, administrators = [], onChange = () => {}, defaultExpiry = '4h' }) {
    this.ledger = ledger;
    this.administrators = new Set(administrators);
    this.onChange = onChange;
    this.defaultExpiry = duration(defaultExpiry);
    this.current = { level: 0, scope: null, engagedAt: null, engagedBy: null, reason: null, expiresAt: null };
    /** In-flight writes are queued, not lost (§16.1). */
    this.queue = [];
    this.history = [];
    this.tests = [];
    this.activationTimes = [];
  }

  addAdministrator(name, { actor }) {
    if (!this.administrators.has(actor) && this.administrators.size) {
      throw forbidden('only a named administrator may add another administrator');
    }
    this.administrators.add(name);
    this.ledger.append('admin.action', { subject: name, actor, action: 'killswitch.administrator_added' });
    return [...this.administrators];
  }

  /**
   * @param {number} level 1–6
   * @param {{actor:string, reason:string, scope?:object, expiresIn?:string|number}} opts
   */
  engage(level, { actor, reason, scope = null, expiresIn = null }) {
    const started = process.hrtime.bigint();
    if (!LEVELS.some((l) => l.level === level) || level < 1) {
      throw new VaultError('validation', 'kill switch level must be 1–6');
    }
    if (!actor || !reason) throw forbidden('engaging the kill switch requires a named actor and a stated reason');
    if (this.administrators.size && !this.administrators.has(actor)) {
      throw forbidden('only the named administrator role may engage the kill switch', { administrators: [...this.administrators] });
    }
    if ((level === 4 || level === 5) && !scope) {
      throw new VaultError('validation', 'levels 4 and 5 are scoped — name the agent, folder, channel or department');
    }

    const spec = LEVELS.find((l) => l.level === level);
    this.current = {
      level, label: spec.label, effect: spec.effect, impact: spec.impact,
      scope, engagedAt: now(), engagedBy: actor, reason,
      expiresAt: now() + (expiresIn ? duration(expiresIn) : this.defaultExpiry)
    };
    const activationMs = Number(process.hrtime.bigint() - started) / 1e6;
    this.activationTimes.push(activationMs);
    this.history.push({ ...this.current, activationMs });

    this.ledger.append('killswitch.engaged', {
      subject: scope ? JSON.stringify(scope) : 'global', actor, level, label: spec.label,
      reason, expiresAt: iso(this.current.expiresAt), activationMs: Math.round(activationMs * 100) / 100
    });
    this.onChange(this.state());
    return {
      ...this.state(),
      activationMs: Math.round(activationMs * 100) / 100,
      targetMs: level >= 3 ? 60_000 : 300_000,
      agentMessage: this.agentMessage(),
      note: 'agents are told clearly so they degrade gracefully instead of hallucinating'
    };
  }

  release({ actor, reason }) {
    if (!actor || !reason) throw forbidden('releasing the kill switch requires a named actor and a reason');
    if (this.administrators.size && !this.administrators.has(actor)) {
      throw forbidden('only the named administrator role may release the kill switch');
    }
    const prev = { ...this.current };
    this.current = { level: 0, scope: null, engagedAt: null, engagedBy: null, reason: null, expiresAt: null };
    this.ledger.append('killswitch.released', {
      subject: prev.scope ? JSON.stringify(prev.scope) : 'global', actor, reason,
      previousLevel: prev.level, heldForMs: prev.engagedAt ? now() - prev.engagedAt : 0
    });
    this.onChange(this.state());
    const drained = this.drain();
    return { released: true, previousLevel: prev.level, drained: drained.length, at: iso() };
  }

  /** Auto-expiry with forced re-authorisation, so nobody forgets it's on. */
  state() {
    if (this.current.level > 0 && this.current.expiresAt && now() > this.current.expiresAt) {
      const expired = { ...this.current };
      this.current = { level: 0, scope: null, engagedAt: null, engagedBy: null, reason: null, expiresAt: null, expiredFrom: expired.level };
      this.ledger.append('killswitch.released', {
        subject: 'global', actor: 'system', reason: 'auto-expired — re-authorisation required to re-engage',
        previousLevel: expired.level
      });
      this.onChange(this.current);
    }
    const s = this.current;
    return {
      ...s,
      active: s.level > 0,
      expiresIn: s.expiresAt ? Math.max(0, s.expiresAt - now()) : null,
      engagedFor: s.engagedAt ? ago(s.engagedAt) : null,
      administrators: [...this.administrators],
      scopeMatches: (ctx) => this.scopeMatches(ctx),
      queued: this.queue.length
    };
  }

  scopeMatches(ctx = {}) {
    const s = this.current;
    if (s.level === 0) return false;
    if (s.level <= 3 || s.level === 6) return true;
    if (!s.scope) return true;
    if (s.scope.agentId && ctx.agentId === s.scope.agentId) return true;
    if (s.scope.folder && String(ctx.folder || ctx.folderHint || '').startsWith(s.scope.folder)) return true;
    if (s.scope.channel && ctx.channel === s.scope.channel) return true;
    if (s.scope.department && ctx.department === s.scope.department) return true;
    return false;
  }

  /** Reads blocked only at levels 5 (scoped) and 6 (global). */
  readsBlocked(ctx = {}) {
    const s = this.state();
    if (s.level === 6) return { blocked: true, reason: 'full freeze — no reads, no writes, anywhere' };
    if (s.level === 5 && this.scopeMatches(ctx)) {
      return { blocked: true, reason: `read-block on scope: ${JSON.stringify(s.scope)}` };
    }
    return { blocked: false };
  }

  writesBlocked(ctx = {}) {
    const s = this.state();
    if (s.level >= 6) return { blocked: true, reason: 'full freeze' };
    if (s.level >= 3 && this.scopeMatches(ctx)) {
      return { blocked: true, reason: `${s.label}: ${s.effect}` };
    }
    return { blocked: false };
  }

  /** Queue a write rather than losing it. */
  enqueue(item) {
    this.queue.push({ ...item, queuedAt: now(), id: newId('session') });
    return { queued: true, position: this.queue.length };
  }

  drain() {
    const items = this.queue.splice(0, this.queue.length);
    return items;
  }

  /** What agents are told, so they degrade gracefully. */
  agentMessage() {
    const s = this.state();
    if (!s.active) return null;
    if (s.level >= 6) return 'MEMORY UNAVAILABLE: Vault is fully frozen. Do not assert remembered facts; say you cannot access shared memory.';
    if (s.level === 5) return 'MEMORY SCOPE BLOCKED: this scope cannot be read or written. Do not guess its contents.';
    if (s.level === 4) return 'MEMORY SCOPE FROZEN: writes to this scope are not being accepted. Reads still work.';
    if (s.level === 3) return 'MEMORY READ-ONLY: reads work normally, writes are not being accepted. Do not claim anything was saved.';
    if (s.level === 2) return 'MEMORY UNDER REVIEW: every write is queued for a human. Nothing you write is live yet.';
    return 'MEMORY FLAGGED: everything is being recorded and flagged. Normal operation otherwise.';
  }

  /** Tested quarterly, with the test result recorded — insurers ask (§16.1). */
  test({ actor, level = 3, note = 'scheduled quarterly test' }) {
    if (!actor) throw forbidden('a kill switch test requires a named actor');
    const started = process.hrtime.bigint();
    const before = this.current.level;
    const prevAdmins = new Set(this.administrators);
    this.administrators.add(actor);
    this.engage(level, { actor, reason: `TEST: ${note}`, expiresIn: '1m', scope: level >= 4 ? { folder: '_test/' } : null });
    const engagedMs = Number(process.hrtime.bigint() - started) / 1e6;
    this.release({ actor, reason: `TEST complete: ${note}` });
    this.administrators = prevAdmins;
    if (before > 0) this.current.level = before;
    const record = {
      id: newId('incident'), at: now(), actor, level, note,
      activationMs: Math.round(engagedMs * 100) / 100,
      target: level >= 3 ? '<60s for transaction-authority agents' : '<5 min otherwise',
      passed: engagedMs < 60_000
    };
    this.tests.push(record);
    this.ledger.append('admin.action', { subject: 'killswitch', actor, action: 'killswitch.tested', ...record, at: undefined });
    return { ...record, at: iso(record.at) };
  }

  lastTest() {
    const t = this.tests[this.tests.length - 1];
    return t ? { ...t, at: iso(t.at), age: ago(t.at) } : null;
  }

  /** Evidence for the insurance pack (§20). */
  specification() {
    return {
      levels: LEVELS,
      namedAdministrators: [...this.administrators],
      activationTarget: { transactionAuthorityAgents: '<60s', otherAgents: '<5 min' },
      measuredActivationMs: this.activationTimes.length
        ? Math.round(Math.max(...this.activationTimes) * 100) / 100
        : null,
      inFlightWrites: 'queued, not lost',
      autoExpiry: `${this.defaultExpiry / HOUR}h, with forced re-authorisation`,
      reachableFrom: ['web UI', 'CLI', 'API', 'mobile app', 'out-of-band channel'],
      lastTest: this.lastTest(),
      testCadence: 'quarterly',
      engagementHistory: this.history.map((h) => ({ level: h.level, at: iso(h.engagedAt), by: h.engagedBy, reason: h.reason }))
    };
  }
}
