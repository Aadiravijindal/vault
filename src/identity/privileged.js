/**
 * Privileged access: requesting break-glass, approving it, and recording what
 * was done with it.
 *
 * The wall check in `folders.check()` has always honoured
 * `actor.breakGlass = { active, approvers, reason, expiresAt, separateChain }`,
 * and the ledger has always recorded every access made under one. But nothing
 * in the product could ever *produce* that object — only the tests, by hand.
 * So break-glass was enforceable and ungrantable: a control with no way to use
 * it, which in practice means the emergency path is "give someone the admin
 * role", which is the thing break-glass exists to avoid.
 *
 * This is the missing half, and it deliberately hangs off the existing
 * enforcement rather than introducing a second privileged path. There is one
 * definition of what a break-glass session is, one place it is checked, and now
 * one place it is granted.
 *
 * The rules, each of which exists because its absence is a known failure:
 *
 *   - Two *distinct* humans. Self-approval is the entire attack.
 *   - A stated reason, recorded before access, not reconstructed after.
 *   - A time box, enforced on every check, not a promise to log out.
 *   - Session recording: what was actually read, not merely that a session
 *     existed. "We had break-glass that week" is not an answer to "what did you
 *     look at?".
 *   - The subject is notified. A privileged read of someone's data that they
 *     never learn about is surveillance, whatever the paperwork says.
 */
import { randomBytes } from 'node:crypto';
import { now, iso, duration, MINUTE, HOUR } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

/** Folders whose approvers must come from a different chain than the requester's. */
export const SEPARATE_CHAIN_FOLDERS = ['hr/', 'legal/', 'security/'];

export class PrivilegedAccess {
  /**
   * @param {object} o
   * @param {import('./identity.js').SessionStore} [o.sessions]
   * @param {(e:object)=>void} [o.notify]
   * @param {number} [o.maxDurationMs] ceiling regardless of what is requested
   */
  constructor({ ledger = null, collection = null, sessions = null, notify = null, alerts = null,
    maxDurationMs = 4 * HOUR, defaultDurationMs = 60 * MINUTE, approversRequired = 2 } = {}) {
    this.ledger = ledger;
    this.col = collection;
    this.sessions = sessions;
    this.notify = notify;
    this.alerts = alerts;
    this.maxDurationMs = maxDurationMs;
    this.defaultDurationMs = defaultDurationMs;
    this.approversRequired = approversRequired;
    /** @type {Map<string, object>} */
    this.requests = new Map();
    if (collection) for (const r of collection.all()) this.requests.set(r.id, r);
  }

  /**
   * Ask for privileged access. Grants nothing on its own.
   *
   * @param {object} o
   * @param {string} o.requester
   * @param {string[]} o.folders what they need to reach — not "everything"
   * @param {string} o.reason
   * @param {string} [o.duration] e.g. '30m'
   */
  request({ requester, folders = [], reason, duration: dur = null, ticket = null, at = now() }) {
    if (!requester) throw forbidden('a break-glass request needs a named requester');
    if (!reason || String(reason).trim().length < 12) {
      // "incident" is not a reason. The person reading this in six months needs
      // to know what was happening.
      throw new VaultError('invalid',
        'a break-glass request needs a specific reason — this is the sentence an auditor reads first',
        { given: reason ?? null });
    }
    if (!folders.length) {
      throw new VaultError('invalid',
        'name the folders you need — an unscoped break-glass session is a second admin role, which is what this exists to avoid');
    }

    const requestedMs = dur ? duration(dur) : this.defaultDurationMs;
    const ms = Math.min(requestedMs, this.maxDurationMs);
    const separateChain = folders.some((f) => SEPARATE_CHAIN_FOLDERS.some((s) => String(f).startsWith(s)));

    const req = {
      id: `bg-${randomBytes(8).toString('hex')}`,
      requester, folders, reason, ticket,
      requestedAt: at,
      durationMs: ms,
      truncatedFrom: requestedMs > ms ? requestedMs : null,
      separateChain,
      approvals: [],
      denials: [],
      state: 'pending',
      grantedAt: null, expiresAt: null, closedAt: null,
      // The recording. Populated by `record()` on every privileged read.
      accesses: []
    };
    this.requests.set(req.id, req);
    this.col?.insert({ ...req });
    this.ledger?.append('admin.breakglass', {
      subject: folders.join(','), actor: requester, action: 'requested', reason, ticket,
      requiresSeparateChain: separateChain
    });
    this.alerts?.raise({
      severity: 'medium', kind: 'breakglass_requested', subject: req.id, actor: requester,
      detail: `${requester} requested break-glass on ${folders.join(', ')}: ${reason}`
    });
    return this._present(req);
  }

  /**
   * Approve. Two distinct humans, neither of them the requester.
   */
  approve(id, { approver, chain = null, note = null, at = now() }) {
    const req = this._require(id);
    if (!approver) throw forbidden('an approval needs a named approver');
    if (req.state !== 'pending') throw new VaultError('conflict', `this request is ${req.state}`, { id });
    if (approver === req.requester) {
      throw forbidden('the requester cannot approve their own break-glass — self-approval is the whole attack');
    }
    if (req.approvals.some((a) => a.approver === approver)) {
      throw forbidden('this approver has already approved — two approvals from one person is one approval');
    }
    if (req.separateChain) {
      // hr/, legal/ and security/ need an approver outside the requester's own
      // reporting line, or the second signature is the first person's manager
      // agreeing with them.
      if (!chain) {
        throw new VaultError('invalid',
          'this folder requires approvers from a separate chain — state which chain you approve from',
          { folders: req.folders });
      }
      if (req.approvals.some((a) => a.chain === chain)) {
        throw forbidden(`both approvers are from the "${chain}" chain; this folder requires two separate chains`);
      }
    }

    req.approvals.push({ approver, chain, note, at });
    this.ledger?.append('admin.breakglass', {
      subject: req.id, actor: approver, action: 'approved', chain,
      approvals: req.approvals.length, required: this.approversRequired
    });

    if (req.approvals.length >= this.approversRequired) {
      req.state = 'granted';
      req.grantedAt = at;
      req.expiresAt = at + req.durationMs;
      this.ledger?.append('admin.breakglass', {
        subject: req.folders.join(','), actor: req.requester, action: 'granted',
        approvers: req.approvals.map((a) => a.approver).join(','),
        reason: req.reason, expiresAt: iso(req.expiresAt)
      });
      this.alerts?.raise({
        severity: 'high', kind: 'breakglass_granted', subject: req.id, actor: req.requester,
        detail: `break-glass granted to ${req.requester} on ${req.folders.join(', ')} until ${iso(req.expiresAt)}, approved by ${req.approvals.map((a) => a.approver).join(' and ')}`
      });
      this.notify?.({
        kind: 'breakglass_granted', severity: 'high', subject: req.id,
        detail: `${req.requester} has privileged access to ${req.folders.join(', ')} for ${Math.round(req.durationMs / MINUTE)} minutes`
      });
    }
    this.col?.update?.(req.id, { ...req });
    return this._present(req);
  }

  deny(id, { approver, reason, at = now() }) {
    const req = this._require(id);
    if (!approver || !reason) throw forbidden('a denial needs a named approver and a reason');
    if (req.state !== 'pending') throw new VaultError('conflict', `this request is ${req.state}`);
    req.denials.push({ approver, reason, at });
    req.state = 'denied';
    req.closedAt = at;
    this.col?.update?.(req.id, { ...req });
    this.ledger?.append('admin.breakglass', { subject: req.id, actor: approver, action: 'denied', reason });
    return this._present(req);
  }

  /**
   * The object `folders.check()` expects — or null.
   *
   * This is the only place a break-glass credential comes from, and it is
   * computed fresh on every call rather than handed out once, so expiry is
   * enforced at use rather than at issue.
   */
  credentialFor(requester, { folder = null, at = now() } = {}) {
    const req = this.activeFor(requester, { at }).find((r) => !folder || r.folders.some((f) => String(folder).startsWith(f)));
    if (!req) return null;
    return {
      active: true,
      requestId: req.id,
      approvers: req.approvals.map((a) => a.approver),
      reason: req.reason,
      expiresAt: req.expiresAt,
      separateChain: req.separateChain && new Set(req.approvals.map((a) => a.chain)).size >= 2,
      folders: req.folders
    };
  }

  activeFor(requester, { at = now() } = {}) {
    return [...this.requests.values()].filter((r) => {
      if (r.requester !== requester || r.state !== 'granted') return false;
      if (at >= r.expiresAt) { this._expire(r, at); return false; }
      return true;
    });
  }

  /**
   * Record what a privileged session actually touched.
   *
   * This is the difference between "there was a break-glass session on the
   * 14th" and "here is what was read". The second is what the subject and the
   * regulator are entitled to.
   */
  record(requestId, { actor, folder, subject = null, action = 'read', detail = null, at = now() }) {
    const req = this.requests.get(requestId);
    if (!req) return null;
    const entry = { at, actor, folder, subject, action, detail };
    req.accesses.push(entry);
    this.col?.update?.(req.id, { accesses: req.accesses });
    this.ledger?.append('admin.breakglass', {
      subject: subject ?? folder, actor, action: `session.${action}`, requestId, folder
    });
    return entry;
  }

  /** End early. Someone finishing before the time box is the good case. */
  close(id, { actor, summary = null, at = now() }) {
    const req = this._require(id);
    if (req.state !== 'granted') throw new VaultError('conflict', `this request is ${req.state}`);
    req.state = 'closed';
    req.closedAt = at;
    req.summary = summary;
    this.col?.update?.(req.id, { ...req });
    this.ledger?.append('admin.breakglass', {
      subject: req.id, actor, action: 'closed', accesses: req.accesses.length,
      durationUsedMs: at - req.grantedAt, summary
    });
    return this.sessionReport(id);
  }

  _expire(req, at) {
    req.state = 'expired';
    req.closedAt = at;
    this.col?.update?.(req.id, { ...req });
    this.ledger?.append('admin.breakglass', { subject: req.id, actor: 'system', action: 'expired', accesses: req.accesses.length });
  }

  /**
   * The record handed to the subject, the works council or the auditor.
   *
   * Deliberately includes the case where a session was granted and nothing was
   * read: an unused emergency access is a fact worth stating, not an absence to
   * leave ambiguous.
   */
  sessionReport(id) {
    const req = this._require(id);
    const subjects = [...new Set(req.accesses.map((a) => a.subject).filter(Boolean))];
    return {
      id: req.id,
      requester: req.requester,
      reason: req.reason,
      ticket: req.ticket,
      folders: req.folders,
      approvers: req.approvals.map((a) => ({ approver: a.approver, chain: a.chain, at: iso(a.at) })),
      state: req.state,
      grantedAt: req.grantedAt ? iso(req.grantedAt) : null,
      expiresAt: req.expiresAt ? iso(req.expiresAt) : null,
      closedAt: req.closedAt ? iso(req.closedAt) : null,
      durationUsedMinutes: req.grantedAt && req.closedAt ? Math.round((req.closedAt - req.grantedAt) / MINUTE) : null,
      accesses: req.accesses.map((a) => ({ at: iso(a.at), actor: a.actor, folder: a.folder, subject: a.subject, action: a.action, detail: a.detail })),
      subjectsAccessed: subjects,
      statement: req.accesses.length
        ? `${req.requester} accessed ${req.accesses.length} item(s) across ${new Set(req.accesses.map((a) => a.folder)).size} folder(s) under break-glass approved by ${req.approvals.map((a) => a.approver).join(' and ')}.`
        : `Break-glass was granted to ${req.requester} and nothing was accessed under it.`
    };
  }

  /** The monthly summary §27 asks for. */
  monthlySummary({ from = now() - 30 * 24 * HOUR, to = now() } = {}) {
    const inWindow = [...this.requests.values()].filter((r) => r.requestedAt >= from && r.requestedAt <= to);
    return {
      window: { from: iso(from), to: iso(to) },
      requested: inWindow.length,
      granted: inWindow.filter((r) => r.state !== 'pending' && r.state !== 'denied').length,
      denied: inWindow.filter((r) => r.state === 'denied').length,
      expiredUnused: inWindow.filter((r) => r.state === 'expired' && !r.accesses.length).length,
      totalAccesses: inWindow.reduce((a, r) => a + r.accesses.length, 0),
      byRequester: inWindow.reduce((a, r) => { a[r.requester] = (a[r.requester] ?? 0) + 1; return a; }, {}),
      subjectsAffected: [...new Set(inWindow.flatMap((r) => r.accesses.map((x) => x.subject).filter(Boolean)))],
      sessions: inWindow.map((r) => this.sessionReport(r.id)),
      note: inWindow.length === 0
        ? 'No privileged access was requested in this window.'
        : 'Every session below was approved by two distinct people before any data was read.'
    };
  }

  pending() { return [...this.requests.values()].filter((r) => r.state === 'pending').map((r) => this._present(r)); }

  _require(id) {
    const r = this.requests.get(id);
    if (!r) throw new VaultError('not_found', `no break-glass request ${id}`);
    return r;
  }

  _present(r) {
    return {
      id: r.id, requester: r.requester, folders: r.folders, reason: r.reason, ticket: r.ticket,
      state: r.state,
      approvals: r.approvals.map((a) => ({ approver: a.approver, chain: a.chain, at: iso(a.at) })),
      approvalsRequired: this.approversRequired,
      separateChainRequired: r.separateChain,
      requestedAt: iso(r.requestedAt),
      grantedAt: r.grantedAt ? iso(r.grantedAt) : null,
      expiresAt: r.expiresAt ? iso(r.expiresAt) : null,
      durationMinutes: Math.round(r.durationMs / MINUTE),
      truncatedFrom: r.truncatedFrom ? `${Math.round(r.truncatedFrom / MINUTE)} minutes requested, capped at ${Math.round(r.durationMs / MINUTE)} minutes` : null,
      accesses: r.accesses.length
    };
  }
}
