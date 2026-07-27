/**
 * NEEDS REVIEW — the room people live in (§12).
 *
 * A queue nobody empties is worse than no queue: it's documented negligence.
 * Everything in here exists to stop that — SLAs that escalate, auto-approve
 * suggestions that never act alone, bulk actions, delegation, volume alarms,
 * fatigue detection and an explain-why panel that says exactly which checks
 * fired and what each one means.
 */
import { newId } from '../util/id.js';
import { now, iso, ago, duration, HOUR, DAY, MINUTE } from '../util/time.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { truncate, jaccard } from '../util/text.js';
import { reinforce } from '../gate/classifier.js';

export const PRIORITIES = ['high', 'medium', 'low'];

export const DEFAULT_SLA = { high: HOUR, medium: DAY, low: 3 * DAY };

export class ReviewQueue {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {import('../facts/folders.js').FolderTree} opts.folders
   * @param {import('../facts/factstore.js').FactStore} opts.facts
   * @param {import('../security/alerts.js').AlertManager} [opts.alerts]
   * @param {import('../security/temporal.js').TemporalDetector} [opts.temporal]
   * @param {import('../archive/archive.js').Archive} [opts.archive]
   */
  constructor({ collection, ledger, folders, facts, alerts = null, temporal = null, archive = null, sla = DEFAULT_SLA, gate = null }) {
    this.col = collection;
    this.ledger = ledger;
    this.folders = folders;
    this.facts = facts;
    this.alerts = alerts;
    this.temporal = temporal;
    this.archive = archive;
    this.gate = gate;
    this.sla = { ...DEFAULT_SLA, ...sla };
    this.col.index('byStatus', (r) => r.status);
    this.col.index('byAssignee', (r) => r.assignedTo);
    this.col.index('byFolder', (r) => r.folder);
    this.col.index('byPriority', (r) => r.priority);
    /** @type {Map<string,{until:number, delegate:string}>} */
    this.outOfOffice = new Map();
    /** @type {Map<string, {approvals:number, rejections:number, pattern:string, examples:string[]}>} */
    this.patterns = new Map();
    this.autoApproveRules = new Map();
    this.depthSamples = [];
  }

  // -- enqueue -------------------------------------------------------------

  /**
   * @param {object} spec { factId, candidate, verdict, ctx }
   */
  enqueue({ factId, candidate, verdict, ctx = {} }) {
    const priority = this._priority(verdict);
    const folder = verdict.folder || candidate.proposedFolder || null;
    const owner = this._ownerFor(folder);
    const item = this.col.insert({
      id: newId('review'),
      kind: 'fact',
      factId,
      claim: candidate.claim,
      claimExcerpt: truncate(candidate.claim, 160),
      folder,
      priority,
      status: 'open',
      openedAt: now(),
      slaDueAt: now() + this.sla[priority],
      // routes to the FOLDER OWNER. Never "IT".
      assignedTo: owner?.businessOwner || null,
      assignedBecause: owner ? `${folder} is owned by ${owner.businessOwner}` : 'no folder owner — this is itself a finding',
      escalationLevel: 0,
      escalationTrail: [],
      // the reasons, in the reviewer's language
      reasons: verdict.reasons,
      checksFired: (verdict.checks || []).filter((c) => c.result !== 'pass' && c.result !== 'n/a'),
      outcome: verdict.outcome,
      escalateTo: verdict.escalateTo || null,
      riskSignals: this._signals(verdict),
      riskScore: this._risk(verdict),
      fourEyes: verdict.outcome === 'require-4-eyes' || this._risk(verdict) >= 0.75,
      decisions: [],
      source: {
        conversationId: candidate.source?.conversationId ?? null,
        offset: candidate.source?.start ?? 0,
        channel: candidate.source?.channel ?? ctx.channel ?? null,
        sender: ctx.source?.sender ?? null,
        agentId: candidate.capturedBy ?? ctx.agentId ?? null
      },
      candidate,
      verdict: { outcome: verdict.outcome, reasons: verdict.reasons, explanation: verdict.explanation },
      patternKey: patternKey(candidate, verdict)
    });

    if (item.escalateTo) {
      this.col.update(item.id, { assignedTo: item.escalateTo, assignedBecause: `escalated by rule to ${item.escalateTo}` });
    }
    this._sampleDepth();
    return this.col.get(item.id);
  }

  _priority(verdict) {
    const r = this._risk(verdict);
    if (r >= 0.7 || verdict.outcome === 'block' || verdict.outcome === 'quarantine') return 'high';
    if (r >= 0.35 || verdict.outcome === 'escalate' || verdict.outcome === 'require-4-eyes') return 'medium';
    return 'low';
  }

  _risk(verdict) {
    let r = 0;
    const signals = this._signals(verdict);
    r += Math.min(0.45, signals.length * 0.15);
    r += (verdict.instructionScore ?? 0) * 0.4;
    if (verdict.reconciliation?.golden) r += 0.5;
    if ((verdict.piiFindings || []).some((f) => f.category === 'credential')) r += 0.5;
    if (verdict.channelTrust === 'untrusted') r += 0.1;
    return Math.min(1, Math.round(r * 100) / 100);
  }

  _signals(verdict) {
    const s = [];
    if (verdict.channelTrust === 'untrusted') s.push('untrusted channel');
    if ((verdict.instructionScore ?? 0) >= 0.5) s.push('instruction-shaped');
    if (verdict.reconciliation?.kind === 'contradiction') {
      s.push(verdict.reconciliation.golden ? 'contradicts a GOLDEN fact' : 'contradicts an existing fact');
    }
    for (const c of verdict.checks || []) {
      if (c.check === 8 && c.matched?.length) s.push(...c.matched.map((m) => `breaks rule ${m.id}`));
      if (c.check === 3 && c.result === 'fail') s.push('source verification failed');
      if (c.check === 4 && c.result !== 'pass') s.push('private information present');
    }
    for (const t of verdict.temporal || []) s.push(t.kind.replace(/_/g, '-'));
    return [...new Set(s)];
  }

  _ownerFor(folder) {
    if (!folder) return null;
    const f = this.folders.resolve(folder);
    if (!f) return null;
    const assignee = this._resolveDelegation(f.businessOwner);
    return { ...f, businessOwner: assignee };
  }

  _resolveDelegation(person) {
    if (!person) return null;
    const ooo = this.outOfOffice.get(person);
    if (ooo && now() < ooo.until) return this._resolveDelegation(ooo.delegate) || ooo.delegate;
    return person;
  }

  // -- the queue -----------------------------------------------------------

  /**
   * @param {{assignee?:string, folder?:string, priority?:string, status?:string, limit?:number}} [q]
   */
  list({ assignee = null, folder = null, priority = null, status = 'open', limit = 100 } = {}) {
    const items = this.col.find((r) =>
      (status === 'all' || r.status === status) &&
      (!assignee || r.assignedTo === assignee) &&
      (!folder || String(r.folder || '').startsWith(folder)) &&
      (!priority || r.priority === priority));
    return items
      .sort((a, b) => (PRIORITIES.indexOf(a.priority) - PRIORITIES.indexOf(b.priority)) || (a.openedAt - b.openedAt))
      .slice(0, limit)
      .map((r) => this.view(r.id));
  }

  /** The full item as a reviewer sees it, including explain-why and the source. */
  view(id) {
    const r = this.col.get(id);
    if (!r) throw notFound('review item', id);
    const overdue = r.status === 'open' && now() > r.slaDueAt;
    return {
      ...r,
      age: ago(r.openedAt),
      slaDue: iso(r.slaDueAt),
      slaBreached: overdue,
      slaIn: overdue ? null : humanMs(r.slaDueAt - now()),
      explainWhy: this.explainWhy(id),
      sourceLink: this.showSource(id),
      actions: this.availableActions(r)
    };
  }

  /** Plain language: exactly which checks fired and what each one means (§12). */
  explainWhy(id) {
    const r = this.col.get(id);
    if (!r) throw notFound('review item', id);
    const lines = [];
    lines.push(`This was ${r.outcome === 'block' ? 'rejected' : 'held'} because ${r.reasons.length} thing${r.reasons.length === 1 ? '' : 's'} fired:`);
    r.reasons.forEach((reason, i) => lines.push(`  ${i + 1}. ${reason}`));
    if (r.checksFired.length) {
      lines.push('');
      lines.push('Checks that did not pass:');
      for (const c of r.checksFired) {
        lines.push(`  · Check ${c.check} — ${c.name}: ${CHECK_MEANING[c.check] || c.result}`);
      }
    }
    if (r.riskSignals.length) {
      lines.push('');
      lines.push(`Risk signals: ${r.riskSignals.join(' · ')} (score ${r.riskScore})`);
    }
    if (r.fourEyes) lines.push('\nThis item needs TWO named approvers before it can go live.');
    return lines.join('\n');
  }

  /** One click to the exact moment in the raw conversation (§12). */
  showSource(id) {
    const r = this.col.get(id);
    if (!r) throw notFound('review item', id);
    if (!r.source.conversationId || !this.archive) return null;
    return this.archive.sourceRef(r.source.conversationId, r.source.offset);
  }

  availableActions(r) {
    const base = ['approve', 'reject', 'edit-and-approve'];
    if (r.folder) base.push('reassign');
    if (r.riskSignals.some((s) => s.includes('contradicts'))) {
      base.push('new-wins', 'keep-old', 'both-true-different-context', 'ask-the-author');
    }
    if (r.source.sender) base.push('block-sender');
    if (r.riskScore >= 0.7) base.push('quarantine-and-open-case');
    if (r.escalateTo) base.push(`send-to-${r.escalateTo.toLowerCase()}`);
    base.push('auto-approve-this-pattern');
    return base;
  }

  // -- decisions -----------------------------------------------------------

  /**
   * @param {string} id
   * @param {{actor:string, decision:string, reason?:string, editedClaim?:string, tookMs?:number}} d
   */
  decide(id, { actor, decision, reason = null, editedClaim = null, tookMs = null, reassignTo = null }) {
    const r = this.col.get(id);
    if (!r) throw notFound('review item', id);
    if (r.status === 'closed') throw new VaultError('conflict', 'this item is already closed', { id });
    if (!actor) throw forbidden('a review decision requires a named reviewer');

    const elapsed = tookMs ?? (now() - r.openedAt);
    const entry = { actor, decision, reason, at: now(), tookMs: elapsed, editedClaim: Boolean(editedClaim) };
    const decisions = [...r.decisions, entry];

    // Four-eyes: two DISTINCT approvers.
    const approvers = new Set(decisions.filter((x) => x.decision === decision).map((x) => x.actor));
    const needed = r.fourEyes ? 2 : 1;
    if (approvers.size < needed) {
      const updated = this.col.update(id, { decisions, status: 'awaiting_second_approver' });
      this.ledger.append('review.decision', { subject: id, actor, decision, factId: r.factId, tookMs: elapsed, status: 'awaiting_second_approver' });
      return { ...updated, note: `four-eyes: ${approvers.size}/${needed} approvers — a second, distinct reviewer is required` };
    }

    let factResult = null;
    if (decision === 'approve' || decision === 'new-wins' || decision === 'edit-and-approve') {
      factResult = this._applyApproval(r, { actor, reason, editedClaim });
    } else if (decision === 'reject' || decision === 'keep-old') {
      factResult = this._applyRejection(r, { actor, reason });
    } else if (decision === 'reassign') {
      const to = this._resolveDelegation(reassignTo);
      const updated = this.col.update(id, { assignedTo: to, decisions, assignedBecause: `reassigned by ${actor}: ${reason || 'no reason given'}` });
      this.ledger.append('review.decision', { subject: id, actor, decision, reassignedTo: to });
      return updated;
    } else if (decision === 'both-true-different-context') {
      factResult = this._applyApproval(r, { actor, reason: reason || 'both true — different context', keepBoth: true });
    } else if (decision === 'quarantine-and-open-case') {
      factResult = this.facts.setStatus(r.factId, 'quarantined', { actor, reason: reason || 'quarantined by reviewer' });
      if (this.alerts) {
        const alert = this.alerts.raise({ severity: 'high', kind: 'reviewer_quarantine', actor, detail: `reviewer quarantined ${r.factId}`, subject: r.factId });
        this.alerts.openCase({ title: `Reviewer escalation: ${truncate(r.claim, 60)}`, alertIds: [alert.id], actor, severity: 'high' });
      }
    }

    const closed = this.col.update(id, {
      decisions, status: 'closed', closedAt: now(), closedBy: actor, resolution: decision
    });

    this.ledger.append('review.decision', {
      subject: id, actor, decision, reason, factId: r.factId,
      tookMs: elapsed, folder: r.folder, priority: r.priority,
      slaBreached: now() > r.slaDueAt
    });

    // Rejection reasons feed detection (§12): tune the classifier and the
    // source's reputation from every human decision.
    this._learn(r, decision, reason);
    if (this.gate && r.source.sender) this.gate.recordReviewOutcome(r.source.sender, decision);
    const fatigue = this.temporal?.observeReview({ reviewer: actor, decision, tookMs: elapsed });
    if (fatigue && this.alerts) this.alerts.raise({ ...fatigue, actor, detail: fatigue.explanation });

    this._sampleDepth();
    return { ...closed, factResult };
  }

  _applyApproval(r, { actor, reason, editedClaim = null, keepBoth = false }) {
    if (!r.factId) return null;
    const patch = { status: 'live', reviewedBy: actor, reviewedAt: now(), claimType: 'verified' };
    if (editedClaim) patch.claim = editedClaim;
    const fact = this.facts.revise(r.factId, patch, { actor, reason: reason || 'approved in review', kind: 'review_approval' });
    if (!keepBoth && r.verdict?.outcome && r.candidate && this.facts.get(r.factId)?.gateVerdict?.reconciliation?.against) {
      // handled by the caller when a supersession is required
    }
    return fact;
  }

  _applyRejection(r, { actor, reason }) {
    if (!r.factId) return null;
    return this.facts.setStatus(r.factId, 'rejected', { actor, reason: reason || 'rejected in review' });
  }

  _learn(item, decision, reason) {
    const key = item.patternKey;
    const p = this.patterns.get(key) || { approvals: 0, rejections: 0, pattern: key, examples: [] };
    if (decision === 'approve' || decision === 'new-wins' || decision === 'edit-and-approve') p.approvals++;
    if (decision === 'reject' || decision === 'keep-old') p.rejections++;
    p.examples = [...p.examples, truncate(item.claim, 100)].slice(-10);
    this.patterns.set(key, p);
    // Feed the instruction classifier: a rejected instruction-shaped claim is a
    // labelled training example.
    if (decision === 'reject' && item.riskSignals.includes('instruction-shaped')) reinforce('instruction', item.claim);
    if ((decision === 'approve') && item.riskSignals.includes('instruction-shaped')) reinforce('fact', item.claim);
  }

  // -- anti-graveyard machinery -------------------------------------------

  /**
   * Ages loudly: escalates to the folder owner, then their manager, then
   * leadership (§12).
   * @param {{managers?:Record<string,string>, leadership?:string}} org
   */
  escalateOverdue({ managers = {}, leadership = 'leadership' } = {}) {
    const escalated = [];
    for (const r of this.col.by('byStatus', 'open')) {
      if (now() <= r.slaDueAt) continue;
      const overdueBy = now() - r.slaDueAt;
      const level = overdueBy > 4 * this.sla[r.priority] ? 2 : 1;
      if (level <= r.escalationLevel) continue;
      const next = level === 1
        ? (managers[r.assignedTo] || leadership)
        : leadership;
      const trail = [...r.escalationTrail, { at: now(), from: r.assignedTo, to: next, level, overdueBy }];
      this.col.update(r.id, { escalationLevel: level, assignedTo: next, escalationTrail: trail });
      this.ledger.append('review.sla_breach', {
        subject: r.id, actor: 'system', priority: r.priority, overdueByMs: overdueBy,
        escalatedTo: next, level
      });
      this.alerts?.raise({
        severity: level >= 2 ? 'high' : 'medium', kind: 'review_sla_breach',
        detail: `review item ${r.id} is ${humanMs(overdueBy)} past its ${r.priority} SLA — escalated to ${next}`,
        subject: r.id
      });
      escalated.push({ id: r.id, to: next, level, overdueBy: humanMs(overdueBy) });
    }
    return escalated;
  }

  /**
   * "This reviewer approved 40/40 of this pattern → automate it?"
   * Suggests, never acts alone (§12).
   */
  autoApproveSuggestions({ minSamples = 20, minRate = 0.95 } = {}) {
    const out = [];
    for (const [key, p] of this.patterns) {
      const total = p.approvals + p.rejections;
      if (total < minSamples) continue;
      const rate = p.approvals / total;
      if (rate < minRate) continue;
      if (this.autoApproveRules.has(key)) continue;
      out.push({
        pattern: key,
        approvals: p.approvals,
        total,
        rate: Math.round(rate * 100) / 100,
        examples: p.examples.slice(0, 3),
        suggestion: `reviewers approved ${p.approvals}/${total} of this pattern — automate it?`,
        requiresHumanEnable: true,
        enable: `queue.enableAutoApprove(${JSON.stringify(key)}, { actor })`
      });
    }
    return out;
  }

  enableAutoApprove(patternKey, { actor, reason = 'reviewer-confirmed pattern', expiresIn = '90d' }) {
    if (!actor) throw forbidden('enabling auto-approval requires a named actor');
    this.autoApproveRules.set(patternKey, { actor, at: now(), reason, expiresAt: now() + duration(expiresIn) });
    this.ledger.append('admin.action', { subject: patternKey, actor, action: 'review.auto_approve_enabled', reason });
    return { patternKey, enabled: true, expiresAt: iso(now() + duration(expiresIn)) };
  }

  isAutoApproved(candidate, verdict) {
    const key = patternKey(candidate, verdict);
    const rule = this.autoApproveRules.get(key);
    if (!rule) return false;
    if (now() > rule.expiresAt) { this.autoApproveRules.delete(key); return false; }
    // Never auto-approve anything carrying a hard signal, regardless of pattern.
    const signals = this._signals(verdict);
    if (signals.some((s) => s.includes('GOLDEN') || s.includes('credential') || s === 'instruction-shaped')) return false;
    return true;
  }

  /** Bulk actions: select 20 similar, one decision (§12). */
  bulkDecide(ids, { actor, decision, reason }) {
    const results = [];
    for (const id of ids) {
      try { results.push({ id, ok: true, result: this.decide(id, { actor, decision, reason }) }); }
      catch (e) { results.push({ id, ok: false, error: e.message }); }
    }
    return { total: ids.length, succeeded: results.filter((r) => r.ok).length, results };
  }

  /** Find similar open items, so a reviewer can act on a group. */
  similar(id, { threshold = 0.6, limit = 25 } = {}) {
    const r = this.col.get(id);
    if (!r) throw notFound('review item', id);
    return this.col.by('byStatus', 'open')
      .filter((x) => x.id !== id)
      .map((x) => ({ item: x, similarity: jaccard(x.claim, r.claim) }))
      .filter((x) => x.similarity >= threshold)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit)
      .map((x) => ({ id: x.item.id, claim: x.item.claimExcerpt, similarity: Math.round(x.similarity * 100) / 100 }));
  }

  /** Delegation & out-of-office — coverage never gaps (§12). */
  setOutOfOffice(person, { until, delegate, actor }) {
    if (!delegate) throw new VaultError('validation', 'out-of-office requires a named delegate — coverage never gaps');
    this.outOfOffice.set(person, { until: typeof until === 'number' ? until : now() + duration(until), delegate });
    // Reassign everything currently open.
    let moved = 0;
    for (const r of this.col.by('byAssignee', person)) {
      if (r.status !== 'open') continue;
      this.col.update(r.id, { assignedTo: delegate, assignedBecause: `${person} is out of office — delegated to ${delegate}` });
      moved++;
    }
    this.ledger.append('admin.action', { subject: person, actor: actor || person, action: 'review.out_of_office', delegate, reassigned: moved });
    return { person, delegate, reassigned: moved };
  }

  /** Volume alarm: growing faster than it drains → alert leadership (§12). */
  _sampleDepth() {
    const depth = this.col.count((r) => r.status === 'open');
    this.depthSamples.push({ at: now(), depth });
    while (this.depthSamples.length > 500) this.depthSamples.shift();
    const flood = this.temporal?.observeQueueDepth(depth);
    if (flood && this.alerts) this.alerts.raise({ ...flood, detail: flood.explanation, subject: 'review_queue' });
    return depth;
  }

  volumeAlarm({ windowMs = 24 * HOUR } = {}) {
    const cutoff = now() - windowMs;
    const opened = this.col.count((r) => r.openedAt >= cutoff);
    const closed = this.col.count((r) => r.closedAt && r.closedAt >= cutoff);
    const depth = this.col.count((r) => r.status === 'open');
    const growing = opened > closed * 1.2 && depth > 10;
    return {
      windowHours: Math.round(windowMs / HOUR),
      opened, closed, depth,
      drainRate: closed / Math.max(opened, 1),
      alarm: growing,
      message: growing
        ? `the queue is growing faster than it drains (${opened} in, ${closed} out, ${depth} waiting) — this is how queue-flooding attacks work and how real threats get rubber-stamped`
        : null
    };
  }

  /** Reviewer scorecard: volume, speed, override rate, agreement with peers (§12). */
  scorecards() {
    const byReviewer = new Map();
    for (const r of this.col.all()) {
      for (const d of r.decisions) {
        const s = byReviewer.get(d.actor) || { reviewer: d.actor, decisions: 0, approvals: 0, rejections: 0, totalMs: 0, items: [] };
        s.decisions++;
        s.totalMs += d.tookMs || 0;
        if (d.decision.startsWith('approve') || d.decision === 'new-wins' || d.decision === 'edit-and-approve') s.approvals++;
        if (d.decision === 'reject' || d.decision === 'keep-old') s.rejections++;
        s.items.push({ id: r.id, decision: d.decision, patternKey: r.patternKey });
        byReviewer.set(d.actor, s);
      }
    }
    const all = [...byReviewer.values()];
    return all.map((s) => {
      // Agreement with peers on the same pattern.
      let agree = 0;
      let compared = 0;
      for (const item of s.items) {
        for (const other of all) {
          if (other.reviewer === s.reviewer) continue;
          for (const oi of other.items) {
            if (oi.patternKey !== item.patternKey) continue;
            compared++;
            if (oi.decision === item.decision) agree++;
          }
        }
      }
      return {
        reviewer: s.reviewer,
        decisions: s.decisions,
        approvalRate: Math.round((s.approvals / Math.max(s.decisions, 1)) * 100) / 100,
        medianSeconds: Math.round(s.totalMs / Math.max(s.decisions, 1) / 100) / 10,
        peerAgreement: compared ? Math.round((agree / compared) * 100) / 100 : null,
        flag: s.decisions >= 20 && s.approvals / s.decisions > 0.95 && s.totalMs / s.decisions < 5000
          ? 'approving nearly everything, very fast — check for fatigue' : null
      };
    });
  }

  /** Queue simulation: before enabling a rule, see the load it adds (§12). */
  simulate({ additionalPerWeek, secondsPerReview = 40, reviewers = 1 }) {
    const current = this.stats();
    const addedMinutes = (additionalPerWeek * secondsPerReview) / 60;
    return {
      currentOpen: current.open,
      currentWeeklyThroughput: current.closedLast7Days,
      additionalPerWeek,
      addedReviewerLoad: `${Math.round(addedMinutes)} min/week (${Math.round(addedMinutes / reviewers)} min per reviewer)`,
      projectedDepth: current.open + Math.max(0, additionalPerWeek - current.closedLast7Days),
      sustainable: additionalPerWeek <= current.closedLast7Days * 1.2,
      warning: additionalPerWeek > current.closedLast7Days * 1.2
        ? 'this rule adds more items per week than your reviewers currently close — add capacity or narrow the rule'
        : null
    };
  }

  stats() {
    const all = this.col.all();
    const open = all.filter((r) => r.status === 'open');
    const week = now() - 7 * DAY;
    const closed = all.filter((r) => r.closedAt);
    const decided = closed.filter((r) => r.closedAt >= week);
    const slaMet = closed.filter((r) => r.closedAt <= r.slaDueAt).length;
    return {
      open: open.length,
      byPriority: PRIORITIES.reduce((acc, p) => ({ ...acc, [p]: open.filter((r) => r.priority === p).length }), {}),
      oldest: open.length ? ago(Math.min(...open.map((r) => r.openedAt))) : null,
      breaching: open.filter((r) => now() > r.slaDueAt).length,
      closedLast7Days: decided.length,
      medianDecisionSeconds: decided.length
        ? Math.round(median(decided.map((r) => (r.closedAt - r.openedAt) / 1000)))
        : null,
      slaCompliance: closed.length ? Math.round((slaMet / closed.length) * 100) : 100,
      awaitingSecondApprover: all.filter((r) => r.status === 'awaiting_second_approver').length
    };
  }

  /** The screen, rendered — for the CLI and the Slack/Teams inline card. */
  render({ folder = null, limit = 6 } = {}) {
    const items = this.list({ folder, limit });
    const s = this.stats();
    const lines = [];
    const title = folder ? `NEEDS REVIEW — ${folder}` : 'NEEDS REVIEW';
    lines.push(`${title.padEnd(42)} ${s.open} waiting · oldest ${s.oldest ?? '—'}`);
    if (s.breaching) lines.push(`${' '.repeat(42)} ⚠️  ${s.breaching} past SLA`);
    lines.push('');
    for (const r of items) {
      const icon = r.priority === 'high' ? '⏳ HIGH ' : r.priority === 'medium' ? '⏳ MED  ' : '⏳ LOW  ';
      lines.push(`${icon} "${truncate(r.claim, 96)}"`);
      lines.push(`   from    ${[r.source.channel, r.source.sender, r.source.agentId].filter(Boolean).join(' · ')}`);
      lines.push(`   held    ${r.reasons.join('\n           + ')}`);
      lines.push(`   risk    ${r.riskScore >= 0.7 ? 'HIGH' : r.riskScore >= 0.35 ? 'MEDIUM' : 'LOW'} — ${r.riskSignals.length} signal${r.riskSignals.length === 1 ? '' : 's'}${r.riskSignals.some((x) => x.includes('GOLDEN')) ? ', one golden conflict' : ''}`);
      lines.push(`   [${r.actions.join('] [')}]`);
      lines.push('');
    }
    return lines.join('\n');
  }
}

const CHECK_MEANING = {
  1: 'the agent could not be identified, is unowned, or is out of scope for this write',
  2: 'the data arrived over a channel that is untrusted by architecture — not by score',
  3: 'the sender could not be verified (SPF/DKIM/DMARC, signature, mTLS, reputation)',
  4: 'private information or a credential was present in the text',
  5: 'the sensitivity classifier was not confident, so the label was raised rather than guessed downward',
  6: 'the write crossed a wall between departments or projects',
  7: 'the text tries to change behaviour rather than describe the world',
  8: 'one or more of your policy rules matched',
  9: 'this contradicts something already stored, and authority decides — not recency',
  10: 'there is no recorded lawful basis for personal data about this person'
};

function patternKey(candidate, verdict) {
  return [
    candidate.source?.channel ?? 'unknown',
    candidate.claimType,
    verdict.outcome,
    (verdict.reasons || []).length ? String(verdict.reasons[0]).slice(0, 40) : 'none'
  ].join('|');
}

function median(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

function humanMs(ms) {
  if (ms < MINUTE) return `${Math.round(ms / 1000)}s`;
  if (ms < HOUR) return `${Math.round(ms / MINUTE)} min`;
  if (ms < DAY) return `${Math.round(ms / HOUR)}h`;
  return `${Math.round(ms / DAY)}d`;
}
