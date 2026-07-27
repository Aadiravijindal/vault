/**
 * L6 — THE HYGIENE ENGINE (§11.6).
 *
 * This is what stops memory rotting. Every action is logged and reversible; the
 * engine never silently deletes anything.
 */
import { now, iso, ago, duration, DAY, MONTH } from '../util/time.js';
import { cosine, truncate } from '../util/text.js';
import { newId } from '../util/id.js';
import { VaultError } from '../util/errors.js';

export class HygieneEngine {
  /**
   * @param {object} deps
   */
  constructor({ facts, folders, entities, search, ledger, archive, registry, alerts = null, tiering = null }) {
    this.facts = facts;
    this.folders = folders;
    this.entities = entities;
    this.search = search;
    this.ledger = ledger;
    this.archive = archive;
    this.registry = registry;
    this.alerts = alerts;
    this.tiering = tiering;
    /** Every hygiene action, so every one of them is reversible. */
    this.actions = [];
  }

  /**
   * Run the whole engine. Returns everything it did, and everything it
   * declined to do because of a hold.
   * @param {{dryRun?:boolean, actor?:string}} [opts]
   */
  run({ dryRun = false, actor = 'hygiene' } = {}) {
    const report = {
      startedAt: iso(),
      dryRun,
      deduplicated: this.deduplicate({ dryRun, actor }),
      expired: this.expire({ dryRun, actor }),
      contradictions: this.detectContradictions(),
      decayed: this.decayConfidence({ dryRun, actor }),
      summaries: this.resummarise({ dryRun, actor }),
      drift: this.detectDrift(),
      orphans: this.detectOrphans(),
      stale: this.detectStaleness(),
      singleSource: this.detectSingleSourceRisk(),
      goldenDue: this.facts.goldenDue(),
      compacted: this.compact({ dryRun }),
      reindexed: dryRun ? null : this.search.reindexAll(),
      consistency: this.consistencyCheck()
    };
    report.finishedAt = iso();
    return report;
  }

  /** Semantically identical facts merge. Sources preserved. Confidence rises. */
  deduplicate({ threshold = 0.88, dryRun = false, actor = 'hygiene' } = {}) {
    const live = this.facts.live().filter((f) => !f.golden && !f.legalHold);
    const merged = [];
    const seen = new Set();
    for (let i = 0; i < live.length; i++) {
      const a = live[i];
      if (seen.has(a.id)) continue;
      for (let j = i + 1; j < live.length; j++) {
        const b = live[j];
        if (seen.has(b.id)) continue;
        if (a.folder !== b.folder) continue;
        if (cosine(a.claim, b.claim) < threshold) continue;
        // Keep the older fact and fold the newer into it: the earliest
        // observation is the one with the strongest provenance chain.
        const [keep, fold] = a.createdAt <= b.createdAt ? [a, b] : [b, a];
        merged.push({ kept: keep.id, folded: fold.id, claim: truncate(keep.claim, 80) });
        seen.add(fold.id);
        if (!dryRun) {
          this.facts.merge(keep.id, {
            claim: fold.claim, source: fold.source
          }, { actor, reason: `semantic duplicate of ${fold.id}` });
          this.facts.setStatus(fold.id, 'superseded', { actor, reason: `merged into ${keep.id}` });
          this._log('deduplicate', { kept: keep.id, folded: fold.id }, actor);
        }
      }
    }
    return { merged: merged.length, details: merged };
  }

  /**
   * "Customer is angry today" dies in 7 days. "Customer's legal name" never does.
   * Legal hold always wins.
   */
  expire({ dryRun = false, actor = 'hygiene' } = {}) {
    const expired = [];
    const heldBack = [];
    for (const f of this.facts.live()) {
      if (!f.expiresAt || f.expiresAt > now()) continue;
      if (f.legalHold) {
        heldBack.push({ id: f.id, reason: `legal hold ${f.legalHold.matter ?? f.legalHold}` });
        continue;
      }
      expired.push({ id: f.id, claim: truncate(f.claim, 70), expiredAt: iso(f.expiresAt), age: ago(f.createdAt) });
      if (!dryRun) {
        this.facts.setStatus(f.id, 'expired', { actor, reason: 'retention TTL reached' });
        this._log('expire', { factId: f.id }, actor);
      }
    }
    return { expired: expired.length, heldBack: heldBack.length, details: expired, heldBackDetails: heldBack };
  }

  /** Contradictions surfaced by authority order; above threshold a human decides. */
  detectContradictions({ threshold = 0.5 } = {}) {
    const live = this.facts.live();
    const out = [];
    for (let i = 0; i < live.length; i++) {
      for (let j = i + 1; j < live.length; j++) {
        const a = live[i];
        const b = live[j];
        if (a.golden && b.golden) continue;
        const sim = cosine(a.claim, b.claim);
        if (sim < threshold) continue;
        const na = numbers(a.claim);
        const nb = numbers(b.claim);
        const numeric = na.length && nb.length && !na.some((x) => nb.includes(x));
        const polarity = /\b(not|never|no)\b/i.test(a.claim) !== /\b(not|never|no)\b/i.test(b.claim);
        if (!numeric && !(sim > 0.7 && polarity)) continue;
        out.push({
          a: { id: a.id, claim: truncate(a.claim, 70), claimType: a.claimType, golden: Boolean(a.golden) },
          b: { id: b.id, claim: truncate(b.claim, 70), claimType: b.claimType, golden: Boolean(b.golden) },
          similarity: Math.round(sim * 100) / 100,
          why: numeric ? `values differ (${na.join(', ')} vs ${nb.join(', ')})` : 'opposite polarity',
          resolution: a.golden ? `${a.id} is golden and wins` : b.golden ? `${b.id} is golden and wins` : 'needs human arbitration'
        });
      }
    }
    return out;
  }

  /**
   * Never referenced or reconfirmed in N months → lower rank, flag for review.
   * NOT deleted.
   */
  decayConfidence({ months = 9, dryRun = false, actor = 'hygiene' } = {}) {
    const cutoff = now() - months * MONTH;
    const decayed = [];
    for (const f of this.facts.live()) {
      if (f.golden || f.legalHold) continue;
      const lastTouch = Math.max(f.lastConfirmedAt || 0, ...(f.readBy || []).map((r) => r.at || 0), f.createdAt);
      if (lastTouch > cutoff) continue;
      if (f.decaying) continue;
      decayed.push({ id: f.id, claim: truncate(f.claim, 70), lastTouched: ago(lastTouch), confidence: f.confidence });
      if (!dryRun) {
        this.facts.revise(f.id, {
          decaying: true,
          confidence: f.confidence === 'high' ? 'medium' : 'low',
          reviewDueAt: now() + 14 * DAY
        }, { actor, reason: `not referenced or reconfirmed in ${months} months — rank lowered, flagged for review, NOT deleted`, kind: 'decay' });
        this._log('decay', { factId: f.id }, actor);
      }
    }
    return { decayed: decayed.length, details: decayed, note: 'decayed facts are demoted and flagged — never deleted' };
  }

  /**
   * 40 related facts get a rolling summary layer on top. Originals untouched.
   * Summaries inherit the STRICTEST wall and label of their inputs (§8.6).
   */
  resummarise({ minCluster = 8, dryRun = false, actor = 'hygiene' } = {}) {
    const byFolder = new Map();
    for (const f of this.facts.live()) {
      if (f.golden) continue;
      const list = byFolder.get(f.folder) || [];
      list.push(f);
      byFolder.set(f.folder, list);
    }
    const summaries = [];
    for (const [folder, list] of byFolder) {
      if (list.length < minCluster) continue;
      const inputs = list.slice(0, 40);
      const wall = this.folders.strictestOf([...new Set(inputs.map((f) => f.folder))]);
      const label = inputs.reduce((acc, f) => (rank(f.sensitivity) > rank(acc) ? f.sensitivity : acc), 'public');
      const summary = {
        id: newId('fact'),
        folder,
        kind: 'rolling_summary',
        inputs: inputs.map((f) => f.id),
        claim: summarise(inputs),
        sensitivity: label,
        wall,
        createdAt: now(),
        note: 'derived content inherits the strictest wall and label of its inputs — inference protection'
      };
      summaries.push(summary);
      if (!dryRun) {
        this.facts.linkDerived(inputs.map((f) => f.id), summary.id);
        this._log('resummarise', { folder, inputs: inputs.length, summaryId: summary.id }, actor);
      }
    }
    return summaries;
  }

  /** Facts quietly contradicting a golden fact get raised (§9.5). */
  detectDrift() {
    return this.facts.contradictionRadar();
  }

  /** Facts whose entity was deleted, agent retired, or folder has no owner. */
  detectOrphans() {
    const out = [];
    for (const f of this.facts.live()) {
      const folder = this.folders.resolve(f.folder);
      if (!folder) {
        out.push({ factId: f.id, kind: 'missing_folder', detail: `folder ${f.folder} no longer exists`, severity: 'medium' });
      } else if (!folder.businessOwner) {
        out.push({ factId: f.id, kind: 'unowned_folder', detail: `${folder.path} has no business owner`, severity: 'medium' });
      }
      if (f.capturedBy) {
        const agent = this.registry.get(f.capturedBy);
        if (!agent) out.push({ factId: f.id, kind: 'unknown_agent', detail: `captured by ${f.capturedBy}, which is not registered`, severity: 'high' });
        else if (agent.status === 'retired') out.push({ factId: f.id, kind: 'retired_agent', detail: `captured by retired agent ${agent.id} — ownership now ${agent.businessOwner}`, severity: 'low' });
      }
      for (const e of f.entities || []) {
        const key = e.id || e.name;
        if (this.entities && !this.entities.get(key) && !this.entities.resolve(e.name).entity) {
          out.push({ factId: f.id, kind: 'orphan_entity', detail: `entity ${e.name} no longer resolves`, severity: 'low' });
        }
      }
    }
    return out;
  }

  /** "This pricing fact is 14 months old and pricing changed twice." */
  detectStaleness({ months = 12 } = {}) {
    const cutoff = now() - months * MONTH;
    const out = [];
    for (const f of this.facts.live()) {
      if (f.golden || f.createdAt > cutoff) continue;
      const sameAttribute = this.facts.live().filter(
        (o) => o.id !== f.id && o.structured?.attribute && o.structured.attribute === f.structured?.attribute &&
               o.createdAt > f.createdAt);
      out.push({
        factId: f.id,
        claim: truncate(f.claim, 80),
        age: ago(f.createdAt),
        supersedingChanges: sameAttribute.length,
        detail: sameAttribute.length
          ? `this ${f.structured?.attribute ?? 'fact'} is ${ago(f.createdAt)} old and the same attribute changed ${sameAttribute.length} time${sameAttribute.length === 1 ? '' : 's'} since`
          : `this fact is ${ago(f.createdAt)} old and has not been reconfirmed`
      });
    }
    return out;
  }

  /** Important facts with only one witness, flagged for corroboration. */
  detectSingleSourceRisk({ importantLabels = ['confidential', 'secret'] } = {}) {
    return this.facts.live()
      .filter((f) => !f.golden && (f.corroboratingSources || 1) === 1 &&
        (importantLabels.includes(f.sensitivity) || (f.readCount || 0) >= 5))
      .map((f) => ({
        factId: f.id,
        claim: truncate(f.claim, 80),
        sensitivity: f.sensitivity,
        reads: f.readCount,
        detail: 'important fact with a single witness — corroborate or downgrade',
        severity: f.sensitivity === 'secret' ? 'high' : 'medium'
      }));
  }

  /** Cold facts to cheap storage. Still traceable, still provable. */
  compact({ dryRun = false, coldAfterMonths = 12 } = {}) {
    if (!this.tiering) return { moved: 0, note: 'tiering not configured' };
    const preview = this.tiering.previewLifecycle();
    if (dryRun) return { ...preview, applied: false };
    const applied = this.tiering.runLifecycle();
    return { ...applied, applied: true };
  }

  /** Three-way reconciliation: ledger vs fact store vs archive (§11.6). */
  consistencyCheck() {
    const problems = [];
    const ledgerFactIds = new Set(
      this.ledger.entries({
        type: ['fact.written', 'fact.held', 'fact.blocked', 'fact.masked', 'fact.escalated', 'fact.quarantined', 'golden.created'],
        limit: Infinity
      }).map((e) => e.subject));
    const storeIds = new Set(this.facts.all().map((f) => f.id));

    for (const id of ledgerFactIds) {
      if (!storeIds.has(id)) {
        // Erased facts legitimately leave the store; the ledger keeps the event.
        const erased = this.ledger.entries({ type: 'fact.erased', limit: Infinity }).some((e) => e.subject === id);
        if (!erased) problems.push({ kind: 'ledger_without_fact', id, detail: 'ledger records this fact but the store does not have it' });
      }
    }
    for (const id of storeIds) {
      if (!ledgerFactIds.has(id)) problems.push({ kind: 'fact_without_ledger', id, detail: 'fact exists but was never recorded in the ledger' });
    }
    // Every fact must point at an archived conversation (or be human-authored).
    for (const f of this.facts.all()) {
      const convId = f.source?.conversationId;
      if (!convId) {
        if (!f.golden) problems.push({ kind: 'fact_without_source', id: f.id, detail: 'non-golden fact has no source conversation' });
        continue;
      }
      if (this.archive && !this.archive.get(convId)) {
        problems.push({ kind: 'missing_archive', id: f.id, detail: `source conversation ${convId} is not in the archive` });
      }
    }
    const integrity = this.facts.verifyIntegrity();
    return {
      ok: problems.length === 0 && integrity.ok,
      problems: [...problems, ...integrity.problems.map((p) => ({ kind: p.problem, id: p.factId }))],
      checked: { ledgerEvents: ledgerFactIds.size, facts: storeIds.size, archive: this.archive?.stats().conversations ?? 0 }
    };
  }

  // -- reversibility -------------------------------------------------------

  _log(action, detail, actor) {
    const record = { id: newId('session'), action, detail, actor, at: now() };
    this.actions.push(record);
    this.ledger.append('hygiene.action', { subject: detail.factId || detail.folder || action, actor, action, ...detail });
    return record;
  }

  /** Every hygiene action is logged and reversible (§11.6). */
  history({ limit = 200 } = {}) {
    return this.actions.slice(-limit).map((a) => ({ ...a, at: iso(a.at) }));
  }

  revert(actionId, { actor, reason }) {
    const a = this.actions.find((x) => x.id === actionId);
    if (!a) throw new VaultError('not_found', 'hygiene action not found', { actionId });
    if (!actor || !reason) throw new VaultError('forbidden', 'reverting a hygiene action requires a named actor and a reason');
    let result;
    switch (a.action) {
      case 'expire':
        result = this.facts.setStatus(a.detail.factId, 'live', { actor, reason });
        break;
      case 'decay':
        result = this.facts.revise(a.detail.factId, { decaying: false, confidence: 'high' }, { actor, reason, kind: 'decay_reverted' });
        break;
      case 'deduplicate':
        result = this.facts.setStatus(a.detail.folded, 'live', { actor, reason });
        break;
      default:
        throw new VaultError('validation', `hygiene action "${a.action}" has no automatic revert — use the undo path`, { actionId });
    }
    this.ledger.append('hygiene.action', { subject: actionId, actor, action: 'revert', reason, reverted: a.action });
    return { reverted: a.action, result };
  }
}

function numbers(s) {
  return (String(s).match(/\d[\d,]*(?:\.\d+)?/g) || []).map((n) => parseFloat(n.replace(/,/g, '')));
}

function rank(l) { return { public: 0, internal: 1, confidential: 2, secret: 3 }[l] ?? 1; }

function summarise(facts) {
  const byAttribute = new Map();
  for (const f of facts) {
    const key = f.structured?.attribute || 'other';
    const list = byAttribute.get(key) || [];
    list.push(f);
    byAttribute.set(key, list);
  }
  const parts = [];
  for (const [attr, list] of byAttribute) {
    if (attr === 'other') continue;
    const latest = list.reduce((a, b) => (a.createdAt > b.createdAt ? a : b));
    parts.push(`${attr.replace(/_/g, ' ')}: ${latest.structured?.value ?? truncate(latest.claim, 50)}`);
  }
  if (!parts.length) parts.push(...facts.slice(0, 3).map((f) => truncate(f.claim, 60)));
  return `Rolling summary of ${facts.length} facts — ${parts.slice(0, 6).join(' · ')}`;
}
