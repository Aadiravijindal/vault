/**
 * Entities (§11.2).
 *
 * "Acme Corp" in a sales call, a support ticket and a bug report resolves to ONE
 * entity. Fuzzy matches below the threshold go to review — never auto-merge,
 * because a wrong merge silently crosses a wall.
 */
import { newId } from '../util/id.js';
import { now, iso } from '../util/time.js';
import { editDistance, jaccard } from '../util/text.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { slug } from '../extract/extract.js';

export const ENTITY_TYPES = ['company', 'person', 'product', 'project', 'contract', 'ticket', 'incident', 'asset', 'location'];

export class EntityResolver {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {number} [opts.autoMergeThreshold]
   */
  constructor({ collection, ledger, autoMergeThreshold = 0.9, reviewThreshold = 0.62 }) {
    this.col = collection;
    this.ledger = ledger;
    this.autoMergeThreshold = autoMergeThreshold;
    this.reviewThreshold = reviewThreshold;
    this.col.index('byType', (e) => e.type);
    this.col.index('byAlias', (e) => [e.name.toLowerCase(), ...(e.aliases || []).map((a) => a.toLowerCase())]);
    this.col.index('byExternalId', (e) => Object.values(e.externalIds || {}));
    /** @type {Array<object>} pending fuzzy matches awaiting a human */
    this.pendingMerges = [];
    /** @type {Array<{from:string, to:string, kind:string, at:number}>} */
    this.relationships = [];
  }

  /**
   * @param {{name:string, type?:string, aliases?:string[], externalIds?:Record<string,string>, domain?:string}} spec
   */
  upsert(spec) {
    const name = String(spec.name || '').trim();
    if (!name) throw new VaultError('validation', 'an entity needs a name');
    const match = this.resolve(name, { type: spec.type, externalIds: spec.externalIds, domain: spec.domain });
    if (match.entity && match.confidence >= this.autoMergeThreshold) {
      const e = match.entity;
      const aliases = [...new Set([...(e.aliases || []), ...(spec.aliases || []), name].filter((a) => a !== e.name))];
      const externalIds = { ...e.externalIds, ...spec.externalIds };
      return this.col.update(e.id, { aliases, externalIds, lastSeenAt: now() });
    }
    if (match.entity && match.confidence >= this.reviewThreshold) {
      // Below the auto-merge threshold → review, not auto-merge.
      this.pendingMerges.push({
        id: newId('review'), candidateName: name, existingId: match.entity.id,
        existingName: match.entity.name, confidence: match.confidence, at: now(),
        reason: 'fuzzy name match below the auto-merge threshold — a human decides'
      });
    }
    return this.col.insert({
      id: `e-${slug(name)}-${String(spec.type || 'unknown').slice(0, 4)}`,
      name,
      type: spec.type && ENTITY_TYPES.includes(spec.type) ? spec.type : 'unknown',
      aliases: spec.aliases || [],
      externalIds: spec.externalIds || {},
      domain: spec.domain || null,
      createdAt: now(),
      lastSeenAt: now(),
      factCount: 0,
      legalHold: null,
      erasureRequested: false,
      mergedInto: null
    });
  }

  /**
   * @returns {{entity:object|null, confidence:number, how:string}}
   */
  resolve(name, { type = null, externalIds = null, domain = null } = {}) {
    const n = String(name || '').trim();
    if (!n) return { entity: null, confidence: 0, how: 'empty' };

    // 1. cross-system id mapping is exact and wins outright
    if (externalIds) {
      for (const v of Object.values(externalIds)) {
        const hits = this.col.by('byExternalId', v);
        if (hits.length) return { entity: this._follow(hits[0]), confidence: 1, how: 'external id match' };
      }
    }
    // 2. exact name/alias
    const exact = this.col.by('byAlias', n.toLowerCase());
    const typed = type ? exact.filter((e) => e.type === type) : exact;
    if (typed.length) return { entity: this._follow(typed[0]), confidence: 1, how: 'exact name or alias' };
    if (exact.length) return { entity: this._follow(exact[0]), confidence: 0.95, how: 'exact name, different type' };

    // 3. domain
    if (domain) {
      const byDomain = this.col.first((e) => e.domain && e.domain.toLowerCase() === domain.toLowerCase());
      if (byDomain) return { entity: this._follow(byDomain), confidence: 0.93, how: 'domain match' };
    }

    // 4. fuzzy: normalised form, then edit distance, then token overlap
    const norm = normaliseName(n);
    let best = null;
    for (const e of this.col.all()) {
      if (e.mergedInto) continue;
      if (type && e.type !== type && e.type !== 'unknown') continue;
      const candidates = [e.name, ...(e.aliases || [])];
      for (const c of candidates) {
        const cn = normaliseName(c);
        let score = 0;
        if (cn === norm) score = 0.97;
        else {
          const dist = editDistance(cn, norm, 3);
          if (dist <= 2 && Math.min(cn.length, norm.length) > 4) score = 0.85 - dist * 0.08;
          else score = jaccard(cn, norm) * 0.8;
        }
        if (!best || score > best.confidence) best = { entity: e, confidence: Math.round(score * 100) / 100, how: 'fuzzy name match' };
      }
    }
    return best && best.confidence >= this.reviewThreshold ? { ...best, entity: this._follow(best.entity) } : { entity: null, confidence: best?.confidence ?? 0, how: 'no match' };
  }

  _follow(e) {
    let cur = e;
    const seen = new Set();
    while (cur?.mergedInto && !seen.has(cur.id)) {
      seen.add(cur.id);
      cur = this.col.get(cur.mergedInto) || cur;
    }
    return cur;
  }

  get(id) { return this.col.get(id); }
  all() { return this.col.find((e) => !e.mergedInto); }
  byType(type) { return this.col.by('byType', type).filter((e) => !e.mergedInto); }

  /** Link the entities on a fact, creating them if new. */
  link(fact) {
    const linked = [];
    for (const e of fact.entities || []) {
      const entity = this.upsert({ name: e.name, type: e.type, externalIds: e.externalIds });
      this.col.update(entity.id, { factCount: (entity.factCount || 0) + 1, lastSeenAt: now() });
      linked.push(entity.id);
    }
    return linked;
  }

  /** Merge and un-merge, both reversible and logged (§11.2). */
  merge(sourceId, targetId, { actor, reason }) {
    if (!actor || !reason) throw forbidden('entity merges require a named actor and a reason');
    const src = this.col.get(sourceId);
    const tgt = this.col.get(targetId);
    if (!src || !tgt) throw notFound('entity', sourceId || targetId);
    this.col.update(sourceId, { mergedInto: targetId, mergedAt: now(), mergedBy: actor, mergeReason: reason });
    this.col.update(targetId, {
      aliases: [...new Set([...(tgt.aliases || []), src.name, ...(src.aliases || [])])],
      externalIds: { ...src.externalIds, ...tgt.externalIds },
      factCount: (tgt.factCount || 0) + (src.factCount || 0)
    });
    this.ledger.append('admin.action', { subject: sourceId, actor, action: 'entity.merged', into: targetId, reason });
    return { merged: sourceId, into: targetId, reversible: true };
  }

  unmerge(sourceId, { actor, reason }) {
    if (!actor || !reason) throw forbidden('un-merging requires a named actor and a reason');
    const src = this.col.get(sourceId);
    if (!src?.mergedInto) throw new VaultError('conflict', 'entity is not merged', { sourceId });
    const target = this.col.get(src.mergedInto);
    this.col.update(sourceId, { mergedInto: null, unmergedAt: now(), unmergedBy: actor });
    if (target) {
      this.col.update(target.id, {
        aliases: (target.aliases || []).filter((a) => a !== src.name && !(src.aliases || []).includes(a))
      });
    }
    this.ledger.append('admin.action', { subject: sourceId, actor, action: 'entity.unmerged', from: src.mergedInto, reason });
    return { unmerged: sourceId, from: src.mergedInto };
  }

  pending() { return this.pendingMerges; }

  decidePending(id, { actor, decision, reason }) {
    const idx = this.pendingMerges.findIndex((p) => p.id === id);
    if (idx < 0) throw notFound('pending entity merge', id);
    const p = this.pendingMerges.splice(idx, 1)[0];
    if (decision === 'merge') {
      const candidate = this.col.first((e) => e.name === p.candidateName);
      if (candidate) return this.merge(candidate.id, p.existingId, { actor, reason: reason || 'reviewer confirmed match' });
    }
    this.ledger.append('review.decision', { subject: id, actor, kind: 'entity_merge', decision, reason });
    return { decided: decision, pending: p };
  }

  // -- relationships -------------------------------------------------------

  relate(fromId, toId, kind, { actor = 'system' } = {}) {
    this.relationships.push({ from: fromId, to: toId, kind, at: now(), actor });
    return { from: fromId, to: toId, kind };
  }

  graph({ rootId = null, depth = 2 } = {}) {
    const nodes = new Map();
    const edges = [];
    const add = (id) => {
      const e = this.col.get(id);
      if (e && !nodes.has(id)) nodes.set(id, { id, name: e.name, type: e.type, factCount: e.factCount });
    };
    if (!rootId) {
      for (const e of this.all()) add(e.id);
      for (const r of this.relationships) if (nodes.has(r.from) && nodes.has(r.to)) edges.push(r);
      return { nodes: [...nodes.values()], edges };
    }
    let frontier = [rootId];
    add(rootId);
    for (let d = 0; d < depth; d++) {
      const next = [];
      for (const id of frontier) {
        for (const r of this.relationships) {
          if (r.from === id) { add(r.to); edges.push(r); next.push(r.to); }
          if (r.to === id) { add(r.from); edges.push(r); next.push(r.from); }
        }
      }
      frontier = next;
    }
    return { nodes: [...nodes.values()], edges };
  }

  /** Entity-level legal hold and erasure (§11.2). */
  setHold(entityId, hold) {
    const e = this.col.get(entityId);
    if (!e) throw notFound('entity', entityId);
    return this.col.update(entityId, { legalHold: hold });
  }

  markErasure(entityId, requested) {
    const e = this.col.get(entityId);
    if (!e) throw notFound('entity', entityId);
    return this.col.update(entityId, { erasureRequested: requested });
  }
}

function normaliseName(s) {
  return String(s)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/\b(inc|corp|corporation|ltd|limited|llc|gmbh|plc|sa|ag|bv|pty|co|company|the)\b/g, '')
    .replace(/[^a-z0-9]+/g, '')
    .trim();
}
