/**
 * Check 9 — reconciliation (§8.9).
 *
 * Contradictions resolve by AUTHORITY, not recency. "Newer wins" was the bug: a
 * stranger's email is always newer than your CFO's approval.
 *
 * Resolution order:
 *   1. approved (golden)          beats everything. Full stop.
 *   2. verified by human          beats unverified
 *   3. trusted channel            beats untrusted channel
 *   4. higher org authority       beats lower (CFO beats rep)
 *   5. more specific              beats general
 *   6. corroborated (2+ sources)  beats single-source
 *   7. ONLY THEN: newer           beats older
 */
import { cosine, jaccard, contentTokens, truncate } from '../util/text.js';
import { CLAIM_TYPES } from '../extract/extract.js';

export const DUPLICATE_THRESHOLD = 0.86;
export const RELATED_THRESHOLD = 0.42;

/** Organisational authority ladder. Configurable per company. */
export const DEFAULT_AUTHORITY = {
  board: 100, ceo: 95, cfo: 90, cto: 90, coo: 90, gc: 90, ciso: 88,
  vp: 80, director: 70, head: 70, manager: 60, lead: 55,
  senior: 45, ic: 40, rep: 35, contractor: 25, external: 15, unknown: 10, agent: 5
};

const TRUST_RANK = { trusted: 3, 'semi-trusted': 2, untrusted: 1, unknown: 0 };

export class Reconciler {
  /**
   * @param {object} opts
   * @param {(ctx:object)=>object[]} opts.findRelated returns existing facts that may relate
   * @param {Record<string,number>} [opts.authority]
   * @param {number} [opts.arbitrationMargin] below this score gap, a human decides
   */
  constructor({ findRelated, authority = DEFAULT_AUTHORITY, arbitrationMargin = 1 }) {
    this.findRelated = findRelated;
    this.authority = authority;
    this.arbitrationMargin = arbitrationMargin;
  }

  /**
   * @param {object} candidate the incoming candidate fact
   * @param {object} ctx
   * @returns {{kind:'novel'|'duplicate'|'refinement'|'contradiction', ...}}
   */
  reconcile(candidate, ctx = {}) {
    const related = this.findRelated(candidate) || [];
    if (!related.length) {
      return { kind: 'novel', action: 'write', related: [], explanation: 'no related fact exists — written as new' };
    }

    const scored = related
      .map((f) => ({ fact: f, similarity: similarity(candidate.claim, f.claim), conflict: this._conflicts(candidate, f) }))
      .sort((a, b) => b.similarity - a.similarity);

    const top = scored[0];

    // Golden facts are unoverwritable by any agent, ever (§9.5).
    const goldenConflict = scored.find((s) => s.fact.golden && s.conflict);
    if (goldenConflict) {
      return {
        kind: 'contradiction',
        action: 'block',
        golden: true,
        against: goldenConflict.fact.id,
        alert: true,
        flagSource: true,
        explanation: `contradicts golden fact ${goldenConflict.fact.id} ("${truncate(goldenConflict.fact.claim, 80)}"), `
          + `approved by ${goldenConflict.fact.approvedBy || 'a named authority'}. An approved fact cannot be overwritten by any agent.`,
        conflictDetail: goldenConflict.conflict
      };
    }

    if (top.similarity >= DUPLICATE_THRESHOLD && !top.conflict) {
      return {
        kind: 'duplicate',
        action: 'merge',
        into: top.fact.id,
        similarity: round(top.similarity),
        explanation: 'same meaning already stored — merged. Both sources kept, confidence rises: one fact, two witnesses.',
        confidenceDelta: +0.05
      };
    }

    const conflicting = scored.filter((s) => s.conflict && s.similarity >= RELATED_THRESHOLD);
    if (conflicting.length) {
      const against = conflicting[0];
      const decision = this.resolve(candidate, against.fact, ctx);
      return {
        kind: 'contradiction',
        action: decision.winner === 'incoming' ? 'supersede'
          : decision.winner === 'existing' ? 'reject'
          : 'arbitrate',
        against: against.fact.id,
        similarity: round(against.similarity),
        conflictDetail: against.conflict,
        ...decision
      };
    }

    if (top.similarity >= RELATED_THRESHOLD) {
      const adds = addsDetail(candidate.claim, top.fact.claim);
      if (adds) {
        return {
          kind: 'refinement',
          action: 'refine',
          into: top.fact.id,
          similarity: round(top.similarity),
          newDetail: adds,
          explanation: 'adds detail without conflicting — merged, version bumped, prior version retained and diffable'
        };
      }
    }

    return { kind: 'novel', action: 'write', related: scored.slice(0, 3).map((s) => ({ id: s.fact.id, similarity: round(s.similarity) })), explanation: 'related but distinct — written as a new fact, entities linked' };
  }

  /**
   * Apply the authority order. Returns the winner and the full reasoning, which
   * the reviewer sees verbatim.
   */
  resolve(incoming, existing, ctx = {}) {
    const steps = [];
    const A = this._profile(incoming, ctx, 'incoming');
    const B = this._profile(existing, ctx, 'existing');

    const rungs = [
      ['approved (golden) beats everything', A.approved, B.approved],
      ['verified by a human beats unverified', A.verified, B.verified],
      ['trusted channel beats untrusted', A.trust, B.trust],
      ['higher org authority beats lower', A.authority, B.authority],
      ['more specific beats general', A.specificity, B.specificity],
      ['corroborated beats single-source', A.corroboration, B.corroboration],
      ['ONLY THEN: newer beats older', A.recency, B.recency]
    ];

    for (const [label, a, b] of rungs) {
      const na = Number(a);
      const nb = Number(b);
      steps.push({ rule: label, incoming: na, existing: nb, decided: na !== nb });
      if (na > nb) {
        return {
          winner: 'incoming', decidedBy: label, steps,
          explanation: `Incoming wins on "${label}" (${na} vs ${nb}). The losing fact moves to history — it is never deleted.`,
          loserDisposition: 'history'
        };
      }
      if (nb > na) {
        return {
          winner: 'existing', decidedBy: label, steps,
          explanation: `Existing fact wins on "${label}" (${nb} vs ${na}). The incoming claim is rejected and recorded as an attempted overwrite.`,
          loserDisposition: 'rejected'
        };
      }
    }

    return {
      winner: 'arbitrate', decidedBy: null, steps,
      explanation: 'Too close to call on every rung of the authority order — BOTH are held and a human arbitrates. Vault does not guess between two plausible truths.',
      loserDisposition: 'both held'
    };
  }

  _profile(fact, ctx, which) {
    const claimType = fact.claimType || 'heard';
    const said = fact.saidBy || {};
    const role = String(said.authority || said.role || said.kind || 'unknown').toLowerCase();
    const authorityScore = this.authority[role]
      ?? Object.entries(this.authority).find(([k]) => role.includes(k))?.[1]
      ?? this.authority.unknown;
    return {
      approved: claimType === 'approved' || fact.golden ? 1 : 0,
      verified: claimType === 'verified' || fact.reviewedBy ? 1 : 0,
      trust: TRUST_RANK[fact.channelTrust || ctx.channelTrust || 'unknown'] ?? 0,
      authority: authorityScore,
      specificity: specificity(fact.claim),
      corroboration: (fact.corroboratingSources ?? (fact.sources?.length || 1)),
      recency: which === 'incoming' ? (fact.extractedAt || Date.now()) : (fact._updated || fact.createdAt || 0),
      claimTypeRank: CLAIM_TYPES[claimType]?.rank ?? 0
    };
  }

  _conflicts(candidate, existing) {
    const a = candidate.claim || '';
    const b = existing.claim || '';
    const sim = similarity(a, b);
    if (sim < RELATED_THRESHOLD) return null;

    // Structured conflict: same entity + attribute, different value. This is the
    // reliable case and the one that matters for thresholds and ceilings.
    const sa = candidate.structured;
    const sb = existing.structured;
    if (sa?.attribute && sb?.attribute && sa.attribute === sb.attribute &&
        sameEntity(sa.entity, sb.entity) && !sameValue(sa.value, sb.value)) {
      return {
        type: 'structured',
        attribute: sa.attribute,
        existingValue: sb.value,
        incomingValue: sa.value,
        detail: `${sa.attribute}: ${format(sb.value, sb.unit)} → ${format(sa.value, sa.unit)}`
      };
    }
    // Polarity conflict: same subject, opposite negation.
    if (sim >= 0.55 && Boolean(candidate.negated) !== Boolean(existing.negated)) {
      return { type: 'polarity', detail: 'same subject asserted with opposite polarity' };
    }
    // Numeric conflict without structure.
    const na = numbers(a);
    const nb = numbers(b);
    if (sim >= 0.5 && na.length && nb.length && !na.some((x) => nb.includes(x))) {
      return { type: 'numeric', detail: `numbers differ: ${nb.join(', ')} → ${na.join(', ')}` };
    }
    return null;
  }
}

// ---------------------------------------------------------------------------

function similarity(a, b) {
  // Blend lexical and vector-ish similarity; either alone is easy to fool.
  return 0.5 * jaccard(a, b) + 0.5 * cosine(a, b);
}

function specificity(claim) {
  const t = contentTokens(claim || '');
  const numbers = (String(claim).match(/\d/g) || []).length;
  const proper = (String(claim).match(/\b[A-Z][a-z]+/g) || []).length;
  return t.length + numbers * 2 + proper * 2;
}

function addsDetail(incoming, existing) {
  const a = new Set(contentTokens(incoming));
  const b = new Set(contentTokens(existing));
  const added = [...a].filter((t) => !b.has(t));
  const removed = [...b].filter((t) => !a.has(t));
  if (added.length >= 2 && removed.length <= 1) return added.slice(0, 8).join(' ');
  return null;
}

function sameEntity(a, b) {
  if (!a || !b) return true; // unknown entity — don't block a conflict on it
  return String(a).toLowerCase() === String(b).toLowerCase() ||
    jaccard(String(a), String(b)) > 0.6;
}

function sameValue(a, b) {
  if (a == null || b == null) return a == b;
  if (typeof a === 'number' && typeof b === 'number') return Math.abs(a - b) < 1e-9;
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

function numbers(s) {
  return (String(s).match(/\d[\d,]*(?:\.\d+)?/g) || []).map((n) => parseFloat(n.replace(/,/g, '')));
}

function format(v, unit) {
  if (v == null) return '—';
  if (unit === 'percent') return `${v}%`;
  if (unit === 'USD') return `$${Number(v).toLocaleString('en-US')}`;
  if (unit === 'GBP') return `£${Number(v).toLocaleString('en-GB')}`;
  if (unit === 'EUR') return `€${Number(v).toLocaleString('en-GB')}`;
  return String(v);
}

const round = (n) => Math.round(n * 100) / 100;
