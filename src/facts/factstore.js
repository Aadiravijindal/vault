/**
 * L5 — THE FACT STORE (§10).
 *
 * Append-only with versioning: "editing" a fact creates a new version. Golden
 * facts live in a separate, more restricted store with human-only write access —
 * there is no API path for an agent to create one.
 *
 * Nothing in the fact model is optional. A fact without provenance isn't a fact,
 * it's a rumour.
 */
import { newId } from '../util/id.js';
import { hashObject, sha256, signMessage, verifyMessage } from '../util/crypto.js';
import { now, iso, ago, duration, DAY, MONTH } from '../util/time.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { truncate, cosine, contentTokens } from '../util/text.js';

export const FACT_STATUS = ['live', 'held', 'rejected', 'superseded', 'expired', 'frozen', 'quarantined', 'erased'];

/** Revision kinds a lock does not block — the lock itself, and a human decision. */
const LOCK_EXEMPT_KINDS = new Set(['lock', 'human_revision', 'review', 'legal', 'erasure']);

/** Default TTL per time-sensitivity class (§11.6 "expire"). */
export const TTL = {
  permanent: null,
  months: '18mo',
  weeks: '8w',
  days: '7d',
  hours: '12h'
};

export class FactStore {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../storage/db.js').Collection} opts.golden separate restricted store
   * @param {import('../storage/db.js').Collection} opts.versions
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {import('../facts/entities.js').EntityResolver} [opts.entities]
   */
  constructor({ collection, golden, versions, ledger, entities = null, signingKey = null }) {
    this.col = collection;
    this.goldenCol = golden;
    this.versions = versions;
    this.ledger = ledger;
    this.entities = entities;
    this.signingKey = signingKey;

    this.col.index('byFolder', (f) => f.folder);
    this.col.index('byStatus', (f) => f.status);
    this.col.index('byEntity', (f) => (f.entities || []).map((e) => e.id || e.name));
    this.col.index('byAgent', (f) => f.capturedBy);
    this.col.index('byConversation', (f) => f.source?.conversationId);
    this.col.index('bySubject', (f) => (f.entities || []).filter((e) => e.type === 'person').map((e) => e.id || e.name));
    // Content tokens, so the reconciler can retrieve candidates by what a claim
    // says rather than by scanning the store. See findRelated.
    this.col.index('byToken', (f) => [...new Set(contentTokens(f.claim || ''))]);
    // Tags are an index, not a wall — so they get an index. A search by
    // `client:acme` still resolves each hit through the folder wall; this only
    // decides what is cheap to find, never what is allowed to be read.
    this.col.index('byTag', (f) => f.tags || []);
    this.goldenCol.index('byFolder', (f) => f.folder);
    this.goldenCol.index('byTag', (f) => f.tags || []);
  }

  // -- write ---------------------------------------------------------------

  /**
   * Write a fact that has passed the gate.
   * @param {object} candidate
   * @param {object} verdict from the gate
   * @param {object} ctx
   */
  write(candidate, verdict, ctx = {}) {
    const status = statusFor(verdict.outcome);
    // If the scan found anything, the FACT STORE gets the masked text — for
    // every outcome, not just MASK. A blocked credential must not survive as a
    // rejected fact anyone can read; §8.4 says blocked entirely, never
    // masked-and-stored. The verbatim original remains only in the sealed raw
    // archive, which is the record of what actually arrived.
    const claim = (verdict.piiFindings?.length && verdict.maskedClaim)
      ? verdict.maskedClaim
      : candidate.claim;

    const fact = {
      id: newId('fact'),
      // IDENTITY
      version: 1,
      createdAt: now(),
      updatedAt: now(),
      status,
      // CONTENT
      claim,
      structured: candidate.structured,
      originalStrings: candidate.structured?.originalString ?? candidate.claim,
      language: candidate.language,
      entities: candidate.entities || [],
      // PROVENANCE
      claimType: candidate.claimType,
      saidBy: candidate.saidBy,
      capturedBy: candidate.capturedBy ?? ctx.agentId,
      connectorMode: candidate.source?.connectorMode ?? ctx.connectorMode ?? null,
      channel: candidate.source?.channel ?? ctx.channel,
      channelTrust: verdict.channelTrust,
      sourceVerification: verdict.checks?.find((c) => c.check === 3) ?? null,
      source: candidate.source,
      model: candidate.source?.model ?? null,
      modelVersion: candidate.source?.modelVersion ?? ctx.modelVersion ?? null,
      extractionConfidence: candidate.confidence,
      // GOVERNANCE
      sensitivity: verdict.label,
      folder: verdict.folder ?? candidate.proposedFolder,
      namespace: (verdict.folder ?? candidate.proposedFolder ?? 'unfiled/').split('/')[0],
      businessOwner: ctx.businessOwner ?? null,
      technicalOwner: ctx.technicalOwner ?? null,
      region: ctx.region ?? null,
      rulesEvaluated: verdict.rulesEvaluated ?? [],
      gateOutcome: verdict.outcome.toUpperCase() + (verdict.fastPath ? ` (fast path, ${verdict.latencyMs}ms)` : ` (${verdict.latencyMs}ms)`),
      gateVerdict: compactVerdict(verdict),
      reviewedBy: null,
      reviewedAt: null,
      // Free-form index applied by the librarian and by humans. Never consulted
      // for access — see the byTag index above.
      tags: candidate.tags ?? [],
      // An administrator saying "this one is right, leave it alone". Weaker
      // than golden (no authority role, no four eyes) and weaker than a legal
      // hold (no disclosure consequence), but it stops every automated pass.
      locked: false,
      lockedBy: null,
      lockReason: null,
      organisedAt: null,
      legalHold: null,
      privileged: Boolean(ctx.privileged),
      regulatoryRecord: ctx.regulatoryRecord ?? null,
      consentBasis: verdict.consentBasis ?? null,
      // LIFECYCLE
      expiresAt: expiryFor(candidate),
      confidence: confidenceLabel(candidate.confidence),
      decaying: false,
      lastConfirmedAt: now(),
      reviewDueAt: null,
      supersedes: [],
      supersededBy: null,
      // USAGE
      readCount: 0,
      readBy: [],
      derivedFacts: [],
      influencedActions: [],
      // SECURITY
      instructionScore: verdict.instructionScore ?? 0,
      piiFindings: verdict.piiFindings ?? [],
      anomalyFlags: (verdict.temporal ?? []).map((t) => t.kind),
      corroboratingSources: 1,
      sources: [candidate.source],
      // INTEGRITY
      contentHash: null,
      ledgerPosition: null,
      prevHash: null,
      signature: null,
      golden: false
    };

    fact.contentHash = hashObject(integrityView(fact));
    const stored = this.col.insert(fact);

    const entry = this.ledger.append(eventFor(verdict.outcome), {
      subject: stored.id,
      actor: stored.capturedBy,
      claim: stored.claim,               // hashed by the ledger, never stored raw
      folder: stored.folder,
      sensitivity: stored.sensitivity,
      claimType: stored.claimType,
      channel: stored.channel,
      channelTrust: stored.channelTrust,
      conversationId: stored.source?.conversationId,
      outcome: verdict.outcome,
      instructionScore: stored.instructionScore,
      factContentHash: stored.contentHash,
      latencyMs: verdict.latencyMs
    });

    const withLedger = this.col.update(stored.id, {
      ledgerPosition: entry.seq,
      prevHash: entry.prevHash,
      signature: this.signingKey?.privateKeyPem ? signMessage(this.signingKey.privateKeyPem, stored.contentHash) : null
    });

    this.entities?.link(withLedger);
    this._snapshot(withLedger, 'created');
    return withLedger;
  }

  // -- read ----------------------------------------------------------------

  get(id) { return this.col.get(id) || this.goldenCol.get(id); }
  require(id) {
    const f = this.get(id);
    if (!f) throw notFound('fact', id);
    return f;
  }
  all() { return [...this.col.all(), ...this.goldenCol.all()]; }
  live() { return this.all().filter((f) => f.status === 'live'); }
  byFolder(folder) {
    return [...this.col.by('byFolder', folder), ...this.goldenCol.by('byFolder', folder)];
  }
  byEntity(entityKey) { return this.col.by('byEntity', entityKey); }
  byTag(tag) { return [...this.col.by('byTag', tag), ...this.goldenCol.by('byTag', tag)]; }
  byConversation(conversationId) { return this.col.by('byConversation', conversationId); }
  bySubject(subject) { return this.col.by('bySubject', subject); }
  held() { return this.col.find((f) => f.status === 'held'); }

  /**
   * Candidate-related facts, for the reconciler.
   *
   * Retrieval must be *complete* — a duplicate or a contradiction the gate does
   * not retrieve is a duplicate or contradiction the gate cannot act on — but it
   * must also not be a full scan, which is what the benchmark harness caught it
   * being. Two paths used to widen without bound: pulling every fact in the
   * candidate's folder, and, whenever fewer than three candidates turned up,
   * scanning every live fact in the store. On a large tenant the second one runs
   * on every write with a novel entity, which is most of them.
   *
   * The content-token index replaces both. Any two claims similar enough to
   * reconcile share at least one content token — cosine similarity over term
   * vectors is zero otherwise — so retrieving by token is not a narrowing of
   * what the reconciler sees, it is the same set reached without reading rows
   * that could never have matched.
   */
  findRelated(candidate, { limit = 12 } = {}) {
    const entityKeys = (candidate.entities || []).map((e) => e.id || e.name);
    const pool = new Set();
    for (const k of entityKeys) for (const f of this.col.by('byEntity', k)) pool.add(f);
    // Golden facts are few by design and authoritative, so they are always in
    // scope: a candidate that contradicts one must be caught even if it shares
    // no vocabulary with it.
    for (const g of this.goldenCol.all()) pool.add(g);
    for (const f of this._byContentTokens(candidate.claim)) pool.add(f);

    return [...pool]
      .filter((f) => f.status === 'live' || f.golden)
      .map((f) => ({ f, s: cosine(f.claim, candidate.claim) }))
      .filter((x) => x.s > 0.12)
      .sort((a, b) => b.s - a.s)
      .slice(0, limit)
      .map((x) => x.f);
  }

  /**
   * Facts sharing at least one content token with `text`.
   *
   * Very common tokens are skipped: a token present in most of the store
   * discriminates nothing and reading its whole posting list is the full scan
   * again by another name. Rarer tokens in the same claim still retrieve
   * anything genuinely similar.
   */
  _byContentTokens(text) {
    const tokens = new Set(contentTokens(text || ''));
    if (!tokens.size) return [];
    const total = this.col.size ?? this.col.all().length;
    const ceiling = Math.max(64, Math.floor(total * 0.25));
    const out = new Set();
    for (const t of tokens) {
      const posting = this.col.by('byToken', t);
      if (posting.length > ceiling) continue;
      for (const f of posting) out.add(f);
    }
    return out;
  }

  // -- versioning ----------------------------------------------------------

  /** Append a new version. The prior version is retained and diffable. */
  revise(id, patch, { actor, reason, kind = 'revision' }) {
    const prev = this.require(id);
    if (prev.golden) throw forbidden('golden facts are revised through the attestation workflow, not this path', { id });
    if (prev.legalHold) throw new VaultError('legal_hold', 'fact is frozen by a legal hold — hygiene and revision cannot touch it', { id, hold: prev.legalHold });
    // A lock stops automated passes and nothing else. Humans still revise a
    // locked fact deliberately — the lock says "don't let a model tidy this
    // up", not "this is now unchangeable", which is what a legal hold says.
    // Enforced here as well as in the librarian, because one check is one bug
    // away from not being a check.
    if (prev.locked && !LOCK_EXEMPT_KINDS.has(kind)) {
      throw forbidden(
        `fact is locked by ${prev.lockedBy ?? 'an administrator'} — no automated pass changes it (${prev.lockReason ?? 'no reason recorded'})`,
        { id, code: 'fact_locked', lockedBy: prev.lockedBy }
      );
    }
    const next = {
      ...prev, ...patch,
      version: prev.version + 1,
      updatedAt: now(),
      lastConfirmedAt: patch.lastConfirmedAt ?? prev.lastConfirmedAt
    };
    next.contentHash = hashObject(integrityView(next));
    const stored = this.col.update(id, next);
    const entry = this.ledger.append('fact.version', {
      subject: id, actor, reason, kind, version: stored.version,
      factContentHash: stored.contentHash, changed: Object.keys(patch)
    });
    this.col.update(id, { ledgerPosition: entry.seq, prevHash: entry.prevHash });
    this._snapshot(stored, kind, { actor, reason });
    return this.col.get(id);
  }

  _snapshot(fact, change, meta = {}) {
    this.versions.insert({
      id: `${fact.id}:v${fact.version}`,
      factId: fact.id,
      version: fact.version,
      at: now(),
      change,
      ...meta,
      snapshot: structuredClone({ ...fact, readBy: undefined })
    });
  }

  history(factId) {
    return this.versions.find((v) => v.factId === factId).sort((a, b) => a.version - b.version);
  }

  /** Diff two versions, for the trace screen. */
  diff(factId, fromVersion, toVersion) {
    const a = this.versions.get(`${factId}:v${fromVersion}`)?.snapshot;
    const b = this.versions.get(`${factId}:v${toVersion}`)?.snapshot;
    if (!a || !b) throw notFound('fact version', `${factId}:v${fromVersion}/${toVersion}`);
    const changes = {};
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of keys) {
      if (['readBy', 'readCount', 'updatedAt', 'contentHash', 'ledgerPosition', 'prevHash'].includes(k)) continue;
      if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) changes[k] = { from: a[k], to: b[k] };
    }
    return { factId, from: fromVersion, to: toVersion, changes };
  }

  // -- reconciliation outcomes --------------------------------------------

  /** Duplicate: merge. Both sources kept. Confidence rises. */
  merge(intoId, candidate, { actor = 'hygiene', reason = 'semantic duplicate' } = {}) {
    const target = this.require(intoId);
    const sources = [...(target.sources || []), candidate.source];
    return this.revise(intoId, {
      sources,
      corroboratingSources: sources.length,
      confidence: confidenceLabel(Math.min(1, (numericConfidence(target.confidence) + 0.05))),
      lastConfirmedAt: now()
    }, { actor, reason, kind: 'merge' });
  }

  /** Refinement: new detail without conflict. */
  refine(intoId, candidate, { actor = 'system', reason = 'refinement' } = {}) {
    const target = this.require(intoId);
    return this.revise(intoId, {
      claim: candidate.claim,
      structured: candidate.structured ?? target.structured,
      sources: [...(target.sources || []), candidate.source],
      corroboratingSources: (target.corroboratingSources || 1) + 1,
      lastConfirmedAt: now()
    }, { actor, reason, kind: 'refinement' });
  }

  /** Contradiction resolved in favour of the incoming fact. Loser → history. */
  supersede(oldId, newFact, { actor, reason, decidedBy }) {
    const old = this.require(oldId);
    this.revise(oldId, { status: 'superseded', supersededBy: newFact.id }, { actor, reason, kind: 'superseded' });
    const updated = this.col.update(newFact.id, { supersedes: [...(newFact.supersedes || []), oldId] });
    this.ledger.append('fact.superseded', { subject: oldId, actor, reason, by: newFact.id, decidedBy });
    return { superseded: oldId, by: newFact.id, decidedBy, note: 'the losing fact moved to history — it is never deleted' };
  }

  // -- golden facts (§9.5) -------------------------------------------------

  /**
   * Human-only creation. Named authority required. Four-eyes above a
   * sensitivity threshold. Cryptographically attested.
   *
   * @param {object} spec
   * @param {{actor:string, actorKind:'human', authorityRole:string, secondApprover?:string}} auth
   */
  createGolden(spec, auth) {
    if (!auth || auth.actorKind !== 'human') {
      throw forbidden('no agent can create a golden fact — ever. There is no API path for agents.', { code: 'golden_human_only' });
    }
    if (!auth.actor || !auth.authorityRole) {
      throw forbidden('a golden fact requires a named human with a defined authority role, tied to the identity provider');
    }
    const sensitivity = spec.sensitivity || 'internal';
    const needsFourEyes = ['confidential', 'secret'].includes(sensitivity);
    if (needsFourEyes && (!auth.secondApprover || auth.secondApprover === auth.actor)) {
      throw forbidden('four-eyes: a second, distinct named approver is required for this sensitivity', { sensitivity });
    }

    const fact = {
      id: newId('golden'),
      version: 1,
      createdAt: now(),
      updatedAt: now(),
      status: 'live',
      golden: true,
      claim: spec.claim,
      structured: spec.structured ?? null,
      originalStrings: spec.claim,
      language: spec.language ?? 'en',
      entities: spec.entities ?? [],
      claimType: 'approved',
      saidBy: { name: auth.actor, kind: 'employee', authority: auth.authorityRole },
      capturedBy: null,
      channel: 'employee_session',
      channelTrust: 'trusted',
      source: { conversationId: null, excerpt: spec.claim, channel: 'employee_session' },
      extractionConfidence: 1,
      sensitivity,
      folder: spec.folder,
      namespace: String(spec.folder || 'company/').split('/')[0],
      businessOwner: spec.businessOwner ?? auth.actor,
      technicalOwner: spec.technicalOwner ?? null,
      region: spec.region ?? null,
      approvedBy: auth.actor,
      approverRole: auth.authorityRole,
      secondApprover: auth.secondApprover ?? null,
      gateOutcome: 'GOLDEN (human-authored, gate not applicable to human attestation)',
      consentBasis: spec.consentBasis ?? null,
      // Golden facts have a review date; stale ones prompt re-attestation, they
      // do not silently rot (§9.5).
      expiresAt: null,
      reviewDueAt: now() + duration(spec.reviewEvery || '12mo'),
      confidence: 'golden',
      decaying: false,
      lastConfirmedAt: now(),
      supersedes: spec.supersedes ?? [],
      supersededBy: null,
      readCount: 0, readBy: [], derivedFacts: [], influencedActions: [],
      instructionScore: 0, piiFindings: [], anomalyFlags: [], corroboratingSources: 1,
      sources: [{ kind: 'human_attestation', by: auth.actor }],
      attestations: [{ by: auth.actor, role: auth.authorityRole, at: now(), second: auth.secondApprover ?? null }],
      contentHash: null, ledgerPosition: null, prevHash: null, signature: null,
      legalHold: null, privileged: Boolean(spec.privileged), regulatoryRecord: spec.regulatoryRecord ?? null
    };
    fact.contentHash = hashObject(integrityView(fact));
    if (this.signingKey?.privateKeyPem) {
      fact.signature = signMessage(this.signingKey.privateKeyPem, fact.contentHash);
    }
    const stored = this.goldenCol.insert(fact);
    const entry = this.ledger.append('golden.created', {
      subject: stored.id, actor: auth.actor, authorityRole: auth.authorityRole,
      secondApprover: auth.secondApprover ?? null, folder: stored.folder,
      sensitivity, claim: stored.claim, factContentHash: stored.contentHash, signed: Boolean(stored.signature)
    });
    this.goldenCol.update(stored.id, { ledgerPosition: entry.seq, prevHash: entry.prevHash });
    this.entities?.link(stored);
    this._snapshot(stored, 'golden_created', { actor: auth.actor });
    return this.goldenCol.get(stored.id);
  }

  goldenFacts() { return this.goldenCol.all().filter((g) => g.status === 'live'); }

  verifyGolden(id) {
    const g = this.goldenCol.get(id);
    if (!g) throw notFound('golden fact', id);
    const recomputed = hashObject(integrityView(g));
    return {
      id,
      contentHashOk: recomputed === g.contentHash,
      signatureOk: g.signature && this.signingKey?.publicKeyPem
        ? verifyMessage(this.signingKey.publicKeyPem, g.contentHash, g.signature)
        : null,
      approvedBy: g.approvedBy,
      attestations: g.attestations?.length ?? 0
    };
  }

  /** Re-attestation workflow (§9.5). */
  reattest(id, { actor, authorityRole, confirms = true, newClaim = null, secondApprover = null, reviewEvery = '12mo' }) {
    const g = this.goldenCol.get(id);
    if (!g) throw notFound('golden fact', id);
    if (!actor || !authorityRole) throw forbidden('re-attestation requires a named human with an authority role');
    const needsFourEyes = ['confidential', 'secret'].includes(g.sensitivity);
    if (newClaim && needsFourEyes && (!secondApprover || secondApprover === actor)) {
      throw forbidden('changing a confidential or secret golden fact requires a second distinct approver');
    }
    const patch = {
      claim: newClaim ?? g.claim,
      version: g.version + 1,
      updatedAt: now(),
      lastConfirmedAt: now(),
      reviewDueAt: now() + duration(reviewEvery),
      attestations: [...(g.attestations || []), { by: actor, role: authorityRole, at: now(), confirms, changed: Boolean(newClaim), second: secondApprover }]
    };
    patch.contentHash = hashObject(integrityView({ ...g, ...patch }));
    if (this.signingKey?.privateKeyPem) patch.signature = signMessage(this.signingKey.privateKeyPem, patch.contentHash);
    const updated = this.goldenCol.update(id, patch);
    this.ledger.append('golden.reattested', {
      subject: id, actor, authorityRole, confirms, changed: Boolean(newClaim),
      version: updated.version, factContentHash: updated.contentHash
    });
    this._snapshot(updated, 'golden_reattested', { actor });
    return updated;
  }

  /** Golden facts due for review — they prompt, they don't rot. */
  goldenDue({ withinDays = 14 } = {}) {
    const cutoff = now() + withinDays * DAY;
    return this.goldenFacts()
      .filter((g) => g.reviewDueAt && g.reviewDueAt <= cutoff)
      .map((g) => ({
        id: g.id, claim: truncate(g.claim, 100), owner: g.businessOwner,
        reviewDue: iso(g.reviewDueAt),
        overdue: g.reviewDueAt < now(),
        message: g.reviewDueAt < now()
          ? `This golden fact's review date passed ${ago(g.reviewDueAt)} ago — confirm or update`
          : `This golden fact expires in ${Math.ceil((g.reviewDueAt - now()) / DAY)} days — confirm or update`
      }));
  }

  /**
   * Contradiction radar: any fact quietly conflicting with a golden fact is
   * raised, even if it never tried to overwrite it (§9.5).
   */
  contradictionRadar({ threshold = 0.45 } = {}) {
    const out = [];
    const goldens = this.goldenFacts();
    for (const f of this.live()) {
      if (f.golden) continue;
      for (const g of goldens) {
        const sim = cosine(f.claim, g.claim);
        if (sim < threshold) continue;
        const fn = numbersOf(f.claim);
        const gn = numbersOf(g.claim);
        const numericConflict = fn.length && gn.length && !fn.some((x) => gn.includes(x));
        const polarityConflict = /\bnot|never|no\b/i.test(f.claim) !== /\bnot|never|no\b/i.test(g.claim);
        if (numericConflict || (sim > 0.7 && polarityConflict)) {
          out.push({
            factId: f.id, goldenId: g.id, similarity: Math.round(sim * 100) / 100,
            fact: truncate(f.claim, 90), golden: truncate(g.claim, 90),
            why: numericConflict ? `values differ (${gn.join(', ')} vs ${fn.join(', ')})` : 'opposite polarity',
            severity: 'medium'
          });
        }
      }
    }
    return out;
  }

  /**
   * Blast-radius report: change a golden fact → see every fact and agent
   * affected BEFORE you commit (§9.5).
   */
  goldenBlastRadius(id) {
    const g = this.goldenCol.get(id);
    if (!g) throw notFound('golden fact', id);
    const related = this.live().filter((f) => !f.golden && cosine(f.claim, g.claim) > 0.35);
    const agents = new Set(related.map((f) => f.capturedBy).filter(Boolean));
    const readers = new Set();
    for (const f of related) for (const r of f.readBy || []) readers.add(r.agentId);
    const derived = related.flatMap((f) => f.derivedFacts || []);
    return {
      goldenId: id,
      claim: truncate(g.claim, 120),
      affectedFacts: related.map((f) => ({ id: f.id, claim: truncate(f.claim, 80), folder: f.folder })),
      affectedFactCount: related.length,
      derivedFacts: derived,
      writingAgents: [...agents],
      readingAgents: [...readers],
      folders: [...new Set(related.map((f) => f.folder))],
      warning: related.length
        ? `changing this golden fact affects ${related.length} facts and ${readers.size} agents that have read them`
        : 'no dependent facts found'
    };
  }

  // -- status transitions --------------------------------------------------

  setStatus(id, status, { actor, reason }) {
    if (!FACT_STATUS.includes(status)) throw new VaultError('validation', `status must be one of ${FACT_STATUS.join(', ')}`);
    const f = this.require(id);
    if (f.legalHold && status !== 'frozen') {
      throw new VaultError('legal_hold', 'fact is under legal hold — its status cannot be changed', { id, hold: f.legalHold });
    }
    const col = f.golden ? this.goldenCol : this.col;
    // Status is part of the integrity view, so a status change re-seals the
    // fact. Otherwise every expiry or rejection would look like tampering.
    const next = { ...f, status, updatedAt: now(), statusReason: reason, statusChangedBy: actor };
    const updated = col.update(id, { ...next, contentHash: hashObject(integrityView(next)) });
    this.ledger.append(status === 'expired' ? 'fact.expired' : 'fact.version', {
      subject: id, actor, reason, status, factContentHash: updated.contentHash
    });
    return updated;
  }

  /**
   * Freeze / release a fact under a legal hold. Status is part of the integrity
   * view, so both re-seal. A hold must never make a fact look tampered with.
   */
  freeze(id, hold) {
    const f = this.require(id);
    const col = f.golden ? this.goldenCol : this.col;
    const next = { ...f, legalHold: hold, status: f.status === 'live' ? 'frozen' : f.status, updatedAt: now() };
    return col.update(id, { ...next, contentHash: hashObject(integrityView(next)) });
  }

  release(id) {
    const f = this.get(id);
    if (!f) return null;
    const col = f.golden ? this.goldenCol : this.col;
    const next = { ...f, legalHold: null, status: f.status === 'frozen' ? 'live' : f.status, updatedAt: now() };
    return col.update(id, { ...next, contentHash: hashObject(integrityView(next)) });
  }

  /**
   * Move a fact into the quarantine namespace, which no agent can read.
   * The folder is part of the integrity view, so this re-seals rather than
   * quietly editing — otherwise quarantining would look like tampering.
   */
  quarantine(id, { actor, reason }) {
    const f = this.require(id);
    const col = f.golden ? this.goldenCol : this.col;
    const next = { ...f, folder: '_quarantine/', namespace: '_quarantine', status: 'quarantined', updatedAt: now(), statusReason: reason };
    const updated = col.update(id, { ...next, contentHash: hashObject(integrityView(next)) });
    this.ledger.append('fact.quarantined', { subject: id, actor, reason, factContentHash: updated.contentHash });
    return updated;
  }

  /** Record a read (§10 USAGE, §11.4 step 10). */
  recordRead(id, { agentId, purpose, fields = null, at = now() }) {
    const f = this.get(id);
    if (!f) return null;
    const col = f.golden ? this.goldenCol : this.col;
    const readBy = [...(f.readBy || []), { agentId, purpose, at, fields }].slice(-500);
    return col.update(id, { readCount: (f.readCount || 0) + 1, readBy });
  }

  /**
   * Store a rolling summary as a real, readable fact (§11.6).
   *
   * It inherits the strictest label and wall of its inputs, which the hygiene
   * engine computed — writing it through the normal fact shape is what makes
   * the read path apply those checks to it. A summary that skipped them would
   * be a cross-wall channel dressed up as a convenience feature.
   */
  writeSummary(summary, { actor = 'hygiene' } = {}) {
    const fact = {
      id: summary.id,
      version: 1,
      createdAt: summary.createdAt ?? now(),
      updatedAt: now(),
      status: 'live',
      kind: 'rolling_summary',
      claim: summary.claim,
      structured: null,
      originalStrings: summary.claim,
      language: 'en',
      entities: [],
      claimType: 'guessed',            // derived, never authoritative
      saidBy: { name: 'vault-hygiene', kind: 'system' },
      capturedBy: null,
      channel: 'derived',
      channelTrust: 'trusted',
      source: { kind: 'derived', inputs: summary.inputs },
      extractionConfidence: 1,
      // The inheritance the leak depends on.
      sensitivity: summary.sensitivity,
      folder: summary.folder,
      namespace: String(summary.folder || 'company/').split('/')[0],
      wall: summary.wall ?? null,
      businessOwner: null, technicalOwner: null, region: null,
      gateOutcome: 'DERIVED (summary of already-gated facts)',
      consentBasis: null,
      expiresAt: null, reviewDueAt: null,
      confidence: 'medium', decaying: false, lastConfirmedAt: now(),
      supersedes: [], supersededBy: null,
      readCount: 0, readBy: [], derivedFacts: [], influencedActions: [],
      instructionScore: 0, piiFindings: [], anomalyFlags: [],
      corroboratingSources: summary.inputs.length,
      sources: [{ kind: 'derived', inputs: summary.inputs.length }],
      inputs: summary.inputs,
      note: summary.note,
      contentHash: null, ledgerPosition: null, prevHash: null, signature: null,
      legalHold: null, privileged: false, regulatoryRecord: null
    };
    fact.contentHash = hashObject(integrityView(fact));
    const stored = this.col.insert(fact);
    const entry = this.ledger.append('fact.written', {
      subject: stored.id, actor, folder: stored.folder, outcome: 'derived',
      claimType: 'guessed', sensitivity: stored.sensitivity, inputs: summary.inputs.length,
      claim: stored.claim
    });
    this.col.update(stored.id, { ledgerPosition: entry.seq, prevHash: entry.prevHash });
    return this.col.get(stored.id);
  }

  linkDerived(sourceIds, derivedId) {
    for (const id of sourceIds) {
      const f = this.get(id);
      if (!f) continue;
      const col = f.golden ? this.goldenCol : this.col;
      col.update(id, { derivedFacts: [...new Set([...(f.derivedFacts || []), derivedId])] });
    }
  }

  recordInfluence(factIds, action) {
    for (const id of factIds) {
      const f = this.get(id);
      if (!f) continue;
      const col = f.golden ? this.goldenCol : this.col;
      col.update(id, { influencedActions: [...(f.influencedActions || []), { ...action, at: now() }] });
    }
  }

  /** Integrity check across the whole corpus. */
  verifyIntegrity({ limit = Infinity } = {}) {
    const problems = [];
    let checked = 0;
    for (const f of this.all()) {
      if (checked >= limit) break;
      checked++;
      const recomputed = hashObject(integrityView(f));
      if (recomputed !== f.contentHash) {
        problems.push({ factId: f.id, problem: 'content_hash_mismatch', version: f.version });
      }
    }
    return { ok: problems.length === 0, checked, problems };
  }

  stats() {
    const all = this.all();
    const byStatus = {};
    for (const s of FACT_STATUS) byStatus[s] = all.filter((f) => f.status === s).length;
    return {
      total: all.length,
      golden: this.goldenCol.size,
      byStatus,
      withFullProvenance: all.filter(hasFullProvenance).length,
      folders: new Set(all.map((f) => f.folder)).size,
      reads: all.reduce((a, f) => a + (f.readCount || 0), 0)
    };
  }
}

// ---------------------------------------------------------------------------

function statusFor(outcome) {
  return {
    pass: 'live', mask: 'live', hold: 'held', block: 'rejected',
    escalate: 'held', quarantine: 'quarantined', 'require-4-eyes': 'held'
  }[outcome] || 'held';
}

function eventFor(outcome) {
  return {
    pass: 'fact.written', mask: 'fact.masked', hold: 'fact.held', block: 'fact.blocked',
    escalate: 'fact.escalated', quarantine: 'fact.quarantined', 'require-4-eyes': 'fact.held'
  }[outcome] || 'fact.held';
}

function expiryFor(candidate) {
  const ttl = TTL[candidate.timeSensitivity ?? 'months'];
  return ttl == null ? null : now() + duration(ttl);
}

function confidenceLabel(n) {
  const v = typeof n === 'number' ? n : numericConfidence(n);
  return v >= 0.85 ? 'high' : v >= 0.6 ? 'medium' : 'low';
}
function numericConfidence(label) {
  return { golden: 1, high: 0.9, medium: 0.7, low: 0.45 }[label] ?? 0.7;
}

/** The fields that the content hash covers. Usage counters are excluded so a
 *  read never changes a fact's integrity hash. */
function integrityView(f) {
  return {
    id: f.id, version: f.version, claim: f.claim, structured: f.structured,
    claimType: f.claimType, saidBy: f.saidBy, source: f.source,
    sensitivity: f.sensitivity, folder: f.folder, status: f.status,
    createdAt: f.createdAt, golden: Boolean(f.golden), approvedBy: f.approvedBy ?? null
  };
}

function compactVerdict(v) {
  return {
    outcome: v.outcome,
    reasons: v.reasons,
    checks: (v.checks || []).map((c) => ({ check: c.check, name: c.name, result: c.result })),
    latencyMs: v.latencyMs,
    fastPath: v.fastPath
  };
}

function hasFullProvenance(f) {
  return Boolean(f.claimType && f.saidBy && f.source?.conversationId !== undefined && f.channel && f.sensitivity && f.folder && f.contentHash);
}

function numbersOf(s) {
  return (String(s).match(/\d[\d,]*(?:\.\d+)?/g) || []).map((n) => parseFloat(n.replace(/,/g, '')));
}
