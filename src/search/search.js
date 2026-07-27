/**
 * 🟢 VAULT SEARCH — our own enterprise search (§11.5).
 *
 * Hybrid retrieval: BM25 lexical + vector-ish semantic + entity + graph +
 * structured filters. Permissions are checked AT QUERY TIME against walls,
 * labels, clearance and region — not baked into the index, because an index
 * built yesterday doesn't know about the wall you moved this morning.
 *
 * Every result carries provenance. Natural-language answers carry mandatory
 * citations — never an unsourced assertion.
 */
import { newId } from '../util/id.js';
import { tokenize, contentTokens, cosine, truncate } from '../util/text.js';
import { now, iso, ago, DAY, MONTH } from '../util/time.js';
import { VaultError } from '../util/errors.js';

export class SearchEngine {
  /**
   * @param {object} opts
   * @param {import('../facts/factstore.js').FactStore} opts.facts
   * @param {import('../facts/entities.js').EntityResolver} [opts.entities]
   * @param {import('../archive/archive.js').Archive} [opts.archive]
   * @param {import('../modules/modules.js').ModuleRegistry} [opts.modules]
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   */
  constructor({ facts, entities = null, archive = null, modules = null, ledger, k1 = 1.4, b = 0.72 }) {
    this.facts = facts;
    this.entities = entities;
    this.archive = archive;
    this.modules = modules;
    this.ledger = ledger;
    this.k1 = k1;
    this.b = b;
    /** @type {Map<string, Map<string, number>>} token → factId → tf */
    this.postings = new Map();
    /** @type {Map<string, number>} factId → doc length */
    this.docLengths = new Map();
    this.totalLength = 0;
    this.indexed = new Set();
    /** External sources indexed with their own ACLs respected. */
    this.externalDocs = new Map();
    this.savedSearches = new Map();
    this.auditLog = [];
    this.version = 0;
  }

  // -- indexing ------------------------------------------------------------

  /** Continuous, on write — not nightly (§11.1). */
  index(fact) {
    if (this.indexed.has(fact.id)) this._remove(fact.id);
    const tokens = contentTokens(`${fact.claim} ${fact.structured?.originalString ?? ''} ${(fact.entities || []).map((e) => e.name).join(' ')}`);
    const tf = new Map();
    for (const t of tokens) tf.set(t, (tf.get(t) || 0) + 1);
    for (const [t, n] of tf) {
      let p = this.postings.get(t);
      if (!p) this.postings.set(t, (p = new Map()));
      p.set(fact.id, n);
    }
    this.docLengths.set(fact.id, tokens.length);
    this.totalLength += tokens.length;
    this.indexed.add(fact.id);
    this.version++;
    this.modules?.dispatch('search', 'index', { id: fact.id, claim: fact.claim, folder: fact.folder, sensitivity: fact.sensitivity });
    return this;
  }

  _remove(id) {
    for (const [t, p] of this.postings) {
      if (p.delete(id) && !p.size) this.postings.delete(t);
    }
    this.totalLength -= this.docLengths.get(id) || 0;
    this.docLengths.delete(id);
    this.indexed.delete(id);
  }

  reindexAll() {
    this.postings.clear();
    this.docLengths.clear();
    this.indexed.clear();
    this.totalLength = 0;
    for (const f of this.facts.all()) this.index(f);
    return { indexed: this.indexed.size };
  }

  /**
   * Index a connected source (Drive, SharePoint, Confluence, Notion, Jira,
   * Slack, Salesforce, Zendesk, GitHub, file shares) with SOURCE ACLs respected.
   */
  indexExternal(doc) {
    if (!doc.id || !doc.text) throw new VaultError('validation', 'external documents need an id and text');
    this.externalDocs.set(doc.id, {
      ...doc,
      tokens: new Set(contentTokens(doc.text)),
      acl: doc.acl || [],           // the SOURCE system's ACL, honoured at query time
      indexedAt: now()
    });
    return { id: doc.id, indexed: true };
  }

  // -- query ---------------------------------------------------------------

  /**
   * @param {string} query
   * @param {object} opts
   * @returns {{results:object[], withheld:number, answer?:object}}
   */
  search(query, {
    actor = { id: 'unknown', kind: 'human' },
    clearance = 'internal',
    canRead = () => true,             // wall check, injected by the read path
    folder = null,
    entity = null,
    from = null,
    to = null,
    asOf = null,                      // point-in-time search
    claimTypes = null,
    includeArchive = false,
    includeExternal = true,
    limit = 20,
    purpose = 'search',
    naturalLanguage = false
  } = {}) {
    const started = Date.now();
    const terms = contentTokens(query);
    const N = Math.max(this.indexed.size, 1);
    const avgdl = this.totalLength / N || 1;

    // -- lexical (BM25) ----------------------------------------------------
    const lexical = new Map();
    for (const t of terms) {
      const p = this.postings.get(t);
      if (!p) continue;
      const idf = Math.log(1 + (N - p.size + 0.5) / (p.size + 0.5));
      for (const [id, tf] of p) {
        const dl = this.docLengths.get(id) || avgdl;
        const score = idf * ((tf * (this.k1 + 1)) / (tf + this.k1 * (1 - this.b + this.b * (dl / avgdl))));
        lexical.set(id, (lexical.get(id) || 0) + score);
      }
    }

    // -- candidate pool ----------------------------------------------------
    let pool = new Set(lexical.keys());
    if (entity && this.entities) {
      const resolved = this.entities.resolve(entity);
      const key = resolved.entity?.id || entity;
      for (const f of this.facts.byEntity(key)) pool.add(f.id);
      // graph traversal: one hop out
      if (resolved.entity) {
        for (const edge of this.entities.graph({ rootId: resolved.entity.id, depth: 1 }).edges) {
          const other = edge.from === resolved.entity.id ? edge.to : edge.from;
          for (const f of this.facts.byEntity(other)) pool.add(f.id);
        }
      }
    }
    if (folder) for (const f of this.facts.byFolder(folder)) pool.add(f.id);
    if (!pool.size && !terms.length) for (const f of this.facts.live()) pool.add(f.id);

    // -- score, filter, rank ----------------------------------------------
    const maxLexical = Math.max(1e-9, ...lexical.values());
    const scored = [];
    let withheld = 0;
    const withheldReasons = new Map();

    for (const id of pool) {
      const fact = this.facts.get(id);
      if (!fact) continue;

      // Point-in-time: what did we believe about X in March?
      const pit = asOf ? this._asOf(fact, asOf) : fact;
      if (!pit) continue;

      // Status filter — drop expired, held, rejected, quarantined, erased.
      if (!['live'].includes(pit.status) && !pit.golden) { continue; }
      if (pit.expiresAt && pit.expiresAt < (asOf || now())) { continue; }
      if (from && pit.createdAt < from) continue;
      if (to && pit.createdAt > to) continue;
      if (claimTypes && !claimTypes.includes(pit.claimType)) continue;

      // Permission checks at QUERY time.
      const allowed = canRead(pit);
      if (!allowed.allowed) {
        withheld++;
        withheldReasons.set(allowed.reason, (withheldReasons.get(allowed.reason) || 0) + 1);
        continue;
      }
      if (rank(pit.sensitivity) > rank(clearance)) {
        withheld++;
        withheldReasons.set('above your clearance', (withheldReasons.get('above your clearance') || 0) + 1);
        continue;
      }

      const lex = (lexical.get(id) || 0) / maxLexical;
      const sem = cosine(query, pit.claim);
      const entityBoost = entity && (pit.entities || []).some((e) => String(e.name).toLowerCase().includes(String(entity).toLowerCase())) ? 0.25 : 0;
      const goldenBoost = pit.golden ? 1.0 : 0;
      const authorityBoost = { approved: 0.5, verified: 0.35, stated: 0.2, heard: 0.05, guessed: -0.15 }[pit.claimType] ?? 0;
      const corroboration = Math.min(0.2, ((pit.corroboratingSources || 1) - 1) * 0.1);
      const freshness = this._freshness(pit, asOf);
      const specificity = Math.min(0.15, contentTokens(pit.claim).length / 100);

      const score = 0.42 * lex + 0.28 * sem + entityBoost + goldenBoost + authorityBoost + corroboration + freshness.boost + specificity;

      scored.push({ fact: pit, score, lex, sem, freshness });
    }

    // -- external documents (source ACLs respected) ------------------------
    const externalResults = [];
    if (includeExternal) {
      for (const doc of this.externalDocs.values()) {
        if (doc.acl.length && !doc.acl.includes(actor.id) && !doc.acl.some((a) => (actor.groups || []).includes(a))) continue;
        const overlap = terms.filter((t) => doc.tokens.has(t)).length;
        if (!overlap) continue;
        externalResults.push({
          kind: 'document',
          id: doc.id, title: doc.title || doc.id, source: doc.source || 'external',
          score: 0.3 * (overlap / Math.max(terms.length, 1)) + 0.2 * cosine(query, doc.text),
          snippet: truncate(doc.text, 240),
          url: doc.url || null,
          indexedAt: iso(doc.indexedAt)
        });
      }
    }

    scored.sort((a, b) => b.score - a.score);
    const top = scored.slice(0, limit);

    const results = top.map((s) => this.present(s.fact, { score: s.score, freshness: s.freshness }));
    const merged = [...results, ...externalResults.sort((a, b) => b.score - a.score).slice(0, Math.max(0, limit - results.length))];

    // -- archive search ----------------------------------------------------
    let archiveHits = [];
    if (includeArchive && this.archive) {
      archiveHits = this.archive.search(query, { limit: 10, from, to });
    }

    // -- federated fallback: query their search and blend -------------------
    const federated = this.modules?.dispatch('search', 'query', { query, actor, limit });

    const tookMs = Date.now() - started;
    const audit = {
      id: newId('session'), at: now(), actor: actor.id, query, purpose,
      returned: merged.length, withheld, tookMs
    };
    this.auditLog.push(audit);
    this.ledger.append('fact.read', {
      actor: actor.id, subject: 'search', query, returned: merged.length, withheld, purpose, tookMs
    });

    const out = {
      query,
      results: merged,
      withheld,
      withheldReasons: [...withheldReasons.entries()].map(([reason, count]) => ({ reason, count })),
      archive: archiveHits,
      federated: federated ?? null,
      tookMs,
      asOf: asOf ? iso(asOf) : null,
      indexVersion: this.version
    };
    if (naturalLanguage) out.answer = this.answer(query, results);
    return out;
  }

  /** Provenance on every result (§11.5). */
  present(fact, { score = 0, freshness = null } = {}) {
    return {
      kind: 'fact',
      id: fact.id,
      claim: fact.claim,
      claimType: fact.claimType,
      badge: BADGES[fact.claimType] || '·',
      golden: Boolean(fact.golden),
      confidence: fact.confidence,
      sensitivity: fact.sensitivity,
      folder: fact.folder,
      entities: (fact.entities || []).map((e) => e.name),
      provenance: {
        saidBy: fact.saidBy?.name ?? null,
        saidByKind: fact.saidBy?.kind ?? null,
        role: fact.saidBy?.role ?? fact.saidBy?.authority ?? null,
        channel: fact.channel,
        channelTrust: fact.channelTrust,
        capturedBy: fact.capturedBy,
        at: iso(fact.createdAt),
        age: ago(fact.createdAt),
        sources: (fact.sources || []).length,
        approvedBy: fact.approvedBy ?? null
      },
      citation: fact.source?.conversationId
        ? { conversationId: fact.source.conversationId, offset: fact.source.start ?? 0, excerpt: fact.source.excerpt }
        : (fact.golden ? { attestation: fact.approvedBy, at: iso(fact.createdAt) } : null),
      stale: freshness?.stale ?? false,
      staleReason: freshness?.reason ?? null,
      warning: fact.claimType === 'guessed' ? 'DO NOT STATE AS FACT — inferred by an AI, nobody said it' : null,
      score: Math.round(score * 1000) / 1000,
      version: fact.version,
      ledgerPosition: fact.ledgerPosition
    };
  }

  /**
   * Natural-language answer WITH MANDATORY CITATIONS. If there are no citable
   * facts, it says so rather than composing something plausible.
   */
  answer(query, results) {
    if (!results.length) {
      return {
        text: "I don't have any facts that answer that. Nothing is being asserted without a source.",
        citations: [],
        confidence: 'none'
      };
    }
    const golden = results.filter((r) => r.golden);
    const verified = results.filter((r) => r.claimType === 'verified' || r.claimType === 'stated');
    const guessed = results.filter((r) => r.claimType === 'guessed');
    const lines = [];
    if (golden.length) {
      lines.push(`Approved policy: ${golden.map((g) => `${g.claim} [${g.id}]`).join('; ')}.`);
    }
    for (const r of verified.slice(0, 4)) {
      lines.push(`${r.claim} — ${r.provenance.saidBy ?? 'unattributed'}, ${r.provenance.channel}, ${r.provenance.age} ago [${r.id}].`);
    }
    if (guessed.length) {
      lines.push(`Unconfirmed signal (AI-inferred, not stated by anyone): ${guessed.map((g) => `${g.claim} [${g.id}]`).join('; ')}.`);
    }
    return {
      text: lines.join('\n'),
      citations: results.slice(0, 8).map((r) => ({ id: r.id, claim: truncate(r.claim, 120), source: r.citation })),
      confidence: golden.length ? 'high (golden)' : verified.length ? 'medium' : 'low — inference only',
      caveat: guessed.length ? 'Contains AI-inferred content, labelled as such. Do not repeat it as fact.' : null
    };
  }

  /** Freshness signals: stale results demoted and labelled (§11.5). */
  _freshness(fact, asOf = null) {
    const at = asOf || now();
    const age = at - fact.createdAt;
    if (fact.golden) return { boost: 0.05, stale: false, reason: null };
    if (fact.expiresAt && fact.expiresAt < at) return { boost: -1, stale: true, reason: 'expired' };
    if (age > 12 * MONTH) return { boost: -0.25, stale: true, reason: `${ago(fact.createdAt, at)} old and never reconfirmed` };
    if (age > 6 * MONTH) return { boost: -0.1, stale: true, reason: `${ago(fact.createdAt, at)} old` };
    if (age < 7 * DAY) return { boost: 0.1, stale: false, reason: null };
    return { boost: 0, stale: false, reason: null };
  }

  /** Point-in-time: reconstruct the fact as it stood at a timestamp. */
  _asOf(fact, at) {
    if (fact.createdAt > at) return null;
    const versions = this.facts.history(fact.id).filter((v) => v.at <= at);
    if (!versions.length) return fact.createdAt <= at ? fact : null;
    return versions[versions.length - 1].snapshot;
  }

  // -- saved searches & alerts (§11.5) ------------------------------------

  save(name, query, opts, { actor, alert = false }) {
    const s = {
      id: newId('session'), name, query, opts, actor, alert,
      createdAt: now(), lastRunAt: null, lastSeenIds: []
    };
    this.savedSearches.set(s.id, s);
    return s;
  }

  /** "Tell me when anything new appears about Acme." */
  runSaved(id, ctx = {}) {
    const s = this.savedSearches.get(id);
    if (!s) throw new VaultError('not_found', 'saved search not found', { id });
    const res = this.search(s.query, { ...s.opts, ...ctx });
    const ids = res.results.map((r) => r.id);
    const newIds = ids.filter((x) => !s.lastSeenIds.includes(x));
    s.lastRunAt = now();
    s.lastSeenIds = ids;
    return { ...res, new: newIds.length, newIds, alert: s.alert && newIds.length > 0 };
  }

  savedSearchList() {
    return [...this.savedSearches.values()].map((s) => ({
      id: s.id, name: s.name, query: s.query, alert: s.alert,
      lastRun: s.lastRunAt ? iso(s.lastRunAt) : null, owner: s.actor
    }));
  }

  /** Search audit: every query logged; who searched for what (§11.5). */
  audit({ limit = 200, actor = null } = {}) {
    return this.auditLog
      .filter((a) => !actor || a.actor === actor)
      .slice(-limit)
      .map((a) => ({ ...a, at: iso(a.at) }));
  }

  stats() {
    return {
      indexedFacts: this.indexed.size,
      externalDocs: this.externalDocs.size,
      terms: this.postings.size,
      savedSearches: this.savedSearches.size,
      queries: this.auditLog.length
    };
  }
}

const BADGES = { approved: '★ GOLDEN', verified: '✓ VERIFIED', stated: '✓ STATED', heard: '· HEARD', guessed: '⚠ GUESSED BY AI' };

function rank(label) {
  return { public: 0, internal: 1, confidential: 2, secret: 3 }[label] ?? 1;
}
