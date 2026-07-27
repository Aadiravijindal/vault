/**
 * L2 — RAW ARCHIVE, and 🟢 VAULT ARCHIVE, the built-in regulated-grade archive
 * (§6).
 *
 * This layer runs FIRST — before extraction, before the gate. Even a write that
 * is ultimately blocked leaves a sealed record that it was attempted. Nobody can
 * ever claim "nothing arrived".
 */
import { newId, derivedId } from '../util/id.js';
import { sha256, hashObject } from '../util/crypto.js';
import { now, iso, ago, DAY, YEAR, duration } from '../util/time.js';
import { VaultError, notFound } from '../util/errors.js';
import { estimateCompressed } from '../storage/tiers.js';
import { tokenize, truncate } from '../util/text.js';

/** Recordkeeping frameworks the retention presets map to (§6.3). */
export const RECORDKEEPING = {
  'sec-17a-4': { name: 'SEC 17a-4(b)(4)/(f)', retention: '6y', worm: true, mode: 'compliance', note: 'Broker-dealer communications; WORM or audit-trail alternative.' },
  'finra-4511': { name: 'FINRA 4511', retention: '6y', worm: true, mode: 'compliance', note: 'Books and records; general retention.' },
  'finra-3110': { name: 'FINRA 3110', retention: '3y', worm: true, mode: 'compliance', note: 'Supervision — review evidence required.' },
  'finra-24-09': { name: 'FINRA Notice 24-09', retention: '6y', worm: true, mode: 'compliance', note: 'AI-generated content is a business record.' },
  'finra-25-07': { name: 'FINRA Notice 25-07', retention: '6y', worm: true, mode: 'compliance', note: 'Supervision of gen-AI communications.' },
  'mifid-ii-16-7': { name: 'MiFID II Art 16(7)', retention: '5y', worm: true, mode: 'compliance', note: 'Records of telephone and electronic communications.' },
  'fca-sysc-10a': { name: 'FCA SYSC 10A', retention: '5y', worm: true, mode: 'compliance', note: 'Recording of telephone conversations.' },
  'cftc-1-31': { name: 'CFTC 1.31', retention: '5y', worm: true, mode: 'compliance', note: 'Records of commodity interest transactions.' },
  'mas-hkma': { name: 'MAS / HKMA equivalents', retention: '7y', worm: true, mode: 'compliance', note: 'APAC recordkeeping equivalents.' },
  'hipaa': { name: 'HIPAA §164.316(b)(2)', retention: '6y', worm: false, mode: 'governance', note: 'Documentation retention.' },
  'gdpr-minimal': { name: 'GDPR storage limitation', retention: '2y', worm: false, mode: 'governance', note: 'Keep no longer than necessary.' }
};

export class Archive {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection WORM collection
   * @param {import('../storage/db.js').Collection} opts.reviews supervision reviews
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {import('../storage/tiers.js').TieringEngine} opts.tiering
   * @param {import('../modules/modules.js').ModuleRegistry} [opts.modules]
   */
  constructor({ collection, reviews, ledger, tiering, modules = null, supervision = {} }) {
    this.col = collection;
    this.reviews = reviews;
    this.ledger = ledger;
    this.tiering = tiering;
    this.modules = modules;
    this.col.index('bySession', (d) => d.sessionId);
    this.col.index('byAgent', (d) => d.agentId);
    this.col.index('byChannel', (d) => d.channel);
    this.col.index('byParticipant', (d) => (d.participants || []).map((p) => p.id || p.name));
    this.col.index('byConnector', (d) => d.connector);
    this.supervision = {
      randomSamplePct: 2,
      riskScoredPct: 100,
      riskThreshold: 0.5,
      lexicons: defaultLexicons(),
      ...supervision
    };
    /** @type {Map<string, number>} inverted index: token -> postings (built lazily) */
    this._index = new Map();
    this._indexedIds = new Set();
    this.productions = new Map();
    /** Employee → accounts (§6.3 employee-to-account linking). */
    this.identityLinks = new Map();
    this.gapReports = [];
  }

  // -- capture -------------------------------------------------------------

  /**
   * Seal a raw interaction. Immutable, hash-chained, whole — not summarised.
   * @param {object} raw
   * @returns {object} the sealed conversation record
   */
  seal(raw) {
    const id = raw.id || (raw.externalId
      ? derivedId('conversation', raw.connector || 'x', raw.externalId)
      : newId('conversation'));

    // Idempotent: reconnecting a connector must never duplicate (§4.4).
    const existing = this.col.get(id);
    if (existing) return existing;

    const content = normaliseContent(raw);
    const compression = estimateCompressed(content.transcriptText);
    const record = {
      id,
      sealedAt: now(),
      // §6.1 — everything, verbatim
      transcript: content.turns,
      transcriptText: content.transcriptText,
      native: raw.native ?? null,           // original format preserved alongside
      nativeFormat: raw.nativeFormat ?? (raw.native ? 'unknown' : null),
      attachments: (raw.attachments || []).map((a) => ({
        name: a.name, mime: a.mime, bytes: a.bytes ?? (a.content ? Buffer.byteLength(String(a.content)) : 0),
        sha256: a.content ? sha256(String(a.content)) : (a.sha256 || null),
        content: a.content ?? null
      })),
      toolCalls: (raw.toolCalls || []).map((t) => ({
        name: t.name, args: t.args ?? null, result: t.result ?? null,
        server: t.server ?? null, latencyMs: t.latencyMs ?? null, error: t.error ?? null
      })),
      model: raw.model ?? null,
      modelVersion: raw.modelVersion ?? null,
      systemPrompt: raw.systemPrompt ?? null,
      systemPromptVersion: raw.systemPromptVersion ?? (raw.systemPrompt ? sha256(raw.systemPrompt).slice(0, 12) : null),
      startedAt: raw.startedAt ?? now(),
      endedAt: raw.endedAt ?? now(),
      timezone: raw.timezone ?? 'UTC',
      participants: raw.participants || [],
      agentId: raw.agentId ?? null,
      channel: raw.channel ?? 'unknown',
      channelTrust: raw.channelTrust ?? null,     // set by the gate, recorded here
      connector: raw.connector ?? null,
      connectorMode: raw.connectorMode ?? null,
      sessionId: raw.sessionId ?? id,
      client: raw.client ?? null,                  // app, version, ip (where lawful), device class
      costUsd: raw.costUsd ?? null,
      latencyMs: raw.latencyMs ?? null,
      errors: raw.errors || [],
      retries: raw.retries ?? 0,
      timeouts: raw.timeouts ?? 0,
      region: raw.region ?? null,
      // integrity
      contentHash: null,
      prevHash: null,
      // lifecycle
      legalHold: false,
      privileged: Boolean(raw.privileged),
      regulatoryRecord: raw.regulatoryRecord ?? null,
      bytes: compression.originalBytes,
      storedBytes: compression.storedBytes,
      compressionRatio: compression.ratio
    };

    // Seal: hash-chained to the previous archive entry.
    const prev = this._lastHash();
    record.contentHash = hashObject({ ...record, contentHash: undefined, prevHash: undefined });
    record.prevHash = prev;
    record.sealHash = sha256(`${prev}\n${record.contentHash}`);

    const stored = this.col.insert(record);
    this._lastSealHash = record.sealHash;

    // Retention placement: regulatory records go to WORM, immediately.
    const framework = record.regulatoryRecord ? RECORDKEEPING[record.regulatoryRecord] : null;
    this.tiering.place(stored.id, {
      bytes: record.storedBytes,
      worm: Boolean(framework?.worm),
      retention: framework?.retention ?? null,
      mode: framework?.mode ?? 'governance',
      dataClass: framework ? `regulatory:${record.regulatoryRecord}` : 'conversation',
      region: record.region
    });

    this.ledger.append('archive.sealed', {
      subject: stored.id,
      actor: record.agentId,
      channel: record.channel,
      connector: record.connector,
      sealHash: record.sealHash,
      turns: record.transcript.length,
      bytes: record.bytes,
      regulatoryRecord: record.regulatoryRecord,
      worm: Boolean(framework?.worm)
    });

    this._indexRecord(stored);
    this._runSupervision(stored);
    this._linkIdentities(stored);

    // 🔵/🟣 push to a connected archive of record (Smarsh, Global Relay, …)
    this.modules?.dispatch('archive', 'push', stored);

    return stored;
  }

  _lastHash() {
    if (this._lastSealHash) return this._lastSealHash;
    const all = this.col.all();
    if (!all.length) return 'GENESIS';
    const last = all.reduce((a, b) => (a.sealedAt > b.sealedAt ? a : b));
    return (this._lastSealHash = last.sealHash || 'GENESIS');
  }

  get(id) { return this.col.get(id); }
  require(id) {
    const c = this.col.get(id);
    if (!c) throw notFound('conversation', id);
    return c;
  }

  /**
   * A clickable, permanent pointer into the raw source: conv-9921 @ 22:14.
   * @param {string} conversationId
   * @param {number} offset character offset into the transcript text
   */
  sourceRef(conversationId, offset = 0) {
    const c = this.get(conversationId);
    if (!c) return { conversationId, offset, label: conversationId };
    const before = c.transcriptText.slice(0, offset);
    const turnIdx = Math.max(0, before.split('\n').length - 1);
    const turn = c.transcript[Math.min(turnIdx, c.transcript.length - 1)];
    const secs = turn?.atSeconds ?? Math.round((offset / Math.max(c.transcriptText.length, 1)) *
      ((c.endedAt - c.startedAt) / 1000));
    const mm = String(Math.floor(secs / 60)).padStart(2, '0');
    const ss = String(Math.round(secs % 60)).padStart(2, '0');
    return {
      conversationId, offset, turn: turnIdx, atSeconds: secs,
      label: `${conversationId} @ ${mm}:${ss}`,
      speaker: turn?.speaker ?? null,
      excerpt: truncate(c.transcriptText.slice(Math.max(0, offset - 40), offset + 160), 200)
    };
  }

  // -- search --------------------------------------------------------------

  _indexRecord(rec) {
    if (this._indexedIds.has(rec.id)) return;
    this._indexedIds.add(rec.id);
    for (const t of new Set(tokenize(rec.transcriptText))) {
      let set = this._index.get(t);
      if (!set) this._index.set(t, (set = new Set()));
      set.add(rec.id);
    }
  }

  /**
   * Full-text + metadata + entity + time-range search over every raw
   * conversation (§6.2 "searchable").
   */
  search(query, { channel, agentId, participant, from, to, limit = 50, privileged = false } = {}) {
    for (const r of this.col.all()) this._indexRecord(r);
    const terms = tokenize(query || '');
    let candidates = terms.length
      ? [...(terms.reduce((acc, t) => {
          const set = this._index.get(t) || new Set();
          if (!acc) return new Set(set);
          for (const id of [...acc]) if (!set.has(id)) acc.delete(id);
          return acc;
        }, null) || new Set())].map((id) => this.col.get(id)).filter(Boolean)
      : this.col.all();

    candidates = candidates.filter((c) => {
      if (channel && c.channel !== channel) return false;
      if (agentId && c.agentId !== agentId) return false;
      if (from && c.startedAt < from) return false;
      if (to && c.startedAt > to) return false;
      if (participant && !(c.participants || []).some((p) => p.id === participant || p.name === participant)) return false;
      if (c.privileged && !privileged) return false;
      return true;
    });

    return candidates
      .sort((a, b) => b.startedAt - a.startedAt)
      .slice(0, limit)
      .map((c) => ({
        id: c.id,
        at: iso(c.startedAt),
        age: ago(c.startedAt),
        channel: c.channel,
        agentId: c.agentId,
        participants: c.participants,
        turns: c.transcript.length,
        snippet: snippet(c.transcriptText, terms),
        sealHash: c.sealHash,
        privileged: c.privileged,
        legalHold: c.legalHold,
        tier: this.tiering.get(c.id)?.tier ?? 'hot'
      }));
  }

  // -- restoration ---------------------------------------------------------

  /** Pull a record back from a cold tier, with an SLA-shaped estimate (§6.3). */
  restore(id, { actor = 'system', reason = 'restoration request' } = {}) {
    const rec = this.require(id);
    const placement = this.tiering.get(id);
    const tier = placement?.tier ?? 'hot';
    const etaMs = tier === 'archive' ? 4 * 60 * 60 * 1000 : tier === 'cold' ? 5000 : 0;
    if (tier !== 'hot' && tier !== 'worm' && !placement?.worm) {
      this.tiering.move(id, 'warm', `restoration: ${reason}`);
    }
    this.ledger.append('archive.restored', { subject: id, actor, fromTier: tier, etaMs, reason });
    return { id, fromTier: tier, nowTier: this.tiering.get(id)?.tier, etaMs, rehydratedAt: iso(), record: rec };
  }

  // -- supervision (§6.3) --------------------------------------------------

  /**
   * Sample-based review for compliance officers: random %, risk-scored %, or
   * rule-triggered. Prioritise the 2% worth reading.
   */
  _runSupervision(rec) {
    const scan = this.lexiconScan(rec.transcriptText);
    const risk = scan.riskScore;
    const triggers = [];
    if (scan.hits.length) triggers.push(...scan.hits.map((h) => `lexicon:${h.lexicon}`));
    const rand = hashToUnit(rec.id);
    const sampled = rand < this.supervision.randomSamplePct / 100;
    if (sampled) triggers.push('random_sample');
    if (risk >= this.supervision.riskThreshold) triggers.push('risk_score');
    if (!triggers.length) return null;

    const review = this.reviews.insert({
      id: newId('review'),
      kind: 'supervision',
      conversationId: rec.id,
      openedAt: now(),
      status: 'open',
      riskScore: risk,
      triggers,
      lexiconHits: scan.hits,
      assignedTo: null,
      priority: risk >= 0.75 ? 'high' : risk >= 0.4 ? 'medium' : 'low',
      slaDueAt: now() + (risk >= 0.75 ? 4 * 60 * 60 * 1000 : DAY),
      decisions: [],
      fourEyes: risk >= 0.75
    });
    return review;
  }

  /** Watch-word lists, regex, semantic risk scoring, per-channel policies. */
  lexiconScan(text, { channel = null } = {}) {
    const hits = [];
    const t = String(text || '');
    for (const lex of this.supervision.lexicons) {
      if (lex.channels && channel && !lex.channels.includes(channel)) continue;
      for (const pattern of lex.patterns) {
        const re = pattern instanceof RegExp ? pattern : new RegExp(pattern, 'gi');
        const matches = t.match(re);
        if (matches) {
          hits.push({ lexicon: lex.name, weight: lex.weight, count: matches.length, sample: truncate(matches[0], 60) });
        }
      }
    }
    const riskScore = Math.min(1, hits.reduce((a, h) => a + h.weight * Math.min(h.count, 3), 0));
    return { hits, riskScore: Math.round(riskScore * 100) / 100 };
  }

  /** Reviewer workflow: assign, escalate, annotate, close with reason (§6.3). */
  decideSupervision(reviewId, { actor, decision, reason, annotation = null, escalateTo = null }) {
    const rev = this.reviews.get(reviewId);
    if (!rev) throw notFound('supervision review', reviewId);
    if (!actor || !decision) throw new VaultError('forbidden', 'supervision decisions require an actor and a decision');
    const entry = { actor, decision, reason, annotation, at: now(), tookMs: now() - rev.openedAt };
    const decisions = [...rev.decisions, entry];
    const needed = rev.fourEyes ? 2 : 1;
    const distinct = new Set(decisions.filter((d) => d.decision === decision).map((d) => d.actor));
    const status = decision === 'escalate' ? 'escalated'
      : distinct.size >= needed ? 'closed' : 'awaiting_second_approver';
    const updated = this.reviews.update(reviewId, {
      decisions, status,
      assignedTo: escalateTo ?? rev.assignedTo,
      closedAt: status === 'closed' ? now() : null
    });
    this.ledger.append('review.decision', {
      subject: reviewId, actor, kind: 'supervision', decision,
      conversationId: rev.conversationId, tookMs: entry.tookMs, status
    });
    return updated;
  }

  supervisionQueue({ status = 'open', limit = 100 } = {}) {
    return this.reviews.find((r) => r.kind === 'supervision' && (status === 'all' || r.status === status))
      .sort((a, b) => (b.riskScore - a.riskScore) || (a.openedAt - b.openedAt))
      .slice(0, limit)
      .map((r) => ({
        ...r,
        age: ago(r.openedAt),
        slaBreached: r.status === 'open' && now() > r.slaDueAt,
        conversation: this.get(r.conversationId) && {
          channel: this.get(r.conversationId).channel,
          participants: this.get(r.conversationId).participants,
          snippet: truncate(this.get(r.conversationId).transcriptText, 240)
        }
      }));
  }

  // -- eDiscovery & productions (§6.3) -------------------------------------

  /**
   * Define a production set, freeze it, and prove it wasn't altered after
   * freezing.
   */
  createProduction({ matter, scope = {}, actor, reason, batesPrefix = 'VLT' }) {
    if (!actor || !matter) throw new VaultError('forbidden', 'a production requires a matter and a named actor');
    const results = this.search(scope.query || '', { ...scope, limit: Infinity, privileged: true });
    const items = results.map((r) => this.require(r.id));
    const production = {
      id: newId('export'),
      matter, actor, reason, createdAt: now(), batesPrefix,
      itemIds: items.map((i) => i.id),
      frozenHash: sha256(items.map((i) => i.sealHash).join('\n')),
      privilegedWithheld: items.filter((i) => i.privileged).map((i) => ({ id: i.id, reason: 'attorney-client privilege / work product' })),
      frozen: true
    };
    this.productions.set(production.id, production);
    this.ledger.append('production.frozen', {
      subject: production.id, actor, matter, items: items.length,
      withheld: production.privilegedWithheld.length, frozenHash: production.frozenHash
    });
    return production;
  }

  verifyProduction(productionId) {
    const p = this.productions.get(productionId);
    if (!p) throw notFound('production', productionId);
    const current = sha256(p.itemIds.map((id) => this.get(id)?.sealHash || 'MISSING').join('\n'));
    return { productionId, ok: current === p.frozenHash, frozenHash: p.frozenHash, currentHash: current, items: p.itemIds.length };
  }

  /**
   * Export in load-file formats an eDiscovery platform actually ingests.
   * @param {string} productionId
   * @param {'edrm'|'concordance'|'eml'|'native'|'csv'} format
   */
  exportProduction(productionId, format = 'edrm', { includePrivileged = false } = {}) {
    const p = this.productions.get(productionId);
    if (!p) throw notFound('production', productionId);
    const items = p.itemIds.map((id) => this.require(id))
      .filter((i) => includePrivileged || !i.privileged);
    const bates = (n) => `${p.batesPrefix}${String(n).padStart(8, '0')}`;

    let payload;
    if (format === 'edrm') {
      payload = edrmXml(items, bates, p);
    } else if (format === 'concordance') {
      payload = concordance(items, bates);
    } else if (format === 'eml') {
      payload = items.map((i, n) => emlFor(i, bates(n + 1))).join('\n\n----- MESSAGE BOUNDARY -----\n\n');
    } else if (format === 'csv') {
      payload = csvFor(items, bates);
    } else {
      payload = JSON.stringify({ production: p, items }, null, 2);
    }
    this.ledger.append('export.created', {
      subject: p.id, actor: p.actor, format, items: items.length,
      withheld: p.itemIds.length - items.length, matter: p.matter
    });
    return {
      productionId, format, items: items.length,
      withheld: p.privilegedWithheld,
      batesRange: items.length ? `${bates(1)}–${bates(items.length)}` : null,
      integrity: this.verifyProduction(productionId),
      payload
    };
  }

  // -- journaling & capture completeness (§6.3) ----------------------------

  /**
   * Prove you captured everything, not just what happened to arrive.
   * @param {{connector:string, expected:number, from:number, to:number}} claim
   */
  reconcileCapture({ connector, expected, from, to }) {
    const actual = this.col.find((c) => c.connector === connector && c.startedAt >= from && c.startedAt <= to).length;
    const gap = expected - actual;
    const report = {
      id: newId('incident'), connector, from: iso(from), to: iso(to),
      expected, actual, gap, complete: gap <= 0, at: iso()
    };
    this.gapReports.push(report);
    if (gap > 0) {
      this.ledger.append('connector.gap', { subject: connector, expected, actual, gap, from: iso(from), to: iso(to) });
    }
    return report;
  }

  /** One person, many accounts, all their communications linked (§6.3). */
  linkIdentity(person, accounts) {
    const set = this.identityLinks.get(person) || new Set();
    for (const a of accounts) set.add(a);
    this.identityLinks.set(person, set);
    return { person, accounts: [...set] };
  }

  _linkIdentities(rec) {
    for (const p of rec.participants || []) {
      if (p.employeeId) this.linkIdentity(p.employeeId, [p.id || p.name].filter(Boolean));
    }
  }

  conversationsForPerson(person) {
    const accounts = new Set([person, ...(this.identityLinks.get(person) || [])]);
    return this.col.find((c) => (c.participants || []).some(
      (p) => accounts.has(p.id) || accounts.has(p.name) || accounts.has(p.employeeId)));
  }

  /** Retention schedules with conflicting obligations surfaced, not resolved. */
  retentionFor(conversationId) {
    const rec = this.require(conversationId);
    const obligations = [];
    if (rec.regulatoryRecord && RECORDKEEPING[rec.regulatoryRecord]) {
      const f = RECORDKEEPING[rec.regulatoryRecord];
      obligations.push({ kind: 'minimum', framework: f.name, keepFor: f.retention, ms: duration(f.retention) });
    }
    if (rec.privileged) obligations.push({ kind: 'minimum', framework: 'legal privilege', keepFor: '7y', ms: 7 * YEAR });
    obligations.push({ kind: 'maximum', framework: 'GDPR storage limitation', keepFor: '2y', ms: 2 * YEAR });
    const minimums = obligations.filter((o) => o.kind === 'minimum');
    const maximums = obligations.filter((o) => o.kind === 'maximum');
    const conflict = minimums.some((mn) => maximums.some((mx) => mn.ms > mx.ms));
    return {
      conversationId, obligations, conflict,
      resolution: conflict
        ? 'CONFLICT SURFACED — records obligation exceeds privacy maximum. Vault holds both and requires a named decision; it does not silently pick one.'
        : 'no conflict',
      effectiveMinimum: minimums.length ? Math.max(...minimums.map((o) => o.ms)) : null,
      effectiveMaximum: maximums.length ? Math.min(...maximums.map((o) => o.ms)) : null
    };
  }

  stats() {
    const all = this.col.all();
    return {
      conversations: all.length,
      turns: all.reduce((a, c) => a + c.transcript.length, 0),
      bytes: all.reduce((a, c) => a + (c.bytes || 0), 0),
      storedBytes: all.reduce((a, c) => a + (c.storedBytes || 0), 0),
      worm: all.filter((c) => this.tiering.get(c.id)?.worm).length,
      privileged: all.filter((c) => c.privileged).length,
      onHold: all.filter((c) => c.legalHold).length,
      supervisionOpen: this.reviews.count((r) => r.kind === 'supervision' && r.status === 'open'),
      productions: this.productions.size,
      gapReports: this.gapReports.length
    };
  }
}

// ---------------------------------------------------------------------------

function normaliseContent(raw) {
  let turns = raw.turns || raw.transcript;
  if (!turns) {
    if (typeof raw.content === 'string') {
      turns = [{ speaker: raw.speaker || 'unknown', text: raw.content, at: raw.startedAt ?? now() }];
    } else {
      turns = [];
    }
  }
  turns = turns.map((t, i) => ({
    seq: i,
    speaker: t.speaker ?? 'unknown',
    role: t.role ?? (t.speaker === 'agent' ? 'assistant' : 'user'),
    text: String(t.text ?? t.content ?? ''),
    at: t.at ?? null,
    atSeconds: t.atSeconds ?? null
  }));
  return { turns, transcriptText: turns.map((t) => `${t.speaker}: ${t.text}`).join('\n') };
}

function snippet(text, terms) {
  if (!terms.length) return truncate(text, 180);
  const lower = text.toLowerCase();
  const idx = Math.max(0, lower.indexOf(terms[0]) - 60);
  return (idx > 0 ? '…' : '') + truncate(text.slice(idx), 200);
}

function hashToUnit(str) {
  const h = sha256(str);
  return parseInt(h.slice(0, 8), 16) / 0xffffffff;
}

function defaultLexicons() {
  return [
    { name: 'guarantee', weight: 0.45, patterns: [/\b(guarantee[ds]?|promise[ds]?|assured?|risk[- ]free|no risk|can't lose)\b/gi] },
    { name: 'unauthorised_commitment', weight: 0.5, patterns: [/\b(i'?ll waive|we'?ll waive|pre-?approved|no need for (?:sign-?off|approval)|skip (?:the )?approval)\b/gi] },
    { name: 'complaint', weight: 0.3, patterns: [/\b(complain[st]?|escalate to (?:the )?regulator|lawsuit|sue you|ombudsman|fca|sec\b)/gi] },
    { name: 'inside_information', weight: 0.6, patterns: [/\b(material non-?public|insider|before the announcement|not yet public)\b/gi] },
    { name: 'off_channel', weight: 0.4, patterns: [/\b(text me|whatsapp|signal|my personal (?:email|phone)|off the record)\b/gi] },
    { name: 'gift_entertainment', weight: 0.25, patterns: [/\b(tickets|dinner on us|gift card|comp(?:limentary)? (?:trip|stay))\b/gi] },
    { name: 'discriminatory', weight: 0.6, patterns: [/\b(too old for|because (?:he|she|they) (?:is|are) (?:pregnant|disabled))\b/gi] }
  ];
}

// -- load-file formats ------------------------------------------------------

function edrmXml(items, bates, production) {
  const esc = (s) => String(s ?? '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
  const docs = items.map((it, n) => `    <Document DocID="${bates(n + 1)}" MimeType="text/plain">
      <Tags>
        <Tag TagName="Matter" TagValue="${esc(production.matter)}"/>
        <Tag TagName="Channel" TagValue="${esc(it.channel)}"/>
        <Tag TagName="Custodian" TagValue="${esc((it.participants || []).map((p) => p.name).join('; '))}"/>
        <Tag TagName="DateSent" TagValue="${iso(it.startedAt)}"/>
        <Tag TagName="SealHash" TagValue="${esc(it.sealHash)}"/>
        <Tag TagName="Privileged" TagValue="${it.privileged ? 'Yes' : 'No'}"/>
      </Tags>
      <Files>
        <File FileType="Text"><ExternalFile FileName="${bates(n + 1)}.txt" FileSize="${it.bytes}" Hash="${it.contentHash}"/></File>
        <File FileType="Native"><ExternalFile FileName="${bates(n + 1)}.json" FileSize="${it.bytes}"/></File>
      </Files>
    </Document>`).join('\n');
  return `<?xml version="1.0" encoding="utf-8"?>
<Root DataInterchangeType="Update">
  <Batch>
    <Documents>
${docs}
    </Documents>
  </Batch>
</Root>`;
}

function concordance(items, bates) {
  const D = String.fromCharCode(20); // Concordance delimiters
  const Q = String.fromCharCode(254);
  const cols = ['BEGDOC', 'ENDDOC', 'CUSTODIAN', 'DATESENT', 'CHANNEL', 'AGENT', 'SEALHASH', 'PRIVILEGED', 'TEXT'];
  const head = cols.map((c) => `${Q}${c}${Q}`).join(D);
  const rows = items.map((it, n) => [
    bates(n + 1), bates(n + 1),
    (it.participants || []).map((p) => p.name).join('; '),
    iso(it.startedAt), it.channel, it.agentId || '', it.sealHash, it.privileged ? 'Y' : 'N',
    it.transcriptText.replace(/[\r\n]+/g, ' ')
  ].map((v) => `${Q}${String(v).replace(new RegExp(Q, 'g'), '')}${Q}`).join(D));
  const opt = items.map((it, n) => `${bates(n + 1)},,${bates(n + 1)}.txt,Y,,,1`).join('\n');
  return { dat: [head, ...rows].join('\n'), opt };
}

function emlFor(item, bates) {
  const from = (item.participants || [])[0];
  return [
    `X-Vault-Bates: ${bates}`,
    `X-Vault-Seal: ${item.sealHash}`,
    `X-Vault-Channel: ${item.channel}`,
    `Message-ID: <${item.id}@vault>`,
    `Date: ${new Date(item.startedAt).toUTCString()}`,
    `From: ${from ? `${from.name} <${from.id || 'unknown'}>` : 'unknown'}`,
    `To: ${(item.participants || []).slice(1).map((p) => p.name).join(', ') || 'unknown'}`,
    `Subject: [${item.channel}] ${item.id}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    item.transcriptText
  ].join('\r\n');
}

function csvFor(items, bates) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const head = ['bates', 'id', 'date', 'channel', 'agent', 'participants', 'sealHash', 'privileged', 'text'].join(',');
  return [head, ...items.map((it, n) => [
    bates(n + 1), it.id, iso(it.startedAt), it.channel, it.agentId,
    (it.participants || []).map((p) => p.name).join('; '), it.sealHash, it.privileged, it.transcriptText
  ].map(esc).join(','))].join('\n');
}
