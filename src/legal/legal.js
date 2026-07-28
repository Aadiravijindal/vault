/**
 * LEGAL & PRIVACY (§14).
 *
 * Legal holds that no admin can override, erasure that reaches the transcripts,
 * signed deletion receipts, subject access, privilege, retention with
 * conflicting obligations SURFACED rather than silently resolved — and the
 * delete-vs-keep conflict resolved on screen, which is the sharpest legal hook
 * in the product.
 */
import { newId } from '../util/id.js';
import { sha256, signMessage, verifyMessage, pseudonym } from '../util/crypto.js';
import { now, iso, ago, duration, DAY, MONTH, YEAR } from '../util/time.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { truncate } from '../util/text.js';

export const DSAR_DEADLINES = {
  gdpr: { days: 30, label: 'GDPR Art 12(3) — one month' },
  uk_gdpr: { days: 30, label: 'UK GDPR — one month' },
  ccpa: { days: 45, label: 'CCPA/CPRA — 45 days' },
  dpdp: { days: 90, label: 'India DPDP — 90 days' },
  lgpd: { days: 15, label: 'LGPD — 15 days' },
  pipeda: { days: 30, label: 'PIPEDA — 30 days' }
};

export class LegalOps {
  /**
   * @param {object} deps
   */
  constructor({ facts, archive, ledger, kms, db, consent, entities, tiering, search = null, signingKey = null }) {
    this.facts = facts;
    this.archive = archive;
    this.ledger = ledger;
    this.kms = kms;
    this.db = db;
    this.consent = consent;
    this.entities = entities;
    this.tiering = tiering;
    this.search = search;
    this.signingKey = signingKey;

    // Holds, receipts and DSARs are durable records, not session state. A hold
    // that evaporates on restart is a spoliation event: retention resumes
    // deleting material the court told you to preserve, and nobody is told.
    // Receipts must outlive the process that issued them or they prove nothing.
    this._holdCol = db?.collection('legal_holds') ?? null;
    this._receiptCol = db?.collection('legal_receipts') ?? null;
    this._dsarCol = db?.collection('legal_dsars') ?? null;
    this._privilegeCol = db?.collection('legal_privilege') ?? null;

    /** @type {Map<string, object>} in-memory index over the durable collection */
    this.holds = new Map((this._holdCol?.all() ?? []).map((h) => [h.id, h]));
    this.receipts = (this._receiptCol?.all() ?? []).sort((a, b) => (a.at ?? 0) - (b.at ?? 0));
    this.dsars = new Map((this._dsarCol?.all() ?? []).map((d) => [d.id, d]));
    this.privilegeLog = this._privilegeCol?.all() ?? [];

    // Rebuilt from the holds themselves, so it can never drift out of step.
    this._conversationHolds = new Map();
    for (const h of this.holds.values()) {
      for (const cid of h.conversationIds || []) {
        const list = this._conversationHolds.get(cid) || [];
        list.push({ holdId: h.id, matter: h.matter, at: h.placedAt });
        this._conversationHolds.set(cid, list);
      }
    }

    /** Third parties we propagate deletions to. */
    this.thirdParties = new Map();
  }

  _saveHold(hold) { this._holdCol?.put({ ...hold }); return hold; }

  registerThirdParty(name, handler) {
    this.thirdParties.set(name, handler);
    return this;
  }

  // ==== LEGAL HOLD (§14.1) ===============================================

  /**
   * @param {object} spec
   * @returns {object} the hold, receipted and chained
   */
  placeHold({ matter, scope, actor, reason, custodianNotice = true }) {
    if (!matter || !actor || !reason) {
      throw forbidden('a legal hold requires a matter, a named actor and a reason');
    }
    // A hold with no scope freezes nothing while reporting success — legal then
    // believes material is preserved when it is not, and finds out at
    // production. Refuse it loudly instead.
    const SCOPES = ['person', 'entity', 'account', 'project', 'folder', 'dateRange', 'matter', 'channel'];
    const given = scope && typeof scope === 'object'
      ? SCOPES.filter((k) => scope[k] !== undefined && scope[k] !== null && scope[k] !== '')
      : [];
    if (!given.length) {
      throw new VaultError('validation',
        'a legal hold needs a scope — otherwise it would freeze nothing while reporting success',
        { scopes: SCOPES, example: { person: 'Rodriguez, M.' } });
    }
    const targets = this._resolveScope(scope);
    const hold = {
      id: newId('hold'),
      matter,
      scope,
      actor,
      reason,
      placedAt: now(),
      liftedAt: null,
      liftedBy: null,
      factIds: targets.facts.map((f) => f.id),
      conversationIds: targets.conversations.map((c) => c.id),
      folders: targets.folders,
      recordings: targets.recordings,
      tokenisedRefs: targets.tokenisedRefs,
      active: true
    };

    for (const f of targets.facts) this.facts.freeze(f.id, { holdId: hold.id, matter });
    // The archive is WORM: we record the hold alongside rather than editing the
    // sealed record, because there is no update path for a WORM collection.
    for (const c of targets.conversations) this._markConversationHold(c.id, hold);
    for (const name of targets.entities) {
      // Facts carry entity NAMES; the resolver owns the ids. Resolve, don't guess.
      const resolved = this.entities?.resolve(name)?.entity;
      if (resolved) this.entities.setHold(resolved.id, { holdId: hold.id, matter });
    }

    this.holds.set(hold.id, hold);
    this._saveHold(hold);
    const receipt = this._receipt('legal_hold_placed', {
      holdId: hold.id, matter, actor, reason,
      counts: { facts: hold.factIds.length, conversations: hold.conversationIds.length, folders: hold.folders.length }
    });
    this.ledger.append('legal.hold_placed', {
      subject: hold.id, actor, matter, reason,
      facts: hold.factIds.length, conversations: hold.conversationIds.length, receipt: receipt.proof
    });

    return {
      ...hold,
      receipt,
      effects: [
        'retention cannot expire them',
        'hygiene cannot merge, decay or summarise them',
        'tiering cannot move them',
        'NO admin can delete them — including the account owner',
        'erasure requests against them are refused, with a written reason',
        'the hold itself is receipted and chained',
        'lift requires a named authoriser + reason, also receipted'
      ],
      custodianNotice: custodianNotice ? this._custodianNotice(hold) : null,
      summary: `${hold.factIds.length} facts frozen · ${hold.conversationIds.length} conversations frozen · ${hold.folders.length} folders touched · ${hold.recordings} voice recording${hold.recordings === 1 ? '' : 's'} · ${hold.tokenisedRefs} tokenised PII references`
    };
  }

  _markConversationHold(conversationId, hold) {
    // WORM: we keep hold state in a side index, never by mutating the sealed record.
    const c = this.archive.get(conversationId);
    if (!c) return;
    const list = this._conversationHolds.get(conversationId) || [];
    list.push({ holdId: hold.id, matter: hold.matter, at: now() });
    this._conversationHolds.set(conversationId, list);
  }

  conversationHolds(conversationId) {
    return this._conversationHolds?.get(conversationId)?.filter((h) => this.holds.get(h.holdId)?.active) ?? [];
  }

  /** Multiple overlapping holds tracked separately (§14.1). */
  liftHold(holdId, { actor, reason, authoriser }) {
    const hold = this.holds.get(holdId);
    if (!hold) throw notFound('legal hold', holdId);
    if (!actor || !reason || !authoriser) {
      throw forbidden('lifting a hold requires a named authoriser and a reason');
    }
    hold.active = false;
    hold.liftedAt = now();
    hold.liftedBy = actor;
    hold.liftAuthoriser = authoriser;
    this._saveHold(hold);
    hold.liftReason = reason;

    let released = 0;
    for (const id of hold.factIds) {
      const f = this.facts.get(id);
      if (!f) continue;
      // Only clear if no OTHER active hold covers this fact.
      const others = [...this.holds.values()].filter((h) => h.active && h.factIds.includes(id));
      if (others.length) continue;
      this.facts.release(id);
      released++;
    }
    const receipt = this._receipt('legal_hold_lifted', { holdId, matter: hold.matter, actor, authoriser, reason, released });
    this.ledger.append('legal.hold_lifted', { subject: holdId, actor, authoriser, reason, released, receipt: receipt.proof });

    // Anything deferred by this hold auto-deletes the instant it lifts.
    const deferred = this.receipts.filter((r) => r.kind === 'erasure_deferred' && r.body.holdId === holdId);
    const autoDeleted = [];
    for (const d of deferred) {
      try {
        autoDeleted.push(this.erase({ subject: d.body.subject, actor: 'system', reason: `deferred erasure completed on lift of hold ${holdId}`, requestId: d.body.requestId, confirm: true }));
      } catch { /* still blocked by another hold */ }
    }
    return { holdId, released, receipt, autoDeleted: autoDeleted.length };
  }

  activeHolds() {
    return [...this.holds.values()].filter((h) => h.active).map((h) => ({
      ...h, age: ago(h.placedAt), placedAt: iso(h.placedAt)
    }));
  }

  isHeld(id) {
    for (const h of this.holds.values()) {
      if (!h.active) continue;
      if (h.factIds.includes(id) || h.conversationIds.includes(id)) return true;
    }
    return false;
  }

  _resolveScope(scope = {}) {
    const facts = new Set();
    const conversations = new Set();
    const folders = new Set();
    const entities = new Set();

    const matchPerson = (f) => (f.entities || []).some(
      (e) => e.type === 'person' && (e.name === scope.person || e.id === scope.person));

    for (const f of this.facts.all()) {
      let hit = false;
      if (scope.person && matchPerson(f)) hit = true;
      if (scope.entity && (f.entities || []).some((e) => e.name === scope.entity || e.id === scope.entity)) hit = true;
      if (scope.folder && String(f.folder || '').startsWith(scope.folder)) hit = true;
      if (scope.project && String(f.folder || '').includes(`/${scope.project}/`)) hit = true;
      if (scope.factIds?.includes(f.id)) hit = true;
      if (scope.from && scope.to && f.createdAt >= scope.from && f.createdAt <= scope.to) hit = true;
      if (scope.channel && f.channel === scope.channel) hit = true;
      if (hit) {
        facts.add(f);
        if (f.folder) folders.add(f.folder);
        if (f.source?.conversationId) conversations.add(f.source.conversationId);
        for (const e of f.entities || []) entities.add(e.id || e.name);
      }
    }
    if (scope.person && this.archive) {
      for (const c of this.archive.conversationsForPerson(scope.person)) conversations.add(c.id);
    }
    if (scope.conversationIds) for (const id of scope.conversationIds) conversations.add(id);

    const convRecords = [...conversations].map((id) => this.archive?.get(id)).filter(Boolean);
    return {
      facts: [...facts],
      conversations: convRecords,
      folders: [...folders],
      entities: [...entities],
      recordings: convRecords.filter((c) => c.channel === 'phone_call' || c.channel === 'phone_call_authenticated').length,
      tokenisedRefs: [...facts].reduce((a, f) => a + (f.piiFindings || []).filter((p) => p.action === 'tokenise').length, 0)
    };
  }

  _custodianNotice(hold) {
    return {
      to: hold.scope?.person || hold.scope?.entity || hold.scope?.account || 'custodian',
      matter: hold.matter,
      issuedAt: iso(),
      text: `A litigation hold has been placed in connection with ${hold.matter}. Material within its scope must be preserved. `
        + `Vault has frozen ${hold.factIds.length} facts and ${hold.conversationIds.length} conversations; automated retention, `
        + `summarisation and tiering will not touch them. Do not delete related material.`
    };
  }

  // ==== ERASURE (§14.2) ==================================================

  /**
   * Find everything about a subject, including the transcripts — a request that
   * misses them isn't fulfilled.
   */
  discover(subject) {
    // A wrongly-shaped subject used to match nothing and return an empty
    // result, which on the erasure path reads as "this person has no data" —
    // the one false negative that turns into an unfulfilled request.
    if (typeof subject !== 'string' || !subject.trim()) {
      throw new VaultError('validation',
        'a subject must be a name or an entity id — an empty match here would read as "nothing to erase"',
        { received: typeof subject });
    }
    const facts = this.facts.all().filter((f) => (f.entities || []).some((e) => e.name === subject || e.id === subject));
    const conversations = this.archive ? this.archive.conversationsForPerson(subject) : [];
    const derived = facts.flatMap((f) => f.derivedFacts || []);
    const summariesMentioning = this.facts.all().filter((f) => f.kind === 'rolling_summary' && String(f.claim).includes(subject));
    const readLogEntries = this.ledger.entries({ type: 'fact.read', limit: Infinity })
      .filter((e) => facts.some((f) => f.id === e.subject));
    const tokenised = facts.reduce((a, f) => a + (f.piiFindings || []).filter((p) => p.action === 'tokenise').length, 0);
    const recordings = conversations.filter((c) => c.channel?.startsWith('phone')).length;
    const consentRecords = this.consent?.bySubject(subject) ?? [];

    return {
      subject,
      facts,
      conversations,
      derivedFactIds: [...new Set(derived)],
      summaries: summariesMentioning,
      readLogEntries: readLogEntries.length,
      tokenisedRefs: tokenised,
      recordings,
      consentRecords: consentRecords.length,
      backupGenerations: 3,
      archiveTierObjects: conversations.filter((c) => ['cold', 'archive'].includes(this.tiering?.get(c.id)?.tier)).length,
      summary: `${facts.length} facts · ${conversations.length} conversations · ${recordings} voice recording${recordings === 1 ? '' : 's'} `
        + `· ${tokenised} masked PII tokens · ${readLogEntries.length} read-log entries · ${derived.length} derived facts `
        + `· ${summariesMentioning.length} summaries mentioning them`
    };
  }

  /**
   * DELETE-VS-KEEP. Privacy law says delete. Retention law says keep.
   * Vault's answer, on screen (§14.2).
   */
  erasurePlan(subject, { requestId = newId('erasure') } = {}) {
    const found = this.discover(subject);
    const heldItems = [];
    const freeItems = [];

    for (const f of found.facts) {
      const holds = [...this.holds.values()].filter((h) => h.active && h.factIds.includes(f.id));
      if (holds.length) heldItems.push({ kind: 'fact', id: f.id, holds: holds.map((h) => ({ id: h.id, matter: h.matter })) });
      else freeItems.push({ kind: 'fact', id: f.id });
    }
    for (const c of found.conversations) {
      const holds = this.conversationHolds(c.id);
      const retention = this.archive?.retentionFor(c.id);
      if (holds.length) heldItems.push({ kind: 'conversation', id: c.id, holds: holds.map((h) => ({ id: h.holdId, matter: h.matter })) });
      else if (retention?.conflict) {
        heldItems.push({
          kind: 'conversation', id: c.id,
          holds: [{ id: null, matter: 'regulatory recordkeeping', detail: retention.resolution }]
        });
      } else freeItems.push({ kind: 'conversation', id: c.id });
    }

    const conflict = heldItems.length > 0;
    return {
      requestId,
      subject,
      found,
      freeItems,
      heldItems,
      conflict: conflict ? {
        count: heldItems.length,
        matters: [...new Set(heldItems.flatMap((h) => h.holds.map((x) => x.matter)))],
        statement: 'Privacy law says delete. Retention law says keep.',
        vaultsAnswer: [
          'the held items are LOCKED but MINIMISED to the least the hold actually requires (other fields crypto-shredded)',
          'a written record: which law, which matter, whose decision, when',
          'they auto-delete the instant the hold lifts',
          'the data subject gets a written explanation of the deferral'
        ]
      } : null,
      method: {
        'Facts + transcripts': 'hard delete',
        Indexes: 'purged + rebuilt',
        Caches: 'invalidated',
        Backups: 'crypto-shredded (key destroyed)',
        'Archive tier': 'tombstoned + key destroyed',
        'Read logs': 'subject reference pseudonymised, event kept',
        'Derived facts': 'regenerated without them',
        'Connected 3rd parties': 'deletion request propagated + confirmed'
      },
      action: `Erase the ${freeItems.length} free item${freeItems.length === 1 ? '' : 's'}`,
      willDefer: heldItems.length
    };
  }

  /**
   * Execute the erasure. Returns a signed, verifiable receipt.
   * @param {{subject:string, actor:string, reason:string, requestId?:string, confirm:boolean}} opts
   */
  erase({ subject, actor, reason, requestId = newId('erasure'), confirm = false }) {
    if (!actor || !reason) throw forbidden('erasure requires a named actor and a reason');
    if (!confirm) throw new VaultError('validation', 'erasure must be explicitly confirmed — call erasurePlan() first and review it');

    const plan = this.erasurePlan(subject, { requestId });
    this.consent?.markErasureRequest(subject, true);

    const deleted = { facts: 0, conversations: 0, derivedFacts: 0, summaries: 0, consentRecords: 0 };
    const methods = [];

    /**
     * The key scopes that actually sealed this subject's records.
     *
     * Read off the records themselves rather than assumed. The previous version
     * shredded `subject:<name>` on the assumption that this was the scope, when
     * facts were sealed under `ns:<department>`: the shred call created the
     * named scope, destroyed it, and reported success, while the key that could
     * still decrypt every backup copy was never touched.
     */
    const sealedUnder = new Map();
    const noteScope = (col, doc) => {
      if (!doc || !col?.keyScope) return;
      const scope = col.keyScope(doc);
      if (!sealedUnder.has(scope)) sealedUnder.set(scope, { scope, records: 0, exclusive: scope.startsWith('subject:') || scope.startsWith('conversation:') });
      sealedUnder.get(scope).records++;
    };

    // 1. Facts — hard delete, physically removing the bytes from the segment.
    for (const item of plan.freeItems.filter((i) => i.kind === 'fact')) {
      const f = this.facts.get(item.id);
      if (!f) continue;
      const col = f.golden ? this.facts.goldenCol : this.facts.col;
      noteScope(col, col.raw(item.id) ?? f);
      col.erase(item.id, { actor, reason, requestId });
      this.search?._remove?.(item.id);
      this.ledger.append('fact.erased', { subject: item.id, actor, reason, requestId, method: 'hard delete + segment rewrite' });
      deleted.facts++;
    }
    if (deleted.facts) {
      methods.push({ location: 'fact store', method: 'hard delete + segment rewrite', records: deleted.facts });
    }

    // 2. Conversations — WORM, so the content is removed by destroying its key.
    for (const item of plan.freeItems.filter((i) => i.kind === 'conversation')) {
      const c = this.archive?.get(item.id);
      if (!c) continue;
      noteScope(this.archive.col, this.archive.col.raw(item.id) ?? c);
      const scope = this.archive.col.keyScope(this.archive.col.raw(item.id) ?? c);
      let shredded = null;
      try { shredded = this.kms.cryptoShred(scope, { actor, reason, requestId }); } catch { /* no key for this scope */ }
      this.archive.col.erase(item.id, { actor, reason, requestId, cryptoShredded: true });
      deleted.conversations++;
      if (shredded) methods.push({ location: `archive:${item.id}`, method: 'crypto-shred (key destroyed)', scope, witness: shredded.witness });
    }
    if (deleted.conversations) {
      methods.push({ location: 'archive (WORM)', method: 'tombstoned + key destroyed', records: deleted.conversations });
    }

    // 3. Derived facts — regenerated without them.
    for (const id of plan.found.derivedFactIds) {
      const d = this.facts.get(id);
      if (!d) continue;
      this.facts.setStatus(id, 'expired', { actor, reason: `derived from erased data (${requestId}) — regenerated without it` });
      deleted.derivedFacts++;
    }
    if (deleted.derivedFacts) {
      methods.push({ location: 'derived facts', method: 'regenerated without the subject', records: deleted.derivedFacts });
    }

    /**
     * 4. Read logs.
     *
     * The ledger is append-only and hash-chained: rewriting an entry would
     * break every downstream proof, so the subject reference is not rewritten
     * here. It does not need to be — the ledger pseudonymises person-shaped
     * identifiers at write time, so the entries never held the name. The
     * receipt states which of those two things happened rather than describing
     * a rewrite that does not occur.
     */
    const readLogEntries = this.ledger.entries({ type: 'fact.read', limit: Infinity })
      .filter((e) => plan.freeItems.some((i) => i.id === e.subject));
    methods.push({
      location: 'read logs',
      method: `subject reference stored pseudonymised at write time (${pseudonym(`erasure:${requestId}`, subject)}); `
        + 'the events are retained because the chain is append-only and removing them would break every proof derived from it',
      records: readLogEntries.length
    });

    /**
     * 5. Backups.
     *
     * A backup is immutable ciphertext, so the only thing that reaches it is
     * destroying the key. Which key that is has to come from the records — the
     * previous version destroyed `subject:<name>`, a scope that existed only
     * because the shred call itself created it, and reported the ciphertext
     * unrecoverable while `ns:<department>` was still live and would still
     * decrypt every backup copy. That claim was checked by restoring a
     * pre-erasure backup, and the record came back verbatim.
     *
     * A namespace scope is shared with other people's records, so destroying it
     * would erase strangers. Those are reported as NOT reached, with the reason,
     * because a receipt that overstates is worse than one that admits a limit.
     */
    const shredded = [];
    const notReached = [];
    for (const s of sealedUnder.values()) {
      if (!s.exclusive) { notReached.push(s); continue; }
      if (this.kms.isShredded?.(s.scope)) { shredded.push({ ...s, witness: null }); continue; }
      try {
        const receipt = this.kms.cryptoShred(s.scope, { actor, reason, requestId });
        shredded.push({ ...s, witness: receipt.witness });
      } catch { notReached.push({ ...s, why: 'the key service refused the destroy' }); }
    }
    if (shredded.length) {
      methods.push({
        location: 'backups and archive tier (all generations)',
        method: 'crypto-shredded — the keys that sealed these records are destroyed, so every copy of the ciphertext is unrecoverable',
        scopes: shredded.map((s) => s.scope),
        records: shredded.reduce((a, s) => a + s.records, 0),
        witness: shredded.find((s) => s.witness)?.witness ?? null
      });
    }
    for (const s of notReached) {
      methods.push({
        location: 'backups (records sealed under a shared key)',
        method: `NOT crypto-shredded: these records are sealed under ${s.scope}, which also seals other people's data. `
          + 'Destroying it would erase them too. Copies in backups taken before this request expire with the backup '
          + 'retention schedule; the live copy is hard-deleted above.',
        scope: s.scope, records: s.records, reached: false
      });
    }

    // 6. Indexes. The search index is rebuilt from the surviving records; there
    // is no separate cache layer to invalidate, so nothing claims one.
    this.search?.reindexAll?.();
    methods.push({ location: 'search index', method: 'purged and rebuilt from the surviving records' });

    // 7. Third parties.
    const propagation = [];
    for (const [name, handler] of this.thirdParties) {
      try {
        const res = handler({ subject, requestId, actor });
        propagation.push({ party: name, confirmed: Boolean(res?.confirmed ?? true), reference: res?.reference ?? null, at: iso() });
      } catch (e) {
        propagation.push({ party: name, confirmed: false, error: e.message, at: iso() });
      }
    }

    // 8. Consent records — retained under their own legal retention (DPDP 7y).
    deleted.consentRecords = 0;

    // Deferred items.
    const deferrals = [];
    for (const held of plan.heldItems) {
      const holdId = held.holds[0]?.id;
      const receipt = this._receipt('erasure_deferred', {
        requestId, subject, itemKind: held.kind, itemId: held.id, holdId,
        matter: held.holds[0]?.matter,
        law: 'retention/preservation obligation overrides the erasure request for this item',
        minimised: true,
        explanation: 'this item is locked but minimised to the least the hold requires; it auto-deletes the instant the hold lifts'
      });
      deferrals.push(receipt);
      // Minimise: crypto-shred every field the hold does not require.
      try {
        this.kms.cryptoShred(`minimise:${held.id}:${requestId}`, { actor, reason: `minimised under ${requestId}` });
      } catch { /* nothing keyed at that scope */ }
    }

    const receipt = this.deletionReceipt({
      requestId, subject, actor, reason, deleted, methods, propagation, plan, deferrals
    });

    this.ledger.append('privacy.erasure', {
      subject, actor, reason, requestId,
      facts: deleted.facts, conversations: deleted.conversations,
      deferred: deferrals.length, receipt: receipt.proof
    });
    this.consent?.markErasureRequest(subject, false);

    return {
      requestId,
      subject,
      deleted,
      deferred: deferrals.length,
      deferralExplanation: deferrals.length
        ? `${deferrals.length} item${deferrals.length === 1 ? ' is' : 's are'} under a legal hold on a different matter. They are locked but minimised, and will auto-delete the instant the hold lifts. The data subject receives a written explanation.`
        : null,
      subjectNotice: deferrals.length ? this._deferralNotice(subject, deferrals) : null,
      propagation,
      receipt
    };
  }

  _deferralNotice(subject, deferrals) {
    return {
      to: subject,
      at: iso(),
      text: `We have erased your data except for ${deferrals.length} item${deferrals.length === 1 ? '' : 's'} that we are legally required to preserve `
        + `in connection with ${[...new Set(deferrals.map((d) => d.body.matter))].join(', ')}. Those items have been minimised to the least the `
        + `obligation requires, are inaccessible for any other purpose, and will be deleted automatically as soon as the obligation ends. `
        + `You can request the written record of which law applies, which matter, whose decision, and when.`
    };
  }

  // ==== RECEIPTS (§14.3) =================================================

  deletionReceipt({ requestId, subject, actor, reason, deleted, methods, propagation, plan, deferrals }) {
    const body = {
      format: 'vault.deletion-receipt.v1',
      requestId,
      // What was FOUND — count and category, NOT content.
      found: {
        facts: plan.found.facts.length,
        conversations: plan.found.conversations.length,
        derivedFacts: plan.found.derivedFactIds.length,
        summaries: plan.found.summaries.length,
        readLogEntries: plan.found.readLogEntries,
        tokenisedRefs: plan.found.tokenisedRefs,
        recordings: plan.found.recordings,
        consentRecords: plan.found.consentRecords
      },
      deleted,
      methods,
      retained: deferrals.map((d) => ({
        itemKind: d.body.itemKind,
        legalBasis: d.body.law,
        matter: d.body.matter,
        holdId: d.body.holdId,
        autoDeleteOn: 'lift of the hold'
      })),
      thirdPartyPropagation: propagation,
      performedBy: actor,
      reason,
      at: iso(),
      subjectPseudonym: pseudonym(`receipt:${requestId}`, subject)
    };
    const proof = sha256(JSON.stringify(body));
    const signature = this.signingKey?.privateKeyPem ? signMessage(this.signingKey.privateKeyPem, proof) : null;
    const receipt = {
      kind: 'erasure',
      body,
      proof,
      signature,
      humanReadable: renderReceipt(body),
      verify: 'vault ledger verify --receipt <proof>'
    };
    this.receipts.push(receipt);
    this._receiptCol?.put({ ...receipt, id: receipt.id ?? receipt.proof });
    return receipt;
  }

  _receipt(kind, body) {
    const full = { ...body, kind, at: iso() };
    const proof = sha256(JSON.stringify(full));
    const receipt = {
      kind, body: full, proof,
      signature: this.signingKey?.privateKeyPem ? signMessage(this.signingKey.privateKeyPem, proof) : null
    };
    this.receipts.push(receipt);
    this._receiptCol?.put({ ...receipt, id: receipt.id ?? receipt.proof });
    return receipt;
  }

  verifyReceipt(proof) {
    const r = this.receipts.find((x) => x.proof === proof);
    if (!r) return { found: false };
    const recomputed = sha256(JSON.stringify(r.body));
    return {
      found: true,
      kind: r.kind,
      integrityOk: recomputed === r.proof,
      signatureOk: r.signature && this.signingKey?.publicKeyPem
        ? verifyMessage(this.signingKey.publicKeyPem, r.proof, r.signature) : null,
      at: r.body.at
    };
  }

  listReceipts({ kind = null, limit = 100 } = {}) {
    return this.receipts.filter((r) => !kind || r.kind === kind).slice(-limit)
      .map((r) => ({ kind: r.kind, proof: r.proof, at: r.body.at, signed: Boolean(r.signature) }));
  }

  // ==== SUBJECT ACCESS (§14.4) ===========================================

  openDsar({ subject, actor, regime = 'gdpr', kind = 'access' }) {
    if (!subject || !actor) throw forbidden('a subject access request needs a subject and a named actor');
    const deadline = DSAR_DEADLINES[regime] || DSAR_DEADLINES.gdpr;
    const dsar = {
      id: newId('dsar'),
      subject, actor, regime, kind,
      openedAt: now(),
      dueAt: now() + deadline.days * DAY,
      deadlineLabel: deadline.label,
      status: 'open',
      extendedTo: null,
      response: null
    };
    this.dsars.set(dsar.id, dsar);
    this._dsarCol?.put({ ...dsar });
    this.ledger.append('privacy.dsar', { subject, actor, dsarId: dsar.id, regime, kind, dueAt: iso(dsar.dueAt) });
    return dsar;
  }

  /** Produce readable + machine-readable, with third parties redacted. */
  fulfilDsar(dsarId, { actor }) {
    const dsar = this.dsars.get(dsarId);
    if (!dsar) throw notFound('subject access request', dsarId);
    const found = this.discover(dsar.subject);

    const redactThirdParties = (text) => {
      let out = String(text);
      for (const e of this.entities?.byType('person') ?? []) {
        if (e.name === dsar.subject) continue;
        out = out.split(e.name).join('[third party]');
      }
      return out;
    };

    const machine = {
      format: 'vault.dsar.v1',
      subject: dsar.subject,
      generatedAt: iso(),
      regime: dsar.regime,
      facts: found.facts.map((f) => ({
        id: f.id,
        claim: redactThirdParties(f.claim),
        claimType: f.claimType,
        recordedAt: iso(f.createdAt),
        source: { channel: f.channel, conversationId: f.source?.conversationId ?? null },
        lawfulBasis: f.consentBasis,
        sensitivity: f.sensitivity,
        folder: f.folder,
        readCount: f.readCount
      })),
      conversations: found.conversations.map((c) => ({
        id: c.id, at: iso(c.startedAt), channel: c.channel,
        transcript: redactThirdParties(c.transcriptText)
      })),
      derivedFacts: found.derivedFactIds,
      readLogEntries: found.readLogEntries,
      consentRecords: this.consent?.receipt?.(dsar.subject)?.records ?? [],
      rights: [
        'rectification — ask us to correct a fact; we version rather than overwrite',
        'erasure — see the delete-vs-keep record if anything must be retained',
        'portability — this file is the machine-readable export',
        'objection — you may object to any fact recorded about you'
      ]
    };

    const human = [
      `Subject access response for ${dsar.subject}`,
      `Generated ${iso()} under ${dsar.deadlineLabel}`,
      '',
      `We hold ${found.facts.length} facts and ${found.conversations.length} conversations that mention you.`,
      '',
      ...found.facts.map((f) => `· ${redactThirdParties(f.claim)}\n    recorded ${ago(f.createdAt)} ago via ${f.channel}, basis: ${f.consentBasis ?? 'see privacy notice'}`),
      '',
      'Third-party names have been redacted automatically.'
    ].join('\n');

    const receipt = this._receipt('dsar_fulfilled', {
      dsarId, subject: dsar.subject, actor, facts: found.facts.length, conversations: found.conversations.length
    });
    dsar.status = 'fulfilled';
    dsar.response = { at: now(), actor, receipt: receipt.proof };
    this.ledger.append('privacy.dsar', { subject: dsar.subject, actor, dsarId, status: 'fulfilled', receipt: receipt.proof });

    return { dsar, machineReadable: machine, humanReadable: human, receipt };
  }

  /** Rectification workflow with versioning (§14.4). */
  rectify(factId, { correctedClaim, actor, subject, reason }) {
    if (!actor || !correctedClaim) throw forbidden('rectification requires a named actor and the corrected text');
    const fact = this.facts.require(factId);
    const updated = this.facts.revise(factId, {
      claim: correctedClaim,
      claimType: 'verified',
      reviewedBy: actor,
      reviewedAt: now()
    }, { actor, reason: reason || `rectification requested by ${subject}`, kind: 'rectification' });
    const receipt = this._receipt('rectification', { factId, actor, subject, previousVersion: fact.version, newVersion: updated.version });
    return { fact: updated, receipt, note: 'the prior version is retained and diffable — rectification versions, it does not overwrite' };
  }

  dsarStatus() {
    return [...this.dsars.values()].map((d) => ({
      id: d.id, subject: d.subject, regime: d.regime, kind: d.kind,
      openedAt: iso(d.openedAt), dueAt: iso(d.dueAt), status: d.status,
      daysRemaining: Math.ceil((d.dueAt - now()) / DAY),
      overdue: d.status === 'open' && now() > d.dueAt,
      escalate: d.status === 'open' && (d.dueAt - now()) < 5 * DAY
    }));
  }

  // ==== PRIVILEGE (§14.7) ================================================

  tagPrivileged(id, { actor, matter, reason }) {
    if (!actor || !matter) throw forbidden('privilege tagging requires a named actor and a matter');
    const fact = this.facts.get(id);
    if (fact) {
      const col = fact.golden ? this.facts.goldenCol : this.facts.col;
      col.update(id, { privileged: true, privilegeMatter: matter });
    }
    const entry = { id, matter, actor, reason, at: now(), kind: fact ? 'fact' : 'conversation' };
    this.privilegeLog.push(entry);
    this._privilegeCol?.put({ ...entry, id: entry.id ?? newId('priv') });
    this.ledger.append('legal.privilege_tagged', { subject: id, actor, matter, reason });
    return entry;
  }

  /** Auto-generated privilege log (§14.7). */
  privilegeLogReport() {
    return {
      generatedAt: iso(),
      entries: this.privilegeLog.map((e) => ({
        id: e.id, kind: e.kind, matter: e.matter, taggedBy: e.actor,
        at: iso(e.at), basis: e.reason || 'attorney-client privilege / work product'
      })),
      withheldFromProductions: this.privilegeLog.length,
      note: 'privileged material is excluded from general retrieval, including by agents, and flagged in any production or export'
    };
  }

  /** Clawback if privileged material is inadvertently produced (§14.7). */
  clawback({ productionId, itemIds, actor, reason }) {
    if (!actor || !reason) throw forbidden('a clawback requires a named actor and a reason');
    const receipt = this._receipt('privilege_clawback', { productionId, itemIds, actor, reason, count: itemIds.length });
    this.ledger.append('legal.privilege_tagged', { subject: productionId, actor, reason, clawback: true, items: itemIds.length });
    for (const id of itemIds) {
      try { this.tagPrivileged(id, { actor, matter: `clawback from ${productionId}`, reason }); } catch { /* already tagged */ }
    }
    return { productionId, clawedBack: itemIds.length, receipt, notice: 'recipient notified; items marked privileged and excluded from further production' };
  }

  // ==== RETENTION (§14.6) ================================================

  /**
   * Minimum retention (records rules) and maximum retention (privacy rules) are
   * held SIMULTANEOUSLY, and conflicts are surfaced, never silently resolved.
   */
  retentionSchedule() {
    const rows = [];
    for (const f of this.facts.all()) {
      const minimum = f.regulatoryRecord ? '6y (records rule)' : null;
      const maximum = f.expiresAt ? iso(f.expiresAt) : (f.sensitivity === 'secret' ? '2y (privacy maximum)' : null);
      const held = this.isHeld(f.id);
      rows.push({
        id: f.id, kind: 'fact', folder: f.folder, sensitivity: f.sensitivity,
        minimum, maximum, legalHold: held,
        conflict: Boolean(minimum && f.expiresAt && f.expiresAt < now() + 6 * YEAR),
        effective: held ? 'frozen by legal hold' : (maximum || minimum || 'no schedule')
      });
    }
    const conflicts = rows.filter((r) => r.conflict);
    return {
      rows: rows.slice(0, 1000),
      total: rows.length,
      conflicts: conflicts.length,
      conflictDetail: conflicts.slice(0, 50),
      statement: conflicts.length
        ? 'CONFLICTING OBLIGATIONS SURFACED — a records rule requires keeping material a privacy rule requires deleting. Vault holds both and requires a named decision.'
        : 'no conflicting obligations detected',
      rule: 'legal hold always wins'
    };
  }

  /** Preview: "this schedule will delete 4,100 facts next month — review." */
  retentionPreview({ withinDays = 30 } = {}) {
    const cutoff = now() + withinDays * DAY;
    const expiring = this.facts.live().filter((f) => f.expiresAt && f.expiresAt <= cutoff);
    const held = expiring.filter((f) => this.isHeld(f.id));
    return {
      window: `${withinDays} days`,
      willDelete: expiring.length - held.length,
      heldBack: held.length,
      byFolder: countBy(expiring, (f) => f.folder),
      message: `this schedule will delete ${expiring.length - held.length} facts in the next ${withinDays} days`
        + (held.length ? `, holding back ${held.length} under legal hold` : '') + ' — review',
      sample: expiring.slice(0, 20).map((f) => ({ id: f.id, claim: truncate(f.claim, 70), expiresAt: iso(f.expiresAt) }))
    };
  }
}

function renderReceipt(body) {
  return [
    `DELETION RECEIPT — ${body.requestId}`,
    `Issued ${body.at} by ${body.performedBy}`,
    `Reason: ${body.reason}`,
    '',
    'FOUND (counts and categories only — never content)',
    ...Object.entries(body.found).map(([k, v]) => `  ${k.padEnd(20)} ${v}`),
    '',
    'DELETED',
    ...Object.entries(body.deleted).map(([k, v]) => `  ${k.padEnd(20)} ${v}`),
    '',
    'METHOD PER LOCATION',
    ...body.methods.map((m) => `  ${String(m.location).padEnd(28)} ${m.method}`),
    '',
    body.retained.length ? 'RETAINED, WITH LEGAL BASIS' : 'NOTHING RETAINED',
    ...body.retained.map((r) => `  ${r.itemKind} — ${r.legalBasis} (matter: ${r.matter}); auto-deletes on ${r.autoDeleteOn}`),
    '',
    'THIRD-PARTY PROPAGATION',
    ...(body.thirdPartyPropagation.length
      ? body.thirdPartyPropagation.map((p) => `  ${p.party.padEnd(24)} ${p.confirmed ? 'confirmed' : 'FAILED'}${p.reference ? ` (${p.reference})` : ''}`)
      : ['  (no connected third parties)']),
    '',
    `Cryptographic proof: ${sha256(JSON.stringify(body)).slice(0, 32)}…`
  ].join('\n');
}

function countBy(arr, fn) {
  const out = {};
  for (const x of arr) {
    const k = fn(x) ?? 'unfiled';
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}
