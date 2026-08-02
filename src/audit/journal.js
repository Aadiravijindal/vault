/**
 * THE JOURNAL — the detailed record, beside the sealed one.
 *
 * The ledger already records everything that happens, and deliberately records
 * very little about it: content is stripped on the way in, payloads are ids and
 * hashes, and the whole thing is designed so it can be handed to an auditor
 * without a privacy review. That is the right design for a tamper-evident chain
 * and it is exactly the wrong design for the question a regulator actually
 * asks, which is never "did seq 4,812 hash correctly". It is:
 *
 *   "Show me everything that ever happened to this record, and who did it."
 *
 * Answering that from the ledger means joining a hash chain to a fact store to
 * a version history to a review queue to an archive, and the joins are where
 * the gaps are. This is that answer, assembled once, at the moment each thing
 * happens, while the context is still in scope.
 *
 * ── WHAT AN ENTRY CARRIES ───────────────────────────────────────────────────
 *
 *   WHO    actor id, kind, department, clearance, on whose behalf, session,
 *          credential, source address
 *   WHAT   the action, the subject, the subject's kind and version
 *   WHEN   wall clock and a monotonic sequence, so ordering survives a clock
 *          that jumps
 *   WHERE  folder, namespace, region, storage tier
 *   WHY    the stated reason, the purpose of the access, the legal basis
 *   HOW    channel, connector, connector mode, API route, whether a model was
 *          involved and which one
 *   WHAT CHANGED  before and after, field by field
 *   RESULT  allowed or refused, and the reason either way
 *
 * ── WHY REFUSALS ARE RECORDED AS LOUDLY AS SUCCESSES ────────────────────────
 *
 * A log of things that worked describes a system nobody attacked. The entries
 * that matter in an investigation are the ones where somebody asked for
 * something and did not get it — the wall hits, the failed searches, the reads
 * that returned less than was there. Those are recorded with the same detail as
 * a successful write, and `refusals()` exists so nobody has to grep for them.
 *
 * ── WHY IT IS SEPARATE FROM THE LEDGER, NOT MERGED INTO IT ──────────────────
 *
 * Because they have opposite requirements. The ledger must be small, content-
 * free and provable. The journal must be complete, which means it holds things
 * the ledger deliberately refuses — excerpts, queries, before-and-after values.
 * Merging them would mean either a ledger that cannot be handed over, or a
 * journal that cannot answer the question. So: two records, cross-referenced,
 * and every journal entry carries the ledger sequence it corresponds to. An
 * auditor can verify the chain and read the detail, and check that the two
 * agree.
 *
 * The journal is hash-chained too. It is a weaker chain than the ledger's —
 * this collection is not WORM — but a chain that makes deletion visible is
 * still worth having, and `verify()` reports gaps rather than hiding them.
 */
import { newId } from '../util/id.js';
import { hashObject, chainHash, sha256, signMessage } from '../util/crypto.js';
import { now, iso, ago, DAY } from '../util/time.js';
import { truncate } from '../util/text.js';
import { VaultError, notFound } from '../util/errors.js';

/**
 * Every action the journal knows how to record.
 *
 * Explicit, like the ledger's list, and for the same reason: a free-text action
 * field means two people log the same event under three names and no query ever
 * finds all of it. An unknown action is a programming error, not a new category.
 */
export const ACTIONS = [
  // capture
  'message.received', 'message.sealed', 'attachment.inspected',
  'fact.extracted', 'fact.written', 'fact.held', 'fact.blocked', 'fact.masked',
  'fact.merged', 'fact.refined', 'fact.superseded', 'fact.quarantined',
  // change
  'fact.revised', 'fact.tagged', 'fact.untagged', 'fact.locked', 'fact.unlocked',
  'fact.moved', 'fact.relabelled', 'fact.expired', 'fact.erased', 'fact.restored',
  'fact.frozen', 'fact.released',
  // access
  'fact.read', 'search.performed', 'ask.performed', 'ask.refused', 'export.performed',
  'read.refused', 'wall.blocked',
  // human decisions
  'review.decided', 'review.escalated', 'golden.created', 'golden.reattested',
  // the model
  'model.called', 'model.filed', 'model.refused', 'model.proposed', 'model.flagged',
  'memory.learned', 'memory.recalled', 'memory.saved',
  // administration
  'folder.created', 'folder.proposed', 'folder.approved', 'folder.rejected',
  'folder.wall_changed', 'agent.registered', 'agent.disconnected', 'admin.action',
  'journal.exported'
];

/** Actions that mean somebody asked for something and did not get it. */
const REFUSALS = new Set(['ask.refused', 'read.refused', 'wall.blocked', 'fact.blocked', 'model.refused', 'folder.rejected']);

export class Journal {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} [opts.ledger]
   * @param {{privateKeyPem?:string, publicKeyPem?:string}} [opts.signingKey]
   * @param {number} [opts.excerptLimit] how much claim text an entry may carry
   */
  constructor({ collection, ledger = null, signingKey = null, excerptLimit = 400 }) {
    this.col = collection;
    this.ledger = ledger;
    this.signingKey = signingKey;
    this.excerptLimit = excerptLimit;
    this.col.index('bySubject', (e) => e.subject);
    this.col.index('byActor', (e) => e.actor?.id);
    this.col.index('byAction', (e) => e.action);
    this.col.index('byFolder', (e) => e.where?.folder);
    const existing = this.col.all().sort((a, b) => a.seq - b.seq);
    this.seq = existing.length ? existing[existing.length - 1].seq : 0;
    this.head = existing.length ? existing[existing.length - 1].hash : 'GENESIS';
  }

  /**
   * Record one thing that happened.
   *
   * Every field is optional except the action and the subject, because a caller
   * that has to assemble a perfect record before it can log anything logs
   * nothing. Whatever context is in scope goes in; what is missing is visibly
   * missing rather than quietly absent.
   *
   * @param {string} action one of ACTIONS
   * @param {object} o
   * @param {string} o.subject what this happened to (a fact id, a folder, an agent)
   * @param {string} [o.subjectKind]
   * @param {object} [o.actor] { id, kind, department, clearance, onBehalfOf, sessionId, credentialId, ip }
   * @param {object} [o.where] { folder, namespace, region, tier }
   * @param {string} [o.why] the stated reason
   * @param {string} [o.purpose] declared purpose of access
   * @param {object} [o.how] { channel, connector, connectorMode, route, model, provider }
   * @param {object} [o.before] state before
   * @param {object} [o.after] state after
   * @param {boolean} [o.allowed]
   * @param {string} [o.outcome]
   * @param {string} [o.excerpt] content, truncated — the one place the journal holds text
   * @param {object} [o.detail] anything else worth keeping
   */
  record(action, {
    subject, subjectKind = 'fact', actor = null, where = null, why = null, purpose = null,
    how = null, before = null, after = null, allowed = true, outcome = null,
    excerpt = null, detail = null, ledgerSeq = null
  } = {}) {
    if (!ACTIONS.includes(action)) {
      throw new VaultError('internal', 'unknown journal action', { action, known: ACTIONS.length });
    }
    const seq = ++this.seq;
    const at = now();
    const body = {
      id: `j-${String(seq).padStart(12, '0')}`,
      seq,
      at,
      atIso: iso(at),
      action,
      subject: subject ?? null,
      subjectKind,
      actor: normaliseActor(actor),
      where: where ?? null,
      why: why ?? null,
      purpose: purpose ?? null,
      how: how ?? null,
      changed: diffOf(before, after),
      before: before ?? null,
      after: after ?? null,
      allowed,
      refusal: REFUSALS.has(action) || allowed === false,
      outcome: outcome ?? (allowed === false ? 'refused' : 'ok'),
      excerpt: excerpt == null ? null : truncate(String(excerpt), this.excerptLimit),
      excerptHash: excerpt == null ? null : sha256(String(excerpt)),
      detail: detail ?? null,
      ledgerSeq: ledgerSeq ?? this.ledger?.seq ?? null
    };
    body.contentHash = hashObject(body);
    body.prevHash = this.head;
    body.hash = chainHash(this.head, body.contentHash);
    this.head = body.hash;
    return this.col.insert(body);
  }

  // == reading it back =====================================================

  /**
   * Everything that ever happened to one subject, oldest first.
   *
   * This is the query the whole file exists for. It is deliberately a single
   * index lookup rather than a scan, because an investigator asking it about a
   * fact in a ten-million-fact estate should not be paying for the other
   * 9,999,999.
   */
  forSubject(subject) {
    return this.col.by('bySubject', subject).sort((a, b) => a.seq - b.seq);
  }

  /** Everything one person or agent did. The other half of an investigation. */
  forActor(actorId, { limit = 500 } = {}) {
    return this.col.by('byActor', actorId).sort((a, b) => b.seq - a.seq).slice(0, limit);
  }

  /**
   * Filtered entries, newest first.
   *
   * An index is chosen to narrow the candidate set, and then EVERY filter is
   * applied to what comes back — including the one the index already covers.
   * Re-checking a condition the index guaranteed looks redundant and is not: the
   * previous version applied only the filters it thought the chosen index had
   * missed, so `{ actor, folder }` picked the folder index and never filtered by
   * actor at all. That is the failure mode that matters here, because it returns
   * MORE than was asked for and the caller cannot tell — an investigator
   * filtering the audit record to one person got everyone.
   */
  entries({ action = null, actor = null, subject = null, folder = null, from = null, to = null, refusalsOnly = false, limit = 500 } = {}) {
    let out = subject ? this.col.by('bySubject', subject)
      : action ? this.col.by('byAction', action)
        : actor ? this.col.by('byActor', actor)
          : folder ? this.col.by('byFolder', folder)
            : this.col.all();
    if (action) out = out.filter((e) => e.action === action);
    if (actor) out = out.filter((e) => e.actor?.id === actor);
    if (subject) out = out.filter((e) => e.subject === subject);
    if (folder) out = out.filter((e) => e.where?.folder === folder);
    if (from != null) out = out.filter((e) => e.at >= from);
    if (to != null) out = out.filter((e) => e.at <= to);
    if (refusalsOnly) out = out.filter((e) => e.refusal);
    return out.sort((a, b) => b.seq - a.seq).slice(0, limit);
  }

  /** Everything somebody asked for and did not get. */
  refusals({ sinceMs = 30 * DAY, limit = 500 } = {}) {
    return this.col.find((e) => e.refusal && e.at >= now() - sinceMs)
      .sort((a, b) => b.seq - a.seq).slice(0, limit);
  }

  /**
   * The complete life of one record, in the shape a regulator reads it.
   *
   * Narrative first, structure underneath. An auditor should be able to read
   * the first screen and understand what happened without knowing anything
   * about how this system is built — and then check every sentence of it
   * against the entries below.
   */
  dossier(subject, { facts = null, ledger = null } = {}) {
    const entries = this.forSubject(subject);
    if (!entries.length && !facts?.get?.(subject)) throw notFound('journal subject', subject);
    const fact = facts?.get?.(subject) ?? null;
    const byAction = {};
    for (const e of entries) byAction[e.action] = (byAction[e.action] ?? 0) + 1;

    const reads = entries.filter((e) => e.action === 'fact.read');
    const changes = entries.filter((e) => e.changed?.length);
    const refused = entries.filter((e) => e.refusal);
    const modelTouches = entries.filter((e) => e.action.startsWith('model.'));
    const first = entries[0];
    const last = entries[entries.length - 1];

    return {
      subject,
      subjectKind: first?.subjectKind ?? 'fact',
      fact: fact ? {
        claim: fact.claim, folder: fact.folder, sensitivity: fact.sensitivity,
        status: fact.status, version: fact.version, tags: fact.tags ?? [],
        golden: Boolean(fact.golden), locked: Boolean(fact.locked),
        legalHold: fact.legalHold ?? null
      } : null,
      timeline: entries.map((e) => ({
        seq: e.seq, at: e.atIso, action: e.action,
        who: e.actor?.id ?? 'system', kind: e.actor?.kind ?? 'system',
        why: e.why, purpose: e.purpose,
        where: e.where?.folder ?? null,
        how: e.how ?? null,
        changed: e.changed,
        allowed: e.allowed,
        outcome: e.outcome,
        ledgerSeq: e.ledgerSeq,
        hash: e.hash
      })),
      counts: { total: entries.length, ...byAction },
      actors: [...new Set(entries.map((e) => e.actor?.id).filter(Boolean))],
      readers: [...new Set(reads.map((e) => e.actor?.id).filter(Boolean))],
      refusals: refused.map((e) => ({ at: e.atIso, who: e.actor?.id, action: e.action, reason: e.outcome })),
      modelInvolvement: modelTouches.length
        ? modelTouches.map((e) => ({ at: e.atIso, action: e.action, model: e.how?.model ?? null, why: e.why }))
        : [],
      ledger: ledger ? ledger.entries({ subject, limit: 1000 }).map((e) => ({ seq: e.seq, type: e.type, at: iso(e.at), hash: e.hash })) : null,
      narrative: entries.length
        ? `This record was first touched ${ago(first.at)} ago (${first.action}) and last touched ${ago(last.at)} ago `
          + `(${last.action}). ${entries.length} action(s) are recorded against it by ${new Set(entries.map((e) => e.actor?.id)).size} `
          + `distinct actor(s): ${reads.length} read(s), ${changes.length} change(s), ${refused.length} refusal(s)`
          + `${modelTouches.length ? `, and ${modelTouches.length} action(s) involving a model` : ', and no model has ever touched it'}. `
          + 'Every line below is individually hash-linked to the one before it, and carries the sealed-ledger sequence it corresponds to.'
        : 'Nothing is recorded against this subject.'
    };
  }

  // == handing it over =====================================================

  /**
   * A signed, self-describing bundle for a regulator or an investigator.
   *
   * Two things make this an evidence bundle rather than a dump. It states its
   * own completeness — the filters that produced it and how many entries were
   * excluded — because a selective export presented as a full one is the oldest
   * way to mislead an auditor with true statements. And it is signed over its
   * own content hash, so the recipient can prove it is the bundle that was
   * handed over and not one edited afterwards.
   *
   * The export is itself journalled. Somebody taking a copy of the record is an
   * event in the record.
   */
  export({ subject = null, actor = null, folder = null, from = null, to = null, action = null, exportedBy, reason } = {}) {
    if (!exportedBy || !reason) {
      throw new VaultError('validation', 'an export must name who is taking it and why — an unattributed copy of the audit record is not evidence, it is a leak');
    }
    const filters = { subject, actor, folder, from: from ? iso(from) : null, to: to ? iso(to) : null, action };
    const total = this.col.count();
    const entries = this.entries({ subject, actor, folder, from, to, action, limit: Infinity }).sort((a, b) => a.seq - b.seq);

    const bundle = {
      format: 'vault.journal.v1',
      exportedAt: iso(),
      exportedBy,
      reason,
      filters,
      completeness: {
        entriesInBundle: entries.length,
        entriesInJournal: total,
        excluded: total - entries.length,
        full: entries.length === total,
        statement: entries.length === total
          ? 'This is the complete journal. Nothing was filtered out.'
          : `This is a FILTERED extract: ${entries.length} of ${total} entries. ${total - entries.length} entries exist that are not in this bundle. `
            + 'The filters that produced it are stated above so the recipient can ask for the rest.'
      },
      chain: {
        head: this.head,
        verified: this.verify(),
        note: 'Each entry links to the one before it by hash. Verify by recomputing contentHash over each entry and chaining prevHash → hash.'
      },
      entries
    };
    bundle.bundleHash = hashObject({ entries: bundle.entries, filters, exportedBy, reason });
    if (this.signingKey?.privateKeyPem) {
      bundle.signature = signMessage(this.signingKey.privateKeyPem, bundle.bundleHash);
      bundle.publicKeyPem = this.signingKey.publicKeyPem ?? null;
    }

    this.record('journal.exported', {
      subject: subject ?? 'journal',
      subjectKind: 'journal',
      actor: { id: exportedBy, kind: 'human' },
      why: reason,
      detail: { filters, entries: entries.length, of: total, bundleHash: bundle.bundleHash, signed: Boolean(bundle.signature) }
    });
    return bundle;
  }

  /** Does the journal's own chain hold? Gaps are reported, not smoothed over. */
  verify({ from = 1, to = Infinity } = {}) {
    const all = this.col.all().filter((e) => e.seq >= from && e.seq <= to).sort((a, b) => a.seq - b.seq);
    const problems = [];
    let prev = from === 1 ? 'GENESIS' : (this.col.first((e) => e.seq === from - 1)?.hash ?? null);
    for (const e of all) {
      const { contentHash, prevHash, hash, _v, _created, _updated, ...body } = e;
      if (hashObject(body) !== contentHash) problems.push({ seq: e.seq, problem: 'content_hash_mismatch' });
      if (prev !== null && prevHash !== prev) problems.push({ seq: e.seq, problem: 'chain_break' });
      if (chainHash(prevHash, contentHash) !== hash) problems.push({ seq: e.seq, problem: 'link_hash_mismatch' });
      prev = e.hash;
    }
    for (let i = 1; i < all.length; i++) {
      if (all[i].seq !== all[i - 1].seq + 1) {
        problems.push({ seq: all[i].seq, problem: 'sequence_gap', missing: `${all[i - 1].seq + 1}..${all[i].seq - 1}` });
      }
    }
    return { ok: problems.length === 0, checked: all.length, problems, head: this.head };
  }

  stats() {
    const all = this.col.all();
    const byAction = {};
    for (const e of all) byAction[e.action] = (byAction[e.action] ?? 0) + 1;
    const actors = new Set(all.map((e) => e.actor?.id).filter(Boolean));
    const refused = all.filter((e) => e.refusal);
    return {
      entries: all.length,
      actions: Object.keys(byAction).length,
      byAction,
      actors: actors.size,
      refusals: refused.length,
      subjects: new Set(all.map((e) => e.subject).filter(Boolean)).size,
      oldest: all.length ? iso(Math.min(...all.map((e) => e.at))) : null,
      newest: all.length ? iso(Math.max(...all.map((e) => e.at))) : null,
      integrity: this.verify(),
      statement: `${all.length} recorded action(s) by ${actors.size} actor(s), of which ${refused.length} were refusals. `
        + 'Every action against every record is here, with who, what, when, where, why, how, and what changed — including the '
        + 'ones that were refused, which are the entries an investigation actually turns on.'
    };
  }
}

// ---------------------------------------------------------------------------

function normaliseActor(actor) {
  if (!actor) return { id: 'system', kind: 'system' };
  if (typeof actor === 'string') return { id: actor, kind: 'unknown' };
  return {
    id: actor.id ?? 'unknown',
    kind: actor.kind ?? 'unknown',
    name: actor.name ?? null,
    department: actor.department ?? null,
    clearance: actor.clearance ?? null,
    onBehalfOf: actor.onBehalfOf ?? null,
    sessionId: actor.sessionId ?? null,
    credentialId: actor.credentialId ?? null,
    ip: actor.ip ?? null
  };
}

/**
 * Field-by-field difference.
 *
 * Recorded as a list of {field, from, to} rather than two whole objects,
 * because "what changed" is the question and making a reader diff two JSON
 * blobs to find out is how a change gets missed. The full before and after are
 * kept alongside for anyone who wants them.
 */
function diffOf(before, after) {
  if (!before || !after) return [];
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const out = [];
  for (const k of keys) {
    const a = before[k];
    const b = after[k];
    if (JSON.stringify(a) === JSON.stringify(b)) continue;
    out.push({ field: k, from: compact(a), to: compact(b) });
  }
  return out;
}

function compact(v) {
  if (v == null) return v;
  if (typeof v === 'string') return truncate(v, 200);
  if (Array.isArray(v)) return v.slice(0, 20);
  return v;
}
