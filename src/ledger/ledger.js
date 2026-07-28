/**
 * The sealed ledger (§13.1–13.2).
 *
 * Every event in the system lands here, in order, hash-chained. There is no edit
 * path and no delete path in this file — that absence is the point.
 *
 * A hash chain the vendor controls proves nothing to an adversary, so the chain
 * is only the first of four layers:
 *   1. internal hash chain          — tamper-evidence for the operator
 *   2. customer-held signing keys   — the customer proves integrity, not us
 *   3. external anchoring           — periodic digests to independent witnesses
 *   4. standalone verifier          — bin/vault-verify.js, trusts neither party
 */
import { hashObject, chainHash, sha256, canonical, signMessage, verifyMessage, generateSigningKeyPair, pseudonym, randomToken } from '../util/crypto.js';
import { now, iso } from '../util/time.js';
import { VaultError } from '../util/errors.js';

export const GENESIS = 'GENESIS';

/** Every event type the ledger records. Kept explicit so nothing gets logged by accident. */
export const EVENT_TYPES = [
  'fact.written', 'fact.held', 'fact.blocked', 'fact.masked', 'fact.escalated', 'fact.quarantined',
  'fact.read', 'fact.superseded', 'fact.version', 'fact.expired', 'fact.erased', 'fact.restored',
  'golden.created', 'golden.attested', 'golden.reattested', 'golden.overwrite_refused',
  'rule.created', 'rule.changed', 'rule.deleted', 'rule.enabled', 'rule.disabled', 'rule.dryrun',
  'agent.registered', 'agent.disconnected', 'agent.scope_changed', 'agent.credential_rotated',
  'agent.suspended', 'agent.retired', 'agent.discovered',
  'review.decision', 'review.escalated', 'review.sla_breach',
  'hygiene.action',
  'folder.wall_changed', 'folder.moved', 'folder.merged',
  'admin.action', 'admin.breakglass', 'admin.module_toggled',
  'legal.hold_placed', 'legal.hold_lifted', 'legal.privilege_tagged',
  'privacy.erasure', 'privacy.dsar', 'privacy.consent_recorded', 'privacy.consent_withdrawn',
  'privacy.mode_changed', 'privacy.reidentification',
  'killswitch.engaged', 'killswitch.released',
  'key.created', 'key.rotated', 'key.destroyed', 'key.accessed', 'key.share_presented',
  'export.created', 'production.frozen',
  'archive.sealed', 'archive.restored',
  'connector.connected', 'connector.gap', 'connector.health',
  'security.alert', 'security.detection',
  'anchor.published',
  'storage.tiered', 'storage.erased', 'storage.lifecycle'
];

export class Ledger {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection WORM collection
   * @param {{privateKeyPem?:string, publicKeyPem?:string}} [opts.signingKey] customer-held
   * @param {Witness[]} [opts.witnesses]
   * @param {number} [opts.anchorEvery] anchor after N entries
   */
  constructor({ collection, signingKey = null, witnesses = [], anchorEvery = 250, pseudonymSalt = null }) {
    this.col = collection;
    this.signingKey = signingKey;
    /**
     * Salt for pseudonymising identifiers that name a person.
     *
     * Has to be stable across restart or `entries({subject})` stops finding
     * yesterday's entries, so the Vault derives it from the persisted root key.
     * A bare Ledger with no salt gets a per-process one: still no plaintext on
     * disk, but lookups do not survive a restart — which is why every Ledger
     * the product constructs is given one.
     *
     * Honest limit: this is pseudonymisation, not anonymisation. Whoever holds
     * the salt can confirm a guessed address by recomputing the HMAC. It stops
     * `grep` over a data directory and it stops an auditor handed the export
     * from reading a staff list; it is not a defence against an attacker who
     * already has the root key.
     */
    this.pseudonymSalt = pseudonymSalt || randomToken(32);
    this._pseudonymise = (v) => pseudonym(this.pseudonymSalt, String(v).trim().toLowerCase());
    this.witnesses = witnesses;
    this.anchorEvery = anchorEvery;
    this.anchors = [];
    const entries = this.col.all().sort((a, b) => a.seq - b.seq);
    this.head = entries.length ? entries[entries.length - 1].hash : GENESIS;
    this.seq = entries.length ? entries[entries.length - 1].seq : 0;
    this.subscribers = new Set();
  }

  /** @param {(entry:object)=>void} fn */
  subscribe(fn) { this.subscribers.add(fn); return () => this.subscribers.delete(fn); }

  /**
   * Append an event. Content is never stored here — only ids, verdicts, counts
   * and hashes, so the ledger itself can be handed to an auditor without a
   * privacy review.
   *
   * @param {string} type
   * @param {object} payload
   * @returns {object} the sealed entry
   */
  append(type, payload = {}) {
    if (!EVENT_TYPES.includes(type)) {
      throw new VaultError('internal', 'unknown ledger event type', { type });
    }
    const body = {
      seq: this.seq + 1,
      type,
      at: now(),
      // `actor` and `subject` are the two fields most likely to hold a person
      // rather than an id, so they get the same shape test as everything else.
      // A rule id survives verbatim; an email address does not.
      actor: this._reduceIdentity(payload.actor),
      subject: this._reduceIdentity(payload.subject),
      ...stripContent(payload, this._pseudonymise)
    };
    const contentHash = hashObject(body);
    const hash = chainHash(this.head, contentHash);
    const entry = { id: `l-${String(body.seq).padStart(12, '0')}`, ...body, contentHash, prevHash: this.head, hash };
    if (this.signingKey?.privateKeyPem) {
      entry.signature = signMessage(this.signingKey.privateKeyPem, hash);
    }
    this.col.insert(entry);
    this.head = hash;
    this.seq = body.seq;
    for (const fn of this.subscribers) {
      try { fn(entry); } catch { /* a subscriber must never break the chain */ }
    }
    if (this.anchorEvery && this.seq % this.anchorEvery === 0) this.anchor();
    return entry;
  }

  get length() { return this.seq; }

  /**
   * The stored form of an identity field.
   *
   * Identifiers pass through, so a trace on `f-123` still works. Anything
   * person-shaped is pseudonymised rather than hashed, because a hash would be
   * a dead end and the point is that lookups keep working — `entries()` runs
   * the caller's query through the same function, so searching by an email
   * address finds the entries written under its pseudonym.
   */
  _reduceIdentity(v) {
    if (v == null) return null;
    const s = String(v);
    if (EMAIL.test(s)) return this._pseudonymise(s);
    return isStructural(s) ? s : this._pseudonymise(s);
  }

  entries({ from = 1, to = Infinity, type = null, subject = null, actor = null, limit = 1000 } = {}) {
    const wantSubject = subject == null ? null : this._reduceIdentity(subject);
    const wantActor = actor == null ? null : this._reduceIdentity(actor);
    return this.col.all()
      .filter((e) => e.seq >= from && e.seq <= to)
      .filter((e) => (type ? (Array.isArray(type) ? type.includes(e.type) : e.type === type) : true))
      .filter((e) => (subject ? e.subject === wantSubject : true))
      .filter((e) => (actor ? e.actor === wantActor : true))
      .sort((a, b) => a.seq - b.seq)
      .slice(0, limit);
  }

  /**
   * Full-corpus verification. Recomputes every content hash and every link.
   * @param {{from?:number, to?:number}} [range]
   */
  verify({ from = 1, to = Infinity } = {}) {
    const started = Date.now();
    // Narrow BEFORE sorting. Verifying a hash chain is unavoidably linear in
    // the range examined — that is what a chain is — but it must not be linear
    // in the whole ledger when the caller asked for a range. At 10B entries the
    // difference between "verify the 400 entries since the last anchor" and
    // "sort 10B rows first" is the difference between a routine check and one
    // nobody ever runs.
    const everything = this.col.all();
    const anchorHash = from === 1 ? GENESIS : (everything.find((e) => e.seq === from - 1)?.hash ?? null);
    const all = everything.filter((e) => e.seq >= from && e.seq <= to).sort((a, b) => a.seq - b.seq);
    let prev = anchorHash;
    const problems = [];
    let checked = 0;
    for (const e of all) {
      checked++;
      const { id, contentHash, prevHash, hash, signature, _v, _created, _updated, ...body } = e;
      const recomputedContent = hashObject(body);
      if (recomputedContent !== contentHash) {
        problems.push({ seq: e.seq, problem: 'content_hash_mismatch', expected: contentHash, actual: recomputedContent });
      }
      if (prev !== null && prevHash !== prev) {
        problems.push({ seq: e.seq, problem: 'chain_break', expected: prev, actual: prevHash });
      }
      const recomputedLink = chainHash(prevHash, contentHash);
      if (recomputedLink !== hash) {
        problems.push({ seq: e.seq, problem: 'link_hash_mismatch', expected: hash, actual: recomputedLink });
      }
      if (signature && this.signingKey?.publicKeyPem) {
        if (!verifyMessage(this.signingKey.publicKeyPem, hash, signature)) {
          problems.push({ seq: e.seq, problem: 'signature_invalid' });
        }
      }
      prev = e.hash;
    }
    // Missing sequence numbers are as much a tamper signal as an altered one.
    const seqs = all.map((e) => e.seq);
    for (let i = 1; i < seqs.length; i++) {
      if (seqs[i] !== seqs[i - 1] + 1) {
        problems.push({ seq: seqs[i], problem: 'sequence_gap', missing: `${seqs[i - 1] + 1}..${seqs[i] - 1}` });
      }
    }
    return {
      ok: problems.length === 0,
      checked,
      range: { from, to: to === Infinity ? this.seq : to },
      full: from === 1 && (to === Infinity || to >= this.seq),
      problems,
      head: this.head,
      durationMs: Date.now() - started,
      anchors: this.anchors.length,
      verifiedAt: iso()
    };
  }

  /**
   * Verify only what has happened since the last external anchor.
   *
   * Everything up to that anchor was already verified when it was published,
   * and its digest is held by independent witnesses — so re-hashing it proves
   * nothing new about that span, only that the local copy still matches. This
   * is the check that can run every few minutes at any ledger size, and the
   * answer to "how do you verify 10 billion entries": you do not, routinely.
   * You verify the tail continuously and the whole chain on a schedule.
   */
  verifySinceAnchor() {
    const last = this.anchors[this.anchors.length - 1];
    if (!last) {
      const full = this.verify();
      return {
        ...full,
        sinceAnchor: false,
        note: 'no anchor has been published yet, so the whole chain was verified. Anchoring is what makes incremental verification meaningful.'
      };
    }
    const out = this.verify({ from: last.seq + 1 });
    return {
      ...out,
      sinceAnchor: true,
      anchoredAt: last.at,
      anchoredSeq: last.seq,
      witnesses: (last.receipts || []).map((r) => r.witness),
      note: `Verified ${out.checked} entries since the anchor at seq ${last.seq}. Entries at or before that point are covered by digests held by ${(last.receipts || []).length} independent witness(es); re-hashing them locally would only prove the local copy is self-consistent, which is the weaker claim.`
    };
  }

  /** Publish a digest to every configured witness (§13.2). */
  anchor() {
    const digest = {
      seq: this.seq,
      head: this.head,
      at: now(),
      corpusHash: sha256(this.col.all().sort((a, b) => a.seq - b.seq).map((e) => e.hash).join('\n'))
    };
    const receipts = [];
    for (const w of this.witnesses) {
      try {
        receipts.push(w.publish(digest));
      } catch (e) {
        receipts.push({ witness: w.name, ok: false, error: e.message });
      }
    }
    const anchor = { ...digest, at: iso(digest.at), receipts };
    this.anchors.push(anchor);
    // Recorded in-band too, so the chain contains its own anchoring history.
    if (this.col) {
      const body = { seq: this.seq + 1, type: 'anchor.published', at: now(), actor: 'system', subject: null, anchorSeq: digest.seq, corpusHash: digest.corpusHash, witnesses: receipts.map((r) => r.witness) };
      const contentHash = hashObject(body);
      const hash = chainHash(this.head, contentHash);
      this.col.insert({ id: `l-${String(body.seq).padStart(12, '0')}`, ...body, contentHash, prevHash: this.head, hash });
      this.head = hash;
      this.seq = body.seq;
    }
    return anchor;
  }

  /** Confirm the chain matches what independent witnesses were told. */
  verifyAnchors() {
    const results = [];
    for (const a of this.anchors) {
      for (const r of a.receipts) {
        const w = this.witnesses.find((x) => x.name === r.witness);
        if (!w) { results.push({ ...r, ok: false, error: 'witness not configured' }); continue; }
        results.push({ witness: r.witness, seq: a.seq, ok: w.confirm(r), at: a.at });
      }
    }
    return {
      ok: results.every((r) => r.ok),
      witnessCount: new Set(results.map((r) => r.witness)).size,
      diverse: new Set(results.map((r) => r.witness)).size > 1,
      results
    };
  }

  /** Portable chain export for the standalone verifier. */
  export({ from = 1, to = Infinity } = {}) {
    return {
      format: 'vault.ledger.v1',
      exportedAt: iso(),
      publicKeyPem: this.signingKey?.publicKeyPem || null,
      genesis: GENESIS,
      head: this.head,
      count: this.seq,
      anchors: this.anchors,
      entries: this.entries({ from, to, limit: Infinity })
    };
  }

  static newSigningKey() { return generateSigningKeyPair(); }
}

/**
 * Keys that are content by definition, hashed whatever they look like.
 *
 * The shape test below is the general defence, but it can be fooled: a claim of
 * "CONFIDENTIAL-RESTORE-CANARY." has no whitespace and reads as an identifier.
 * So these names are hashed unconditionally and first. The two rules are not
 * redundant — this one catches content that looks structural, the shape test
 * catches content under a key nobody thought to list.
 */
const CONTENT_KEYS = new Set(['content', 'text', 'claim', 'transcript', 'body', 'raw', 'value', 'plaintext', 'message', 'query', 'input', 'output', 'prompt', 'transcriptText', 'excerpt', 'snippet']);

/**
 * Operator-authored prose that stays readable, on purpose.
 *
 * These are the fields an auditor actually reads: why break-glass was used, why
 * a hold was lifted, what a rule is for. Hashing them would leave a chain that
 * verifies and answers no question anyone has, so they pass through verbatim —
 * a deliberate trade, not an oversight.
 *
 * The trade is only sound because these are written by named operators into an
 * admin field, never lifted out of a customer conversation. `assertNoContent`
 * below is what stops the second kind from arriving here by accident.
 */
const AUDIT_PROSE = new Set([
  'reason', 'note', 'notes', 'matter', 'purpose', 'justification', 'resolution',
  'remediation', 'rootCause', 'detail', 'description', 'title', 'name', 'label',
  'expression', 'scope', 'disclosure', 'finding', 'findings', 'summary'
]);

/**
 * The envelope owns these names. A payload key that collides with one silently
 * overwrites the chain's own field, and the entry then fails verification
 * forever — with no way to tell tampering from a naming accident. So collisions
 * are renamed deterministically rather than trusted not to happen.
 */
const RESERVED = new Set(['id', 'seq', 'contentHash', 'prevHash', 'hash', 'signature', '_v', '_created', '_updated']);

/** RFC-5322-ish, deliberately loose: over-matching here costs a lookup, under-matching costs a leak. */
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * A string shaped like an identifier, an enum, a hash, a path or a timestamp.
 *
 * Everything the ledger legitimately carries is one of those. Free text is not:
 * it has whitespace, or it is long, or both. So the test is on the *shape of
 * the value*, not on the name of the key — which is the whole point, because
 * the bug this replaces was a denylist of nine key names that a tenth key
 * walked straight past.
 */
const STRUCTURAL = /^[A-Za-z0-9_.:/@+=-]{0,128}$/;

function isStructural(v) {
  return STRUCTURAL.test(v) && !EMAIL.test(v);
}

/**
 * Reduce one payload value to something safe to hand an auditor.
 *
 * Fail-safe by construction: a value only survives verbatim if it is a
 * non-string primitive, an identifier-shaped string, or operator prose on the
 * explicit list. Anything else — including every key nobody thought about when
 * this was written — becomes a hash and a length. A new event type carrying a
 * new free-text field therefore lands here already redacted, rather than
 * leaking until someone notices.
 */
function reduceValue(key, v, pseudonymise) {
  if (CONTENT_KEYS.has(key)) {
    const s = v == null ? '' : typeof v === 'string' ? v : canonical(v);
    return { hash: sha256(s), len: s.length };
  }
  if (v == null || typeof v === 'number' || typeof v === 'boolean') return { verbatim: v };
  if (typeof v === 'string') {
    if (EMAIL.test(v)) return { verbatim: pseudonymise(v) };
    if (isStructural(v)) return { verbatim: v };
    if (AUDIT_PROSE.has(key)) return { verbatim: v };
    return { hash: sha256(v), len: v.length };
  }
  if (Array.isArray(v)) {
    // An array of ids or counts is structural; an array of sentences is not.
    const parts = v.map((item) => reduceValue(key, item, pseudonymise));
    if (parts.every((p) => 'verbatim' in p)) return { verbatim: parts.map((p) => p.verbatim) };
    return { hash: sha256(canonical(v)), len: v.length };
  }
  // Recurse rather than blanket-hash. `before: {read:['sales','support']}` on a
  // wall change is exactly the field an auditor asks about, and it is entirely
  // department names; hashing it would leave the chain answering "something
  // changed" and nothing else. An object survives only if every leaf in it
  // survives, so one sentence anywhere inside still redacts the whole thing.
  const reduced = {};
  for (const [k, item] of Object.entries(v)) {
    const r = reduceValue(k, item, pseudonymise);
    if (!('verbatim' in r)) return { hash: sha256(canonical(v)), len: Object.keys(v).length };
    reduced[k] = r.verbatim;
  }
  return { verbatim: reduced };
}

function stripContent(payload, pseudonymise) {
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (k === 'actor' || k === 'subject') continue;
    const key = RESERVED.has(k) ? `payload_${k}` : k;
    const r = reduceValue(k, v, pseudonymise);
    if ('verbatim' in r) { out[key] = r.verbatim; continue; }
    out[`${key}Hash`] = r.hash;
    out[`${key}Len`] = r.len;
  }
  return out;
}

/**
 * An independent append-only witness. Real deployments point these at a public
 * transparency log, a notary service, or a customer-chosen third party; the
 * interface is deliberately tiny so a customer can supply their own.
 */
export class Witness {
  constructor(name) {
    this.name = name;
    this.log = [];
  }
  publish(digest) {
    const record = { witness: this.name, seq: digest.seq, head: digest.head, corpusHash: digest.corpusHash, at: iso() };
    record.receipt = sha256(`${this.name}|${digest.seq}|${digest.head}|${digest.corpusHash}`);
    this.log.push(record);
    return { witness: this.name, ok: true, receipt: record.receipt, seq: digest.seq, at: record.at };
  }
  confirm(receipt) {
    return this.log.some((r) => r.receipt === receipt.receipt && r.seq === receipt.seq);
  }
}
