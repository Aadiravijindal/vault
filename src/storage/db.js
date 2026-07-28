/**
 * Append-only, replayable object store.
 *
 * Zero external dependencies on purpose: the whole engine has to run from a
 * fresh clone with `node .`, including on-prem and air-gapped, where "just add a
 * database" is a six-week procurement.
 *
 * On-disk format is one JSONL file per collection, each line an operation:
 *   {"o":"i","id":"f-1","t":1690000000000,"d":{...}}   insert
 *   {"o":"u","id":"f-1","t":...,"d":{...}}             new full revision
 *   {"o":"x","id":"f-1","t":...,"r":"erasure REQ-1"}   physical erasure tombstone
 *
 * Properties this buys us, all of which the spec depends on:
 *  - append-only by construction; "editing" a fact writes a new revision
 *  - WORM collections reject update and delete at the code level, not by
 *    permission — there is no code path (§6.2)
 *  - erasure physically rewrites the segment, so a deleted transcript is gone
 *    from the bytes, not just from an index (§14.2)
 *  - optional envelope encryption per record, keyed by scope, so crypto-shred
 *    reaches backups too (§5.6)
 */
import { mkdirSync, existsSync, readFileSync, writeFileSync, appendFileSync, renameSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { newId } from '../util/id.js';
import { now } from '../util/time.js';
import { VaultError, immutable, notFound } from '../util/errors.js';
import { ShardedMap } from './shardedmap.js';

export class Db {
  /**
   * @param {object} [opts]
   * @param {string|null} [opts.dir] null = in-memory only (tests, ephemeral demos)
   * @param {import('./kms.js').Kms|null} [opts.kms]
   * @param {(e:object)=>void} [opts.onEvent]
   */
  /**
   * @param {object} [opts]
   * @param {string|null} [opts.dir] null = in-memory only (tests, ephemeral demos)
   * @param {import('./kms.js').Kms|null} [opts.kms]
   * @param {boolean} [opts.encryptByDefault] seal every collection unless allowlisted
   * @param {Map<string,string>} [opts.plaintextCollections] name -> why it may stay readable
   * @param {(doc:any)=>string} [opts.defaultKeyScope]
   * @param {(e:object)=>void} [opts.onEvent]
   */
  constructor({ dir = null, kms = null, onEvent, encryptByDefault = false, plaintextCollections = new Map(), defaultKeyScope = null } = {}) {
    this.dir = dir;
    this.kms = kms;
    this.onEvent = onEvent || (() => {});
    /**
     * Encryption at rest is opt-OUT, not opt-in.
     *
     * It used to be opt-in, and the result was the bug this inverts: the
     * envelope machinery was correct, tested and wired to nothing, because
     * every new collection defaulted to plaintext and nobody remembered the
     * flag. A whole-directory canary scan found employee names, data-subject
     * names, saved search queries and case notes sitting in readable JSON.
     *
     * With the default the other way round, a collection added next year is
     * sealed unless someone writes down why it should not be — and the reason
     * is stored here rather than in a commit message, so the A2 test can read
     * it back and assert every exemption is justified.
     */
    this.encryptByDefault = encryptByDefault;
    this.plaintextCollections = plaintextCollections;
    this.defaultKeyScope = defaultKeyScope;
    /** @type {Map<string, Collection>} */
    this.collections = new Map();
    if (dir) mkdirSync(dir, { recursive: true });
  }

  /** Why `name` is allowed to sit on disk in the clear, or null if it is not. */
  plaintextReason(name) {
    return this.plaintextCollections.get(name) ?? null;
  }

  /**
   * @param {string} name
   * @param {{worm?:boolean, encrypted?:boolean, keyScope?:(doc:any)=>string}} [opts]
   * @returns {Collection}
   */
  collection(name, opts = {}) {
    let c = this.collections.get(name);
    if (!c) {
      // An explicit `encrypted:` from the caller always wins; the default only
      // fills the gap where nobody said anything, which is the case that used
      // to fail silently.
      const encrypted = opts.encrypted !== undefined
        ? opts.encrypted
        : this.encryptByDefault && !this.plaintextCollections.has(name);
      const keyScope = opts.keyScope ?? (encrypted ? this.defaultKeyScope : null) ?? undefined;
      c = new Collection(this, name, { ...opts, encrypted, ...(keyScope ? { keyScope } : {}) });
      this.collections.set(name, c);
      c._load();
    }
    return c;
  }

  stats() {
    const out = {};
    for (const [name, c] of this.collections) {
      out[name] = { records: c.size, ops: c.opCount, bytes: c.bytesOnDisk(), worm: c.worm, encrypted: c.encrypted };
    }
    return out;
  }

  /** Rewrite every collection with only live records. Reclaims erased space. */
  compactAll() {
    let reclaimed = 0;
    for (const c of this.collections.values()) reclaimed += c.compact();
    return { reclaimed };
  }
}

export class Collection {
  /**
   * @param {Db} db
   * @param {string} name
   */
  constructor(db, name, { worm = false, encrypted = false, keyScope, fields = null, shards = 64 } = {}) {
    this.db = db;
    this.name = name;
    this.worm = worm;
    this.encrypted = encrypted;
    this.keyScope = keyScope || (() => `collection:${name}`);
    /**
     * Field-level encryption policy, if this collection has one.
     *
     * Applied on the way in and reversed on the way out, so callers see
     * plaintext while the file on disk holds ciphertext for exactly the named
     * fields. Independent of `encrypted`: a collection can be field-sealed
     * without being whole-record sealed, which is the case where the
     * distinction is observable — and therefore the case the tests use.
     */
    this.fieldPolicy = fields ? (fields.crypto.assertPolicy(fields.policy), fields.policy) : null;
    this.fieldCrypto = fields?.crypto ?? null;
    this.path = db.dir ? join(db.dir, `${name}.jsonl`) : null;
    /**
     * @type {import('./shardedmap.js').ShardedMap}
     *
     * Not a Map. V8 caps a Map at 16,777,216 entries and throws after that,
     * which capped the whole product at 17% of its stated 100M-fact target.
     * See shardedmap.js — the interface is identical, the ceiling is not.
     */
    this.records = new ShardedMap(shards);
    /** @type {Map<string, Map<any, Set<string>>>} */
    this.indexes = new Map();
    /** @type {Map<string, (doc:any)=>any|any[]>} */
    this.indexFns = new Map();
    this.opCount = 0;
    this._pendingWrites = [];
  }

  get size() { return this.records.size; }

  // -- indexing ------------------------------------------------------------

  /**
   * Declare a secondary index. Rebuilt immediately over existing records.
   * @param {string} name
   * @param {(doc:any)=>any|any[]} keyFn
   */
  index(name, keyFn) {
    this.indexFns.set(name, keyFn);
    const map = new Map();
    this.indexes.set(name, map);
    for (const doc of this.records.values()) this._indexDoc(name, doc);
    return this;
  }

  _indexDoc(indexName, doc) {
    const keyFn = this.indexFns.get(indexName);
    const map = this.indexes.get(indexName);
    if (!keyFn || !map) return;
    let keys = keyFn(doc);
    if (keys == null) return;
    if (!Array.isArray(keys)) keys = [keys];
    for (const k of keys) {
      if (k == null) continue;
      let set = map.get(k);
      if (!set) map.set(k, (set = new Set()));
      set.add(doc.id);
    }
  }

  _deindexDoc(doc) {
    for (const [name, map] of this.indexes) {
      const keyFn = this.indexFns.get(name);
      let keys = keyFn?.(doc);
      if (keys == null) continue;
      if (!Array.isArray(keys)) keys = [keys];
      for (const k of keys) map.get(k)?.delete(doc.id);
    }
  }

  /** @returns {any[]} */
  by(indexName, key) {
    const ids = this.indexes.get(indexName)?.get(key);
    if (!ids) return [];
    return [...ids].map((id) => this.records.get(id)).filter(Boolean);
  }

  // -- reads ---------------------------------------------------------------

  get(id) { const r = this.records.get(id); return r ? this._open(r) : null; }
  has(id) { return this.records.has(id); }
  /** The stored form, still sealed. Internal callers that must not decrypt. */
  raw(id) { return this.records.get(id) || null; }
  require(id) {
    const d = this.records.get(id);
    if (!d) throw notFound(this.name, id);
    return d;
  }
  all() { return [...this.records.values()].map((d) => this._open(d)); }
  find(pred) { return [...this.records.values()].filter(pred).map((d) => this._open(d)); }
  first(pred) { for (const d of this.records.values()) if (pred(d)) return this._open(d); return null; }
  count(pred) { return pred ? this.find(pred).length : this.records.size; }
  *[Symbol.iterator]() { yield* this.records.values(); }

  // -- writes --------------------------------------------------------------

  /**
   * @param {object} doc
   * @returns {object} the stored document (frozen shallow copy semantics: we
   * store a clone so callers can't mutate history by holding a reference)
   */
  insert(doc) {
    const id = doc.id || newId(this.name.replace(/s$/, ''));
    if (this.records.has(id)) {
      throw new VaultError('conflict', `duplicate id in ${this.name}`, { id });
    }
    const rec = this._seal({ ...doc, id, _v: 1, _created: doc._created ?? now(), _updated: now() });
    this.records.set(id, rec);
    for (const name of this.indexes.keys()) this._indexDoc(name, rec);
    this._append({ o: 'i', id, t: rec._updated, d: rec });
    return this._open(rec);
  }

  /**
   * Append a new revision. Throws on WORM collections — there is no edit path.
   * @param {string} id
   * @param {object|((doc:any)=>object)} patch
   */
  update(id, patch) {
    if (this.worm) {
      throw immutable(`${this.name} is write-once — no update path exists`, { id, collection: this.name });
    }
    const prev = this.require(id);
    this._deindexDoc(prev);
    const delta = typeof patch === 'function' ? patch(structuredClone(this._open(prev))) : patch;
    // Re-sealed from the opened previous record, so a field that was already
    // sealed and is not being changed does not get double-wrapped, and one that
    // IS being changed never touches the file in the clear.
    const rec = this._seal({ ...this._open(prev), ...delta, id, _v: prev._v + 1, _created: prev._created, _updated: now() });
    this.records.set(id, rec);
    for (const name of this.indexes.keys()) this._indexDoc(name, rec);
    this._append({ o: 'u', id, t: rec._updated, d: rec });
    return this._open(rec);
  }

  /** Insert or update. */
  put(doc) {
    return this.records.has(doc.id) ? this.update(doc.id, doc) : this.insert(doc);
  }

  /**
   * Physically erase a record and rewrite the segment so the bytes are gone.
   * Only reachable from the receipted erasure path — callers must pass an
   * authorisation object, and WORM collections additionally require that the
   * content was crypto-shredded rather than deleted.
   *
   * @param {string} id
   * @param {{actor:string, reason:string, requestId?:string, cryptoShredded?:boolean}} auth
   */
  erase(id, auth) {
    if (!auth?.actor || !auth?.reason) {
      throw new VaultError('forbidden', 'erasure requires a named actor and a stated reason');
    }
    if (this.worm && !auth.cryptoShredded) {
      throw immutable(`${this.name} is WORM — content is removed by destroying its key, not by deletion`, { id });
    }
    const rec = this.records.get(id);
    if (!rec) return false;
    this._deindexDoc(rec);
    this.records.delete(id);
    this._append({ o: 'x', id, t: now(), r: auth.requestId || auth.reason });
    this.compact();
    this.db.onEvent({ type: 'storage.erased', collection: this.name, id, requestId: auth.requestId });
    return true;
  }

  // -- field-level encryption ----------------------------------------------

  _seal(rec) {
    return this.fieldPolicy ? this.fieldCrypto.seal(this.name, rec, this.fieldPolicy) : rec;
  }

  _open(rec) {
    return this.fieldCrypto ? this.fieldCrypto.open(rec) : rec;
  }

  /**
   * Exact-match search over a sealed field, without decrypting anything.
   *
   * The token is computed from the query value and compared against the tokens
   * stored beside the ciphertext. Nothing here opens a seal — which is why this
   * keeps working after the field's key has been destroyed, and why a fallback
   * to "decrypt everything and scan" is refused rather than provided: that
   * fallback would quietly undo the entire property.
   */
  byEncrypted(field, value) {
    if (!this.fieldPolicy) {
      throw new VaultError('config', `${this.name} has no field-encryption policy, so it has no blind indexes`, { field });
    }
    if (!String(this.fieldPolicy[field] ?? '').includes('indexed')) {
      throw new VaultError('unsupported',
        `${field} is not indexed — searching it would mean decrypting every record and scanning, which defeats the reason it is sealed`,
        { field, indexed: Object.keys(this.fieldPolicy).filter((f) => this.fieldPolicy[f].includes('indexed')) });
    }
    const token = this.fieldCrypto.indexToken(this.name, field, value);
    const out = [];
    for (const rec of this.records.values()) {
      if (rec.__bi?.[field] === token) out.push(this._open(rec));
    }
    return out;
  }

  // -- persistence ---------------------------------------------------------

  _serialise(op) {
    if (op.d && this.encrypted && this.db.kms) {
      const scope = this.keyScope(op.d);
      const sealed = this.db.kms.seal(scope, JSON.stringify(op.d), op.id);
      return JSON.stringify({ ...op, d: undefined, e: sealed });
    }
    return JSON.stringify(op);
  }

  _deserialise(line) {
    const op = JSON.parse(line);
    if (op.e) {
      if (!this.db.kms) throw new VaultError('config', `${this.name} is encrypted but no key service is configured`);
      try {
        op.d = JSON.parse(this.db.kms.open(op.e));
      } catch (e) {
        if (e.code === 'crypto_shredded') return { ...op, o: 'x', d: undefined, shredded: true };
        throw e;
      }
      delete op.e;
    }
    return op;
  }

  _append(op) {
    this.opCount++;
    if (!this.path) return;
    appendFileSync(this.path, this._serialise(op) + '\n');
  }

  _load() {
    if (!this.path || !existsSync(this.path)) return;
    const raw = readFileSync(this.path, 'utf8');
    // Replaying stored records is not key activity. Without this, opening an
    // encrypted collection re-derives its namespace key and emits key.created
    // into the ledger, so a restart appends events and the chain head no longer
    // matches where it was left — a restart would look like tampering.
    const done = this.db.kms?.beginReplay?.();
    try {
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        let op;
        try { op = this._deserialise(line); } catch { continue; }
        this.opCount++;
        if (op.o === 'x' || op.shredded) { this.records.delete(op.id); continue; }
        if (op.d) this.records.set(op.id, op.d);
      }
    } finally { done?.(); }
    for (const name of this.indexes.keys()) {
      this.indexes.set(name, new Map());
      for (const doc of this.records.values()) this._indexDoc(name, doc);
    }
  }

  /** Rewrite the segment containing only live records. Returns bytes reclaimed. */
  compact() {
    if (!this.path || !existsSync(this.path)) return 0;
    const before = statSync(this.path).size;
    const tmp = `${this.path}.compact`;
    mkdirSync(dirname(tmp), { recursive: true });
    const lines = [];
    for (const rec of this.records.values()) {
      lines.push(this._serialise({ o: 'i', id: rec.id, t: rec._updated, d: rec }));
    }
    writeFileSync(tmp, lines.length ? lines.join('\n') + '\n' : '');
    renameSync(tmp, this.path);
    this.opCount = lines.length;
    return Math.max(0, before - statSync(this.path).size);
  }

  bytesOnDisk() {
    try { return this.path && existsSync(this.path) ? statSync(this.path).size : 0; } catch { return 0; }
  }
}
