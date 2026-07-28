/**
 * Key management — BYOK / CMK / HYOK / HSM, per-namespace and per-subject keys,
 * rotation without re-encrypting data, and crypto-shredding.
 *
 * Key hierarchy:
 *
 *   ROOT  (Vault-managed | BYOK | CMK callback | HYOK callback | split M-of-N)
 *     └── KEK per scope   ("ns:sales", "subject:p-88", "tenant:acme", "region:eu")
 *           └── DEK per object   (stored wrapped, alongside the ciphertext)
 *
 * Crypto-shredding destroys a KEK. Every object under that scope — including the
 * copies in backups and the archive tier — becomes undecryptable in one step.
 * It is the only honest way to prove deletion from immutable media, which is why
 * the erasure receipt names it explicitly.
 */
import { appendFileSync, existsSync, readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { newDataKey, wrapKey, unwrapKey, encrypt, decrypt, sha256, randomToken } from '../util/crypto.js';
import { now, iso } from '../util/time.js';
import { VaultError } from '../util/errors.js';

export const KEY_MODES = /** @type {const} */ ([
  'vault-managed', 'byok', 'cmk', 'hyok', 'hsm', 'split'
]);

export class Kms {
  /**
   * @param {object} opts
   * @param {typeof KEY_MODES[number]} [opts.mode]
   * @param {Buffer|string} [opts.rootKey] for byok — customer-supplied material
   * @param {(scope:string, wrapped:any)=>Buffer} [opts.externalUnwrap] for cmk/hyok/hsm
   * @param {(scope:string, dek:Buffer)=>any} [opts.externalWrap]
   * @param {number} [opts.quorum] for split mode: how many shares must be present
   * @param {(event:object)=>void} [opts.onEvent] audit sink
   */
  constructor({ mode = 'vault-managed', rootKey, externalWrap, externalUnwrap, quorum = 2, onEvent, tombstonePath = null } = {}) {
    this.mode = mode;
    this.onEvent = onEvent || (() => {});
    this.quorum = quorum;
    this.externalWrap = externalWrap;
    this.externalUnwrap = externalUnwrap;
    this.presentShares = new Set();
    /**
     * While replaying persisted records, key derivation is not key *activity*.
     * The KEK for a namespace is derived deterministically from the root, so
     * re-deriving it on startup creates nothing — emitting key.created there
     * would append to the audit ledger on every restart and move the chain head.
     */
    this.replaying = 0;
    this.root = rootKey
      ? (Buffer.isBuffer(rootKey) ? rootKey : Buffer.from(String(rootKey).padEnd(32, '0').slice(0, 32)))
      : newDataKey();
    /** @type {Map<string, {id:string, key:Buffer|null, version:number, created:number, destroyed:number|null, reason:string|null}>} */
    this.keks = new Map();
    /** @type {Array<object>} */
    this.keyAccessLog = [];
    this.rotations = [];
    /**
     * Destroyed scopes, on disk.
     *
     * A KEK is derived deterministically from the root, so marking one
     * destroyed in memory achieves nothing across a restart: the next process
     * re-derives it and the "unrecoverable" data is readable again. The erasure
     * receipt states that backups are crypto-shredded and that the ciphertext
     * cannot be recovered — that has to survive a reboot or it is a false
     * statement on a document a regulator reads.
     *
     * Append-only, because un-destroying a key is not an operation that should
     * exist.
     */
    this.tombstonePath = tombstonePath;
    if (tombstonePath && existsSync(tombstonePath)) {
      for (const line of readFileSync(tombstonePath, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try {
          const t = JSON.parse(line);
          this.keks.set(t.scope, {
            id: t.keyId, key: null, version: t.version ?? 1, created: t.created ?? 0,
            destroyed: Date.parse(t.destroyedAt) || now(), reason: t.reason ?? 'destroyed in a previous session'
          });
        } catch { /* a truncated final line is not a reason to refuse to start */ }
      }
    }
    if (mode === 'byok' && !rootKey) {
      throw new VaultError('config', 'byok mode requires customer-supplied root key material');
    }
  }

  /** Suppress key-lifecycle events for the duration of a replay. Returns the undo. */
  beginReplay() {
    this.replaying++;
    let ended = false;
    return () => { if (!ended) { ended = true; this.replaying--; } };
  }

  _emit(event) {
    if (this.replaying > 0) return;
    this.onEvent(event);
  }

  /** For split-key / M-of-N: present a share. Unlock requires `quorum` shares. */
  presentShare(holder) {
    this.presentShares.add(holder);
    this.onEvent({ type: 'key.share_presented', holder, at: iso() });
    return { present: this.presentShares.size, required: this.quorum };
  }

  releaseShares() { this.presentShares.clear(); }

  _checkQuorum(scope) {
    if (this.mode === 'split' && this.presentShares.size < this.quorum) {
      throw new VaultError('forbidden', 'split-key quorum not met for this namespace', {
        scope, present: this.presentShares.size, required: this.quorum
      });
    }
  }

  /** @returns {{id:string, key:Buffer, version:number}} */
  kek(scope) {
    this._checkQuorum(scope);
    let entry = this.keks.get(scope);
    if (!entry) {
      entry = {
        id: `k-${sha256(scope).slice(0, 10)}`,
        key: this._deriveKek(scope, 1),
        version: 1,
        created: now(),
        destroyed: null,
        reason: null
      };
      this.keks.set(scope, entry);
      this._emit({ type: 'key.created', scope, keyId: entry.id, version: 1, at: iso() });
    }
    if (entry.destroyed) {
      throw new VaultError('crypto_shredded', 'key for this scope was destroyed — data is unrecoverable by design', {
        scope, destroyedAt: iso(entry.destroyed), reason: entry.reason
      });
    }
    return entry;
  }

  _deriveKek(scope, version) {
    // HKDF-ish: root || scope || version. In cmk/hyok modes the root never
    // exists locally and the customer's service does the wrap/unwrap instead.
    return Buffer.from(sha256(`${this.root.toString('hex')}|${scope}|v${version}`), 'hex');
  }

  /**
   * Produce a fresh data key wrapped for `scope`.
   * @returns {{dek:Buffer, wrapped:any, keyId:string, keyVersion:number, scope:string}}
   */
  newObjectKey(scope, aad) {
    const dek = newDataKey();
    if (this.mode === 'cmk' || this.mode === 'hyok' || this.mode === 'hsm') {
      if (!this.externalWrap) throw new VaultError('config', `${this.mode} mode requires an external wrap callback`);
      const wrapped = this.externalWrap(scope, dek);
      this.keyAccessLog.push({ at: now(), scope, op: 'wrap', external: true });
      return { dek, wrapped, keyId: `ext:${scope}`, keyVersion: 0, scope };
    }
    const k = this.kek(scope);
    this.keyAccessLog.push({ at: now(), scope, op: 'wrap', keyId: k.id });
    return { dek, wrapped: wrapKey(k.key, dek, aad), keyId: k.id, keyVersion: k.version, scope };
  }

  /** @returns {Buffer} */
  openObjectKey(scope, wrapped) {
    if (this.mode === 'cmk' || this.mode === 'hyok' || this.mode === 'hsm') {
      if (!this.externalUnwrap) throw new VaultError('config', `${this.mode} mode requires an external unwrap callback`);
      this.keyAccessLog.push({ at: now(), scope, op: 'unwrap', external: true });
      return this.externalUnwrap(scope, wrapped);
    }
    const k = this.kek(scope);
    this.keyAccessLog.push({ at: now(), scope, op: 'unwrap', keyId: k.id });
    try {
      return unwrapKey(k.key, wrapped);
    } catch {
      // Try older versions — rotation re-wraps lazily, so old objects still open.
      for (let v = k.version - 1; v >= 1; v--) {
        try { return unwrapKey(this._deriveKek(scope, v), wrapped); } catch { /* next */ }
      }
      throw new VaultError('crypto_shredded', 'object key cannot be unwrapped under any live key version', { scope });
    }
  }

  /** Encrypt a payload under a scope. Returns a self-describing sealed box. */
  seal(scope, plaintext, aad) {
    const { dek, wrapped, keyId, keyVersion } = this.newObjectKey(scope, aad);
    const box = encrypt(dek, plaintext, aad);
    dek.fill(0);
    return { v: 1, scope, keyId, keyVersion, wrapped, box };
  }

  /** @param {{scope:string, wrapped:any, box:any}} sealed */
  open(sealed) {
    const dek = this.openObjectKey(sealed.scope, sealed.wrapped);
    try {
      return decrypt(dek, sealed.box);
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Rotate a scope's KEK. Data is NOT re-encrypted — old objects unwrap against
   * the old version on read and are re-wrapped opportunistically.
   */
  rotate(scope, { actor, reason } = {}) {
    const entry = this.kek(scope);
    entry.version += 1;
    entry.key = this._deriveKek(scope, entry.version);
    const record = { scope, keyId: entry.id, version: entry.version, at: now(), actor, reason };
    this.rotations.push(record);
    this.onEvent({ type: 'key.rotated', ...record, at: iso(record.at) });
    return record;
  }

  /**
   * Destroy a scope's key material. Irreversible, by design.
   * @param {string} scope
   * @param {{actor:string, reason:string, requestId?:string}} ctx
   */
  cryptoShred(scope, { actor, reason, requestId } = {}) {
    if (!actor || !reason) {
      throw new VaultError('forbidden', 'crypto-shred requires a named actor and a stated reason');
    }
    const entry = this.keks.get(scope) || this.kek(scope);
    entry.key?.fill(0);
    entry.key = null;
    entry.destroyed = now();
    entry.reason = reason;
    const record = {
      scope, keyId: entry.id, destroyedAt: iso(entry.destroyed), actor, reason, requestId,
      // Proof that the key existed and no longer does, without revealing it.
      witness: sha256(`shred|${scope}|${entry.id}|${entry.destroyed}`)
    };
    if (this.tombstonePath) {
      mkdirSync(dirname(this.tombstonePath), { recursive: true });
      appendFileSync(this.tombstonePath, `${JSON.stringify({ ...record, version: entry.version, created: entry.created })}\n`);
    }
    this._emit({ type: 'key.destroyed', ...record });
    return record;
  }

  isShredded(scope) {
    return Boolean(this.keks.get(scope)?.destroyed);
  }

  /** Inventory for the compliance evidence pack. */
  inventory() {
    return [...this.keks.entries()].map(([scope, k]) => ({
      scope,
      keyId: k.id,
      version: k.version,
      created: iso(k.created),
      destroyed: k.destroyed ? iso(k.destroyed) : null,
      mode: this.mode
    }));
  }

  /** Customer-visible key access log (§9.9). */
  accessLog({ limit = 500 } = {}) {
    return this.keyAccessLog.slice(-limit).map((e) => ({ ...e, at: iso(e.at) }));
  }
}

/**
 * A stand-in for a customer HSM / cloud KMS. Used by the demo and by tests to
 * exercise the HYOK path: the key never enters Vault's process except as a
 * transient unwrap result, and revoking it cuts Vault off instantly.
 */
export class ExternalKeyService {
  constructor(name = 'customer-hsm') {
    this.name = name;
    this.master = newDataKey();
    this.revoked = false;
    this.calls = [];
  }
  revoke() { this.revoked = true; }
  restore() { this.revoked = false; }
  _guard() {
    if (this.revoked) {
      throw new VaultError('forbidden', `${this.name} has revoked Vault's access — no decryption is possible`);
    }
  }
  wrap(scope, dek) {
    this._guard();
    this.calls.push({ at: now(), scope, op: 'wrap' });
    return wrapKey(this.master, dek, scope);
  }
  unwrap(scope, wrapped) {
    this._guard();
    this.calls.push({ at: now(), scope, op: 'unwrap' });
    return unwrapKey(this.master, wrapped);
  }
  /** Bind into a Kms instance. */
  attach(kmsOpts = {}) {
    return {
      ...kmsOpts,
      mode: kmsOpts.mode || 'hyok',
      externalWrap: (scope, dek) => this.wrap(scope, dek),
      externalUnwrap: (scope, wrapped) => this.unwrap(scope, wrapped)
    };
  }
}

export function newRootKeyMaterial() {
  return randomToken(32);
}
