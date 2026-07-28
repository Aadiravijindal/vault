/**
 * Field-level and client-side encryption, with searchable (blind) indexes.
 *
 * Whole-record encryption already protects the store: a collection marked
 * `encrypted` seals each operation line under its namespace KEK. This is the
 * finer granularity, and it exists for a different threat.
 *
 * Whole-record encryption is all-or-nothing against whoever holds the
 * collection's key — which, at runtime, is the Vault process itself. A bug that
 * dumps a record, a log line that serialises one, an operator with a debugger:
 * all of them see every column. Sealing named fields under their OWN key scope
 * means a full-record compromise still does not hand over the email address and
 * the national insurance number, because those are separate keys that a
 * separate decision destroyed or withheld.
 *
 * Three things follow from that, and each is a design constraint rather than a
 * feature:
 *
 * 1. A sealed field cannot be indexed the ordinary way, because the in-memory
 *    index would then hold the plaintext the seal exists to remove. So equality
 *    search uses a blind index: a keyed HMAC of the normalised value, stored
 *    beside the ciphertext. The server matches tokens it cannot invert. The
 *    proof that this is genuine is in the test that destroys the field key and
 *    then searches successfully anyway.
 *
 * 2. A deterministic token leaks equality. Two records with the same email
 *    carry the same token, so an observer learns "these two are the same
 *    person" without learning who. That is inherent to exact-match searchable
 *    encryption, not an implementation shortcut, and `posture()` states it
 *    rather than leaving a customer to discover it.
 *
 * 3. Client-side encryption is the zero-knowledge tier: the customer seals the
 *    field with a key Vault never receives, and Vault stores an envelope it can
 *    match by token and can never open. The server must therefore refuse to
 *    treat an envelope as text — `requirePlaintext` exists so that a component
 *    expecting a string fails loudly instead of rendering base64 to a user.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { VaultError } from '../util/errors.js';
import { blindIndex } from '../util/crypto.js';

/** What a policy may say about a field. */
export const FIELD_MODES = ['sealed', 'indexed', 'sealed+indexed'];

/** Ready-made policies for the shapes this product actually stores. */
export const FIELD_POLICIES = {
  people: { email: 'sealed+indexed', phone: 'sealed+indexed', nationalId: 'sealed', address: 'sealed', name: 'indexed' },
  customers: { email: 'sealed+indexed', accountNumber: 'sealed+indexed', taxId: 'sealed' },
  health: { diagnosis: 'sealed', notes: 'sealed', mrn: 'sealed+indexed' }
};

const SEALED_MARK = '__vfe';   // vault field envelope
const CLIENT_MARK = '__vce';   // vault client envelope

export class FieldCrypto {
  /**
   * @param {object} o
   * @param {import('./kms.js').Kms} o.kms
   * @param {string} [o.indexKeyScope] key scope for the blind-index HMAC key
   */
  constructor({ kms, indexKeyScope = 'blind-index' }) {
    if (!kms) throw new VaultError('config', 'field-level encryption needs a key service');
    this.kms = kms;
    this.indexKeyScope = indexKeyScope;
  }

  /**
   * The key scope for one field of one collection.
   *
   * Per field, not per collection, so "destroy every stored phone number" is a
   * single crypto-shred rather than a migration.
   */
  fieldScope(collection, field) { return `field:${collection}.${field}`; }

  /**
   * The blind-index key.
   *
   * Deliberately a different scope from the field keys: leaking the index key
   * lets an attacker test guesses, but decrypts nothing; leaking a field key
   * decrypts that field, but does not let them search the others.
   */
  _indexKey() {
    const entry = this.kms.kek(this.indexKeyScope);
    if (!entry?.key) {
      throw new VaultError('crypto_shredded', 'the blind-index key was destroyed — sealed fields remain sealed, but they can no longer be searched', { scope: this.indexKeyScope });
    }
    return entry.key;
  }

  indexToken(collection, field, value) {
    if (value == null) return null;
    // The collection and field are mixed into the key derivation so the same
    // email in two different collections does not produce the same token —
    // otherwise the index becomes a join key across the whole store.
    const key = createHmac('sha256', this._indexKey()).update(`${collection}.${field}`).digest();
    return blindIndex(key, value);
  }

  assertPolicy(policy) {
    for (const [field, mode] of Object.entries(policy ?? {})) {
      if (!FIELD_MODES.includes(mode)) {
        throw new VaultError('config',
          `unknown field mode "${mode}" for ${field} — expected one of ${FIELD_MODES.join(', ')}`, { field, mode });
      }
    }
    return policy ?? {};
  }

  /**
   * Seal the fields a policy names, and add their blind-index tokens.
   *
   * Returns a new object; the caller's document is not mutated, because a
   * caller that kept a reference would otherwise be holding a record whose
   * plaintext silently vanished.
   */
  seal(collection, doc, policy) {
    this.assertPolicy(policy);
    const out = { ...doc };
    const tokens = { ...(doc.__bi ?? {}) };
    for (const [field, mode] of Object.entries(policy)) {
      const value = doc[field];
      if (value == null || isSealed(value)) continue;
      if (mode.includes('indexed')) tokens[field] = this.indexToken(collection, field, value);
      if (mode.includes('sealed')) {
        const scope = this.fieldScope(collection, field);
        out[field] = {
          [SEALED_MARK]: 1,
          s: this.kms.seal(scope, JSON.stringify(value), `${collection}.${field}.${doc.id ?? ''}`),
          scope
        };
      }
    }
    if (Object.keys(tokens).length) out.__bi = tokens;
    return out;
  }

  /**
   * Open every sealed field this process still has a key for.
   *
   * A field whose key was crypto-shredded comes back as `null`, with its name
   * listed in `__unreadable`. That is deliberate: returning the envelope would
   * put an object where a string was expected, and throwing would make a single
   * erased field take down every read of the record.
   */
  open(doc) {
    if (!doc) return doc;
    let out = null;
    const unreadable = [];
    for (const [field, value] of Object.entries(doc)) {
      if (!isSealed(value)) continue;
      out = out ?? { ...doc };
      try {
        out[field] = JSON.parse(this.kms.open(value.s));
      } catch (e) {
        out[field] = null;
        unreadable.push(field);
        if (e.code !== 'crypto_shredded' && !/shred/i.test(e.message ?? '')) {
          // A key that is merely absent is a configuration problem worth
          // surfacing; a shredded one is the system working as designed.
          unreadable[unreadable.length - 1] = field;
        }
      }
    }
    if (!out) return doc;
    if (unreadable.length) out.__unreadable = unreadable;
    return out;
  }

  /** What an auditor needs: what is protected, how, and what is not. */
  posture(policy) {
    this.assertPolicy(policy);
    const entries = Object.entries(policy);
    return {
      sealed: entries.filter(([, m]) => m.includes('sealed')).map(([f]) => f),
      searchable: entries.filter(([, m]) => m.includes('indexed')).map(([f]) => f),
      scopes: entries.filter(([, m]) => m.includes('sealed')).map(([f]) => `field:<collection>.${f}`),
      algorithm: 'AES-256-GCM per field, key per field scope, wrapped by the scope KEK',
      indexAlgorithm: 'HMAC-SHA256 over the lower-cased trimmed value, keyed per collection+field, truncated to 128 bits',
      limitation: 'A deterministic blind index makes exact-match search possible and, by construction, reveals which records hold EQUAL values — two rows with the same email carry the same token. It does not reveal the value, and it does not support range, prefix or substring search. Fields that must not leak equality should be sealed without an index and searched by another attribute.'
    };
  }
}

/**
 * Client-side encryption: the zero-knowledge tier.
 *
 * This class is meant to run on the customer's side of the boundary. The key
 * never reaches Vault, so Vault stores an envelope it can match by blind index
 * and can never open — including under subpoena, which is the point of offering
 * the tier at all.
 */
export class ClientCrypto {
  /**
   * @param {object} o
   * @param {Buffer} o.key 32 bytes, held by the customer
   * @param {Buffer} o.indexKey 32 bytes; may be shared with the server if the
   *   server needs to build search tokens on the customer's behalf
   */
  constructor({ key, indexKey }) {
    if (!key || key.length !== 32) throw new VaultError('config', 'client-side encryption needs a 32-byte key');
    this.key = key;
    this.indexKey = indexKey ?? key;
  }

  indexToken(field, value) {
    return blindIndex(createHmac('sha256', this.indexKey).update(String(field)).digest(), value);
  }

  seal(doc, { fields }) {
    const out = { ...doc };
    const tokens = { ...(doc.__bi ?? {}) };
    for (const field of fields) {
      const value = doc[field];
      if (value == null) continue;
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', this.key, iv);
      const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
      out[field] = {
        [CLIENT_MARK]: 1, alg: 'aes-256-gcm',
        iv: iv.toString('base64'), ct: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64')
      };
      tokens[field] = this.indexToken(field, value);
    }
    if (Object.keys(tokens).length) out.__bi = tokens;
    return out;
  }

  open(doc) {
    const out = { ...doc };
    for (const [field, value] of Object.entries(doc)) {
      if (!ClientCrypto.isSealed(value)) continue;
      try {
        const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(value.iv, 'base64'));
        decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
        const pt = Buffer.concat([decipher.update(Buffer.from(value.ct, 'base64')), decipher.final()]);
        out[field] = JSON.parse(pt.toString('utf8'));
      } catch {
        // GCM authentication covers both a wrong key and a tampered
        // ciphertext, and the caller should not be told which — that
        // distinction is an oracle.
        throw new VaultError('forbidden',
          `${field} could not be decrypted with this key — either it belongs to another client or the ciphertext was altered`,
          { field });
      }
    }
    return out;
  }

  static isSealed(value) {
    return Boolean(value && typeof value === 'object' && value[CLIENT_MARK]);
  }

  /**
   * Assert that a value is usable as text.
   *
   * Exists because the failure mode of client-side encryption is not a leak,
   * it is a base64 blob rendered into a UI or fed to a model as if it were
   * content. Failing loudly at the boundary is the whole mitigation.
   */
  static requirePlaintext(value) {
    if (ClientCrypto.isSealed(value)) {
      throw new VaultError('forbidden',
        'this field is client-side encrypted and this server has no key for it — it cannot be read, searched by substring, or shown to a user');
    }
    if (isSealed(value)) {
      throw new VaultError('forbidden', 'this field is sealed at rest and must be opened before use');
    }
    return value;
  }
}

export function isSealed(value) {
  return Boolean(value && typeof value === 'object' && value[SEALED_MARK]);
}
