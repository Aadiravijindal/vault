/**
 * Cryptographic primitives.
 *
 * Everything here is real crypto from node:crypto — hash chains, envelope
 * encryption, detached signatures, blind indexes and crypto-shredding. The only
 * thing simulated is the *location* of the root key material (an HSM/CMK is
 * modelled as a callback boundary, see storage/kms.js), because that boundary is
 * the customer's to own.
 */
import {
  createHash,
  createHmac,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  timingSafeEqual
} from 'node:crypto';

export const HASH_ALGO = 'sha256';
export const CIPHER = 'aes-256-gcm';

/** @param {string|Buffer} data */
export function sha256(data) {
  return createHash(HASH_ALGO).update(data).digest('hex');
}

/**
 * Canonical JSON — key-sorted, stable across runs and machines.
 * Hashes computed over anything else are worthless as evidence.
 * @param {any} value
 */
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

/** @param {any} value */
export function hashObject(value) {
  return sha256(canonical(value));
}

/** Chain link: H(prev || content). The order is fixed and documented. */
export function chainHash(prevHash, contentHash) {
  return sha256(`${prevHash || 'GENESIS'}\n${contentHash}`);
}

// ---------------------------------------------------------------------------
// Envelope encryption
// ---------------------------------------------------------------------------

export function newDataKey() {
  return randomBytes(32);
}

/**
 * @param {Buffer} key 32 bytes
 * @param {string|Buffer} plaintext
 * @param {string} [aad] additional authenticated data (we bind the record id)
 */
export function encrypt(key, plaintext, aad) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(CIPHER, key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return {
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    aad: aad || undefined
  };
}

/**
 * @param {Buffer} key
 * @param {{iv:string,ct:string,tag:string,aad?:string}} box
 */
export function decrypt(key, box) {
  const decipher = createDecipheriv(CIPHER, key, Buffer.from(box.iv, 'base64'));
  if (box.aad) decipher.setAAD(Buffer.from(box.aad));
  decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(box.ct, 'base64')), decipher.final()]).toString('utf8');
}

/** Wrap a data key with a key-encryption key. */
export function wrapKey(kek, dek, aad) {
  return encrypt(kek, dek.toString('base64'), aad);
}

export function unwrapKey(kek, box) {
  return Buffer.from(decrypt(kek, box), 'base64');
}

// ---------------------------------------------------------------------------
// Signatures — customer-held keys. Ed25519: small, fast, no parameter choices to
// get wrong.
// ---------------------------------------------------------------------------

export function generateSigningKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  };
}

/** @param {string} privateKeyPem @param {string} message */
export function signMessage(privateKeyPem, message) {
  return nodeSign(null, Buffer.from(message), createPrivateKey(privateKeyPem)).toString('base64');
}

/** @param {string} publicKeyPem @param {string} message @param {string} signatureB64 */
export function verifyMessage(publicKeyPem, message, signatureB64) {
  try {
    return nodeVerify(
      null,
      Buffer.from(message),
      createPublicKey(publicKeyPem),
      Buffer.from(signatureB64, 'base64')
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Blind index — equality search over encrypted fields without decrypting them.
// ---------------------------------------------------------------------------

/** @param {Buffer} indexKey @param {string} value */
export function blindIndex(indexKey, value) {
  return createHmac(HASH_ALGO, indexKey)
    .update(String(value).trim().toLowerCase())
    .digest('hex')
    .slice(0, 32);
}

/** Pseudonymisation token for Employee Privacy Mode. Rotates with the epoch salt. */
export function pseudonym(salt, subject) {
  return 'p_' + createHmac(HASH_ALGO, salt).update(String(subject)).digest('hex').slice(0, 12);
}

export function constantTimeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function randomToken(bytes = 24) {
  return randomBytes(bytes).toString('base64url');
}

/** Shannon entropy in bits/char — used by the secret detector. */
export function shannonEntropy(str) {
  if (!str.length) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}
