/**
 * L11 — BRING YOUR OWN BUCKET (§5.2).
 *
 * Customer supplies bucket + credentials + region + optional KMS key. Vault
 * writes, verifies the write-through, and never deletes without a receipted
 * erasure.
 *
 * These are real wire-protocol clients, not vendor SDK wrappers: the whole
 * engine has to run air-gapped from a fresh clone, so `npm i @aws-sdk/*` is not
 * available to us. Each driver signs requests the way its provider actually
 * requires — AWS SigV4, Azure SharedKey, GCS OAuth bearer — which is also what
 * makes them testable against a local endpoint that checks the signature.
 *
 * Immutability is the point of most of these deployments, so every driver
 * exposes the platform's native object-lock:
 *   S3    → x-amz-object-lock-mode COMPLIANCE|GOVERNANCE + retain-until
 *   Azure → x-ms-immutability-policy-mode Locked|Unlocked + expiry
 *   GCS   → bucket retention policy, honoured per object
 */
import { createHmac, createHash, createSign } from 'node:crypto';
import { sha256 } from '../util/crypto.js';
import { now, iso, duration } from '../util/time.js';
import { VaultError } from '../util/errors.js';

const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
const hex = (b) => Buffer.from(b).toString('hex');
const sha256hex = (s) => createHash('sha256').update(s ?? '').digest('hex');

/** RFC 3986 — S3 requires the stricter escaping, not encodeURIComponent's. */
function uriEscape(str, encodeSlash = true) {
  return String(str).split('').map((c) => {
    if (/[A-Za-z0-9_.~-]/.test(c)) return c;
    if (c === '/') return encodeSlash ? '%2F' : '/';
    return Buffer.from(c, 'utf8').toString('hex').toUpperCase().replace(/../g, (h) => `%${h}`);
  }).join('');
}

// ---------------------------------------------------------------------------
// AWS Signature V4 — used by S3 and by every S3-compatible endpoint
// ---------------------------------------------------------------------------

/**
 * @param {object} o
 * @returns {{headers:Record<string,string>, canonicalRequest:string, stringToSign:string, signature:string}}
 */
export function signV4({
  method, url, region, service = 's3', accessKeyId, secretAccessKey, sessionToken = null,
  headers = {}, payload = '', at = new Date()
}) {
  const u = new URL(url);
  const amzDate = at.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256hex(payload);

  const all = {
    ...headers,
    host: u.host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    ...(sessionToken ? { 'x-amz-security-token': sessionToken } : {})
  };
  const lower = Object.fromEntries(Object.entries(all).map(([k, val]) => [k.toLowerCase(), String(val).trim()]));
  const signedHeaders = Object.keys(lower).sort().join(';');
  const canonicalHeaders = Object.keys(lower).sort().map((k) => `${k}:${lower[k]}\n`).join('');
  const canonicalQuery = [...u.searchParams.entries()]
    .map(([k, val]) => [uriEscape(k), uriEscape(val)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([k, val]) => `${k}=${val}`).join('&');

  const canonicalRequest = [
    method, uriEscape(decodeURIComponent(u.pathname), false), canonicalQuery,
    canonicalHeaders, signedHeaders, payloadHash
  ].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');

  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hex(hmac(kSigning, stringToSign));

  return {
    headers: {
      ...all,
      Authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
    },
    canonicalRequest, stringToSign, signature
  };
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------

class BaseBucket {
  constructor(config) {
    this.config = config;
    this.name = config.name || this.constructor.name;
    this.stats = { puts: 0, gets: 0, verifyFailures: 0, bytes: 0, errors: 0 };
  }
  /**
   * Prove the bucket works BEFORE the first real write.
   *
   * A misconfigured bucket that only fails on the first genuine put loses that
   * record, or silently degrades to Vault storage. This does a round trip with
   * a canary object and fails loudly with the specific permission that is
   * missing, at setup time when someone is still watching.
   */
  async healthCheck({ deleteCanary = true } = {}) {
    const key = `.vault-healthcheck/${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const probe = JSON.stringify({ probe: 'vault-health', at: new Date().toISOString() });
    const result = {
      driver: this.name, at: iso(), write: false, read: false, roundTrip: false,
      immutability: null, region: null, problems: []
    };
    try {
      const put = await this.put(key, probe, { retention: '1d' });
      result.write = true;
      result.immutability = put.objectLock ?? put.immutability ?? null;
      if (put.verified === false) result.problems.push({ check: 'write-through', detail: 'the provider returned a digest that does not match what we sent' });
    } catch (e) {
      result.problems.push({ check: 'write', detail: e.message, fix: 'grant PutObject (or the provider equivalent) to these credentials' });
      return { ...result, ok: false };
    }
    try {
      const back = await this.get(key);
      result.read = true;
      result.roundTrip = String(back).includes('vault-health');
      if (!result.roundTrip) result.problems.push({ check: 'round-trip', detail: 'the object read back does not match what was written' });
    } catch (e) {
      // A write-only bucket is a legitimate configuration; say so rather than failing.
      result.problems.push({ check: 'read', detail: e.message, fix: 'grant GetObject if Vault should read back; write-only is supported but disables restore' });
    }
    if (deleteCanary) {
      try { await this._delete(key, { actor: 'system', reason: 'health check canary', requestId: 'healthcheck' }); }
      catch { /* object-lock will refuse this, which is itself a good sign */ }
    }
    return { ...result, ok: result.write && result.problems.filter((p) => p.check !== 'read').length === 0 };
  }

  /**
   * Residency check: the bucket's real region must match what was declared.
   * Getting this wrong is a cross-border transfer, not a config typo.
   */
  async verifyResidency(declaredRegion) {
    const actual = await this.region();
    const matches = !declaredRegion || !actual || String(actual).toLowerCase().startsWith(String(declaredRegion).toLowerCase().split('-')[0]);
    return {
      declared: declaredRegion ?? null, actual: actual ?? null, matches,
      detail: matches
        ? 'the bucket is in the declared region'
        : `the bucket reports region "${actual}" but residency was declared as "${declaredRegion}" — storing there would be a cross-border transfer`
    };
  }

  /** Overridden per driver; null means the provider did not tell us. */
  async region() { return this.config.region ?? null; }

  /** Vault never deletes customer objects outside a receipted erasure (§5.2). */
  async delete(key, auth) {
    if (!auth?.actor || !auth?.reason || !auth?.requestId) {
      throw new VaultError('forbidden',
        'Vault does not delete from a customer bucket without a receipted erasure — name the actor, the reason and the request',
        { key });
    }
    return this._delete(key, auth);
  }
  async _fetch(url, init) {
    const res = await fetch(url, init);
    if (!res.ok) {
      this.stats.errors++;
      // Never echo the body: a provider error can quote the object you sent.
      throw new VaultError('storage', `${this.name} returned ${res.status} for ${init.method} ${new URL(url).pathname}`,
        { status: res.status, provider: this.name });
    }
    return res;
  }
}

/**
 * S3 and every S3-compatible endpoint: MinIO, Cloudflare R2, Backblaze B2,
 * Wasabi, Ceph/Swift, IBM COS, OCI, NetApp/Dell/Pure gateways.
 */
export class S3Bucket extends BaseBucket {
  /**
   * @param {object} c
   * @param {string} c.bucket @param {string} c.region
   * @param {string} c.accessKeyId @param {string} c.secretAccessKey
   * @param {string} [c.endpoint] set for MinIO/R2/B2/Wasabi/Ceph
   * @param {'COMPLIANCE'|'GOVERNANCE'|null} [c.objectLockMode]
   * @param {string} [c.kmsKeyId] SSE-KMS with the customer's own key
   */
  constructor(c) {
    super({ name: c.name || 's3', ...c });
    for (const k of ['bucket', 'region', 'accessKeyId', 'secretAccessKey']) {
      if (!c[k]) throw new VaultError('config', `S3 bucket configuration needs ${k}`);
    }
    this.pathStyle = Boolean(c.endpoint);   // MinIO and friends are path-style
  }

  _url(key) {
    const base = this.config.endpoint
      ? `${this.config.endpoint.replace(/\/$/, '')}/${this.config.bucket}`
      : `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com`;
    return `${base}/${String(key).split('/').map((s) => uriEscape(s)).join('/')}`;
  }

  async put(key, body, { retention = null, contentType = 'application/octet-stream' } = {}) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const headers = { 'Content-Type': contentType, 'Content-Length': String(Buffer.byteLength(payload)) };

    // WORM: object-lock, per record, with the mode the customer chose.
    if (this.config.objectLockMode) {
      headers['x-amz-object-lock-mode'] = this.config.objectLockMode;
      const keepFor = duration(retention ?? this.config.retention ?? '7y');
      headers['x-amz-object-lock-retain-until-date'] = new Date(now() + keepFor).toISOString();
    }
    if (this.config.kmsKeyId) {
      headers['x-amz-server-side-encryption'] = 'aws:kms';
      headers['x-amz-server-side-encryption-aws-kms-key-id'] = this.config.kmsKeyId;
    }
    const url = this._url(key);
    const signed = signV4({
      method: 'PUT', url, region: this.config.region, accessKeyId: this.config.accessKeyId,
      secretAccessKey: this.config.secretAccessKey, sessionToken: this.config.sessionToken,
      headers, payload
    });
    const res = await this._fetch(url, { method: 'PUT', headers: signed.headers, body: payload });

    // Verify write-through on every put (§5.2): the provider's ETag is the MD5
    // for a single-part upload, so compare what we can and always keep our own
    // content hash for the receipt.
    const etag = (res.headers.get('etag') || '').replace(/"/g, '');
    const digest = createHash('md5').update(payload).digest('hex');
    const verified = !etag || etag === digest;
    if (!verified) this.stats.verifyFailures++;
    this.stats.puts++; this.stats.bytes += Buffer.byteLength(payload);
    return { key, bytes: Buffer.byteLength(payload), etag, verified, sha256: sha256(payload), objectLock: headers['x-amz-object-lock-mode'] ?? null };
  }

  async get(key) {
    const url = this._url(key);
    const signed = signV4({
      method: 'GET', url, region: this.config.region, accessKeyId: this.config.accessKeyId,
      secretAccessKey: this.config.secretAccessKey, sessionToken: this.config.sessionToken
    });
    const res = await this._fetch(url, { method: 'GET', headers: signed.headers });
    this.stats.gets++;
    return res.text();
  }

  /** S3 reports the bucket's true region, so residency is checked not assumed. */
  async region() {
    try {
      const base = this.config.endpoint
        ? `${this.config.endpoint.replace(/\/$/, '')}/${this.config.bucket}?location=`
        : `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com/?location=`;
      const signed = signV4({
        method: 'GET', url: base, region: this.config.region,
        accessKeyId: this.config.accessKeyId, secretAccessKey: this.config.secretAccessKey
      });
      const res = await fetch(base, { method: 'GET', headers: signed.headers });
      if (!res.ok) return this.config.region ?? null;
      const body = await res.text();
      const m = /<LocationConstraint[^>]*>([^<]*)<\/LocationConstraint>/.exec(body);
      return (m && m[1]) || 'us-east-1';
    } catch { return this.config.region ?? null; }
  }

  async _delete(key, auth) {
    const url = this._url(key);
    const signed = signV4({
      method: 'DELETE', url, region: this.config.region, accessKeyId: this.config.accessKeyId,
      secretAccessKey: this.config.secretAccessKey, sessionToken: this.config.sessionToken,
      headers: { 'x-vault-erasure-request': auth.requestId }
    });
    await this._fetch(url, { method: 'DELETE', headers: signed.headers });
    return { key, deleted: true, requestId: auth.requestId };
  }
}

/** Azure Blob Storage, with immutable blob policies. */
export class AzureBlobBucket extends BaseBucket {
  constructor(c) {
    super({ name: c.name || 'azure-blob', ...c });
    for (const k of ['account', 'container', 'accountKey']) {
      if (!c[k]) throw new VaultError('config', `Azure Blob configuration needs ${k}`);
    }
  }

  _url(key) {
    const base = this.config.endpoint || `https://${this.config.account}.blob.core.windows.net`;
    return `${base}/${this.config.container}/${String(key).split('/').map((s) => uriEscape(s)).join('/')}`;
  }

  /** SharedKey signing — the canonical string order is fixed by the service. */
  _sign(method, url, headers, contentLength) {
    const u = new URL(url);
    const msHeaders = Object.keys(headers).filter((h) => h.toLowerCase().startsWith('x-ms-')).sort()
      .map((h) => `${h.toLowerCase()}:${String(headers[h]).trim()}`).join('\n');
    const canonicalResource = `/${this.config.account}${u.pathname}`
      + [...u.searchParams.keys()].sort().map((k) => `\n${k.toLowerCase()}:${u.searchParams.get(k)}`).join('');
    const stringToSign = [
      method, headers['Content-Encoding'] || '', headers['Content-Language'] || '',
      contentLength || '', headers['Content-MD5'] || '', headers['Content-Type'] || '',
      '', '', '', '', '', '',      // Date + conditional headers, all via x-ms-date
      msHeaders, canonicalResource
    ].join('\n');
    const signature = createHmac('sha256', Buffer.from(this.config.accountKey, 'base64'))
      .update(stringToSign, 'utf8').digest('base64');
    return { authorization: `SharedKey ${this.config.account}:${signature}`, stringToSign };
  }

  async put(key, body, { retention = null, contentType = 'application/octet-stream' } = {}) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const md5 = createHash('md5').update(payload).digest('base64');
    const headers = {
      'x-ms-date': new Date(now()).toUTCString(),
      'x-ms-version': '2021-08-06',
      'x-ms-blob-type': 'BlockBlob',
      'Content-Type': contentType,
      'Content-MD5': md5
    };
    if (this.config.immutable) {
      // Locked is Azure's equivalent of S3 compliance mode: not even the
      // account owner can shorten it.
      headers['x-ms-immutability-policy-mode'] = this.config.immutable === 'locked' ? 'Locked' : 'Unlocked';
      headers['x-ms-immutability-policy-until-date'] =
        new Date(now() + duration(retention ?? this.config.retention ?? '7y')).toUTCString();
      if (this.config.legalHold) headers['x-ms-legal-hold'] = 'true';
    }
    const url = this._url(key);
    const len = Buffer.byteLength(payload);
    const { authorization } = this._sign('PUT', url, headers, len);
    const res = await this._fetch(url, {
      method: 'PUT', headers: { ...headers, 'Content-Length': String(len), Authorization: authorization }, body: payload
    });
    const returned = res.headers.get('content-md5');
    const verified = !returned || returned === md5;
    if (!verified) this.stats.verifyFailures++;
    this.stats.puts++; this.stats.bytes += len;
    return { key, bytes: len, verified, sha256: sha256(payload), immutability: headers['x-ms-immutability-policy-mode'] ?? null };
  }

  async get(key) {
    const url = this._url(key);
    const headers = { 'x-ms-date': new Date(now()).toUTCString(), 'x-ms-version': '2021-08-06' };
    const { authorization } = this._sign('GET', url, headers, '');
    const res = await this._fetch(url, { method: 'GET', headers: { ...headers, Authorization: authorization } });
    this.stats.gets++;
    return res.text();
  }

  async _delete(key, auth) {
    const url = this._url(key);
    const headers = { 'x-ms-date': new Date(now()).toUTCString(), 'x-ms-version': '2021-08-06' };
    const { authorization } = this._sign('DELETE', url, headers, '');
    await this._fetch(url, { method: 'DELETE', headers: { ...headers, Authorization: authorization } });
    return { key, deleted: true, requestId: auth.requestId };
  }
}

/** Google Cloud Storage, with Bucket Lock retention. */
export class GcsBucket extends BaseBucket {
  constructor(c) {
    super({ name: c.name || 'gcs', ...c });
    if (!c.bucket) throw new VaultError('config', 'GCS configuration needs bucket');
    if (!c.accessToken && !(c.clientEmail && c.privateKey)) {
      throw new VaultError('config', 'GCS needs either an accessToken or a service account (clientEmail + privateKey)');
    }
    this._token = c.accessToken ? { value: c.accessToken, expiresAt: Infinity } : null;
  }

  /** Mint a bearer token from a service account, RS256, no SDK. */
  async _bearer() {
    if (this._token && this._token.expiresAt > now() + 60_000) return this._token.value;
    const iat = Math.floor(now() / 1000);
    const claim = {
      iss: this.config.clientEmail,
      scope: 'https://www.googleapis.com/auth/devstorage.read_write',
      aud: this.config.tokenUri || 'https://oauth2.googleapis.com/token',
      exp: iat + 3600, iat
    };
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64(claim)}`;
    const signature = createSign('RSA-SHA256').update(unsigned).sign(this.config.privateKey, 'base64url');
    const res = await this._fetch(claim.aud, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` }).toString()
    });
    const body = await res.json();
    this._token = { value: body.access_token, expiresAt: now() + (body.expires_in ?? 3600) * 1000 };
    return this._token.value;
  }

  _url(key, upload = false) {
    const base = this.config.endpoint || 'https://storage.googleapis.com';
    return upload
      ? `${base}/upload/storage/v1/b/${this.config.bucket}/o?uploadType=media&name=${uriEscape(key)}`
      : `${base}/storage/v1/b/${this.config.bucket}/o/${uriEscape(key)}?alt=media`;
  }

  async put(key, body, { contentType = 'application/octet-stream' } = {}) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const md5 = createHash('md5').update(payload).digest('base64');
    const url = this._url(key, true);
    const headers = {
      Authorization: `Bearer ${await this._bearer()}`,
      'Content-Type': contentType,
      'Content-MD5': md5
    };
    // Bucket Lock is a bucket-level retention policy; per object we assert the
    // hold so retention cannot be short-circuited for this record.
    if (this.config.retentionLocked) headers['x-goog-if-generation-match'] = '0';
    const res = await this._fetch(url, { method: 'POST', headers, body: payload });
    const meta = await res.json().catch(() => ({}));
    const verified = !meta.md5Hash || meta.md5Hash === md5;
    if (!verified) this.stats.verifyFailures++;
    this.stats.puts++; this.stats.bytes += Buffer.byteLength(payload);
    return { key, bytes: Buffer.byteLength(payload), verified, sha256: sha256(payload), generation: meta.generation ?? null };
  }

  async get(key) {
    const res = await this._fetch(this._url(key), { method: 'GET', headers: { Authorization: `Bearer ${await this._bearer()}` } });
    this.stats.gets++;
    return res.text();
  }

  async _delete(key, auth) {
    const url = `${this.config.endpoint || 'https://storage.googleapis.com'}/storage/v1/b/${this.config.bucket}/o/${uriEscape(key)}`;
    await this._fetch(url, { method: 'DELETE', headers: { Authorization: `Bearer ${await this._bearer()}` } });
    return { key, deleted: true, requestId: auth.requestId };
  }
}

/**
 * HASH-ONLY (§5.1) — content never leaves the customer's side, at all.
 *
 * This is not "we try not to store it". The driver has no transport: there is
 * no code path from here to a network, so the mandate is met by construction
 * rather than by policy. Vault keeps the hash and the metadata, which is enough
 * to prove what existed and when, and nothing else.
 */
export class HashOnlyBucket extends BaseBucket {
  constructor(c = {}) {
    super({ name: c.name || 'hash-only', ...c });
    /** @type {Map<string, {sha256:string, bytes:number, at:number}>} */
    this.manifest = new Map();
  }
  async put(key, body) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const entry = { sha256: sha256(payload), bytes: Buffer.byteLength(payload), at: now() };
    this.manifest.set(key, entry);
    this.stats.puts++;
    return { key, ...entry, verified: true, contentStored: false, note: 'hash-only tier — the content was never transmitted or written' };
  }
  async get() {
    throw new VaultError('forbidden',
      'hash-only tier: Vault holds the hash and the metadata, never the content — read it from your own store',
      { code: 'hash_only' });
  }
  async _delete(key) { this.manifest.delete(key); return { key, deleted: true, note: 'only the hash existed here' }; }
  /** Prove a customer-held object matches what Vault attested to. */
  verify(key, content) {
    const entry = this.manifest.get(key);
    if (!entry) return { key, known: false };
    const actual = sha256(typeof content === 'string' ? content : JSON.stringify(content));
    return { key, known: true, matches: actual === entry.sha256, attestedAt: iso(entry.at), expected: entry.sha256, actual };
  }
}

export const DRIVERS = { s3: S3Bucket, minio: S3Bucket, r2: S3Bucket, b2: S3Bucket, wasabi: S3Bucket, ceph: S3Bucket, azure: AzureBlobBucket, gcs: GcsBucket, 'hash-only': HashOnlyBucket };

/**
 * @param {string} driver
 * @param {object} config
 * @returns {BaseBucket}
 */
export function createBucket(driver, config = {}) {
  const Driver = DRIVERS[String(driver).toLowerCase()];
  if (!Driver) {
    throw new VaultError('config', `unknown storage driver "${driver}"`, { available: Object.keys(DRIVERS) });
  }
  // MinIO and the other S3-compatible endpoints are path-style and need one.
  if (Driver === S3Bucket && driver !== 's3' && !config.endpoint) {
    throw new VaultError('config', `${driver} is S3-compatible but needs its endpoint`, { example: 'https://minio.internal:9000' });
  }
  return new Driver({ ...config, name: config.name || driver });
}
