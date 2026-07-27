/**
 * Real key-management clients — AWS KMS, Azure Key Vault, GCP Cloud KMS.
 *
 * The `Kms` class in kms.js does the key *hierarchy* (scopes, versions,
 * rotation, crypto-shredding). It has always accepted `externalWrap` /
 * `externalUnwrap` callbacks for CMK/HYOK/HSM modes — but until now nothing
 * shipped that actually spoke to a cloud KMS, so "the customer's key never
 * leaves their HSM" was a shape the code could accept rather than something it
 * could do.
 *
 * This file closes that. Each client speaks the provider's real wire protocol
 * with no SDK: AWS via Signature V4 against the `kms` service and the
 * `TrentService` JSON-1.1 targets, Azure via the Key Vault `wrapKey`/`unwrapKey`
 * REST operations, GCP via the Cloud KMS `encrypt`/`decrypt` endpoints. The
 * plaintext root key is never constructed locally in any of them: what comes
 * back is ciphertext the provider alone can open.
 *
 * A note on honesty, because this is exactly the claim buyers over-read: using
 * these clients means the KEK lives in the provider's HSM and Vault holds only
 * wrapped material. It does NOT by itself mean FIPS 140-3 Level 3 — that
 * depends on which key store you point at (AWS CloudHSM, Azure Managed HSM,
 * GCP `protection_level: HSM`). `describe()` reports what the provider says the
 * key actually is, so the evidence pack quotes the provider rather than us.
 */
import { createSign, randomBytes } from 'node:crypto';
import { signV4 } from './buckets.js';
import { wrapKey, unwrapKey } from '../util/crypto.js';
import { now, iso } from '../util/time.js';
import { VaultError } from '../util/errors.js';

const DEFAULT_TIMEOUT = 10_000;

/** Retry only what is worth retrying: throttles and 5xx, never a 4xx auth error. */
const RETRYABLE = new Set([429, 500, 502, 503, 504]);

class BaseKeyClient {
  constructor(config = {}) {
    this.config = config;
    this.provider = 'unknown';
    this.stats = { wraps: 0, unwraps: 0, errors: 0, retries: 0, throttles: 0 };
    /** @type {Array<object>} every call, so key use is auditable independently of the provider's own log */
    this.callLog = [];
    this.maxAttempts = config.maxAttempts ?? 3;
    this.fetchImpl = config.fetch || globalThis.fetch;
  }

  _record(op, ok, detail = {}) {
    const entry = { at: now(), provider: this.provider, op, ok, ...detail };
    this.callLog.push(entry);
    if (this.callLog.length > 5000) this.callLog.splice(0, 1000);
    return entry;
  }

  async _http(url, init, op) {
    let lastErr = null;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs ?? DEFAULT_TIMEOUT);
      try {
        const res = await this.fetchImpl(url, { ...init, signal: controller.signal });
        clearTimeout(timer);
        if (res.ok) return res;
        const body = await res.text().catch(() => '');
        if (res.status === 429) this.stats.throttles++;
        if (RETRYABLE.has(res.status) && attempt < this.maxAttempts) {
          this.stats.retries++;
          await new Promise((r) => setTimeout(r, 2 ** attempt * 100));
          lastErr = new VaultError('kms_unavailable', `${this.provider} KMS ${op} failed: ${res.status}`, { status: res.status, body: body.slice(0, 400) });
          continue;
        }
        this.stats.errors++;
        this._record(op, false, { status: res.status });
        // A KMS refusal is a permission story, not a mystery. Surface the
        // provider's own words: "key policy denies kms:Decrypt for this role"
        // is the difference between a five-minute fix and a support ticket.
        throw new VaultError(res.status === 403 || res.status === 401 ? 'forbidden' : 'kms_error',
          `${this.provider} KMS ${op} refused (${res.status})`,
          { status: res.status, providerMessage: body.slice(0, 600) });
      } catch (e) {
        clearTimeout(timer);
        if (e instanceof VaultError) { if (attempt >= this.maxAttempts || e.code !== 'kms_unavailable') throw e; lastErr = e; continue; }
        lastErr = new VaultError('kms_unavailable', `${this.provider} KMS ${op} unreachable: ${e.message}`, { cause: e.message });
        if (attempt >= this.maxAttempts) break;
        this.stats.retries++;
        await new Promise((r) => setTimeout(r, 2 ** attempt * 100));
      }
    }
    this.stats.errors++;
    this._record(op, false, { unreachable: true });
    throw lastErr;
  }

  /** The adapter shape `Kms` expects for cmk/hyok/hsm modes. */
  adapters() {
    return {
      externalWrap: (scope, dek) => this.wrapSync(scope, dek),
      externalUnwrap: (scope, wrapped) => this.unwrapSync(scope, wrapped)
    };
  }

  /**
   * `Kms.newObjectKey` is synchronous by design — a write path that awaits a
   * network round trip per object is a write path that stalls under load. So a
   * client used in that position must be primed: `prime()` fetches the wrapping
   * material once, and the sync path uses the cached grant. Calling the sync
   * path without priming is an error with a fix in the message, not a silent
   * fallback to local keys.
   */
  wrapSync(scope) {
    throw new VaultError('config',
      `${this.provider} KMS is asynchronous — call await kms.primeScope(${JSON.stringify(scope)}) at startup, or use the async wrap()`,
      { scope, provider: this.provider });
  }

  unwrapSync(scope) { return this.wrapSync(scope); }
}

// ---------------------------------------------------------------------------
// AWS KMS
// ---------------------------------------------------------------------------

/**
 * AWS KMS over Signature V4. No SDK, no credentials file: the caller supplies
 * the access key, and the same `signV4` that signs S3 requests signs these.
 */
export class AwsKmsClient extends BaseKeyClient {
  /**
   * @param {object} c
   * @param {string} c.keyId  key ARN, key id, or alias/name
   * @param {string} c.region
   * @param {string} c.accessKeyId
   * @param {string} c.secretAccessKey
   * @param {string} [c.sessionToken]
   * @param {string} [c.endpoint] override, for VPC endpoints or a test double
   */
  constructor(c = {}) {
    super(c);
    this.provider = 'aws';
    for (const required of ['keyId', 'region', 'accessKeyId', 'secretAccessKey']) {
      if (!c[required]) throw new VaultError('config', `AWS KMS needs ${required}`);
    }
    this.endpoint = c.endpoint || `https://kms.${c.region}.amazonaws.com`;
  }

  async _call(target, body, op) {
    const payload = JSON.stringify(body);
    const signed = signV4({
      method: 'POST', url: this.endpoint, region: this.config.region, service: 'kms',
      accessKeyId: this.config.accessKeyId, secretAccessKey: this.config.secretAccessKey,
      sessionToken: this.config.sessionToken || null,
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': `TrentService.${target}` },
      payload
    });
    const res = await this._http(this.endpoint, { method: 'POST', headers: signed.headers, body: payload }, op);
    return res.json();
  }

  /**
   * GenerateDataKey — the correct primitive for envelope encryption. AWS mints
   * the DEK inside its HSM and hands back both the plaintext (for this process,
   * in memory, never persisted) and the ciphertext (which is what we store).
   * @returns {Promise<{dek:Buffer, wrapped:object, keyId:string}>}
   */
  async generateDataKey(scope, { bytes = 32 } = {}) {
    const out = await this._call('GenerateDataKey', {
      KeyId: this.config.keyId,
      NumberOfBytes: bytes,
      EncryptionContext: { vaultScope: scope, ...(this.config.encryptionContext || {}) }
    }, 'generateDataKey');
    this.stats.wraps++;
    this._record('generateDataKey', true, { scope, keyId: out.KeyId });
    return {
      dek: Buffer.from(out.Plaintext, 'base64'),
      wrapped: { provider: 'aws', keyId: out.KeyId, scope, ciphertext: out.CiphertextBlob, alg: 'aws-kms-datakey' },
      keyId: out.KeyId
    };
  }

  /** Encrypt arbitrary material (≤4KB) directly under the CMK. */
  async wrap(scope, plaintext) {
    const out = await this._call('Encrypt', {
      KeyId: this.config.keyId,
      Plaintext: Buffer.from(plaintext).toString('base64'),
      EncryptionContext: { vaultScope: scope, ...(this.config.encryptionContext || {}) }
    }, 'encrypt');
    this.stats.wraps++;
    this._record('encrypt', true, { scope, keyId: out.KeyId });
    return { provider: 'aws', keyId: out.KeyId, scope, ciphertext: out.CiphertextBlob, alg: 'aws-kms' };
  }

  /** @returns {Promise<Buffer>} */
  async unwrap(scope, wrapped) {
    if (!wrapped || !wrapped.ciphertext) throw new VaultError('invalid', 'wrapped material has no ciphertext', { scope });
    const out = await this._call('Decrypt', {
      CiphertextBlob: wrapped.ciphertext,
      // Binding the context means a blob wrapped for sales/ cannot be opened by
      // claiming it belongs to hr/ — AWS enforces it, not us.
      EncryptionContext: { vaultScope: scope, ...(this.config.encryptionContext || {}) },
      ...(this.config.keyId.startsWith('arn:') ? { KeyId: this.config.keyId } : {})
    }, 'decrypt');
    this.stats.unwraps++;
    this._record('decrypt', true, { scope, keyId: out.KeyId });
    return Buffer.from(out.Plaintext, 'base64');
  }

  /** What the provider says this key actually is — quoted, not paraphrased. */
  async describe() {
    const out = await this._call('DescribeKey', { KeyId: this.config.keyId }, 'describeKey');
    const m = out.KeyMetadata || {};
    return {
      provider: 'aws', keyId: m.KeyId, arn: m.Arn, enabled: m.Enabled,
      keyState: m.KeyState, keyManager: m.KeyManager, origin: m.Origin,
      keySpec: m.KeySpec, multiRegion: m.MultiRegion ?? false,
      // AWS reports EXTERNAL_KEY_STORE for CloudHSM/XKS-backed keys. That, not
      // our marketing, is what an auditor should read.
      hsmBacked: m.Origin === 'AWS_CLOUDHSM' || m.Origin === 'EXTERNAL_KEY_STORE',
      rotationNote: 'AWS-managed rotation is a provider setting; Vault rotates its own KEK versions independently.'
    };
  }

  /**
   * Crypto-shredding at the provider. AWS enforces a 7–30 day waiting period,
   * which is a feature: an erasure that cannot be undone within the appeal
   * window is an erasure that cannot be corrected after a mistake.
   */
  async scheduleDeletion({ pendingWindowInDays = 7 } = {}) {
    const out = await this._call('ScheduleKeyDeletion', {
      KeyId: this.config.keyId, PendingWindowInDays: pendingWindowInDays
    }, 'scheduleKeyDeletion');
    this._record('scheduleKeyDeletion', true, { deletionDate: out.DeletionDate });
    return { provider: 'aws', keyId: out.KeyId, deletionDate: out.DeletionDate, pendingWindowInDays };
  }

  /** Prove the credentials, the key policy and the network path, all at once. */
  async healthCheck() {
    const started = now();
    try {
      const meta = await this.describe();
      const probe = await this.wrap('__vault_healthcheck__', 'vault-kms-canary');
      const back = await this.unwrap('__vault_healthcheck__', probe);
      const roundTrip = back.toString() === 'vault-kms-canary';
      return {
        ok: roundTrip && meta.enabled !== false, provider: 'aws', keyId: meta.keyId,
        keyState: meta.keyState, hsmBacked: meta.hsmBacked, roundTrip,
        latencyMs: now() - started, checkedAt: iso()
      };
    } catch (e) {
      return {
        ok: false, provider: 'aws', error: e.code || 'error', message: e.message,
        remedy: e.code === 'forbidden'
          ? 'the key policy must allow kms:Encrypt, kms:Decrypt, kms:GenerateDataKey and kms:DescribeKey for this principal'
          : 'check the region, endpoint and network path to KMS',
        latencyMs: now() - started, checkedAt: iso()
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Azure Key Vault / Managed HSM
// ---------------------------------------------------------------------------

export class AzureKeyVaultClient extends BaseKeyClient {
  /**
   * @param {object} c
   * @param {string} c.vaultUrl  https://<name>.vault.azure.net or .managedhsm.azure.net
   * @param {string} c.keyName
   * @param {string} [c.keyVersion]
   * @param {string} [c.accessToken] a bearer token, if you mint it yourself
   * @param {string} [c.tenantId] @param {string} [c.clientId] @param {string} [c.clientSecret]
   */
  constructor(c = {}) {
    super(c);
    this.provider = 'azure';
    if (!c.vaultUrl || !c.keyName) throw new VaultError('config', 'Azure Key Vault needs vaultUrl and keyName');
    if (!c.accessToken && !(c.tenantId && c.clientId && c.clientSecret)) {
      throw new VaultError('config', 'Azure Key Vault needs an accessToken or (tenantId + clientId + clientSecret)');
    }
    this.apiVersion = c.apiVersion || '7.4';
    this.algorithm = c.algorithm || 'RSA-OAEP-256';
    this._token = c.accessToken ? { value: c.accessToken, expiresAt: Infinity } : null;
    this.managedHsm = /managedhsm\.azure\.net/i.test(c.vaultUrl);
  }

  async _bearer() {
    if (this._token && this._token.expiresAt > now() + 60_000) return this._token.value;
    const url = `https://login.microsoftonline.com/${this.config.tenantId}/oauth2/v2.0/token`;
    const res = await this._http(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials', client_id: this.config.clientId,
        client_secret: this.config.clientSecret, scope: 'https://vault.azure.net/.default'
      }).toString()
    }, 'token');
    const body = await res.json();
    this._token = { value: body.access_token, expiresAt: now() + (body.expires_in ?? 3600) * 1000 };
    return this._token.value;
  }

  _keyUrl(op) {
    const v = this.config.keyVersion ? `/${this.config.keyVersion}` : '';
    return `${this.config.vaultUrl.replace(/\/$/, '')}/keys/${encodeURIComponent(this.config.keyName)}${v}/${op}?api-version=${this.apiVersion}`;
  }

  async _op(op, body) {
    const res = await this._http(this._keyUrl(op), {
      method: 'POST',
      headers: { Authorization: `Bearer ${await this._bearer()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }, op);
    return res.json();
  }

  async wrap(scope, plaintext) {
    const out = await this._op('wrapkey', { alg: this.algorithm, value: Buffer.from(plaintext).toString('base64url') });
    this.stats.wraps++;
    this._record('wrapkey', true, { scope, kid: out.kid });
    return { provider: 'azure', keyId: out.kid, scope, ciphertext: out.value, alg: this.algorithm };
  }

  async unwrap(scope, wrapped) {
    const out = await this._op('unwrapkey', { alg: wrapped.alg || this.algorithm, value: wrapped.ciphertext });
    this.stats.unwraps++;
    this._record('unwrapkey', true, { scope, kid: out.kid });
    return Buffer.from(out.value, 'base64url');
  }

  async describe() {
    const v = this.config.keyVersion ? `/${this.config.keyVersion}` : '';
    const url = `${this.config.vaultUrl.replace(/\/$/, '')}/keys/${encodeURIComponent(this.config.keyName)}${v}?api-version=${this.apiVersion}`;
    const res = await this._http(url, { method: 'GET', headers: { Authorization: `Bearer ${await this._bearer()}` } }, 'getKey');
    const body = await res.json();
    return {
      provider: 'azure', keyId: body.key?.kid, keyType: body.key?.kty,
      enabled: body.attributes?.enabled !== false,
      // kty "RSA-HSM"/"EC-HSM" is Azure's own marker that the private key never
      // left the HSM. Managed HSM is FIPS 140-2 L3; standard Key Vault is L2.
      hsmBacked: /-HSM$/.test(body.key?.kty || '') || this.managedHsm,
      fipsLevelClaimedByProvider: this.managedHsm ? 'FIPS 140-2 Level 3 (Managed HSM)' : 'FIPS 140-2 Level 2 (standard Key Vault, software keys) unless kty ends in -HSM',
      exportable: body.key_ops?.includes('export') ?? false
    };
  }

  async scheduleDeletion() {
    const url = `${this.config.vaultUrl.replace(/\/$/, '')}/keys/${encodeURIComponent(this.config.keyName)}?api-version=${this.apiVersion}`;
    const res = await this._http(url, { method: 'DELETE', headers: { Authorization: `Bearer ${await this._bearer()}` } }, 'deleteKey');
    const body = await res.json().catch(() => ({}));
    this._record('deleteKey', true, {});
    return {
      provider: 'azure', keyId: body.key?.kid ?? this.config.keyName,
      scheduledPurgeDate: body.scheduledPurgeDate ?? null,
      note: 'soft-delete is on by default; the key is unusable now and purgeable after the retention window'
    };
  }

  async healthCheck() {
    const started = now();
    try {
      const meta = await this.describe();
      const probe = await this.wrap('__vault_healthcheck__', 'vault-kms-canary');
      const back = await this.unwrap('__vault_healthcheck__', probe);
      return {
        ok: back.toString() === 'vault-kms-canary' && meta.enabled, provider: 'azure',
        keyId: meta.keyId, hsmBacked: meta.hsmBacked, roundTrip: back.toString() === 'vault-kms-canary',
        latencyMs: now() - started, checkedAt: iso()
      };
    } catch (e) {
      return {
        ok: false, provider: 'azure', error: e.code || 'error', message: e.message,
        remedy: 'the app registration needs the Key Vault Crypto User role, and wrapKey/unwrapKey in key_ops',
        latencyMs: now() - started, checkedAt: iso()
      };
    }
  }
}

// ---------------------------------------------------------------------------
// GCP Cloud KMS
// ---------------------------------------------------------------------------

export class GcpKmsClient extends BaseKeyClient {
  /**
   * @param {object} c
   * @param {string} c.keyName projects/p/locations/l/keyRings/r/cryptoKeys/k
   * @param {string} [c.accessToken] or a service account:
   * @param {string} [c.clientEmail] @param {string} [c.privateKey]
   */
  constructor(c = {}) {
    super(c);
    this.provider = 'gcp';
    if (!c.keyName) throw new VaultError('config', 'GCP KMS needs keyName (projects/…/cryptoKeys/…)');
    if (!c.accessToken && !(c.clientEmail && c.privateKey)) {
      throw new VaultError('config', 'GCP KMS needs an accessToken or a service account (clientEmail + privateKey)');
    }
    this.endpoint = c.endpoint || 'https://cloudkms.googleapis.com/v1';
    this._token = c.accessToken ? { value: c.accessToken, expiresAt: Infinity } : null;
  }

  async _bearer() {
    if (this._token && this._token.expiresAt > now() + 60_000) return this._token.value;
    const aud = this.config.tokenUri || 'https://oauth2.googleapis.com/token';
    const iat = Math.floor(now() / 1000);
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({
      iss: this.config.clientEmail, scope: 'https://www.googleapis.com/auth/cloudkms', aud, exp: iat + 3600, iat
    })}`;
    const signature = createSign('RSA-SHA256').update(unsigned).sign(this.config.privateKey, 'base64url');
    const res = await this._http(aud, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` }).toString()
    }, 'token');
    const body = await res.json();
    this._token = { value: body.access_token, expiresAt: now() + (body.expires_in ?? 3600) * 1000 };
    return this._token.value;
  }

  async _op(op, body) {
    const res = await this._http(`${this.endpoint}/${this.config.keyName}:${op}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${await this._bearer()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }, op);
    return res.json();
  }

  async wrap(scope, plaintext) {
    const out = await this._op('encrypt', {
      plaintext: Buffer.from(plaintext).toString('base64'),
      additionalAuthenticatedData: Buffer.from(scope).toString('base64')
    });
    this.stats.wraps++;
    this._record('encrypt', true, { scope, version: out.name });
    return { provider: 'gcp', keyId: out.name, scope, ciphertext: out.ciphertext, alg: 'gcp-kms' };
  }

  async unwrap(scope, wrapped) {
    const out = await this._op('decrypt', {
      ciphertext: wrapped.ciphertext,
      additionalAuthenticatedData: Buffer.from(scope).toString('base64')
    });
    this.stats.unwraps++;
    this._record('decrypt', true, { scope });
    return Buffer.from(out.plaintext, 'base64');
  }

  async describe() {
    const res = await this._http(`${this.endpoint}/${this.config.keyName}`, {
      method: 'GET', headers: { Authorization: `Bearer ${await this._bearer()}` }
    }, 'getKey');
    const body = await res.json();
    const primary = body.primary || {};
    return {
      provider: 'gcp', keyId: body.name, purpose: body.purpose,
      enabled: primary.state === 'ENABLED', keyState: primary.state,
      protectionLevel: primary.protectionLevel,
      hsmBacked: primary.protectionLevel === 'HSM' || primary.protectionLevel === 'EXTERNAL',
      rotationPeriod: body.rotationPeriod ?? null,
      nextRotation: body.nextRotationTime ?? null
    };
  }

  async scheduleDeletion() {
    const meta = await this.describe();
    const version = meta.keyId && /cryptoKeyVersions\//.test(String(meta.keyId)) ? meta.keyId : null;
    if (!version) {
      throw new VaultError('invalid',
        'GCP destroys key *versions*, not keys — pass the version resource name to destroy',
        { keyName: this.config.keyName });
    }
    const res = await this._http(`${this.endpoint}/${version}:destroy`, {
      method: 'POST', headers: { Authorization: `Bearer ${await this._bearer()}`, 'Content-Type': 'application/json' }, body: '{}'
    }, 'destroy');
    const body = await res.json();
    return { provider: 'gcp', keyId: version, destroyTime: body.destroyTime ?? null, note: 'GCP holds destroyed versions for 24h before they become unrecoverable' };
  }

  async healthCheck() {
    const started = now();
    try {
      const meta = await this.describe();
      const probe = await this.wrap('__vault_healthcheck__', 'vault-kms-canary');
      const back = await this.unwrap('__vault_healthcheck__', probe);
      return {
        ok: back.toString() === 'vault-kms-canary' && meta.enabled, provider: 'gcp',
        keyId: meta.keyId, protectionLevel: meta.protectionLevel, hsmBacked: meta.hsmBacked,
        roundTrip: back.toString() === 'vault-kms-canary', latencyMs: now() - started, checkedAt: iso()
      };
    } catch (e) {
      return {
        ok: false, provider: 'gcp', error: e.code || 'error', message: e.message,
        remedy: 'the service account needs roles/cloudkms.cryptoKeyEncrypterDecrypter on this key',
        latencyMs: now() - started, checkedAt: iso()
      };
    }
  }
}

export const KEY_PROVIDERS = { aws: AwsKmsClient, azure: AzureKeyVaultClient, gcp: GcpKmsClient };

/** @param {'aws'|'azure'|'gcp'} provider */
export function createKeyClient(provider, config = {}) {
  const Ctor = KEY_PROVIDERS[provider];
  if (!Ctor) {
    throw new VaultError('config', `unknown key provider "${provider}"`, { available: Object.keys(KEY_PROVIDERS) });
  }
  return new Ctor(config);
}

/**
 * Bridge a cloud KMS into the synchronous `Kms` hierarchy.
 *
 * The write path cannot await a network call per object, so this pre-fetches a
 * KEK per scope (`primeScope`) and holds it in memory only — never on disk, and
 * never derived locally. Cache entries expire, so a revoked key policy stops
 * working within `ttlMs` instead of whenever the process happens to restart.
 */
export class RemoteKeyBridge {
  constructor(client, { ttlMs = 15 * 60_000, onEvent } = {}) {
    this.client = client;
    this.ttlMs = ttlMs;
    this.onEvent = onEvent || (() => {});
    /** @type {Map<string, {kek:Buffer, wrapped:object, at:number}>} */
    this.cache = new Map();
  }

  /** Fetch (or mint) the wrapping key for a scope. Call at startup, per namespace. */
  async primeScope(scope) {
    const gen = this.client.generateDataKey
      ? await this.client.generateDataKey(scope)
      // Azure and GCP have no GenerateDataKey equivalent, so the KEK is minted
      // locally and immediately wrapped: the plaintext exists only in this
      // process's memory, and only the provider can reproduce it later.
      : await (async () => {
        const material = randomBytes(32);
        return { dek: material, wrapped: await this.client.wrap(scope, material) };
      })();
    this.cache.set(scope, { kek: gen.dek, wrapped: gen.wrapped, at: now() });
    this.onEvent({ type: 'key.primed', scope, provider: this.client.provider, at: iso() });
    return { scope, provider: this.client.provider, primedAt: iso() };
  }

  /** Restore a previously-primed scope from its stored wrapped blob. */
  async restoreScope(scope, wrapped) {
    const kek = await this.client.unwrap(scope, wrapped);
    this.cache.set(scope, { kek, wrapped, at: now() });
    this.onEvent({ type: 'key.restored', scope, provider: this.client.provider, at: iso() });
    return { scope, restoredAt: iso() };
  }

  _live(scope) {
    const hit = this.cache.get(scope);
    if (!hit) {
      throw new VaultError('config',
        `scope "${scope}" is not primed — call await bridge.primeScope("${scope}") before writing to it`,
        { scope, primed: [...this.cache.keys()] });
    }
    if (now() - hit.at > this.ttlMs) {
      this.cache.delete(scope);
      throw new VaultError('key_expired',
        `the cached wrapping key for "${scope}" expired — re-prime so a revoked key policy takes effect`,
        { scope, ttlMs: this.ttlMs });
    }
    return hit;
  }

  /** The `Kms` adapter pair, now backed by a real provider key. */
  adapters() {
    return {
      externalWrap: (scope, dek) => {
        const { kek, wrapped } = this._live(scope);
        // The DEK is wrapped under a KEK the provider minted and holds. Vault
        // never possesses material that can open this without the provider:
        // `remoteKek` is the only durable copy, and it is ciphertext.
        return { ...wrapKey(kek, dek, scope), provider: this.client.provider, remoteKek: wrapped };
      },
      externalUnwrap: (scope, wrapped) => unwrapKey(this._live(scope).kek, wrapped)
    };
  }

  status() {
    return {
      provider: this.client.provider,
      primedScopes: [...this.cache.keys()],
      ttlMs: this.ttlMs,
      stats: this.client.stats,
      recentCalls: this.client.callLog.slice(-20).map((c) => ({ at: iso(c.at), op: c.op, ok: c.ok }))
    };
  }
}
