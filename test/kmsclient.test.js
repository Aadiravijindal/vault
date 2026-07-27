/**
 * Real cloud KMS clients (§22, §5.2).
 *
 * "Your key never leaves your HSM" is the single most over-claimed sentence in
 * this category, so these tests do not check that a function exists — they
 * stand up an HTTP server that speaks the provider's actual protocol, verify
 * the Signature V4 the client produced using an independent implementation of
 * the algorithm, and only then check the round trip. If the signature were
 * wrong, AWS would reject it and so does this server.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import { AwsKmsClient, AzureKeyVaultClient, GcpKmsClient, createKeyClient, RemoteKeyBridge } from '../src/storage/kmsclient.js';
import { Kms } from '../src/storage/kms.js';

// --- an independent SigV4 verifier, written from the spec, not from our code -
function verifySigV4(req, body, { accessKeyId, secretAccessKey, region, service }) {
  const auth = req.headers.authorization || '';
  const m = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]+)$/.exec(auth);
  if (!m) return { ok: false, why: `unparseable Authorization header: ${auth.slice(0, 80)}` };
  const [, key, dateStamp, sigRegion, sigService, signedHeaders, signature] = m;
  if (key !== accessKeyId) return { ok: false, why: 'wrong access key' };
  if (sigRegion !== region) return { ok: false, why: `signed for region ${sigRegion}, expected ${region}` };
  if (sigService !== service) return { ok: false, why: `signed for service ${sigService}, expected ${service}` };

  const hash = (s) => createHash('sha256').update(s).digest('hex');
  const names = signedHeaders.split(';');
  const canonicalHeaders = names.map((n) => `${n}:${String(req.headers[n]).trim()}\n`).join('');
  const url = new URL(req.url, 'http://localhost');
  const canonicalRequest = [
    req.method, url.pathname, '', canonicalHeaders, signedHeaders, hash(body)
  ].join('\n');
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', req.headers['x-amz-date'], scope, hash(canonicalRequest)].join('\n');
  const hmac = (k, d) => createHmac('sha256', k).update(d).digest();
  const signing = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, dateStamp), region), service), 'aws4_request');
  const expected = createHmac('sha256', signing).update(stringToSign).digest('hex');
  return expected === signature
    ? { ok: true, signedHeaders: names }
    : { ok: false, why: 'signature mismatch', expected, got: signature };
}

const CREDS = { accessKeyId: 'AKIAVAULTTEST', secretAccessKey: 'secret-shh-not-real', region: 'eu-central-1' };

/** A KMS that behaves like the real one: enforces the signature and the encryption context. */
async function fakeAwsKms({ failWith = null, keyState = 'Enabled', origin = 'AWS_KMS' } = {}) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const check = verifySigV4(req, body, { ...CREDS, service: 'kms' });
      if (!check.ok) {
        res.writeHead(403, { 'Content-Type': 'application/x-amz-json-1.1' });
        return res.end(JSON.stringify({ __type: 'InvalidSignatureException', message: check.why }));
      }
      const target = String(req.headers['x-amz-target'] || '').replace('TrentService.', '');
      const input = JSON.parse(body || '{}');
      seen.push({ target, input, signedHeaders: check.signedHeaders });
      if (failWith) {
        res.writeHead(failWith.status, { 'Content-Type': 'application/x-amz-json-1.1' });
        return res.end(JSON.stringify({ __type: failWith.type, message: failWith.message }));
      }
      const ctx = JSON.stringify(input.EncryptionContext || {});
      const reply = (o) => { res.writeHead(200, { 'Content-Type': 'application/x-amz-json-1.1' }); res.end(JSON.stringify(o)); };
      if (target === 'Encrypt') {
        // Ciphertext binds the context, exactly as AWS does.
        return reply({ KeyId: 'arn:aws:kms:eu-central-1:1:key/k1', CiphertextBlob: Buffer.from(`${ctx}::${input.Plaintext}`).toString('base64') });
      }
      if (target === 'Decrypt') {
        const raw = Buffer.from(input.CiphertextBlob, 'base64').toString();
        const [boundCtx, plaintext] = raw.split('::');
        if (boundCtx !== ctx) {
          res.writeHead(400, { 'Content-Type': 'application/x-amz-json-1.1' });
          return res.end(JSON.stringify({ __type: 'InvalidCiphertextException', message: 'encryption context mismatch' }));
        }
        return reply({ KeyId: 'arn:aws:kms:eu-central-1:1:key/k1', Plaintext: plaintext });
      }
      if (target === 'GenerateDataKey') {
        const dek = randomBytes(input.NumberOfBytes || 32).toString('base64');
        return reply({ KeyId: 'arn:aws:kms:eu-central-1:1:key/k1', Plaintext: dek, CiphertextBlob: Buffer.from(`${ctx}::${dek}`).toString('base64') });
      }
      if (target === 'DescribeKey') {
        return reply({ KeyMetadata: { KeyId: 'k1', Arn: 'arn:aws:kms:eu-central-1:1:key/k1', Enabled: keyState === 'Enabled', KeyState: keyState, KeyManager: 'CUSTOMER', Origin: origin, KeySpec: 'SYMMETRIC_DEFAULT', MultiRegion: false } });
      }
      if (target === 'ScheduleKeyDeletion') {
        return reply({ KeyId: 'k1', DeletionDate: Date.now() / 1000 + 7 * 86400 });
      }
      res.writeHead(400); res.end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return { server, seen, endpoint: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

const awsClient = (endpoint, extra = {}) => new AwsKmsClient({ keyId: 'arn:aws:kms:eu-central-1:1:key/k1', ...CREDS, endpoint, maxAttempts: 1, ...extra });

describe('AWS KMS — the wire protocol, not a mock of it', () => {
  test('every call carries a Signature V4 that verifies against an independent implementation', async () => {
    const kms = await fakeAwsKms();
    try {
      const c = awsClient(kms.endpoint);
      await c.describe();
      await c.wrap('ns:sales', 'material');
      assert.equal(kms.seen.length, 2, 'both calls reached the server, which rejects bad signatures with 403');
      // The signature must cover the target header — otherwise an attacker who
      // captured a DescribeKey could replay it as a Decrypt.
      for (const call of kms.seen) {
        assert.ok(call.signedHeaders.includes('x-amz-target'), `${call.target} did not sign x-amz-target`);
        assert.ok(call.signedHeaders.includes('x-amz-content-sha256'), `${call.target} did not sign the payload hash`);
        assert.ok(call.signedHeaders.includes('host'));
      }
    } finally { await kms.close(); }
  });

  test('encrypt/decrypt round-trips, and the scope is bound into the encryption context', async () => {
    const kms = await fakeAwsKms();
    try {
      const c = awsClient(kms.endpoint);
      const wrapped = await c.wrap('ns:sales', 'the-actual-key-material');
      assert.equal(wrapped.provider, 'aws');
      assert.ok(wrapped.ciphertext, 'ciphertext must come back');
      assert.equal(String(wrapped.ciphertext).includes('the-actual-key-material'), false,
        'the plaintext must not be recoverable from the stored blob without the provider');

      const back = await c.unwrap('ns:sales', wrapped);
      assert.equal(back.toString(), 'the-actual-key-material');

      // The whole point of the context: a blob wrapped for sales cannot be
      // opened by asking for it as hr.
      await assert.rejects(() => c.unwrap('ns:hr', wrapped), (e) => {
        assert.match(String(e.message), /refused|400/i);
        return true;
      });
    } finally { await kms.close(); }
  });

  test('GenerateDataKey returns material AWS minted, and the stored blob is ciphertext only', async () => {
    const kms = await fakeAwsKms();
    try {
      const c = awsClient(kms.endpoint);
      const gen = await c.generateDataKey('ns:hr', { bytes: 32 });
      assert.equal(gen.dek.length, 32, 'a real 256-bit data key');
      assert.equal(gen.wrapped.alg, 'aws-kms-datakey');
      assert.equal(gen.wrapped.ciphertext.includes(gen.dek.toString('base64')), false,
        'the wrapped blob must not contain the plaintext key');
      const call = kms.seen.find((s) => s.target === 'GenerateDataKey');
      assert.equal(call.input.EncryptionContext.vaultScope, 'ns:hr');
    } finally { await kms.close(); }
  });

  test('a denied key policy produces a permission error naming the fix, not a 500', async () => {
    const kms = await fakeAwsKms({ failWith: { status: 403, type: 'AccessDeniedException', message: 'not authorized to perform kms:Decrypt' } });
    try {
      const c = awsClient(kms.endpoint);
      const health = await c.healthCheck();
      assert.equal(health.ok, false);
      assert.equal(health.error, 'forbidden');
      assert.match(health.remedy, /kms:Decrypt/, 'the remedy must name the missing permission');
      assert.match(health.message, /refused/);
      assert.equal(typeof health.latencyMs, 'number');
    } finally { await kms.close(); }
  });

  test('describe reports what the provider says, so HSM backing is quoted not claimed', async () => {
    const soft = await fakeAwsKms({ origin: 'AWS_KMS' });
    try {
      assert.equal((await awsClient(soft.endpoint).describe()).hsmBacked, false,
        'a plain KMS key is not an HSM key, and must not be reported as one');
    } finally { await soft.close(); }

    const hsm = await fakeAwsKms({ origin: 'EXTERNAL_KEY_STORE' });
    try {
      const meta = await awsClient(hsm.endpoint).describe();
      assert.equal(meta.hsmBacked, true);
      assert.equal(meta.keyManager, 'CUSTOMER');
    } finally { await hsm.close(); }
  });

  test('a throttle is retried; a 403 never is', async () => {
    let hits = 0;
    const server = createServer((req, res) => {
      let body = ''; req.on('data', (c) => { body += c; });
      req.on('end', () => {
        hits++;
        if (hits < 3) { res.writeHead(429); return res.end('{"__type":"ThrottlingException"}'); }
        res.writeHead(200, { 'Content-Type': 'application/x-amz-json-1.1' });
        res.end(JSON.stringify({ KeyMetadata: { KeyId: 'k1', Enabled: true, KeyState: 'Enabled', Origin: 'AWS_KMS' } }));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const c = awsClient(`http://127.0.0.1:${server.address().port}`, { maxAttempts: 4 });
      const meta = await c.describe();
      assert.equal(meta.keyId, 'k1');
      assert.equal(hits, 3, 'it retried the throttle');
      assert.ok(c.stats.retries >= 2);
      assert.ok(c.stats.throttles >= 2);
    } finally { await new Promise((r) => server.close(r)); }

    const denied = await fakeAwsKms({ failWith: { status: 403, type: 'AccessDeniedException', message: 'no' } });
    try {
      const c = awsClient(denied.endpoint, { maxAttempts: 4 });
      await assert.rejects(() => c.describe());
      assert.equal(denied.seen.length, 1, 'a permission error is final — retrying it is just noise');
    } finally { await denied.close(); }
  });

  test('scheduled deletion goes through the provider, with its waiting period intact', async () => {
    const kms = await fakeAwsKms();
    try {
      const out = await awsClient(kms.endpoint).scheduleDeletion({ pendingWindowInDays: 7 });
      assert.equal(out.pendingWindowInDays, 7);
      assert.ok(out.deletionDate, 'the provider tells us when it becomes unrecoverable');
      assert.equal(kms.seen.at(-1).input.PendingWindowInDays, 7);
    } finally { await kms.close(); }
  });

  test('every call is logged locally, so key use is auditable without the provider console', async () => {
    const kms = await fakeAwsKms();
    try {
      const c = awsClient(kms.endpoint);
      const w = await c.wrap('ns:sales', 'x');
      await c.unwrap('ns:sales', w);
      const ops = c.callLog.map((l) => l.op);
      assert.deepEqual(ops, ['encrypt', 'decrypt']);
      assert.ok(c.callLog.every((l) => l.ok && l.at && l.provider === 'aws'));
    } finally { await kms.close(); }
  });
});

describe('the bridge from a cloud KMS into the key hierarchy', () => {
  test('an unprimed scope fails loudly rather than silently using a local key', async () => {
    const kms = await fakeAwsKms();
    try {
      const bridge = new RemoteKeyBridge(awsClient(kms.endpoint));
      const { externalWrap, externalUnwrap } = bridge.adapters();
      // The dangerous failure mode is degrading to Vault-managed keys while
      // still reporting HYOK. It must throw instead.
      assert.throws(() => externalWrap('ns:sales', randomBytes(32)), /not primed/);
      assert.throws(() => externalUnwrap('ns:sales', {}), /not primed/);
    } finally { await kms.close(); }
  });

  test('a primed scope encrypts and decrypts real data through the KMS-held key', async () => {
    const kms = await fakeAwsKms();
    try {
      const bridge = new RemoteKeyBridge(awsClient(kms.endpoint));
      await bridge.primeScope('ns:sales');
      const hierarchy = new Kms({ mode: 'hyok', ...bridge.adapters() });

      const box = hierarchy.seal('ns:sales', 'Globex renewal is 340 seats');
      const plain = hierarchy.open(box);
      assert.equal(String(plain), 'Globex renewal is 340 seats');
      assert.equal(JSON.stringify(box).includes('340 seats'), false, 'the ciphertext must not contain the plaintext');

      const status = bridge.status();
      assert.deepEqual(status.primedScopes, ['ns:sales']);
      assert.equal(status.provider, 'aws');
      assert.ok(status.stats.wraps >= 1, 'the provider really was called');
    } finally { await kms.close(); }
  });

  test('an expired cache entry stops working, so a revoked key policy takes effect', async () => {
    const kms = await fakeAwsKms();
    try {
      const bridge = new RemoteKeyBridge(awsClient(kms.endpoint), { ttlMs: 1 });
      await bridge.primeScope('ns:sales');
      await new Promise((r) => setTimeout(r, 5));
      assert.throws(() => bridge.adapters().externalWrap('ns:sales', randomBytes(32)), /expired/);
    } finally { await kms.close(); }
  });
});

describe('Azure and GCP clients', () => {
  test('Azure signs with a bearer token and speaks wrapKey/unwrapKey', async () => {
    const seen = [];
    const server = createServer((req, res) => {
      let body = ''; req.on('data', (c) => { body += c; });
      req.on('end', () => {
        seen.push({ url: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : null });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (/unwrapkey/.test(req.url)) {
          const inner = Buffer.from(JSON.parse(body).value, 'base64url').toString().replace('wrapped:', '');
          return res.end(JSON.stringify({ kid: 'https://v/keys/k/1', value: inner }));
        }
        if (/wrapkey/.test(req.url)) return res.end(JSON.stringify({ kid: 'https://v/keys/k/1', value: Buffer.from(`wrapped:${JSON.parse(body).value}`).toString('base64url') }));
        res.end(JSON.stringify({ key: { kid: 'https://v/keys/k/1', kty: 'RSA-HSM', key_ops: ['wrapKey', 'unwrapKey'] }, attributes: { enabled: true } }));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const c = new AzureKeyVaultClient({ vaultUrl: `http://127.0.0.1:${server.address().port}`, keyName: 'k', accessToken: 'tok', maxAttempts: 1 });
      const w = await c.wrap('ns:sales', 'material-here');
      assert.equal((await c.unwrap('ns:sales', w)).toString(), 'material-here');
      assert.ok(seen.every((s) => s.auth === 'Bearer tok'), 'every call carries the token');
      const meta = await c.describe();
      assert.equal(meta.hsmBacked, true, 'kty RSA-HSM is Azure saying the private key never left the HSM');
      assert.match(meta.fipsLevelClaimedByProvider, /FIPS 140-2/);
    } finally { await new Promise((r) => server.close(r)); }
  });

  test('GCP binds the scope as additional authenticated data', async () => {
    const seen = [];
    const server = createServer((req, res) => {
      let body = ''; req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const input = body ? JSON.parse(body) : {};
        seen.push({ url: req.url, input });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (/:encrypt$/.test(req.url)) return res.end(JSON.stringify({ name: 'projects/p/…/cryptoKeyVersions/1', ciphertext: Buffer.from(`${input.additionalAuthenticatedData}::${input.plaintext}`).toString('base64') }));
        if (/:decrypt$/.test(req.url)) {
          const [aad, pt] = Buffer.from(input.ciphertext, 'base64').toString().split('::');
          if (aad !== input.additionalAuthenticatedData) { res.writeHead(400); return res.end('{"error":"aad mismatch"}'); }
          return res.end(JSON.stringify({ plaintext: pt }));
        }
        res.end(JSON.stringify({ name: 'projects/p/locations/l/keyRings/r/cryptoKeys/k', purpose: 'ENCRYPT_DECRYPT', primary: { state: 'ENABLED', protectionLevel: 'HSM' } }));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const c = new GcpKmsClient({
        keyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k',
        accessToken: 'tok', endpoint: `http://127.0.0.1:${server.address().port}/v1`, maxAttempts: 1
      });
      const w = await c.wrap('ns:sales', 'material');
      assert.equal((await c.unwrap('ns:sales', w)).toString(), 'material');
      const enc = seen.find((s) => /:encrypt$/.test(s.url));
      assert.equal(Buffer.from(enc.input.additionalAuthenticatedData, 'base64').toString(), 'ns:sales');
      const meta = await c.describe();
      assert.equal(meta.protectionLevel, 'HSM');
      assert.equal(meta.hsmBacked, true);
    } finally { await new Promise((r) => server.close(r)); }
  });

  test('an unknown provider is a config error listing the real ones', () => {
    assert.throws(() => createKeyClient('oracle', {}), (e) => {
      assert.deepEqual(e.meta.available, ['aws', 'azure', 'gcp']);
      return true;
    });
    assert.throws(() => createKeyClient('aws', { region: 'eu-west-1' }), /keyId/);
  });
});
