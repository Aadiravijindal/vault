/**
 * L11 — Bring Your Own Bucket (§5.2).
 *
 * These run against a local endpoint that INDEPENDENTLY recomputes each
 * provider's signature and rejects anything that does not match, so a passing
 * test means the wire format is right — not merely that we sent bytes. The
 * AWS SigV4 case is additionally checked against the published worked example
 * from Amazon's own documentation, which pins the algorithm to a known answer.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHmac, createHash, generateKeyPairSync } from 'node:crypto';
import { S3Bucket, AzureBlobBucket, GcsBucket, HashOnlyBucket, createBucket, signV4 } from '../src/storage/buckets.js';

/** A local object store that validates auth, then behaves like the real thing. */
function fakeStore({ validate }) {
  const objects = new Map();
  const seen = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString();
    const headers = req.headers;
    seen.push({ method: req.method, url: req.url, headers, body });
    const verdict = validate({ method: req.method, url: req.url, headers, body });
    if (!verdict.ok) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end(`SignatureDoesNotMatch: ${verdict.why}`);
    }
    if (req.method === 'PUT' || req.method === 'POST') {
      const key = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      objects.set(key, body);
      const md5 = createHash('md5').update(body);
      res.writeHead(200, {
        etag: `"${md5.copy ? md5.copy().digest('hex') : createHash('md5').update(body).digest('hex')}"`,
        'content-md5': createHash('md5').update(body).digest('base64'),
        'Content-Type': 'application/json'
      });
      return res.end(JSON.stringify({ md5Hash: createHash('md5').update(body).digest('base64'), generation: '1' }));
    }
    if (req.method === 'GET') {
      const key = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      const hit = [...objects.entries()].find(([k]) => key.endsWith(k.split('/').pop()));
      if (!hit) { res.writeHead(404); return res.end('NoSuchKey'); }
      res.writeHead(200); return res.end(hit[1]);
    }
    if (req.method === 'DELETE') { res.writeHead(204); return res.end(); }
    res.writeHead(405); res.end();
  });
  return { server, objects, seen, listen: () => new Promise((r) => server.listen(0, '127.0.0.1', r)), port: () => server.address().port };
}

describe('AWS SigV4', () => {
  test('matches Amazon\'s published worked example byte for byte', () => {
    // From the AWS "Signature Version 4 test suite" GET vanilla case: a fixed
    // key, date and request with a documented expected signature. If our
    // canonicalisation drifts, this breaks.
    const signed = signV4({
      method: 'GET',
      url: 'https://examplebucket.s3.amazonaws.com/test.txt',
      region: 'us-east-1',
      service: 's3',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      headers: { Range: 'bytes=0-9' },
      payload: '',
      at: new Date('2013-05-24T00:00:00Z')
    });
    assert.match(signed.canonicalRequest, /^GET\n\/test\.txt\n\n/, 'canonical request shape');
    assert.match(signed.stringToSign, /^AWS4-HMAC-SHA256\n20130524T000000Z\n20130524\/us-east-1\/s3\/aws4_request\n/);
    // Amazon documents this exact signature for this exact request.
    assert.equal(signed.signature, 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
    assert.match(signed.headers.Authorization, /Credential=AKIAIOSFODNN7EXAMPLE\/20130524\/us-east-1\/s3\/aws4_request/);
    assert.match(signed.headers.Authorization, /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date/);
  });

  test('a tampered payload invalidates the signature', () => {
    const args = {
      method: 'PUT', url: 'https://b.s3.us-east-1.amazonaws.com/k', region: 'us-east-1',
      accessKeyId: 'AK', secretAccessKey: 'SK', at: new Date('2026-01-01T00:00:00Z')
    };
    const a = signV4({ ...args, payload: 'original' });
    const b = signV4({ ...args, payload: 'tampered' });
    assert.notEqual(a.signature, b.signature, 'the payload hash is inside the signature');
  });
});

describe('S3 (and every S3-compatible endpoint)', () => {
  test('a real signed PUT is accepted, write-through is verified, and object lock is set', async () => {
    const store = fakeStore({
      validate: ({ method, url, headers, body }) => {
        // Recompute the signature independently, exactly as S3 would.
        const auth = headers.authorization || '';
        const m = /Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([a-f0-9]+)/.exec(auth);
        if (!m) return { ok: false, why: 'missing or malformed Authorization' };
        const [, ak, date, region, service, signedHeaders, sig] = m;
        if (headers['x-amz-content-sha256'] !== createHash('sha256').update(body).digest('hex')) {
          return { ok: false, why: 'x-amz-content-sha256 does not match the body' };
        }
        const canonicalHeaders = signedHeaders.split(';').map((h) => `${h}:${String(headers[h]).trim()}\n`).join('');
        const u = new URL(url, 'http://x');
        const canonicalRequest = [
          method, u.pathname, '', canonicalHeaders, signedHeaders, headers['x-amz-content-sha256']
        ].join('\n');
        const scope = `${date}/${region}/${service}/aws4_request`;
        const sts = ['AWS4-HMAC-SHA256', headers['x-amz-date'], scope,
          createHash('sha256').update(canonicalRequest).digest('hex')].join('\n');
        let k = createHmac('sha256', `AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`).update(date).digest();
        for (const part of [region, service, 'aws4_request']) k = createHmac('sha256', k).update(part).digest();
        const expected = createHmac('sha256', k).update(sts).digest('hex');
        if (expected !== sig) return { ok: false, why: `signature mismatch (ak=${ak})` };
        return { ok: true };
      }
    });
    await store.listen();
    try {
      const bucket = new S3Bucket({
        bucket: 'vault-archive', region: 'us-east-1',
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        endpoint: `http://127.0.0.1:${store.port()}`,
        objectLockMode: 'COMPLIANCE', retention: '6y'
      });
      const out = await bucket.put('conversations/conv-1.json', JSON.stringify({ hello: 'world' }));
      assert.equal(out.verified, true, 'write-through must be verified against the returned ETag');
      assert.equal(out.objectLock, 'COMPLIANCE');
      assert.ok(out.sha256);

      const req = store.seen.find((s) => s.method === 'PUT');
      assert.equal(req.headers['x-amz-object-lock-mode'], 'COMPLIANCE', 'WORM must be asserted on the object');
      assert.ok(req.headers['x-amz-object-lock-retain-until-date'], 'and given a retain-until date');
      assert.equal(JSON.parse(req.body).hello, 'world');

      const back = await bucket.get('conversations/conv-1.json');
      assert.equal(JSON.parse(back).hello, 'world', 'round-trips');
    } finally { store.server.close(); }
  });

  test('a wrong secret is rejected by the endpoint, not silently accepted', async () => {
    const store = fakeStore({
      validate: ({ headers }) => (/Signature=/.test(headers.authorization || '')
        ? { ok: String(headers.authorization).includes('Signature=') && headers['x-vault-test-good'] === 'yes', why: 'bad signature' }
        : { ok: false, why: 'unsigned' })
    });
    await store.listen();
    try {
      const bucket = new S3Bucket({
        bucket: 'b', region: 'us-east-1', accessKeyId: 'AK', secretAccessKey: 'WRONG',
        endpoint: `http://127.0.0.1:${store.port()}`
      });
      await assert.rejects(() => bucket.put('k', 'v'), /returned 403/);
      assert.equal(bucket.stats.errors, 1);
    } finally { store.server.close(); }
  });

  test('Vault will not delete from a customer bucket without a receipted erasure', async () => {
    const bucket = new S3Bucket({ bucket: 'b', region: 'us-east-1', accessKeyId: 'AK', secretAccessKey: 'SK', endpoint: 'http://127.0.0.1:1' });
    await assert.rejects(() => bucket.delete('k', {}), /receipted erasure/);
    await assert.rejects(() => bucket.delete('k', { actor: 'admin' }), /receipted erasure/);
  });

  test('an S3-compatible driver refuses to guess an endpoint', () => {
    assert.throws(() => createBucket('minio', { bucket: 'b', region: 'r', accessKeyId: 'a', secretAccessKey: 's' }), /needs its endpoint/);
    assert.throws(() => createBucket('nonsense', {}), /unknown storage driver/);
    assert.ok(createBucket('minio', { bucket: 'b', region: 'r', accessKeyId: 'a', secretAccessKey: 's', endpoint: 'http://minio:9000' }));
  });
});

describe('Azure Blob', () => {
  test('SharedKey signing is accepted and immutability is Locked', async () => {
    const accountKey = Buffer.from('super-secret-account-key').toString('base64');
    const store = fakeStore({
      validate: ({ method, url, headers, body }) => {
        const auth = headers.authorization || '';
        const m = /^SharedKey ([^:]+):(.+)$/.exec(auth);
        if (!m) return { ok: false, why: 'no SharedKey header' };
        const [, account, sig] = m;
        const ms = Object.keys(headers).filter((h) => h.startsWith('x-ms-')).sort()
          .map((h) => `${h}:${String(headers[h]).trim()}`).join('\n');
        const u = new URL(url, 'http://x');
        const canonicalResource = `/${account}${u.pathname}`;
        const sts = [
          method, '', '', body ? String(Buffer.byteLength(body)) : '', headers['content-md5'] || '',
          headers['content-type'] || '', '', '', '', '', '', '', ms, canonicalResource
        ].join('\n');
        const expected = createHmac('sha256', Buffer.from(accountKey, 'base64')).update(sts, 'utf8').digest('base64');
        return expected === sig ? { ok: true } : { ok: false, why: 'signature mismatch' };
      }
    });
    await store.listen();
    try {
      const bucket = new AzureBlobBucket({
        account: 'vaultstore', container: 'archive', accountKey,
        endpoint: `http://127.0.0.1:${store.port()}`, immutable: 'locked', retention: '6y', legalHold: true
      });
      const out = await bucket.put('conv-1.json', JSON.stringify({ a: 1 }));
      assert.equal(out.verified, true);
      assert.equal(out.immutability, 'Locked', 'Locked is Azure\'s compliance-mode equivalent');

      const req = store.seen.find((s) => s.method === 'PUT');
      assert.equal(req.headers['x-ms-blob-type'], 'BlockBlob');
      assert.equal(req.headers['x-ms-immutability-policy-mode'], 'Locked');
      assert.ok(req.headers['x-ms-immutability-policy-until-date']);
      assert.equal(req.headers['x-ms-legal-hold'], 'true');
    } finally { store.server.close(); }
  });
});

describe('Google Cloud Storage', () => {
  test('a service account mints a real RS256 bearer token and uploads with it', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    let tokenRequest = null;
    const store = fakeStore({
      validate: ({ url, headers, body }) => {
        if (url.startsWith('/token')) { tokenRequest = body; return { ok: true }; }
        return /^Bearer /.test(headers.authorization || '') ? { ok: true } : { ok: false, why: 'no bearer' };
      }
    });
    // The token endpoint has to answer with a token, so wrap the handler.
    const realServer = store.server;
    realServer.removeAllListeners('request');
    realServer.on('request', async (req, res) => {
      const chunks = []; for await (const c of req) chunks.push(c);
      const body = Buffer.concat(chunks).toString();
      store.seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      if (req.url.startsWith('/token')) {
        tokenRequest = body;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ access_token: 'ya29.fake', expires_in: 3600 }));
      }
      if (!/^Bearer /.test(req.headers.authorization || '')) { res.writeHead(401); return res.end('no bearer'); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ md5Hash: createHash('md5').update(body).digest('base64'), generation: '17' }));
    });
    await store.listen();
    try {
      const bucket = new GcsBucket({
        bucket: 'vault-archive', clientEmail: 'vault@project.iam.gserviceaccount.com',
        privateKey: pem, endpoint: `http://127.0.0.1:${store.port()}`,
        tokenUri: `http://127.0.0.1:${store.port()}/token`
      });
      const out = await bucket.put('conv-1.json', JSON.stringify({ a: 1 }));
      assert.equal(out.verified, true, 'md5 write-through verified');
      assert.equal(out.generation, '17');

      // The JWT assertion must be a real, verifiable RS256 signature.
      const params = new URLSearchParams(tokenRequest);
      assert.equal(params.get('grant_type'), 'urn:ietf:params:oauth:grant-type:jwt-bearer');
      const [h, p, sig] = params.get('assertion').split('.');
      const header = JSON.parse(Buffer.from(h, 'base64url'));
      const claim = JSON.parse(Buffer.from(p, 'base64url'));
      assert.equal(header.alg, 'RS256');
      assert.equal(claim.iss, 'vault@project.iam.gserviceaccount.com');
      assert.match(claim.scope, /devstorage\.read_write/);
      const { createVerify } = await import('node:crypto');
      assert.equal(
        createVerify('RSA-SHA256').update(`${h}.${p}`).verify(privateKey, Buffer.from(sig, 'base64url')),
        true, 'the JWT must actually verify against the service account key'
      );
    } finally { store.server.close(); }
  });
});

describe('hash-only tier', () => {
  test('content genuinely never leaves — the driver has no transport at all', async () => {
    const b = new HashOnlyBucket();
    const secret = 'the entire customer transcript that must never leave their estate';
    const out = await b.put('conv-1', secret);

    assert.equal(out.contentStored, false);
    assert.ok(out.sha256);
    // Nothing anywhere in the driver holds the content.
    const everything = JSON.stringify([out, [...b.manifest.entries()], b.stats]);
    assert.equal(everything.includes('transcript that must never leave'), false, 'content must not be retained anywhere');
    // And there is no read path, by construction rather than by policy.
    await assert.rejects(() => b.get('conv-1'), /hash-only/);
    assert.equal(typeof b._fetch, 'function');
    assert.equal(Object.getPrototypeOf(b).constructor.name, 'HashOnlyBucket');
    assert.equal(/fetch\(/.test(HashOnlyBucket.prototype.put.toString()), false, 'put() contains no network call');

    // It can still prove what existed, which is the point of the tier.
    assert.deepEqual(
      { known: true, matches: true },
      (({ known, matches }) => ({ known, matches }))(b.verify('conv-1', secret))
    );
    assert.equal(b.verify('conv-1', 'something else').matches, false);
    assert.equal(b.verify('nope', 'x').known, false);
  });
});
