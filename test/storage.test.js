/**
 * L11 — STORAGE (§5): keys, crypto-shredding, hash-only, tiering lifecycle.
 *
 * The claims under test are the ones a regulated buyer will actually probe:
 * can Vault still read the data after the customer revokes the key, and is
 * "deleted" provable rather than asserted.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { Kms, ExternalKeyService } from '../src/storage/kms.js';
import { HashOnlyBucket } from '../src/storage/buckets.js';
import { setClock, DAY } from '../src/util/time.js';

describe('keys — BYOK, HYOK and crypto-shredding', () => {
  test('crypto-shredding makes the data unrecoverable, and says so rather than returning nothing', () => {
    const kms = new Kms({ mode: 'vault' });
    const sealed = kms.seal('sales', 'the entire customer transcript', 'obj-1');
    assert.equal(kms.open(sealed), 'the entire customer transcript');
    assert.equal(JSON.stringify(sealed).includes('entire customer transcript'), false, 'ciphertext, not plaintext');

    const receipt = kms.cryptoShred('sales', { actor: 'dpo', reason: 'REQ-2026-0881' });
    assert.ok(receipt.keyId && receipt.witness, 'the shred is itself receipted and witnessed');
    assert.equal(kms.isShredded('sales'), true);

    // Not "returns empty" — refuses, with a code an erasure receipt can cite.
    assert.throws(() => kms.open(sealed), (e) => {
      assert.equal(e.code, 'crypto_shredded');
      assert.match(e.message, /destroyed — data is unrecoverable by design/);
      return true;
    });
  });

  test('shredding one namespace does not open or destroy another', () => {
    const kms = new Kms({ mode: 'vault' });
    const sales = kms.seal('sales', 'sales content', 'o1');
    const hr = kms.seal('hr', 'hr content', 'o2');
    kms.cryptoShred('sales', { actor: 'dpo', reason: 'x' });
    assert.throws(() => kms.open(sales), /crypto_shredded|destroyed/);
    assert.equal(kms.open(hr), 'hr content', 'per-namespace keys mean one compromise is not all of them');
  });

  test('HYOK: revoking at the customer HSM locks Vault out immediately', () => {
    const hsm = new ExternalKeyService('customer-hsm');
    const kms = new Kms(hsm.attach({ mode: 'hyok' }));
    const sealed = kms.seal('hr', 'payroll detail for M. Rodriguez', 'obj-2');
    assert.equal(kms.open(sealed), 'payroll detail for M. Rodriguez');

    hsm.revoke();
    assert.throws(() => kms.open(sealed), /revoked Vault's access — no decryption is possible/);
    assert.equal(JSON.stringify(sealed).includes('payroll detail'), false, 'and the blob alone gives nothing away');

    hsm.restore();
    assert.equal(kms.open(sealed), 'payroll detail for M. Rodriguez', 'restoring access restores reads');
    assert.ok(hsm.calls.length >= 3, 'every decryption is a call the customer can see and count');
  });

  test('split-key: one share is not enough to unlock a namespace', () => {
    const kms = new Kms({ mode: 'split', quorum: 2, shares: ['alice', 'bob'] });
    assert.throws(() => kms.seal('finance', 'x', 'o'), /quorum|share/i);
    kms.presentShare('alice');
    assert.throws(() => kms.seal('finance', 'x', 'o'), /quorum|share/i);
    kms.presentShare('bob');
    const sealed = kms.seal('finance', 'the forecast', 'o');
    assert.equal(kms.open(sealed), 'the forecast', 'two named humans, then it opens');
  });
});

describe('hash-only tier', () => {
  test('content never reaches Vault, and the attestation still proves what existed', async () => {
    const b = new HashOnlyBucket();
    const content = 'a transcript that is contractually forbidden to leave the customer estate';
    const put = await b.put('conv-1', content);
    assert.equal(put.contentStored, false);
    assert.equal(JSON.stringify([...b.manifest.values()]).includes('forbidden to leave'), false);
    await assert.rejects(() => b.get('conv-1'), /hash-only/);
    assert.equal(b.verify('conv-1', content).matches, true, 'Vault can still attest to what the customer holds');
    assert.equal(b.verify('conv-1', `${content} tampered`).matches, false);
  });
});

describe('storage tiering', () => {
  test('the lifecycle actually moves records, and legal hold holds them back', () => {
    let clock = Date.parse('2026-01-01T00:00:00Z');
    setClock(() => clock);
    try {
      const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
      v.registerAgent({ id: 'a-1', name: 'A', purpose: 'p', businessOwner: 'o', technicalOwner: 't', department: 'sales', mode: 'inline', folders: ['sales/'] });
      let cred = v.issueCredential('a-1', {}).credential;
      const write = (text) => v.ingest({
        agentId: 'a-1', channel: 'system_of_record',
        participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
        turns: [{ speaker: 'Sarah Reyes', text }]
      }, { credential: cred });

      v.consent.record({ subject: 'Marcus Chen', basis: 'contract', purpose: 'memory_governance', actor: 'legal' });
      const held = write('Marcus Chen is the CTO at Acme Corp.');
      write('Globex has 340 seats provisioned.');
      v.legal.placeHold({ matter: 'Case 114', scope: { person: 'Marcus Chen' }, actor: 'gc', reason: 'litigation' });

      assert.throws(() => v.runStorageLifecycle({}), /named actor/);
      const before = v.tiering.previewLifecycle();
      assert.ok(before.moves.length === 0, 'nothing is old enough yet');

      // 200 days on, hot content is due to move.
      clock += 200 * DAY;
      const preview = v.runStorageLifecycle({ actor: 'platform', dryRun: true });
      assert.ok(preview.moves.length > 0, 'the lifecycle has work to do');
      assert.ok(preview.moves.some((m) => m.heldBack), 'held material must be marked, not moved');

      const run = v.runStorageLifecycle({ actor: 'platform' });
      assert.ok(run.moved > 0, `${run.moved} records moved`);
      assert.ok(run.heldBack > 0, 'and the held ones stayed');
      assert.equal(v.tiering.get(held.conversationId).tier, 'hot', 'legal hold beats the schedule');
      assert.ok(
        v.ledger.entries({ limit: Infinity }).some((e) => e.action === 'storage.lifecycle_run'),
        'running the lifecycle is an admin action on the chain'
      );
    } finally { setClock(() => Date.now()); }
  });

  test('the storage screen reports where data lives and under whose keys', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), seedRules: false });
    const s = v.storage();
    assert.equal(s.bucket.driver, 'vault-managed', 'no customer bucket configured');
    assert.ok(s.driversAvailable.includes('s3') && s.driversAvailable.includes('minio') && s.driversAvailable.includes('hash-only'));
    assert.ok(s.keys.mode);

    const byob = new Vault({
      signingKey: Ledger.newSigningKey(), seedRules: false,
      bucket: { driver: 'minio', bucket: 'vault', region: 'us-east-1', accessKeyId: 'a', secretAccessKey: 'b', endpoint: 'http://minio:9000', objectLockMode: 'COMPLIANCE' }
    });
    const s2 = byob.storage();
    assert.equal(s2.bucket.bucket, 'vault');
    assert.equal(s2.bucket.immutability, 'COMPLIANCE');
    assert.equal(s2.bucket.contentLeavesTheEstate, true);

    const hashOnly = new Vault({ signingKey: Ledger.newSigningKey(), seedRules: false, bucket: { driver: 'hash-only' } });
    assert.equal(hashOnly.storage().bucket.contentLeavesTheEstate, false, 'the hash-only tier must report itself honestly');
  });
});
