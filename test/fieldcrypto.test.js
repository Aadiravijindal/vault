/**
 * Field-level and client-side encryption, with searchable (blind) indexes.
 *
 * Whole-record encryption is already on. This is the finer granularity: within
 * a record, named fields are sealed under their own key scope, so a process
 * that can read the collection still cannot read the sensitive columns — and a
 * blind index lets those columns be searched for equality without anyone
 * decrypting anything.
 *
 * The proof that the search is genuinely blind is the test that destroys the
 * field key and then searches anyway. If the lookup still finds the record and
 * the read still refuses it, no decryption was involved. That is not something
 * an implementation can fake by reading the plaintext it kept somewhere.
 *
 * Client-side encryption is checked the same way: the server is handed
 * ciphertext it has no key for, and the assertion is that a raw scan of its
 * disk does not contain the plaintext and that reading it back yields a
 * refusal rather than content.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Db } from '../src/storage/db.js';
import { Kms } from '../src/storage/kms.js';
import { FieldCrypto, ClientCrypto, FIELD_POLICIES } from '../src/storage/fields.js';
import { blindIndex } from '../src/util/crypto.js';

const dirs = [];
function tmp() {
  const d = mkdtempSync(join(tmpdir(), 'vault-fc-'));
  dirs.push(d);
  return d;
}
process.on('exit', () => { for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* gone */ } } });

function allBytes(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isFile()) out.push(readFileSync(join(dir, e.name)));
  }
  return Buffer.concat(out).toString('utf8');
}

/**
 * A collection that is NOT whole-record encrypted, so the disk scan can tell
 * the difference between a field that was sealed and a field that was not.
 * Whole-record encryption would make every assertion below pass trivially.
 */
function setup({ policy = { email: 'sealed+indexed', ssn: 'sealed', name: 'indexed' } } = {}) {
  const dir = tmp();
  const kms = new Kms({ rootKey: Buffer.alloc(32, 7), tombstonePath: join(dir, 'shredded.jsonl') });
  const fields = new FieldCrypto({ kms, indexKeyScope: 'blind-index' });
  const db = new Db({ dir, kms });
  const people = db.collection('people', { encrypted: false, fields: { policy, crypto: fields } });
  return { dir, kms, fields, db, people, policy };
}

describe('field-level encryption — sealed columns in a readable row', () => {
  test('the sealed field is absent from the disk while its neighbours are readable', () => {
    const { dir, people } = setup();
    people.insert({
      id: 'p1', name: 'Marcus Chen', department: 'engineering',
      email: 'marcus.chen@acme.com', ssn: '123-45-6789'
    });

    const bytes = allBytes(dir);
    // The point of *field*-level: the row is still operable.
    assert.ok(bytes.includes('engineering'), 'a non-sensitive field must stay readable, or this is just row encryption');
    assert.ok(bytes.includes('p1'), 'the record id must stay readable');
    // And the point of encryption: the sensitive columns are not there.
    assert.ok(!bytes.includes('marcus.chen@acme.com'), 'the email was written to disk in the clear');
    assert.ok(!bytes.includes('123-45-6789'), 'the SSN was written to disk in the clear');
  });

  test('a field marked indexed-only is searchable but NOT sealed, and says which is which', () => {
    const { dir, people, fields } = setup();
    people.insert({ id: 'p2', name: 'Priya Raman', email: 'priya@acme.com' });
    const bytes = allBytes(dir);
    assert.ok(bytes.includes('Priya Raman'), 'an indexed-only field is not encrypted — that is what the policy said');
    assert.ok(!bytes.includes('priya@acme.com'));
    const posture = fields.posture({ email: 'sealed+indexed', ssn: 'sealed', name: 'indexed' });
    assert.deepEqual(posture.sealed.sort(), ['email', 'ssn']);
    assert.deepEqual(posture.searchable.sort(), ['email', 'name']);
  });

  test('reading the record back through the collection returns the plaintext', () => {
    const { people } = setup();
    people.insert({ id: 'p3', name: 'Dana Ito', email: 'dana@acme.com', ssn: '999-99-9999' });
    const got = people.get('p3');
    assert.equal(got.email, 'dana@acme.com', 'the field must round-trip for a caller that holds the key');
    assert.equal(got.ssn, '999-99-9999');
    assert.equal(got.name, 'Dana Ito');
  });

  test('the sealed value survives a restart, which is where naive field crypto breaks', () => {
    const { dir, people } = setup();
    people.insert({ id: 'p4', name: 'Sam Vero', email: 'sam@acme.com', ssn: '111-11-1111' });

    // A second process over the same directory and the same root key.
    const kms2 = new Kms({ rootKey: Buffer.alloc(32, 7), tombstonePath: join(dir, 'shredded.jsonl') });
    const fields2 = new FieldCrypto({ kms: kms2, indexKeyScope: 'blind-index' });
    const db2 = new Db({ dir, kms: kms2 });
    const people2 = db2.collection('people', {
      encrypted: false, fields: { policy: { email: 'sealed+indexed', ssn: 'sealed', name: 'indexed' }, crypto: fields2 }
    });
    assert.equal(people2.get('p4').email, 'sam@acme.com');
    assert.equal(people2.get('p4').ssn, '111-11-1111');
  });

  test('an update re-seals rather than leaving the old plaintext behind', () => {
    const { dir, people } = setup();
    people.insert({ id: 'p5', name: 'Old Name', email: 'old@acme.com' });
    people.update('p5', { email: 'new@acme.com' });
    const bytes = allBytes(dir);
    assert.ok(!bytes.includes('old@acme.com'), 'the superseded value was appended in the clear');
    assert.ok(!bytes.includes('new@acme.com'));
    assert.equal(people.get('p5').email, 'new@acme.com');
  });

  test('a field the policy does not name is left alone — no silent scope creep', () => {
    const { dir, people } = setup();
    people.insert({ id: 'p6', name: 'X', notes: 'this is an ordinary operational note' });
    assert.ok(allBytes(dir).includes('this is an ordinary operational note'));
  });
});

describe('blind index — equality search without decryption', () => {
  test('an exact-match search over a sealed field finds the record', () => {
    const { people } = setup();
    people.insert({ id: 'q1', name: 'A', email: 'target@acme.com' });
    people.insert({ id: 'q2', name: 'B', email: 'someone-else@acme.com' });

    const hits = people.byEncrypted('email', 'target@acme.com');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].id, 'q1');
    assert.equal(people.byEncrypted('email', 'nobody@acme.com').length, 0);
  });

  test('search is case- and whitespace-insensitive the way an equality search must be', () => {
    const { people } = setup();
    people.insert({ id: 'q3', name: 'A', email: 'Mixed.Case@Acme.COM' });
    assert.equal(people.byEncrypted('email', '  mixed.case@acme.com ')[0]?.id, 'q3');
  });

  test('THE PROOF: destroy the field key, and the search still works while the read does not', () => {
    // If the lookup went anywhere near the plaintext, it would fail here too.
    const { people, kms, fields } = setup();
    people.insert({ id: 'q4', name: 'Findable', email: 'findme@acme.com', ssn: '222-22-2222' });

    kms.cryptoShred(fields.fieldScope('people', 'email'), { actor: 'dpo', reason: 'field-level erasure test' });

    const hits = people.byEncrypted('email', 'findme@acme.com');
    assert.equal(hits.length, 1, 'the blind index must not depend on the field key — that is what makes it blind');
    assert.equal(hits[0].id, 'q4');
    assert.equal(hits[0].email, null, 'the value must not come back after its key was destroyed');
    assert.equal(hits[0].__unreadable?.includes('email'), true, 'the record must say which fields it can no longer show');

    // A field with its own scope is unaffected — the granularity is real.
    assert.equal(hits[0].ssn, '222-22-2222');
  });

  test('the index token is keyed: a different index key finds nothing', () => {
    const { people, fields } = setup();
    people.insert({ id: 'q5', name: 'A', email: 'keyed@acme.com' });
    const stored = readFileSync(join(fields.kms.tombstonePath.replace('shredded.jsonl', 'people.jsonl')), 'utf8');

    // The token on disk must be the keyed HMAC, not a bare hash of the value.
    const bare = blindIndex(Buffer.alloc(32, 0), 'keyed@acme.com');
    assert.ok(!stored.includes(bare), 'an unkeyed digest is a rainbow table away from the plaintext');

    const real = fields.indexToken('people', 'email', 'keyed@acme.com');
    assert.ok(stored.includes(real), 'the keyed token must be what is actually stored');
  });

  test('equality leaks equality, and the posture report says so out loud', () => {
    // Two people with the same email produce the same token. That is inherent
    // to deterministic equality search and must be stated, not hidden.
    const { people, fields } = setup();
    people.insert({ id: 'q6', name: 'A', email: 'shared@acme.com' });
    people.insert({ id: 'q7', name: 'B', email: 'shared@acme.com' });
    assert.equal(people.byEncrypted('email', 'shared@acme.com').length, 2);
    const posture = fields.posture({ email: 'sealed+indexed' });
    assert.match(posture.limitation, /equal/i,
      'a searchable-encryption feature that does not disclose what it leaks is mis-sold');
  });

  test('searching a field that is not indexed is refused rather than silently scanning', () => {
    const { people } = setup();
    people.insert({ id: 'q8', name: 'A', email: 'x@acme.com', ssn: '333-33-3333' });
    assert.throws(() => people.byEncrypted('ssn', '333-33-3333'), /not indexed/,
      'a fallback to a full decrypt-and-scan would defeat the entire point');
  });
});

describe('client-side encryption — the server holds what it cannot read', () => {
  test('a client-sealed field never reaches the server as plaintext', () => {
    const clientKey = randomBytes(32);
    const client = new ClientCrypto({ key: clientKey, indexKey: randomBytes(32) });
    const { dir, people } = setup({ policy: {} });

    const sealed = client.seal({ id: 'c1', name: 'Zero Knowledge', diagnosis: 'CLIENT-ONLY-CANARY' }, { fields: ['diagnosis'] });
    people.insert(sealed);

    assert.ok(!allBytes(dir).includes('CLIENT-ONLY-CANARY'),
      'the server wrote client-encrypted content to disk in the clear');
    // And the server cannot produce it either.
    const server = people.get('c1');
    assert.notEqual(server.diagnosis, 'CLIENT-ONLY-CANARY');
    assert.equal(ClientCrypto.isSealed(server.diagnosis), true);
  });

  test('the server refuses to guess rather than returning an opaque blob as if it were content', () => {
    const client = new ClientCrypto({ key: randomBytes(32), indexKey: randomBytes(32) });
    const { people } = setup({ policy: {} });
    people.insert(client.seal({ id: 'c2', diagnosis: 'private' }, { fields: ['diagnosis'] }));
    const record = people.get('c2');
    assert.throws(() => ClientCrypto.requirePlaintext(record.diagnosis),
      /client-side encrypted/,
      'handing a ciphertext envelope to something expecting text is how it ends up rendered to a user');
  });

  test('the client can read back what it sealed, and a different client cannot', () => {
    const key = randomBytes(32);
    const indexKey = randomBytes(32);
    const client = new ClientCrypto({ key, indexKey });
    const { people } = setup({ policy: {} });
    people.insert(client.seal({ id: 'c3', diagnosis: 'CLIENT-ONLY-CANARY' }, { fields: ['diagnosis'] }));

    assert.equal(client.open(people.get('c3')).diagnosis, 'CLIENT-ONLY-CANARY');
    const stranger = new ClientCrypto({ key: randomBytes(32), indexKey });
    assert.throws(() => stranger.open(people.get('c3')), /could not be decrypted/);
  });

  test('the server can still find a client-encrypted record by blind index', () => {
    // This is what makes zero-knowledge storage usable: the server searches
    // tokens it cannot invert.
    const indexKey = randomBytes(32);
    const client = new ClientCrypto({ key: randomBytes(32), indexKey });
    const { people } = setup({ policy: {} });
    people.insert(client.seal({ id: 'c4', diagnosis: 'FINDABLE-CONDITION' }, { fields: ['diagnosis'] }));
    people.insert(client.seal({ id: 'c5', diagnosis: 'SOMETHING-ELSE' }, { fields: ['diagnosis'] }));

    const token = client.indexToken('diagnosis', 'FINDABLE-CONDITION');
    const hits = people.find((r) => r.__bi?.diagnosis === token);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].id, 'c4');

    // The token is a keyed digest of the value, not the value: it must not
    // contain it, and it must not be reproducible without the index key.
    assert.ok(!token.includes('FINDABLE'));
    const guesser = new ClientCrypto({ key: randomBytes(32), indexKey: randomBytes(32) });
    assert.notEqual(guesser.indexToken('diagnosis', 'FINDABLE-CONDITION'), token,
      'anyone who guesses the plaintext must still need the index key to build the token');
  });

  test('a tampered client ciphertext is refused, not silently returned as garbage', () => {
    const key = randomBytes(32);
    const client = new ClientCrypto({ key, indexKey: randomBytes(32) });
    const sealed = client.seal({ id: 'c6', diagnosis: 'AUTHENTIC' }, { fields: ['diagnosis'] });
    // Flip a byte in the ciphertext. AES-GCM must catch it.
    const env = sealed.diagnosis;
    const ct = Buffer.from(env.ct, 'base64');
    ct[0] ^= 0xff;
    sealed.diagnosis = { ...env, ct: ct.toString('base64') };
    assert.throws(() => client.open(sealed), /could not be decrypted/);
  });
});

describe('the posture report an auditor reads', () => {
  test('it names every sealed field, its key scope, and what is not protected', () => {
    const { fields } = setup();
    const p = fields.posture(FIELD_POLICIES.people);
    assert.ok(p.sealed.length > 0);
    assert.ok(p.scopes.every((s) => s.startsWith('field:')));
    assert.ok(p.limitation.length > 20, 'a posture report with no stated limitation is marketing');
  });

  test('a policy naming a mode that does not exist is refused at construction', () => {
    const { people, fields } = setup();
    assert.throws(() => fields.assertPolicy({ email: 'encrypted-ish' }), /unknown field mode/);
  });
});

describe('the identity collections on a real Vault, scanned on disk', () => {
  test('SCIM users and sessions hold no employee identifier in the clear', async () => {
    // This is the check that found the gap: before field-level encryption,
    // scim_users.jsonl and sessions.jsonl carried email addresses, names and
    // departments as readable JSON.
    const { Vault } = await import('../src/index.js');
    const dir = tmp();
    const vault = new Vault({ dir, seedRules: false });
    const user = vault.scim.createUser({
      userName: 'CANARY-dana@acme.com',
      emails: [{ value: 'CANARY-dana@acme.com', primary: true }],
      name: { givenName: 'CANARY-Dana', familyName: 'CANARY-Ito' },
      department: 'CANARY-Engineering',
      groups: [{ display: 'vault-security' }]
    });
    vault.sessions.create({ principal: { name: 'CANARY-dana@acme.com', role: 'security' }, amr: ['hwk'] });

    for (const file of readdirSync(dir)) {
      const bytes = readFileSync(join(dir, file), 'utf8');
      if (!bytes.includes('CANARY-')) continue;
      // The ledger is the one legitimate exception: it is the audit chain, it
      // must stay verifiable by a standalone tool that holds no keys, and an
      // audit trail that cannot name who did what is not an audit trail.
      assert.equal(file, 'ledger.jsonl',
        `${file} contains an employee identifier in the clear: ${bytes.split('\n').find((l) => l.includes('CANARY-'))?.slice(0, 200)}`);
    }

    // And the product still works: the values round-trip, and the lookups that
    // deprovisioning depends on still resolve.
    assert.equal(vault.scim.require(user.id).userName, 'CANARY-dana@acme.com');
    assert.equal(vault.scim.require(user.id).department, 'CANARY-Engineering');
    assert.ok(vault.scim.byUserName('CANARY-dana@acme.com'));

    // Including across a restart, which is where field crypto usually breaks.
    const reopened = new Vault({ dir, seedRules: false });
    assert.equal(reopened.scim.require(user.id).userName, 'CANARY-dana@acme.com');
    assert.equal(reopened.scim.require(user.id).displayName, 'CANARY-dana@acme.com');
  });

  test('the sealed userName is searchable on disk by blind index without a key', async () => {
    const { Vault } = await import('../src/index.js');
    const dir = tmp();
    const vault = new Vault({ dir, seedRules: false });
    const user = vault.scim.createUser({ userName: 'blind@acme.com' });
    const col = vault.db.collection('scim_users');
    const hits = col.byEncrypted('userName', 'blind@acme.com');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].id, user.id);
    assert.equal(col.byEncrypted('userName', 'someone@else.com').length, 0);
  });
});
