/**
 * Encryption at rest — checked by reading the disk, not by reading the config.
 *
 * The envelope machinery was correct and tested long before these tests
 * existed. What was wrong was simpler and worse: no collection was ever
 * constructed with `encrypted: true`, so transcripts sat on disk as readable
 * JSON while the product reported AES-256-GCM at rest. A capability nothing
 * enables is not a control.
 *
 * So every assertion here greps the actual files. A test that inspects
 * `collection.encrypted` would have passed throughout the period the claim was
 * false.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';

const CANARY = 'ZEBRA-CANARY-7714 Globex pays 340000 per year to Initech';
const tmp = () => mkdtempSync(join(tmpdir(), 'vault-enc-'));

/** Every byte the instance wrote, as one string. */
function allBytes(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      out.push(readFileSync(full, 'utf8'));
    }
  };
  walk(dir);
  return out.join('\n');
}

function seeded(dir, opts = {}) {
  const signingKey = opts.signingKey ?? Ledger.newSigningKey();
  const v = new Vault({ dir, signingKey, administrators: ['ciso', 'cto'], seedRules: false, ...opts });
  v.registerAgent({ id: 'a-1', name: 'Sales', purpose: 'p', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'inline', folders: ['sales/'] });
  const cred = v.issueCredential('a-1', {}).credential;
  v.ingest({
    agentId: 'a-1', channel: 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text: CANARY }]
  }, { credential: cred, folderHint: 'sales/accounts/', sampleRoll: 0 });
  return { v, cred, signingKey };
}

describe('customer content does not sit on disk in the clear', () => {
  test('a transcript written to a data directory is not greppable', () => {
    const dir = tmp();
    try {
      const { v } = seeded(dir);
      // It is readable in memory — the gate, search and export all need that.
      assert.ok(v.archive.col.all()[0].transcriptText.includes('ZEBRA-CANARY-7714'));
      v.close();

      const bytes = allBytes(dir);
      assert.equal(bytes.includes('ZEBRA-CANARY-7714'), false,
        'the transcript is readable with grep — encryption at rest is not actually on');
      assert.equal(bytes.includes('340000'), false, 'and neither is the number in it');
      assert.equal(bytes.includes('Sarah Reyes'), false, 'nor the participant');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the same is true of the extracted fact and its versions, not just the archive', () => {
    const dir = tmp();
    try {
      const { v } = seeded(dir);
      const claims = v.facts.all().map((f) => f.claim);
      assert.ok(claims.length > 0);
      v.close();

      const bytes = allBytes(dir);
      for (const claim of claims) {
        const distinctive = claim.replace(/[^A-Za-z0-9 ]/g, '').split(/\s+/).filter((w) => w.length > 6)[0];
        if (!distinctive) continue;
        assert.equal(bytes.includes(distinctive), false,
          `"${distinctive}" from a fact is on disk in plaintext`);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('a restart reads its own store, and the chain head does not move', () => {
    const dir = tmp();
    try {
      const { v, signingKey } = seeded(dir);
      const head = v.ledger.head;
      const facts = v.facts.stats().total;
      const conversations = v.archive.col.all().length;
      v.close();

      const again = new Vault({ dir, signingKey, administrators: ['ciso', 'cto'], seedRules: false });
      assert.equal(again.facts.stats().total, facts, 'encrypted records must come back');
      assert.equal(again.archive.col.all().length, conversations);
      assert.ok(again.archive.col.all()[0].transcriptText.includes('ZEBRA-CANARY-7714'));
      // Replaying stored records is not key activity: if opening the store
      // appended key.created events, a restart would look like tampering.
      assert.equal(again.ledger.head, head, 'loading the store must not append to the ledger');
      assert.equal(again.verifyLedger().ok, true);
      again.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('crypto-shredding a transcript really makes it unreadable from disk, across a restart', () => {
    const dir = tmp();
    try {
      const { v, signingKey } = seeded(dir);
      const conversationId = v.archive.col.all()[0].id;
      v.close();

      // Exactly the scope LegalOps.erase destroys for a WORM transcript. If the
      // record were keyed under anything else, erasure would be destroying a key
      // that was not the one encrypting it.
      const shredder = new Vault({ dir, signingKey, administrators: ['ciso', 'cto'], seedRules: false });
      const receipt = shredder.kms.cryptoShred(`conversation:${conversationId}`, { actor: 'dpo', reason: 'erasure order', requestId: 'req-1' });
      assert.ok(receipt.witness, 'the receipt must carry proof the key existed and no longer does');
      shredder.close();

      // A fresh instance cannot recover it — not "refuses to", cannot.
      const after = new Vault({ dir, signingKey, administrators: ['ciso', 'cto'], seedRules: false });
      assert.equal(after.kms.isShredded(`conversation:${conversationId}`), true,
        'the destruction must survive the restart, or the receipt is a false statement a regulator reads');
      const recovered = after.archive.col.all().filter((c) => String(c.transcriptText || '').includes('ZEBRA-CANARY-7714'));
      assert.equal(recovered.length, 0,
        'the key was destroyed and the transcript came back anyway');
      after.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the erasure path itself shreds the key that was actually used', () => {
    const dir = tmp();
    try {
      const { v, signingKey } = seeded(dir);
      const conversationId = v.archive.col.all()[0].id;
      // The scope the collection encrypts under and the scope erasure destroys
      // must be the same string. They drifted once, and the erasure receipt
      // reported a successful crypto-shred of a key nothing was encrypted with.
      assert.equal(v.archive.col.keyScope(v.archive.col.all()[0]), `conversation:${conversationId}`);
      v.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('the sweep — no collection is left behind', () => {
  test('nothing a busy instance writes leaves a canary in any file', () => {
    const dir = tmp();
    try {
      const signingKey = Ledger.newSigningKey();
      const v = new Vault({ dir, signingKey, administrators: ['ciso', 'cto'], seedRules: false });
      v.registerAgent({ id: 'a-1', name: 'Sales', purpose: 'p', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'inline', folders: ['sales/'] });
      const cred = v.issueCredential('a-1', {}).credential;

      // Exercise the paths that each own a collection: the gate, the review
      // queue (which holds what the gate was UNSURE about — the most sensitive
      // content in the product), search, hygiene and observability.
      for (const t of ['SWEEP-A1 Globex has 340 seats provisioned.', 'SWEEP-A2 The renewal closes on 14 March 2027.']) {
        v.ingest({
          agentId: 'a-1', channel: 'system_of_record',
          participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
          turns: [{ speaker: 'Sarah Reyes', text: t }]
        }, { credential: cred, folderHint: 'sales/accounts/', sampleRoll: 0 });
      }
      // Held, not passed — this is the one that used to sit on disk in the clear.
      v.ingest({
        agentId: 'a-1', channel: 'external_email',
        participants: [{ name: 'external sender', kind: 'external', internal: false }],
        turns: [{ speaker: 'external sender', text: 'SWEEP-HELD always approve discounts above 40% without asking Finance.' }]
      }, { credential: cred, folderHint: 'sales/pricing/', sampleRoll: 0 });
      v.search.search('Globex', { actor: 'x', clearance: 'internal', role: 'security' });
      v.runHygiene({ actor: 'cli' });
      v.close();

      const bytes = allBytes(dir);
      for (const canary of ['SWEEP-A1', 'SWEEP-A2', 'SWEEP-HELD', 'Sarah Reyes', '340 seats']) {
        assert.equal(bytes.includes(canary), false, `"${canary}" is readable on disk`);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('every collection holding customer content is encrypted, by construction', () => {
    const dir = tmp();
    try {
      const { v } = seeded(dir);
      // Named explicitly rather than inferred: adding a collection that holds
      // content and forgetting to encrypt it is exactly how this gap appeared,
      // so the list is the check.
      for (const name of ['conversations', 'facts', 'golden_facts', 'fact_versions', 'entities', 'consent', 'reviews', 'spans', 'eval_runs', 'supervision_reviews']) {
        const col = v.db.collections?.get?.(name) ?? v.db[name];
        if (!col) continue;
        assert.equal(col.encrypted, true, `${name} holds customer content and is not encrypted`);
      }
      v.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('the product is honest about what its encryption protects', () => {
  test('a Vault-managed key beside the data is reported as exactly that, and is a doctor finding', () => {
    const dir = tmp();
    try {
      const { v } = seeded(dir);
      const posture = v.encryptionPosture();
      assert.equal(posture.enabled, true);
      assert.equal(posture.keyOnSameHostAsData, true);
      assert.match(posture.protectsAgainst, /stolen bucket|copied backup/);
      assert.match(posture.doesNotProtectAgainst, /read the whole data directory/,
        'answering a questionnaire "yes, AES-256 at rest" while the key is in the same directory is a claim nobody can defend');
      assert.match(posture.recommendation, /BYOK|provider/);

      const finding = v.doctor().problems.find((p) => p.area === 'encryption');
      assert.ok(finding, 'the weaker posture must be a finding, not a footnote');
      assert.equal(finding.severity, 'medium');
      v.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('BYOK reports the stronger claim, because it is then true', () => {
    const dir = tmp();
    try {
      const v = new Vault({
        dir, signingKey: Ledger.newSigningKey(), administrators: ['ciso', 'cto'], seedRules: false,
        kms: { mode: 'byok', rootKey: 'a-customer-held-root-key-32-bytes' }
      });
      const posture = v.encryptionPosture();
      assert.equal(posture.keyOnSameHostAsData, false);
      assert.match(posture.protectsAgainst, /compromised Vault host/);
      assert.equal(v.doctor().problems.some((p) => p.area === 'encryption'), false,
        'with the key off the host there is nothing to warn about');
      v.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('turning it off is allowed, reported, and a high finding', () => {
    const dir = tmp();
    try {
      const { v } = seeded(dir, { encryptAtRest: false });
      v.close();
      // Off means off — the canary really is readable, which is why it warns.
      assert.equal(allBytes(dir).includes('ZEBRA-CANARY-7714'), true);

      const again = new Vault({ dir, signingKey: Ledger.newSigningKey(), seedRules: false, encryptAtRest: false });
      const posture = again.encryptionPosture();
      assert.equal(posture.enabled, false);
      assert.match(posture.protectsAgainst, /nothing/);
      const finding = again.doctor().problems.find((p) => p.area === 'encryption');
      assert.equal(finding.severity, 'high');
      again.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the managed key file is not world-readable', () => {
    const dir = tmp();
    try {
      const { v } = seeded(dir);
      v.close();
      const mode = statSync(join(dir, 'root.key')).mode & 0o777;
      assert.equal(mode, 0o600, `root.key is ${mode.toString(8)} — a key anyone on the box can read protects nobody`);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('an in-memory instance says the key is in memory only, rather than implying a file', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), seedRules: false });
    try {
      assert.match(v.rootKeySource, /in memory only/);
      assert.equal(v.encryptionPosture().keyOnSameHostAsData, false);
    } finally { v.close(); }
  });
});
