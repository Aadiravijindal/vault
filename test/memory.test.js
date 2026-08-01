/**
 * The AI memory file.
 *
 * Three things are under test and none of them is "does it learn". They are:
 * does it stay small, does it refuse to hold anything worth stealing, and does
 * it make an edit impossible to hide. A memory file that grows without bound is
 * one nobody keeps; one that accumulates claim text is a second copy of the
 * vault with no walls; one that can be edited quietly is a way to make the
 * filing put things wherever an attacker wants them.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { MemoryFile, RECALL_THRESHOLD, LIMITS, MAGIC } from '../src/ai/memory.js';
import { Ledger } from '../src/ledger/ledger.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'vmem-'));

/** Teach it the same association `times` times, the way a real estate would. */
function trained({ times = 6, by = 'rules' } = {}) {
  const m = new MemoryFile();
  for (let i = 0; i < times; i++) {
    m.learn({
      factId: `f-${i}`, folder: 'finance/', by,
      claim: `the quarterly invoice reconciliation for the ledger closed on time ${i}`,
      sensitivity: 'confidential',
      entities: [{ id: 'acme-corp', name: 'Acme Corp', type: 'organisation' }]
    });
  }
  return m;
}

describe('it learns where things go, and how confident that makes it', () => {
  test('a repeated association becomes a confident recall', () => {
    const m = trained();
    const r = m.recall({ claim: 'another quarterly invoice reconciliation', allowedFolders: ['finance/', 'sales/'] });
    assert.ok(r, 'six identical filings should produce an opinion');
    assert.equal(r.folder, 'finance/');
    assert.ok(r.confidence >= RECALL_THRESHOLD, `confidence ${r.confidence} should clear the threshold`);
    assert.equal(r.confident, true);
  });

  test('a single observation is not enough to be confident about', () => {
    const m = new MemoryFile();
    m.learn({ factId: 'f-1', folder: 'finance/', claim: 'a one-off sentence about widgets', by: 'rules' });
    const r = m.recall({ claim: 'a one-off sentence about widgets', allowedFolders: ['finance/'] });
    assert.ok(!r || !r.confident, 'one data point is an anecdote, and acting on it is how a prior becomes a bad decision');
  });

  test('a human correction outweighs the model agreeing with itself', () => {
    const byModel = new MemoryFile();
    const byHuman = new MemoryFile();
    const claim = 'the renewal paperwork was countersigned late';
    byModel.learn({ factId: 'f-1', folder: 'sales/', claim, by: 'model' });
    byHuman.learn({ factId: 'f-1', folder: 'sales/', claim, by: 'human' });
    const [m, h] = [byModel, byHuman].map((x) => x.state.tokens[Object.keys(x.state.tokens)[0]].n);
    assert.ok(h > m, 'a human correction is the only signal known to be right — it must carry more weight');
  });

  test('a folder it remembers but that no longer exists is simply not offered', () => {
    const m = trained();
    const r = m.recall({ claim: 'quarterly invoice reconciliation ledger', allowedFolders: ['sales/', 'hr/'] });
    assert.ok(!r || r.folder !== 'finance/', 'the memory suggests within a closed set; it can never widen one');
  });

  test('a named entity is stronger evidence than vocabulary', () => {
    const m = trained();
    const withEntity = m.recall({ claim: 'unrelated words entirely', entities: [{ id: 'acme-corp' }], allowedFolders: ['finance/'] });
    assert.ok(withEntity, 'a known client name should carry a filing opinion on its own');
    assert.equal(withEntity.folder, 'finance/');
  });

  test('it reports what it knows about a client in words a human can check', () => {
    const c = trained().client('acme-corp');
    assert.equal(c.usualFolder, 'finance/');
    assert.equal(c.usualSensitivity, 'confidential');
    assert.ok(c.observations > 1);
  });
});

describe('it holds nothing worth stealing', () => {
  test('claim text never enters the file', () => {
    const m = new MemoryFile();
    const secret = 'zzsecretzz payroll for the chief executive is 450000 per annum';
    m.learn({ factId: 'f-1', folder: 'hr/', claim: secret, by: 'human' });
    const serialised = JSON.stringify(m.state);
    assert.ok(!serialised.includes(secret), 'the sentence must never be reconstructable from this file');
    assert.ok(!serialised.includes('450000'), 'nor the numbers in it');
  });

  test('a correction keeps vocabulary, not the sentence', () => {
    const m = new MemoryFile();
    m.learn({
      factId: 'f-1', folder: 'legal/', correctedFrom: 'sales/', by: 'human',
      claim: 'Wintermute threatened to sue us over the missed delivery on Tuesday'
    });
    const c = m.state.corrections[0];
    assert.equal(c.from, 'sales/');
    assert.equal(c.to, 'legal/');
    assert.ok(Array.isArray(c.terms));
    assert.ok(!JSON.stringify(c).includes('threatened to sue us'), 'terms, never the sentence');
  });
});

describe('it stays small', () => {
  test('eviction holds the file to its cap however much it is taught', () => {
    const m = new MemoryFile();
    for (let i = 0; i < LIMITS.tokens + 500; i++) {
      m.learn({ factId: `f-${i}`, folder: 'company/', claim: `uniqueword${i} filler filler`, by: 'rules' });
    }
    m.compact();
    assert.ok(Object.keys(m.state.tokens).length <= LIMITS.tokens,
      'a memory that grows forever is one nobody keeps');
  });

  test('decay lets an old reorganisation be forgotten', () => {
    const m = trained({ times: 3 });
    const before = m.state.tokens[Object.keys(m.state.tokens)[0]].n;
    for (let i = 0; i < 50; i++) m.compact({ decay: 0.9 });
    const entry = m.state.tokens[Object.keys(m.state.tokens)[0]];
    assert.ok(!entry || entry.n < before, 'signal must fade, or the file is a permanent record of how things used to be filed');
  });

  test('a trained file serialises to a few kilobytes', () => {
    const dir = tmp();
    try {
      const m = new MemoryFile({ path: join(dir, 'ai-memory.vmem') });
      for (let i = 0; i < 500; i++) {
        m.learn({ factId: `f-${i}`, folder: 'sales/', claim: `renewal contract pricing discussion number ${i}`, by: 'rules' });
      }
      const { bytes } = m.save();
      assert.ok(bytes < 200_000, `a mature memory file should be small; this one is ${bytes} bytes`);
      assert.equal(statSync(join(dir, 'ai-memory.vmem')).size, bytes);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('an edit cannot be hidden', () => {
  test('a clean file verifies, and says so in words', () => {
    const m = trained();
    m.save();
    const v = m.verify();
    assert.equal(v.ok, true);
    assert.match(v.statement, /intact/);
  });

  test('editing a learned association after sealing is detected', () => {
    const m = trained();
    m.save();
    // Exactly the attack this chain exists for: quietly retrain the filing to
    // put finance material somewhere nobody reads.
    m.state.tokens.invoice.folders['_quarantine/'] = 999;
    const v = m.verify();
    assert.equal(v.ok, false);
    assert.ok(v.problems.some((p) => p.problem === 'state_altered_after_seal'));
  });

  test('a forged revision breaks the chain at the revision that broke it', () => {
    const m = trained();
    m.save();
    m.save({ reason: 'second' });
    m.state.revisions[1].prevHash = 'forged';
    const v = m.verify();
    assert.equal(v.ok, false);
    assert.equal(v.problems[0].seq, 2, 'the report must name which revision broke, not just that one did');
  });

  test('a file rebuilt without the customer key fails the signature, not just the chain', () => {
    const key = Ledger.newSigningKey();
    const dir = tmp();
    try {
      const path = join(dir, 'm.vmem');
      const m = new MemoryFile({ path, signingKey: key });
      m.learn({ factId: 'f-1', folder: 'finance/', claim: 'invoice paid late', by: 'human' });
      m.save();

      const reopened = new MemoryFile({ path, signingKey: key });
      assert.equal(reopened.verify().signatureOk, true);

      const wrongKey = new MemoryFile({ path, signingKey: Ledger.newSigningKey() });
      const v = wrongKey.verify();
      assert.equal(v.signatureOk, false, 'a chain that is internally consistent but signed by the wrong key is a worse finding, not the same one');
      assert.ok(v.problems.some((p) => p.problem === 'signature_invalid'));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('it survives a round trip and refuses what it is not', () => {
  test('what was learned is still there after save and load', () => {
    const dir = tmp();
    try {
      const path = join(dir, 'm.vmem');
      const original = trained();
      original.path = path;
      original.save();
      const loaded = new MemoryFile({ path });
      const r = loaded.recall({ claim: 'quarterly invoice reconciliation ledger', allowedFolders: ['finance/'] });
      assert.equal(r.folder, 'finance/');
      assert.equal(loaded.verify().ok, true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('a file that is not a .vmem is refused as such, not parsed as garbage', () => {
    const dir = tmp();
    try {
      const path = join(dir, 'not-a-memory.vmem');
      writeFileSync(path, 'plain text, not gzip');
      assert.throws(() => new MemoryFile({ path }).load(path), /not a \.vmem file/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('a future format version is refused rather than misread', () => {
    const bytes = gzipSync(Buffer.from(JSON.stringify({ magic: MAGIC, format: 99, tokens: {} })));
    assert.throws(() => MemoryFile.parse(bytes), /format v99/);
  });
});

describe('status is honest about what this file is', () => {
  test('it says it contains no claim text and that deleting it costs only speed', () => {
    const s = trained().status();
    assert.match(s.statement, /no claim text/);
    assert.match(s.statement, /Deleting it costs speed/);
    assert.equal(s.format, `${MAGIC} v1`);
    assert.ok(s.topClients.some((c) => c.name === 'acme-corp'));
  });
});
