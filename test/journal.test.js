/**
 * The journal — the exhaustive record beside the sealed one.
 *
 * The question this file has to answer is the one a regulator actually asks:
 * "show me everything that ever happened to this record, and who did it". So
 * what is under test is completeness and honesty rather than mechanics —
 * whether a refusal is recorded as loudly as a success, whether a filtered
 * export admits to being filtered, and whether deleting a line is visible.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { Journal } from '../src/audit/journal.js';

function vault() {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  v.registerAgent({
    id: 'sales-bot', name: 'sales bot', purpose: 'capture', businessOwner: 'VP Sales',
    technicalOwner: 'Platform', department: 'sales', mode: 'inline', pinnedModel: 'test',
    folders: ['sales/', 'company/', 'support/', 'finance/']
  });
  v.cred = v.issueCredential('sales-bot', {}).credential;
  return v;
}

function ingested(v, text = 'Acme signed the renewal at 48 seats.') {
  return v.ingest({
    agentId: 'sales-bot', channel: 'system_of_record',
    participants: [{ name: 'Dana', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Dana', text }]
  }, { credential: v.cred });
}

describe('every action against a record is recorded, with all of it', () => {
  test('a write records who, what, when, where, why and how', () => {
    const v = vault();
    const r = ingested(v);
    const factId = r.facts[0].factId;
    const entries = v.journal.forSubject(factId);
    assert.ok(entries.length, 'a written fact must have a journal entry');
    const e = entries[0];
    assert.equal(e.actor.id, 'sales-bot');
    assert.equal(e.actor.kind, 'agent');
    assert.ok(e.where.folder, 'where it was filed');
    assert.ok(e.how.channel, 'which channel it came in on');
    assert.ok(e.detail.checks.length, 'every gate check that ran, with its result');
    assert.ok(e.detail.conversationId, 'a jump back to the sealed conversation');
    assert.ok(e.detail.contentHash, 'the integrity hash at the time');
    assert.ok(typeof e.detail.latencyMs === 'number');
    assert.ok(e.atIso.includes('T'), 'a readable timestamp, not just an epoch');
  });

  test('the message is recorded even when it produced no facts at all', () => {
    const v = vault();
    v.ingest({ agentId: 'sales-bot', channel: 'phone_call_authenticated', content: 'ok. thanks. bye.' });
    const sealed = v.journal.entries({ action: 'message.sealed' });
    assert.equal(sealed.length, 1, '"nothing was captured from that call" is an answer an investigator needs, and silence cannot give it');
    assert.ok(sealed[0].detail.sealHash);
  });

  test('a read records what came back AND what was held back', () => {
    const v = vault();
    ingested(v);
    v.read('renewal', { actor: 'dana', department: 'sales', clearance: 'internal', purpose: 'support' });
    const queries = v.journal.entries({ action: 'search.performed' });
    assert.equal(queries.length, 1);
    assert.equal(queries[0].actor.id, 'dana');
    assert.equal(queries[0].purpose, 'support');
    assert.ok('withheld' in queries[0].detail, 'a read returning 3 of 11 is a different event from 3 of 3');
  });

  test('every disclosed record is attributed to the record itself', () => {
    const v = vault();
    const factId = ingested(v).facts[0].factId;
    v.read('renewal', { actor: 'dana', department: 'sales', clearance: 'internal', purpose: 'support' });
    const reads = v.journal.forSubject(factId).filter((e) => e.action === 'fact.read');
    assert.equal(reads.length, 1, '"who has read this fact" must be answerable from the fact, not by scanning every query ever run');
    assert.equal(reads[0].actor.id, 'dana');
    assert.equal(reads[0].where.folder, v.facts.get(factId).folder);
  });

  test('a change records the fields that changed, not two blobs to diff by eye', () => {
    const v = vault();
    const factId = ingested(v).facts[0].factId;
    v.librarian.tag(factId, ['client:acme corp'], { actor: 'dana' });
    const tagged = v.journal.entries({ action: 'fact.tagged' })[0];
    assert.deepEqual(tagged.changed.map((c) => c.field), ['tags']);
    assert.deepEqual(tagged.changed[0].to, ['client:acme corp']);
  });
});

describe('refusals are recorded as loudly as successes', () => {
  test('an ask by somebody not permitted is journalled, with the question', () => {
    const v = vault();
    assert.rejects(() => v.answer('what is everyone paid?', { actor: { id: 'mallory', kind: 'human' } }));
    return new Promise((resolve) => setImmediate(() => {
      const refused = v.journal.entries({ action: 'ask.refused' });
      assert.equal(refused.length, 1, 'a refused ask is exactly the entry an investigation turns on');
      assert.equal(refused[0].actor.id, 'mallory');
      assert.equal(refused[0].allowed, false);
      assert.match(refused[0].excerpt, /what is everyone paid/);
      resolve();
    }));
  });

  test('refusals() collects them without anyone having to grep', () => {
    const v = vault();
    const j = v.journal;
    j.record('wall.blocked', { subject: 'hr/', subjectKind: 'folder', actor: { id: 'bob', kind: 'human' }, allowed: false, why: 'not on the read list' });
    j.record('fact.written', { subject: 'f-1' });
    const r = j.refusals();
    assert.equal(r.length, 1);
    assert.equal(r[0].action, 'wall.blocked');
  });

  test('a blocked write is recorded as a refusal, not omitted as a non-event', () => {
    const v = vault();
    const r = ingested(v, 'My AWS key is AKIAIOSFODNN7EXAMPLE and the password is hunter2.');
    const blocked = v.journal.entries({ action: 'fact.blocked' });
    if (r.facts.some((f) => f.outcome === 'block')) {
      assert.ok(blocked.length, 'a blocked credential must leave a trace of having been attempted');
      assert.equal(blocked[0].refusal, true);
    }
  });
});

describe('the dossier answers the question a regulator asks', () => {
  test('it reads as a narrative first and structure underneath', () => {
    const v = vault();
    const factId = ingested(v).facts[0].factId;
    v.read('renewal', { actor: 'dana', department: 'sales', clearance: 'internal' });
    const d = v.journal.dossier(factId, { facts: v.facts, ledger: v.ledger });
    assert.ok(d.narrative.length > 80, 'an auditor should be able to read the first screen and understand what happened');
    assert.match(d.narrative, /hash-linked/);
    assert.ok(d.timeline.length);
    assert.ok(d.timeline.every((t) => t.hash), 'every line individually linked');
    assert.ok(d.fact, 'the current state of the record itself');
    assert.ok(Array.isArray(d.ledger), 'cross-referenced to the sealed chain');
  });

  test('it says plainly when no model has ever touched a record', () => {
    const v = vault();
    const factId = ingested(v).facts[0].factId;
    assert.match(v.journal.dossier(factId, { facts: v.facts }).narrative, /no model has ever touched it/);
  });

  test('an unknown subject is a not-found, never an empty dossier that implies nothing happened', () => {
    const v = vault();
    assert.throws(() => v.journal.dossier('f-nope'), /not found/i);
  });
});

describe('handing it over', () => {
  test('a filtered export says it is filtered and how much is missing', () => {
    const v = vault();
    ingested(v);
    ingested(v, 'Beacon asked about the security questionnaire.');
    const all = v.journal.export({ exportedBy: 'ciso', reason: 'annual audit' });
    assert.equal(all.completeness.full, true);
    assert.match(all.completeness.statement, /complete journal/);

    const some = v.journal.export({ action: 'fact.written', exportedBy: 'ciso', reason: 'narrow request' });
    assert.equal(some.completeness.full, false);
    assert.ok(some.completeness.excluded > 0);
    assert.match(some.completeness.statement, /FILTERED extract/);
    assert.match(some.completeness.statement, /ask for the rest/);
  });

  test('an export is signed over its own contents', () => {
    const v = vault();
    ingested(v);
    const b = v.journal.export({ exportedBy: 'ciso', reason: 'regulator request' });
    assert.ok(b.bundleHash);
    assert.ok(b.signature, 'the recipient must be able to prove this is the bundle handed over');
    assert.ok(b.publicKeyPem);
  });

  test('an unattributed export is refused', () => {
    const v = vault();
    assert.throws(() => v.journal.export({ exportedBy: 'ciso' }), /why/);
    assert.throws(() => v.journal.export({ reason: 'because' }), /who is taking it/);
  });

  test('taking a copy of the record is itself in the record', () => {
    const v = vault();
    ingested(v);
    v.journal.export({ exportedBy: 'ciso', reason: 'audit' });
    const exports = v.journal.entries({ action: 'journal.exported' });
    assert.equal(exports.length, 1);
    assert.equal(exports[0].actor.id, 'ciso');
    assert.ok(exports[0].detail.bundleHash);
  });
});

describe('a deleted line is visible', () => {
  test('the chain holds over an untouched journal', () => {
    const v = vault();
    ingested(v);
    ingested(v, 'Beacon renewed early.');
    assert.equal(v.journal.verify().ok, true);
  });

  test('removing an entry leaves a sequence gap rather than a clean record', () => {
    const v = vault();
    ingested(v);
    ingested(v, 'Beacon renewed early.');
    const victim = v.journal.col.all().sort((a, b) => a.seq - b.seq)[1];
    v.journal.col.records.delete(victim.id);
    const r = v.journal.verify();
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => p.problem === 'sequence_gap' || p.problem === 'chain_break'));
  });

  test('editing an entry breaks its own content hash', () => {
    const v = vault();
    ingested(v);
    const first = v.journal.col.all()[0];
    v.journal.col.update(first.id, { why: 'a reason nobody actually gave' });
    assert.equal(v.journal.verify().ok, false);
  });
});

describe('it refuses to log by accident', () => {
  test('an unknown action is a programming error, not a new category', () => {
    const v = vault();
    assert.throws(() => v.journal.record('fact.vibed', { subject: 'f-1' }), /unknown journal action/);
  });

  test('stats says what it holds, including how much of it is refusals', () => {
    const v = vault();
    ingested(v);
    const s = v.journal.stats();
    assert.ok(s.entries > 0);
    assert.ok(s.actors > 0);
    assert.match(s.statement, /including the/);
    assert.equal(s.integrity.ok, true);
  });
});

describe('it is separate from the ledger and cross-referenced to it', () => {
  test('a journal entry carries the sealed-chain sequence it corresponds to', () => {
    const v = vault();
    const factId = ingested(v).facts[0].factId;
    const e = v.journal.forSubject(factId)[0];
    assert.ok(e.ledgerSeq, 'an auditor must be able to verify the chain and read the detail, and check the two agree');
    assert.ok(v.ledger.entries({ subject: factId }).length, 'and the sealed chain must actually have it');
  });

  test('the journal holds text the ledger deliberately refuses', () => {
    const v = vault();
    const factId = ingested(v).facts[0].factId;
    const j = v.journal.forSubject(factId)[0];
    const l = v.ledger.entries({ subject: factId })[0];
    assert.ok(j.excerpt, 'the journal keeps an excerpt so the record is readable');
    assert.equal(l.claim, undefined, 'the ledger never stores content — that is why it can be handed over unreviewed');
    assert.ok(l.claimHash, 'it keeps a hash instead');
  });
});

describe('the API boundaries on the new surfaces', () => {
  test('who can read the record, approve a folder, and ask', async () => {
    const { ApiServer } = await import('../src/api/server.js');
    const v = vault();
    ingested(v);
    const p = v.librarian.propose({ path: 'sales/renewals/', because: 'distinct workflow' });
    const server = new ApiServer({ vault: v, port: 0 });
    const tok = (role, name = role) => server.issueToken({ name, role, clearance: 'secret', department: role });
    const admin = tok('admin', 'ciso');
    const auditor = tok('auditor');
    const finance = tok('finance');
    const legal = tok('legal');
    await server.listen();
    const port = server.server.address().port;
    const call = (path, token, opts = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
      method: opts.method ?? 'GET',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });

    try {
      // The audit record is not an auditors-only screen. A trail only one role
      // can see is one nobody checks.
      assert.equal((await call('/api/journal', auditor)).status, 200);
      assert.equal((await call('/api/journal', legal)).status, 200);
      assert.equal((await call('/api/journal', finance)).status, 403, 'but it is not open to everyone either');

      // Creating an access boundary is administrators only, whatever else a
      // role can see.
      const byAuditor = await call(`/api/librarian/proposals/${p.id}/approve`, auditor, { method: 'POST', body: { reason: 'x' } });
      assert.equal(byAuditor.status, 403, 'reading the record does not imply deciding what the folders are');
      const byAdmin = await call(`/api/librarian/proposals/${p.id}/approve`, admin, {
        method: 'POST', body: { reason: 'renewals really are separate', read: ['sales'] }
      });
      assert.equal(byAdmin.status, 200);
      assert.ok(v.folders.get('sales/renewals/'), 'and only then does the folder exist');

      // Ask: granted by role, and separate from administrator.
      assert.equal((await call('/api/ask/permitted', legal)).status, 200);
      assert.equal((await (await call('/api/ask/permitted', legal)).json()).allowed, true);
      assert.equal((await (await call('/api/ask/permitted', finance)).json()).allowed, false);
      assert.equal((await call('/api/ask', finance, { method: 'POST', body: { question: 'what do we know?' } })).status, 403);

      // A lawyer may ask without thereby gaining administrator-only folders.
      const lawyerActor = { id: 'legal', kind: 'human', department: 'legal', canAsk: true };
      assert.equal(v.mayAsk(lawyerActor).allowed, true);
      assert.equal(v.folders.check('read', lawyerActor, 'admin/').allowed, false,
        'collapsing "may ask" into "is an administrator" is exactly how a lawyer ends up reading the board folder');
    } finally { await server.close(); }
  });

  test('an export over the API is attributed to the principal, not to whatever the body claims', async () => {
    const { ApiServer } = await import('../src/api/server.js');
    const v = vault();
    ingested(v);
    const server = new ApiServer({ vault: v, port: 0 });
    const t = server.issueToken({ name: 'real-auditor', role: 'auditor', clearance: 'secret' });
    await server.listen();
    const port = server.server.address().port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/journal/export`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'regulator request', exportedBy: 'someone-else-entirely' })
      });
      const b = await res.json();
      assert.equal(b.exportedBy, 'real-auditor', 'who took a copy of the audit record is decided by the session, never by the request body');
    } finally { await server.close(); }
  });
});
