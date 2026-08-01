/**
 * The librarian — the model organising the file room.
 *
 * Nothing here reaches the network: the provider takes an injected fetch, so
 * every test drives a specific model response, including hostile ones. What is
 * under test is where the authority stops. The model gets full freedom over
 * tags, because a tag is an index and every read through one is still checked
 * against the folder wall underneath. It gets none at all over folders,
 * because a folder IS the wall.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { ModelProvider } from '../src/ai/provider.js';
import { normaliseTag } from '../src/ai/orchestrate.js';

/** A model that always answers with the same organising decision. */
function modelSaying(obj) {
  return new ModelProvider({
    provider: 'anthropic', apiKey: 'k', model: 'test-model',
    fetchImpl: async () => ({
      ok: true, status: 200,
      json: async () => ({ content: [{ type: 'text', text: JSON.stringify(obj) }] })
    })
  });
}

function vault({ model = null } = {}) {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  if (model) v.model = model;
  v.registerAgent({
    id: 'sales-bot', name: 'sales bot', purpose: 'capture', businessOwner: 'VP Sales',
    technicalOwner: 'Platform', department: 'sales', mode: 'inline', pinnedModel: 'test',
    folders: ['sales/', 'company/', 'support/', 'finance/']
  });
  v.cred = v.issueCredential('sales-bot', {}).credential;
  return v;
}

function aFact(v, text = 'Acme signed the renewal at 48 seats.') {
  const r = v.ingest({
    agentId: 'sales-bot', channel: 'system_of_record',
    participants: [{ name: 'Dana', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Dana', text }]
  }, { credential: v.cred });
  const written = r.facts.find((f) => f.factId && ['pass', 'mask'].includes(f.outcome));
  assert.ok(written, `the fixture must actually store a fact: ${JSON.stringify(r.facts.map((f) => f.reasons))}`);
  return v.facts.get(written.factId);
}

describe('tags are free, because a tag is an index and not a wall', () => {
  test('the model invents tags and they are applied', async () => {
    const v = vault({ model: modelSaying({ tags: ['client:acme corp', 'topic:renewal'], folder: null, significance: 0, confident: true }) });
    const f = aFact(v);
    const r = await v.organize({ limit: 5 });
    assert.ok(r.tagged.length, 'the librarian must be able to invent a client tag nobody predefined');
    assert.deepEqual(v.facts.get(f.id).tags.sort(), ['client:acme corp', 'topic:renewal']);
  });

  test('an untyped tag is rejected — a bare "acme" is ambiguous forever', () => {
    assert.equal(normaliseTag('acme'), null);
    assert.equal(normaliseTag('client:acme'), 'client:acme');
    assert.equal(normaliseTag('CLIENT:Acme Corp'), 'client:acme corp');
    assert.equal(normaliseTag('nonsense:x'), null, 'the kind must be one of the known kinds');
    assert.equal(normaliseTag('client:<script>'), null, 'a tag is a name, not a payload');
  });

  test('tagging is a fact version, so who tagged it and when is answerable', () => {
    const v = vault();
    const f = aFact(v);
    v.librarian.tag(f.id, ['client:acme corp'], { actor: 'dana', reason: 'account review' });
    const after = v.facts.get(f.id);
    assert.equal(after.version, f.version + 1);
    const entry = v.journal.entries({ action: 'fact.tagged' })[0];
    assert.equal(entry.actor.id, 'dana');
    assert.equal(entry.why, 'account review');
  });

  test('a tag never widens what a search can reach', () => {
    const v = vault();
    const f = aFact(v);
    v.librarian.tag(f.id, ['client:acme corp'], { actor: 'dana' });
    const before = v.folders.get(f.folder);
    assert.deepEqual(v.folders.get(f.folder).read, before.read, 'tagging must not touch the wall');
    assert.ok(v.facts.byTag('client:acme corp').length, 'it only makes the fact findable');
  });

  test('the model is shown the existing vocabulary so it reuses rather than invents near-duplicates', async () => {
    const v = vault({ model: modelSaying({ tags: ['client:acme corp'], folder: null, significance: 0, confident: true }) });
    aFact(v);
    await v.organize({ limit: 5 });
    let prompt = '';
    v.model.fetchImpl = async (url, opts) => {
      prompt = JSON.parse(opts.body).messages[0].content;
      return { ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text: '{"tags":[]}' }] }) };
    };
    aFact(v, 'Acme asked a second question about invoicing.');
    await v.organize({ limit: 5 });
    assert.match(prompt, /client:acme corp/, 'showing it the vocabulary is what stops acme-corp and acme_corp both existing');
  });
});

describe('folders are proposed, never created', () => {
  test('a model naming a folder that does not exist creates nothing', async () => {
    const v = vault({ model: modelSaying({ tags: [], folder: 'totally/made/up/', significance: 0, confident: true }) });
    const f = aFact(v);
    await v.organize({ limit: 5 });
    assert.ok(!v.folders.get('totally/made/up/'), 'the model cannot conjure an access boundary');
    assert.equal(v.facts.get(f.id).folder, f.folder, 'and the fact stays where the rules put it');
  });

  test('a proposal queues with its evidence and creates nothing', async () => {
    const v = vault({
      model: modelSaying({
        tags: [], folder: null, significance: 0, confident: true,
        proposeFolder: { path: 'sales/renewals/', because: 'renewals are a distinct workflow', wall: 'sales' }
      })
    });
    aFact(v);
    await v.organize({ limit: 5 });
    const open = v.librarian.openProposals();
    assert.equal(open.length, 1);
    assert.equal(open[0].path, 'sales/renewals/');
    assert.match(open[0].because, /distinct workflow/);
    assert.ok(!v.folders.get('sales/renewals/'), 'proposed is not created');
  });

  test('the same proposal twice accumulates evidence instead of filling the queue', async () => {
    const v = vault({
      model: modelSaying({
        tags: [], folder: null, significance: 0, confident: true,
        proposeFolder: { path: 'sales/renewals/', because: 'renewals are distinct' }
      })
    });
    aFact(v, 'Acme renewed for a year.');
    await v.organize({ limit: 5 });
    aFact(v, 'Beacon renewed for two years.');
    await v.organize({ limit: 5 });
    const open = v.librarian.openProposals();
    assert.equal(open.length, 1);
    assert.ok(open[0].count >= 2, '"the model has wanted this 50 times" is the signal that makes the decision easy');
  });

  test('only a named administrator may approve, and only with a reason', () => {
    const v = vault();
    const p = v.librarian.propose({ path: 'sales/renewals/', because: 'test' });
    assert.throws(() => v.librarian.approveProposal(p.id, { actor: 'dana', reason: 'sure' }), /not an administrator/);
    assert.throws(() => v.librarian.approveProposal(p.id, { actor: 'ciso' }), /reason/);
  });

  test('approval creates the folder with the wall the HUMAN chose, not the one the model suggested', () => {
    const v = vault();
    const p = v.librarian.propose({ path: 'sales/renewals/', because: 'test', wall: 'everyone' });
    const { folder } = v.librarian.approveProposal(p.id, {
      actor: 'ciso', reason: 'renewals really are a separate workflow', read: ['sales'], write: ['sales']
    });
    assert.deepEqual(folder.read, ['sales']);
    assert.ok(!folder.read.includes('everyone'), 'an access boundary a model chose is one nobody chose');
  });

  test('the approval names a human in the record, which is what an auditor asks for', () => {
    const v = vault();
    const p = v.librarian.propose({ path: 'sales/renewals/', because: 'test' });
    v.librarian.approveProposal(p.id, { actor: 'ciso', reason: 'agreed after review' });
    const j = v.journal.entries({ action: 'folder.approved' })[0];
    assert.equal(j.actor.id, 'ciso');
    assert.equal(j.why, 'agreed after review');
    const l = v.ledger.entries({ subject: 'sales/renewals/' });
    assert.ok(l.some((e) => e.action === 'folder.proposal_approved'));
  });

  test('a rejection needs a reason, so the same thing is not re-proposed into a void', () => {
    const v = vault();
    const p = v.librarian.propose({ path: 'sales/renewals/', because: 'test' });
    assert.throws(() => v.librarian.rejectProposal(p.id, { actor: 'ciso' }), /reason/);
    v.librarian.rejectProposal(p.id, { actor: 'ciso', reason: 'sales/ is enough' });
    assert.equal(v.librarian.openProposals().length, 0);
  });

  test('proposing a folder that already exists is a no-op, not a duplicate', () => {
    const v = vault();
    assert.equal(v.librarian.propose({ path: 'sales/', because: 'exists' }), null);
  });
});

describe('it tells a human when something matters, and does nothing else about it', () => {
  test('a significant fact raises a notice', async () => {
    const v = vault({ model: modelSaying({ tags: [], folder: null, significance: 3, why: 'threat of litigation', confident: true }) });
    aFact(v, 'Wintermute says they will sue over the missed delivery.');
    const r = await v.organize({ limit: 5 });
    assert.equal(r.notices.length, 1);
    assert.equal(r.notices[0].level, 'urgent');
  });

  test('a notice changes nothing about the fact itself', async () => {
    const v = vault({ model: modelSaying({ tags: [], folder: null, significance: 3, why: 'big', confident: true }) });
    const f = aFact(v);
    await v.organize({ limit: 5 });
    const after = v.facts.get(f.id);
    assert.equal(after.folder, f.folder, 'the model may have an opinion about significance without it doing anything to the record');
    assert.equal(after.sensitivity, f.sensitivity);
    assert.equal(after.status, f.status);
  });

  test('an inbox does not leak the contents of a folder you cannot read', () => {
    const v = vault();
    v.folders.ensure('hr/reviews/');
    v.librarian.notify({ factId: null, level: 'urgent', why: 'someone resigned', folder: 'hr/reviews/' });
    const forHr = v.librarian.inbox({ actor: { id: 'h', kind: 'human', department: 'hr' } });
    const forSales = v.librarian.inbox({ actor: { id: 's', kind: 'human', department: 'sales' } });
    assert.equal(forHr.open, 1);
    assert.equal(forSales.open, 0);
    assert.equal(forSales.withheld, 1, 'counted, never silently dropped');
    assert.match(forSales.note, /quotes the fact it is about/);
  });
});

describe('what it may never touch', () => {
  test('a golden fact is left alone', async () => {
    const v = vault({ model: modelSaying({ tags: ['topic:pricing'], folder: 'hr/', significance: 0, confident: true }) });
    const g = v.facts.createGolden(
      { claim: 'List price is 48,000 per year.', folder: 'sales/pricing/', sensitivity: 'internal' },
      { actor: 'ciso', actorKind: 'human', authorityRole: 'CFO' }
    );
    await v.organize({ limit: 20 });
    const after = v.facts.get(g.id);
    assert.equal(after.folder, 'sales/pricing/');
    assert.deepEqual(after.tags ?? [], [], 'human-attested material is not something an automated pass tidies up');
  });

  test('a locked fact refuses every automated pass, at both layers', async () => {
    const v = vault({ model: modelSaying({ tags: ['topic:x'], folder: 'hr/', significance: 0, confident: true }) });
    const f = aFact(v);
    v.librarian.lock(f.id, { actor: 'ciso', reason: 'this one is right, leave it alone' });
    await v.organize({ limit: 5 });
    const after = v.facts.get(f.id);
    assert.equal(after.folder, f.folder);
    assert.equal(after.locked, true);
    // The store refuses too — one check is one bug away from not being a check.
    assert.throws(() => v.facts.revise(f.id, { folder: 'hr/' }, { actor: 'x', reason: 'y', kind: 'model_refile' }), /locked/);
  });

  test('a human can still deliberately change a locked fact', () => {
    const v = vault();
    const f = aFact(v);
    v.librarian.lock(f.id, { actor: 'ciso', reason: 'verified' });
    const revised = v.facts.revise(f.id, { sensitivity: 'confidential' }, { actor: 'ciso', reason: 'reclassified', kind: 'human_revision' });
    assert.equal(revised.sensitivity, 'confidential', 'a lock says "no model tidies this", not "this is now unchangeable"');
  });

  test('only an administrator may lock', () => {
    const v = vault();
    const f = aFact(v);
    assert.throws(() => v.librarian.lock(f.id, { actor: 'dana', reason: 'mine now' }), /not an administrator/);
  });

  test('nothing automated moves a fact out of an administrator-only folder', async () => {
    const v = vault({ model: modelSaying({ tags: [], folder: 'sales/', significance: 0, confident: true }) });
    const f = aFact(v);
    v.facts.revise(f.id, { folder: 'admin/', namespace: 'admin' }, { actor: 'ciso', reason: 'sensitive', kind: 'human_revision' });
    const r = await v.organize({ limit: 5 });
    assert.equal(v.facts.get(f.id).folder, 'admin/', 'out of an administrator-only folder is always a widening');
    assert.ok(r.skipped.some((s) => /administrator-only/.test(s.reason)));
    assert.ok(v.journal.entries({ action: 'model.refused' }).length);
  });

  test('an uncertain move on something sensitive goes to a human instead', async () => {
    const v = vault({ model: modelSaying({ tags: [], folder: 'finance/', significance: 0, confident: false }) });
    const f = aFact(v);
    const before = v.review.list({ status: 'open' }).length;
    await v.organize({ limit: 5 });
    assert.equal(v.facts.get(f.id).folder, f.folder, 'it does not move on a guess');
    assert.ok(v.review.list({ status: 'open' }).length > before, 'a human decides');
  });
});

describe('the learned memory is what makes it fast', () => {
  test('a confident recall settles a fact without a model call at all', async () => {
    let calls = 0;
    const v = vault({
      model: new ModelProvider({
        provider: 'anthropic', apiKey: 'k', model: 'm',
        fetchImpl: async () => { calls++; return { ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text: '{"tags":[]}' }] }) }; }
      })
    });
    const f = aFact(v);
    // Teach it the association the rules already made, several times over.
    for (let i = 0; i < 8; i++) {
      v.memory.learn({ factId: `seed-${i}`, folder: f.folder, claim: f.claim, sensitivity: f.sensitivity, by: 'human' });
    }
    const r = await v.organize({ limit: 5 });
    assert.equal(calls, 0, 'a microsecond recall must displace a call that costs hundreds of milliseconds');
    assert.ok(r.fromMemory >= 1);
    assert.match(r.statement, /settled by the learned memory/);
  });

  test('every write teaches the memory, for free, with no model involved', () => {
    const v = vault();
    assert.equal(v.memory.size().entries, 0);
    aFact(v);
    assert.ok(v.memory.size().tokens > 0, 'the rules just made a filing decision and that is a training signal');
    assert.ok(v.memory.state.counters.rules > 0);
  });

  test('with no model at all the pass still runs on memory alone, and says so', async () => {
    const v = vault();
    const f = aFact(v);
    for (let i = 0; i < 8; i++) {
      v.memory.learn({ factId: `seed-${i}`, folder: f.folder, claim: f.claim, by: 'human' });
    }
    const r = await v.organize({ limit: 5 });
    assert.equal(r.ran, true);
    assert.equal(r.modelCalls, 0);
  });
});

describe('status is honest about the deal being made', () => {
  test('it states the tag-versus-folder distinction rather than leaving it implied', () => {
    const s = vault().librarian.status({ actor: { id: 'ciso', kind: 'human' } });
    assert.match(s.statement, /never creates a folder/);
    assert.match(s.proposals.note, /a folder is a wall/i);
    assert.ok(Array.isArray(s.administrators));
  });
});
