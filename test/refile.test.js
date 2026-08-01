/**
 * Semantic re-filing — the model pass that runs AFTER the gate.
 *
 * The property under test is containment: a model that is confidently wrong,
 * or that has been talked into something by the fact it is reading, must not
 * be able to move anything out from behind a wall or lower a label. Every
 * model response here is injected, so each hostile case is exact.
 *
 * The fixtures deliberately use claims that PASS the gate, because a held fact
 * has not been filed yet and is not this pass's business — a human is already
 * looking at it.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { ModelProvider } from '../src/ai/provider.js';

/** A claim confirmed to pass the gate cleanly and land in sales/. */
const PASSES = 'the renewal slipped because procurement never countersigned the agreement';

function vaultSaying(text) {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  v.model = new ModelProvider({
    provider: 'anthropic', apiKey: 'k', model: 'm',
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text }] }) })
  });
  v.registerAgent({
    id: 'a-1', name: 'A', purpose: 'p', businessOwner: 'o', technicalOwner: 't',
    department: 'sales', mode: 'inline', folders: ['sales/', 'finance/', 'legal/', 'hr/']
  });
  for (const f of ['finance/', 'legal/', 'hr/']) v.folders.ensure(f);
  const cred = v.issueCredential('a-1', {}).credential;

  /** Write and return the fact that actually landed live, or null. */
  const write = (claim = PASSES) => {
    const r = v.ingest({
      agentId: 'a-1', channel: 'system_of_record',
      participants: [{ name: 'Dana', kind: 'employee', internal: true }],
      turns: [{ speaker: 'Dana', text: claim }]
    }, { credential: cred });
    const passed = r.facts.find((f) => f.outcome === 'pass' && f.factId);
    return passed ? v.facts.get(passed.factId) : null;
  };
  return { v, write };
}

const json = (o) => JSON.stringify(o);

describe('the re-file pass stays inside its box', () => {
  test('with no model it does not run, and says the rules result is complete not degraded', async () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), seedRules: false });
    const r = await v.refileWithModel();
    assert.equal(r.ran, false);
    assert.match(r.statement, /complete and safe answer, not a degraded one/);
  });

  test('a confident move to an existing folder is applied as a new version', async () => {
    const { v, write } = vaultSaying(json({ folder: 'legal/', sensitivity: 'internal', confident: true, why: 'contract execution' }));
    const before = write();
    assert.ok(before, 'the fixture must produce a live fact');
    assert.equal(before.folder, 'sales/');

    const r = await v.refileWithModel();
    assert.equal(r.ran, true);
    assert.equal(r.moved.length, 1, JSON.stringify(r.skipped));

    const after = v.facts.get(before.id);
    assert.equal(after.folder, 'legal/');
    assert.equal(after.version, before.version + 1, 'a re-file must be a new version, not an in-place edit');
  });

  test('a model that invents a folder changes nothing', async () => {
    const { v, write } = vaultSaying(json({ folder: 'public/everyone/', sensitivity: 'internal', confident: true, why: 'x' }));
    const before = write();
    assert.ok(before);

    const r = await v.refileWithModel();
    assert.equal(r.moved.length, 0, 'a folder that does not exist must never be a destination');
    assert.equal(v.facts.get(before.id).folder, before.folder);
  });

  test('a model that tries to LOWER sensitivity changes nothing', async () => {
    const { v, write } = vaultSaying(json({ folder: 'sales/', sensitivity: 'public', confident: true, why: 'announcement' }));
    const before = write();
    assert.ok(before);
    assert.equal(before.sensitivity, 'internal');

    await v.refileWithModel();
    assert.equal(v.facts.get(before.id).sensitivity, 'internal', 'a model may never widen access');
  });

  test('a model may RAISE sensitivity — that direction is always safe', async () => {
    const { v, write } = vaultSaying(json({ folder: 'sales/', sensitivity: 'secret', confident: true, why: 'unannounced' }));
    const before = write();
    assert.ok(before);

    const r = await v.refileWithModel();
    assert.equal(r.raised.length, 1, JSON.stringify(r.skipped));
    assert.equal(v.facts.get(before.id).sensitivity, 'secret');
  });

  test('an unconfident model on a sensitive proposal routes to a human instead of moving it', async () => {
    const { v, write } = vaultSaying(json({ folder: 'legal/', sensitivity: 'confidential', confident: false, why: 'unclear' }));
    const before = write();
    assert.ok(before);

    const r = await v.refileWithModel();
    assert.equal(r.moved.length, 0, 'an unconfident model must not move a fact');
    assert.equal(r.toReview.length, 1, 'it must land on a human instead of being dropped');
    assert.equal(v.facts.get(before.id).folder, before.folder);
  });

  test('a golden fact is never touched by this path', async () => {
    const { v } = vaultSaying(json({ folder: 'legal/', sensitivity: 'secret', confident: true, why: 'x' }));
    const g = v.createGoldenFact(
      { claim: 'Our legal entity is Acme Ltd', folder: 'legal/', sensitivity: 'internal' },
      { actor: 'ciso', actorKind: 'human', authorityRole: 'General Counsel' }
    );
    const r = await v.refileWithModel();
    assert.ok(!r.moved.some((m) => m.id === g.id), 'golden facts are human-attested — this is not that path');
    assert.equal(v.facts.get(g.id).folder, 'legal/');
  });

  test('a fact already re-filed is not reconsidered on the next pass', async () => {
    const { v, write } = vaultSaying(json({ folder: 'legal/', sensitivity: 'internal', confident: true, why: 'x' }));
    write();

    const first = await v.refileWithModel();
    assert.equal(first.moved.length, 1);
    const second = await v.refileWithModel();
    assert.equal(second.moved.length, 0, 'a re-filed fact must not be reconsidered every pass');
    assert.equal(second.considered, 0);
  });

  test('a model outage leaves every fact exactly where the rules put it', async () => {
    const { v, write } = vaultSaying('not json at all');
    const before = write();
    assert.ok(before);

    const r = await v.refileWithModel();
    assert.equal(r.moved.length, 0);
    assert.equal(r.raised.length, 0);
    assert.equal(v.facts.get(before.id).folder, before.folder);
  });

  test('every move is attributed in the ledger and reversible', async () => {
    const { v, write } = vaultSaying(json({ folder: 'legal/', sensitivity: 'internal', confident: true, why: 'contract execution' }));
    const before = write();
    await v.refileWithModel({ actor: 'ops-ran-this' });

    const history = v.facts.history(before.id);
    const refile = history.find((h) => h.change === 'model_refile');
    assert.ok(refile, 'a re-file must appear in the fact history');
    assert.equal(refile.actor, 'ops-ran-this');
    assert.equal(refile.snapshot.folder, 'legal/');
    assert.ok(history.some((h) => h.snapshot.folder === 'sales/'), 'the pre-move version must still be recoverable');
  });
});
