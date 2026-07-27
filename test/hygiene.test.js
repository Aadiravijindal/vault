/**
 * L6 — THE HYGIENE ENGINE (§11.6).
 *
 * The one with real leak potential is re-summarisation: a summary that does not
 * inherit the strictest wall and label of its inputs is a cross-wall channel
 * dressed up as a convenience feature.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { setClock, DAY } from '../src/util/time.js';

function seeded() {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  v.registerAgent({ id: 'a-1', name: 'A', purpose: 'p', businessOwner: 'o', technicalOwner: 't', department: 'sales', mode: 'inline', folders: ['sales/'] });
  const cred = v.issueCredential('a-1', {}).credential;
  const w = (text, ctx = {}) => v.ingest({
    agentId: 'a-1', channel: ctx.channel || 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text }]
  }, { credential: cred, ...ctx });
  return { v, cred, w };
}

// Deliberately unrelated sentences, so reconciliation does not fold them
// together before hygiene ever sees them.
const DISTINCT = [
  'Globex has 340 seats provisioned.',
  'The renewal closes on 14 March 2027.',
  'Priya Raman leads procurement at Initech.',
  'Support ticket 4412 was resolved by restarting the ingest worker.',
  'The Frankfurt region went live last quarter.',
  'Contract 88-B uses net-45 payment terms.',
  'Onboarding takes about nine working days.',
  'The competitor lost the Halifax account in June.',
  'Invoicing moved to monthly in the Nordics.',
  'Two seats were removed from the Dublin office.'
];

describe('hygiene — deduplication', () => {
  test('two identical claims from different sources become one fact with both witnesses', () => {
    const { v, w } = seeded();
    const first = w('Globex has 340 seats provisioned.');
    const second = w('Globex has 340 seats provisioned.', { channel: 'employee_session' });

    const live = v.facts.live().filter((f) => /340 seats/.test(f.claim));
    assert.equal(live.length, 1, 'one fact, not two');
    const fact = live[0];
    assert.ok((fact.sources || []).length >= 2 || (fact.corroboratingSources ?? 1) >= 2,
      `both witnesses must be preserved: ${JSON.stringify({ sources: fact.sources, corroborating: fact.corroboratingSources })}`);
    assert.ok(second.facts.some((f) => ['merged', 'pass'].includes(f.outcome)));
  });
});

describe('hygiene — decay, staleness and orphans', () => {
  test('a fact nobody reads or reconfirms is flagged, and never deleted', () => {
    let clock = Date.parse('2026-01-01T00:00:00Z');
    setClock(() => clock);
    try {
      const { v, w } = seeded();
      w('The Frankfurt region went live last quarter.');
      const before = v.facts.live().length;

      clock += 400 * DAY;
      const report = v.runHygiene({ actor: 'cli' });
      assert.ok(report.decayed.decayed > 0, `nothing decayed: ${JSON.stringify(report.decayed)}`);
      assert.match(report.decayed.note, /never deleted/);
      assert.equal(v.facts.live().length, before, 'decay demotes and flags — it does not delete');
      const fact = v.facts.live()[0];
      assert.equal(fact.decaying, true, 'and the fact carries the flag so ranking can demote it');
    } finally { setClock(() => Date.now()); }
  });

  test('a fact whose agent retired, in a folder with no owner, is an orphan', () => {
    const { v, w } = seeded();
    w('Globex has 340 seats provisioned.');
    v.registry.retire('a-1', { actor: 'admin', reason: 'decommissioned' });

    const orphans = v.hygiene.detectOrphans();
    assert.ok(orphans.length > 0, 'a retired agent leaves its writes behind — those need a new owner');
    assert.ok(orphans.some((o) => /retired|owner/i.test(JSON.stringify(o))), JSON.stringify(orphans[0]));
    assert.ok(v.facts.live().length > 0, 'and the facts themselves remain — retiring an agent is not a deletion');
  });
});

describe('hygiene — re-summarisation must not become a cross-wall channel', () => {
  test('a summary inherits the strictest label and wall of its inputs', () => {
    const { v, w } = seeded();
    for (const text of DISTINCT) w(text);
    // One confidential fact among otherwise internal ones.
    v.createGoldenFact(
      { claim: 'Acme rollout pricing is restricted to 120000.', folder: 'sales/', sensitivity: 'confidential' },
      { actor: 'cfo', actorKind: 'human', authorityRole: 'CFO', secondApprover: 'ceo' }
    );
    w('Pricing for the Dublin renewal is commercially restricted.', { label: 'confidential' });

    // Facts route to sub-folders, so cluster at the size this corpus produces.
    const summaries = v.hygiene.resummarise({ dryRun: true, minCluster: 2 });
    assert.ok(summaries.length > 0, `no cluster formed from ${v.facts.live().length} live facts across ${new Set(v.facts.live().map((f) => f.folder)).size} folders`);

    for (const s of summaries) {
      const inputs = s.inputs.map((id) => v.facts.get(id)).filter(Boolean);
      const rank = { public: 0, internal: 1, confidential: 2, secret: 3 };
      const strictest = inputs.reduce((acc, f) => (rank[f.sensitivity] > rank[acc] ? f.sensitivity : acc), 'public');
      assert.equal(s.sensitivity, strictest,
        `a summary over ${inputs.map((f) => f.sensitivity).join(',')} must be labelled ${strictest}, not ${s.sensitivity}`);
      assert.ok(s.wall, 'and carry the strictest wall of its inputs');
      assert.match(s.note, /inherits the strictest wall and label/);
    }
  });

  test('a summary is never built from facts an agent could not read anyway', () => {
    const { v, w } = seeded();
    v.registerAgent({ id: 'a-hr', name: 'HR', purpose: 'p', businessOwner: 'o', technicalOwner: 't', department: 'hr', mode: 'inline', folders: ['hr/'] });
    const hrCred = v.issueCredential('a-hr', {}).credential;
    for (const text of DISTINCT) w(text);
    v.ingest({
      agentId: 'a-hr', channel: 'system_of_record',
      participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
      turns: [{ speaker: 'Sarah Reyes', text: 'The compensation review for engineering completed.' }]
    }, { credential: hrCred, folderHint: 'hr/' });

    for (const s of v.hygiene.resummarise({ dryRun: true, minCluster: 2 })) {
      const folders = new Set(s.inputs.map((id) => v.facts.get(id)?.folder));
      assert.equal(folders.size, 1, `a summary spanning ${[...folders].join(' + ')} would leak across a wall`);
      assert.equal([...folders][0], s.folder);
    }
  });
});

describe('hygiene — the whole run', () => {
  test('every action is logged and the three-way consistency check passes', () => {
    const { v, w } = seeded();
    for (const text of DISTINCT.slice(0, 4)) w(text);
    const report = v.runHygiene({ actor: 'cli' });

    assert.equal(report.consistency.ok, true, JSON.stringify(report.consistency.problems?.slice(0, 2)));
    // Force an action that definitely happens, then check it was recorded.
    v.hygiene.resummarise({ actor: 'cli', minCluster: 2 });
    const history = v.hygiene.history();
    assert.ok(history.length > 0, 'every hygiene action is logged');
    assert.ok(history.every((h) => h.actor && h.at), 'with an actor and a time');
    assert.ok(v.ledger.entries({ limit: Infinity }).some((e) => e.type === 'hygiene.action'),
      'and the ledger records it, so a hygiene action is as auditable as a write');
  });
});
