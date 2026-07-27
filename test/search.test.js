/**
 * 🟢 VAULT SEARCH + the read path (§11.4, §11.5).
 *
 * The load-bearing property: permissions are checked at QUERY time, and walled
 * or above-clearance content never leaves the server. These tests inspect the
 * bytes on the wire, not just the parsed object, because "filtered in the UI"
 * is not a control.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { ApiServer } from '../src/api/server.js';
import { setClock, DAY } from '../src/util/time.js';

function company() {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  const creds = {};
  for (const [id, department, folder] of [['a-sales', 'sales', 'sales/'], ['a-hr', 'hr', 'hr/'], ['a-fin', 'finance', 'finance/']]) {
    v.registerAgent({ id, name: id, purpose: 'p', businessOwner: 'o', technicalOwner: 't', department, mode: 'inline', folders: [folder] });
    creds[id] = v.issueCredential(id, {}).credential;
  }
  const w = (agentId, text, ctx = {}) => v.ingest({
    agentId, channel: 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text }]
  }, { credential: creds[agentId], ...ctx });
  const read = (agentId, q, ctx = {}) => v.read(q, {
    agentId, credential: creds[agentId], actor: agentId,
    clearance: 'internal', purpose: 'memory_governance', ...ctx
  });
  return { v, creds, w, read };
}
const claims = (r) => (r.facts || []).map((f) => f.claim).join(' | ');

describe('search — permissions are enforced at query time', () => {
  test('a sales agent never receives hr content, and is told it was withheld', () => {
    const { v, w, read } = company();
    w('a-hr', 'The compensation review for engineering completed.', { folderHint: 'hr/' });
    w('a-sales', 'Globex renewal is worth 240000 dollars annually.');

    const r = read('a-sales', 'compensation review');
    assert.equal(claims(r).includes('compensation'), false, 'walled content must not be returned');
    assert.ok(r.withheld >= 1, 'silently returning nothing hides the wall — say it was withheld');
    assert.ok(r.withheldReasons.some((x) => x.reason === 'walled'));

    // and the owning department does get it — the wall is a wall, not a black hole
    assert.ok(claims(read('a-hr', 'compensation review')).includes('compensation'));
  });

  test('above-clearance content is withheld even inside a folder the agent may read', () => {
    const { v, w, read } = company();
    w('a-sales', 'Globex renewal is worth 240000 dollars annually.');
    // A live `secret` fact in the agent's own folder.
    v.createGoldenFact(
      { claim: 'Project Nightfall pricing is set at 480000.', folder: 'sales/pricing/', sensitivity: 'secret' },
      { actor: 'cfo', actorKind: 'human', authorityRole: 'CFO', secondApprover: 'ceo' }
    );
    const low = read('a-sales', 'Nightfall pricing', { clearance: 'internal' });
    assert.equal(claims(low).includes('480000'), false, 'clearance is checked at read time');
    assert.ok(low.withheld >= 1);
    assert.ok(low.withheldReasons.some((x) => /clearance/i.test(x.reason)));

    const high = read('a-sales', 'Nightfall pricing', { clearance: 'secret' });
    assert.ok(claims(high).includes('480000'), 'and a cleared reader does get it');
  });

  test('walled and above-clearance content never leaves the server, on the wire', async () => {
    const { v, w } = company();
    w('a-hr', 'The compensation review for engineering completed.', { folderHint: 'hr/' });
    v.createGoldenFact(
      { claim: 'Project Nightfall pricing is set at 480000.', folder: 'sales/pricing/', sensitivity: 'secret' },
      { actor: 'cfo', actorKind: 'human', authorityRole: 'CFO', secondApprover: 'ceo' }
    );
    const server = new ApiServer({ vault: v, port: 0 });
    const tok = server.issueToken({ name: 'sales-head', role: 'department_head', department: 'sales', clearance: 'internal' });
    await server.listen();
    const port = server.server.address().port;
    try {
      const post = async (query) => {
        const res = await fetch(`http://127.0.0.1:${port}/api/search`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ query, limit: 50 })
        });
        return res.text();   // the raw bytes, before any client could filter
      };
      // Query terms that do not themselves contain the secret, so a hit is a real leak.
      const hrBody = await post('engineering review');
      assert.equal(/compensation/i.test(hrBody), false, `hr content crossed the wire: ${hrBody.slice(0, 200)}`);

      const secretBody = await post('Nightfall');
      assert.equal(secretBody.includes('480000'), false, `above-clearance content crossed the wire: ${secretBody.slice(0, 200)}`);
    } finally { await server.close(); }
  });
});

describe('search — ranking, provenance and time', () => {
  test('golden facts rank first and are labelled as such', () => {
    const { v, w, read } = company();
    w('a-sales', 'Some reps offer a discount of about 35 percent on renewals.');
    v.createGoldenFact({ claim: 'Maximum discount without Finance approval is 20%.', folder: 'sales/pricing/' },
      { actor: 'cfo', actorKind: 'human', authorityRole: 'CFO', secondApprover: 'ceo' });

    const r = read('a-sales', 'discount', { clearance: 'secret' });
    assert.ok(r.facts.length >= 2, 'both should be retrievable');
    assert.equal(r.facts[0].golden, true, 'approved facts outrank inferences');
    assert.equal(r.facts[0].badge, '★ GOLDEN');
    assert.equal(r.facts[0].claimType, 'approved');
  });

  test('every returned fact carries provenance and a citation', () => {
    const { w, read } = company();
    w('a-sales', 'Globex renewal is worth 240000 dollars annually.');
    const r = read('a-sales', 'Globex renewal', { clearance: 'secret' });
    assert.ok(r.facts.length > 0);
    for (const f of r.facts) {
      assert.ok(f.claimType, 'a fact without a claim type is a rumour');
      assert.ok(f.provenance, 'who said it, when, through which channel');
      assert.ok(f.provenance.channel && f.provenance.channelTrust);
      assert.ok(f.citation, 'answers must link back to a source');
      assert.ok(typeof f.ledgerPosition === 'number', 'and to its place on the chain');
    }
  });

  test('point-in-time search answers "what did we believe then", not "now"', () => {
    let clock = Date.parse('2026-01-01T09:00:00Z');
    setClock(() => clock);
    try {
      const { v, creds } = company();
      const write = (text) => v.ingest({
        agentId: 'a-sales', channel: 'system_of_record',
        participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
        turns: [{ speaker: 'Sarah Reyes', text }]
      }, { credential: creds['a-sales'] });
      write('Globex renewal is worth 240000 dollars annually.');
      const cutoff = clock;
      clock += 60 * DAY;
      // Credentials are short-lived by design, so 60 days on they have expired.
      creds['a-sales'] = v.issueCredential('a-sales', {}).credential;
      const later = write('Globex renewal is now worth 300000 dollars annually.');
      assert.ok(later.facts.some((f) => f.outcome !== 'block'), JSON.stringify(later.facts.map((f) => f.outcome)));

      const nowView = v.search.search('Globex renewal', { clearance: 'secret', canRead: () => true });
      const thenView = v.search.search('Globex renewal', { clearance: 'secret', canRead: () => true, asOf: cutoff + DAY });
      const text = (res) => res.results.map((r) => r.claim).join(' | ');

      assert.ok(text(nowView).includes('300000'), 'the current view has the newer figure');
      assert.equal(text(thenView).includes('300000'), false, 'a point-in-time view must not see the future');
      assert.ok(text(thenView).includes('240000'), 'but does see what was believed at the time');
    } finally { setClock(() => Date.now()); }
  });

  test('every query is logged with who asked', () => {
    const { v, read } = company();
    read('a-sales', 'Globex');
    read('a-sales', 'Acme');
    const log = v.search.audit();
    assert.ok(log.length >= 2, `${log.length} queries logged`);
    assert.ok(log.every((e) => 'actor' in e && 'query' in e), JSON.stringify(log[0]));
  });

  test('a boolean permission predicate is honoured, not read as an object', () => {
    const { v, w } = company();
    w('a-sales', 'Globex renewal is worth 240000 dollars annually.');
    // canRead accepts a boolean or a {allowed, reason} verdict. Reading .allowed
    // off a boolean gave undefined, which withheld EVERY fact and reported the
    // reason as undefined — an empty result set with no explanation.
    const asBool = v.search.search('Globex renewal', { clearance: 'secret', canRead: () => true });
    assert.equal(asBool.results.length > 0, true, JSON.stringify(asBool.withheldReasons));
    assert.equal(asBool.withheld, 0);

    const denied = v.search.search('Globex renewal', { clearance: 'secret', canRead: () => false });
    assert.equal(denied.results.length, 0);
    assert.equal(denied.withheld, 1);
    assert.equal(denied.withheldReasons[0].reason, 'walled', 'a withheld result always states why');

    const verdictForm = v.search.search('Globex renewal', {
      clearance: 'secret', canRead: () => ({ allowed: false, reason: 'project isolation' })
    });
    assert.equal(verdictForm.withheldReasons[0].reason, 'project isolation');
  });

  test('hybrid retrieval: a lexical miss is still found by entity and structure', () => {
    const { v, w, read } = company();
    w('a-sales', 'Globex renewal is worth 240000 dollars annually.');
    // Not a literal substring of the claim — retrieval must do more than indexOf.
    const r = read('a-sales', 'What is the Globex contract value?', { clearance: 'secret' });
    assert.ok(claims(r).includes('240000'), `hybrid retrieval failed: ${JSON.stringify(r.facts)}`);
  });
});
