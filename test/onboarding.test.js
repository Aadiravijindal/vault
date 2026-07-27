/**
 * Day 0 — the guided setup, the sample tenant, and the status page.
 *
 * The failure mode a setup wizard invites is reporting green because a form was
 * submitted. Every test here changes real system state and then asks the wizard
 * what it thinks, so a step can only be "done" when the underlying thing exists.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { STEPS, TARGET_MS, recommendedFirstConnectors, timingReport } from '../src/onboarding/onboarding.js';
import { COMPONENTS } from '../src/status/status.js';
import { setClock, MINUTE, DAY } from '../src/util/time.js';

const bare = (opts = {}) => new Vault({ seedRules: false, ...opts });
const keyed = (opts = {}) => new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso', 'cto'], seedRules: false, ...opts });

describe('the setup wizard checks the system, not the form', () => {
  test('a fresh instance with nothing configured reports every gap, with a fix for each', () => {
    const v = bare();
    try {
      const s = v.onboarding.status();
      assert.equal(s.complete, false);
      const todo = s.steps.filter((x) => x.state === 'todo');
      assert.ok(todo.length >= 6, `a bare instance should be mostly incomplete, got ${todo.length} todo`);
      for (const step of todo) {
        assert.ok(step.detail, `${step.id} says it is incomplete but not why`);
        assert.ok(step.fix || step.blockedBy, `${step.id} gives no way forward`);
      }
      // The two that matter most on a bare instance.
      assert.equal(s.steps.find((x) => x.id === 'signing_key').state, 'todo');
      assert.equal(s.steps.find((x) => x.id === 'administrators').state, 'todo');
    } finally { v.close(); }
  });

  test('configuring a thing for real flips exactly that step, and nothing else', () => {
    const v = keyed();
    try {
      const before = v.onboarding.status();
      assert.equal(before.steps.find((x) => x.id === 'signing_key').state, 'done', 'a customer key was passed');
      assert.equal(before.steps.find((x) => x.id === 'administrators').state, 'done', 'two administrators were named');
      assert.equal(before.steps.find((x) => x.id === 'first_agent').state, 'todo');

      v.registerAgent({ id: 'a-1', name: 'Sales', purpose: 'p', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'watch', folders: ['sales/'] });
      const after = v.onboarding.status();
      assert.equal(after.steps.find((x) => x.id === 'first_agent').state, 'done');
      assert.equal(after.steps.find((x) => x.id === 'go_live').state, 'todo', 'watch mode is not go-live');
    } finally { v.close(); }
  });

  test('an agent with no owner does not count as a registered agent', () => {
    const v = keyed();
    try {
      // The registry may allow it; the wizard must not call it done, because an
      // unowned agent is an incident with nobody to call.
      try {
        v.registerAgent({ id: 'a-orphan', name: 'Orphan', purpose: 'p', businessOwner: '', technicalOwner: '', department: 'sales', mode: 'watch', folders: ['sales/'] });
      } catch {
        return; // registry refused outright, which is a stronger guarantee
      }
      const step = v.onboarding.status().steps.find((x) => x.id === 'first_agent');
      assert.equal(step.state, 'todo');
      assert.match(step.detail, /no named owner/);
    } finally { v.close(); }
  });

  test('a step whose own check throws is reported as not done, not as passed', () => {
    const v = keyed();
    try {
      // Break the thing a step depends on. A wizard that swallows this reports
      // green on a broken install, which is the worst possible outcome.
      const original = v.registry.inventory;
      v.registry.inventory = () => { throw new Error('registry unavailable'); };
      const step = v.onboarding.status().steps.find((x) => x.id === 'first_agent');
      assert.equal(step.state, 'todo');
      assert.match(step.detail, /check failed: registry unavailable/);
      v.registry.inventory = original;
    } finally { v.close(); }
  });

  test('blocked steps name what blocks them instead of just sitting there', () => {
    const v = bare();
    try {
      const s = v.onboarding.status();
      const firstAgent = s.steps.find((x) => x.id === 'first_agent');
      assert.deepEqual(firstAgent.blockedBy, ['signing_key'], 'you cannot meaningfully register agents before you hold the key');
      const goLive = s.steps.find((x) => x.id === 'go_live');
      assert.ok(goLive.blockedBy.includes('administrators'));
      assert.ok(goLive.blockedBy.includes('first_agent'));
      // next() must never point at something that cannot be started.
      const next = v.onboarding.next();
      assert.equal(s.steps.find((x) => x.id === next.step).blockedBy, undefined);
    } finally { v.close(); }
  });

  test('only optional steps can be skipped, and a skip needs a reason for the auditor', () => {
    const v = keyed();
    try {
      v.onboarding.start({ actor: 'admin' });
      assert.throws(() => v.onboarding.skip('first_agent', { actor: 'admin', reason: 'later' }),
        (e) => { assert.match(e.message, /cannot be skipped/); return true; },
        'registering an agent is not optional');
      assert.throws(() => v.onboarding.skip('jurisdiction', { actor: 'admin' }), /requires a reason/);

      const s = v.onboarding.skip('jurisdiction', { actor: 'admin', reason: 'US-only, at-will, no state monitoring statute' });
      assert.deepEqual(s.skipped, ['jurisdiction']);
      const evt = s.events.find((e) => e.what === 'skipped');
      assert.equal(evt.reason, 'US-only, at-will, no state monitoring statute');
      assert.ok(v.ledger.entries({ limit: Infinity }).some((e) => e.action === 'onboarding.step_skipped'),
        'a skipped control is a governance decision and belongs in the ledger');
    } finally { v.close(); }
  });

  test('elapsed time is reported as it happened, including when it blows the target', () => {
    let clock = Date.parse('2026-01-01T09:00:00Z');
    setClock(() => clock);
    try {
      const v = keyed();
      v.onboarding.start({ actor: 'admin' });
      clock += 41 * MINUTE;
      const s = v.onboarding.status();
      assert.equal(s.timing.elapsedMinutes, 41);
      assert.equal(s.timing.withinTarget, false);
      assert.equal(s.timing.targetMinutes, TARGET_MS / MINUTE);
      assert.match(s.timing.verdict, /41 minutes/, 'no rounding in our favour');
      v.close();
    } finally { setClock(() => Date.now()); }
  });

  test('a full run completes, is recorded in the ledger, and reports the real duration', () => {
    let clock = Date.parse('2026-01-01T09:00:00Z');
    setClock(() => clock);
    try {
      const v = keyed({ mirrorDir: null });
      v.onboarding.start({ actor: 'admin' });
      clock += 3 * MINUTE;

      v.privacy.apply('uk', { actor: 'dpo' });
      v.registerAgent({ id: 'a-1', name: 'Sales', purpose: 'p', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'watch', folders: ['sales/'] });
      v.connectors.connect({ catalogId: 'slack-bot', mode: 'watch', credential: { token: 'x', expiresAt: clock + 30 * DAY }, actor: 'admin', owner: 'dana', technicalOwner: 'sam' });
      clock += 9 * MINUTE;

      const cred = v.issueCredential('a-1', {}).credential;
      v.ingest({
        agentId: 'a-1', channel: 'system_of_record',
        participants: [{ name: 'Dana', kind: 'employee', internal: true }],
        turns: [{ speaker: 'Dana', text: 'Globex has 340 seats provisioned.' }]
        // Privacy mode samples capture, so force this one through: the point of
        // the step is that a real write reached the gate, not that the dice fell
        // a particular way.
      }, { credential: cred, folderHint: 'sales/accounts/', sampleRoll: 0 });
      v.folders.setOwners('sales/accounts/', { businessOwner: 'dana', technicalOwner: 'sam', actor: 'admin' });
      v.registry.changeScope('a-1', { mode: 'inline' }, { actor: 'admin', reason: 'go live', approvedBy: 'dana' });
      clock += 6 * MINUTE;

      const s = v.onboarding.status();
      const notDone = s.steps.filter((x) => !x.optional && x.state !== 'done');
      assert.deepEqual(notDone.map((x) => x.id), ['continuity'], `unexpected incomplete: ${JSON.stringify(notDone.map((x) => [x.id, x.detail]))}`);
      v.close();
    } finally { setClock(() => Date.now()); }
  });

  test('the first-connector suggestions are real catalogue entries with their real costs', () => {
    const picks = recommendedFirstConnectors();
    assert.ok(picks.length >= 3);
    for (const p of picks) {
      assert.ok(p.why && p.why.length > 20, `${p.id} suggested without saying why`);
      assert.equal(typeof p.setupMinutes, 'number', `${p.id} must carry its real setup cost`);
      assert.ok(Array.isArray(p.modes) && p.modes.length);
      assert.ok(p.auth, `${p.id} must say how it authenticates before someone picks it`);
    }
  });

  test('the timing report states its caveat rather than promising thirty minutes unconditionally', () => {
    const v = keyed();
    try {
      const r = timingReport(v.onboarding);
      assert.equal(r.estimateIfFollowedExactly, STEPS.reduce((a, s) => a + s.estimateMinutes, 0));
      assert.match(r.caveat, /OAuth|identity/i,
        'the honest caveat is that your own IT approving an OAuth app is not in our control');
      assert.equal(r.perStepEstimate.length, STEPS.length);
    } finally { v.close(); }
  });
});

describe('the sample tenant', () => {
  test('it seeds a populated Map and every attack is stopped', () => {
    const v = keyed();
    try {
      const r = v.demo.load({ actor: 'admin' });
      assert.equal(r.agents, 3);
      assert.ok(r.facts > 5, `only ${r.facts} facts — an evaluator would see an empty Map`);
      assert.ok(v.facts.live().length > 0, 'and some must be live, not all held');
      assert.equal(r.attacks.attempted, 4);
      assert.deepEqual(r.attacks.landed, [], 'an attack that becomes a durable fact is a gate regression');
      assert.equal(r.attacks.stopped, 4);
      assert.match(r.note, /All 4 attacks were stopped/);
      // And the Map itself is genuinely populated.
      const map = v.map();
      assert.equal(map.agents.length, 3);
      assert.ok(map.folders.length > 0);
    } finally { v.close(); }
  });

  test('the demo writes into the real folder tree, so the walls it demonstrates are the real walls', () => {
    const v = keyed();
    try {
      v.demo.load({ actor: 'admin' });
      const folders = new Set(v.facts.all().map((f) => f.folder));
      for (const f of folders) {
        assert.ok(v.folders.get(f), `${f} is not in the folder tree — a made-up folder defaults to the strictest wall and would block everything for the wrong reason`);
      }
      assert.ok([...folders].some((f) => f.startsWith('sales/')));
    } finally { v.close(); }
  });

  test('it refuses to seed over real data unless someone explicitly accepts the mixing', () => {
    const v = keyed();
    try {
      v.registerAgent({ id: 'real', name: 'Real', purpose: 'p', businessOwner: 'o', technicalOwner: 't', department: 'sales', mode: 'inline', folders: ['sales/'] });
      const cred = v.issueCredential('real', {}).credential;
      v.ingest({
        agentId: 'real', channel: 'system_of_record',
        participants: [{ name: 'Dana', kind: 'employee', internal: true }],
        turns: [{ speaker: 'Dana', text: 'The Frankfurt region went live last quarter.' }]
      }, { credential: cred, folderHint: 'sales/accounts/' });

      assert.throws(() => v.demo.load({ actor: 'admin' }), (e) => {
        assert.equal(e.code, 'forbidden');
        assert.match(e.message, /already holds/);
        return true;
      }, 'mixing sample facts into a production store is very hard to unpick afterwards');

      const forced = v.demo.load({ actor: 'admin', force: true });
      assert.ok(forced.loaded);
    } finally { v.close(); }
  });

  test('purge removes exactly what it created, and is honest about what it cannot remove', () => {
    const v = keyed();
    try {
      v.demo.load({ actor: 'admin' });
      const archivedBefore = v.archive.col.all().length;
      assert.ok(archivedBefore > 0);

      const p = v.demo.purge({ actor: 'admin' });
      assert.ok(p.facts > 0);
      assert.equal(p.agents, 3);
      assert.equal(v.facts.all().filter((f) => f.demo && f.status !== 'erased').length, 0, 'no demo fact survives as live');
      assert.match(p.note, /WORM archive/, 'the archive genuinely has no delete path, and the receipt must say so');
      assert.equal(v.archive.col.all().length, archivedBefore, 'and it really does not delete from it');

      // The record that demo data existed and was removed survives.
      const events = v.ledger.entries({ limit: Infinity }).map((e) => e.action);
      assert.ok(events.includes('demo.loaded') && events.includes('demo.purged'));
      assert.equal(v.facts.verifyIntegrity().ok, true, 'purging must not break fact integrity');
      assert.equal(v.verifyLedger().ok, true);
    } finally { v.close(); }
  });

  test('loading twice is a conflict, and purging nothing is a not-found', () => {
    const v = keyed();
    try {
      v.demo.load({ actor: 'admin' });
      assert.throws(() => v.demo.load({ actor: 'admin' }), (e) => { assert.equal(e.code, 'conflict'); return true; });
      v.demo.purge({ actor: 'admin' });
      assert.throws(() => v.demo.purge({ actor: 'admin' }), (e) => { assert.equal(e.code, 'not_found'); return true; });
    } finally { v.close(); }
  });
});

describe('the status page', () => {
  test('component health is computed from real signals, and a broken probe degrades rather than lies', () => {
    const v = keyed();
    try {
      const comps = v.statusPage.components();
      assert.equal(comps.length, Object.keys(COMPONENTS).length);
      assert.ok(comps.every((c) => c.state === 'operational'), JSON.stringify(comps.filter((c) => c.state !== 'operational')));

      // Break the ledger check itself.
      const original = v.verifyLedger.bind(v);
      v.verifyLedger = () => { throw new Error('verifier exploded'); };
      const led = v.statusPage.components().find((c) => c.id === 'ledger');
      assert.equal(led.state, 'degraded');
      assert.match(led.detail, /health probe failed/);
      v.verifyLedger = original;
    } finally { v.close(); }
  });

  test('the kill switch shows as a deliberate stop, not as us being broken', () => {
    const v = keyed();
    try {
      // Level 3 is read-only: writes stop, reads continue.
      v.killswitch.engage(3, { actor: 'ciso', reason: 'suspected poisoning' });
      const overall = v.statusPage.overall();
      assert.equal(overall.state, 'major_outage');
      assert.match(overall.summary, /deliberately by an administrator/,
        '"down because you pressed stop" and "down because we broke" are different sentences');
      const ingest = v.statusPage.components().find((c) => c.id === 'ingest');
      assert.equal(ingest.deliberate, true);
    } finally { v.close(); }
  });

  test('a declared incident overrides a green probe, because the human wins', () => {
    const v = keyed();
    try {
      assert.equal(v.statusPage.components().find((c) => c.id === 'search').state, 'operational');
      const inc = v.statusPage.declare({ title: 'Search returning stale results', severity: 'major', components: ['search'], actor: 'sre', customerImpact: 'Reads may miss recent facts' });
      const search = v.statusPage.components().find((c) => c.id === 'search');
      assert.equal(search.state, 'partial_outage');
      assert.equal(search.incident, inc.id);
      assert.equal(v.statusPage.overall().openIncidents, 1);
    } finally { v.close(); }
  });

  test('the public view is an allow-list, so who-did-what never leaks', () => {
    const v = keyed();
    try {
      const inc = v.statusPage.declare({ title: 'Ingest degraded', severity: 'major', components: ['ingest'], detail: 'Investigating slow writes', actor: 'priya.internal.sre', customerImpact: 'Writes slower than usual' });
      v.statusPage.update(inc.id, { state: 'identified', body: 'Bucket throttling', actor: 'priya.internal.sre' });
      v.statusPage.resolve(inc.id, { cause: 'upstream bucket throttling', summary: 'Throughput restored', actor: 'priya.internal.sre' });

      const pub = JSON.stringify(v.statusPage.publicView());
      assert.equal(pub.includes('priya.internal.sre'), false, 'the public page must not name internal staff');
      assert.match(pub, /Throughput restored/, 'but it must carry the customer-facing summary');

      const internal = JSON.stringify(v.statusPage.internalView());
      assert.match(internal, /priya\.internal\.sre/, 'the internal view keeps accountability');
    } finally { v.close(); }
  });

  test('resolving needs a cause and a summary; a post-mortem needs owners on its actions', () => {
    const v = keyed();
    try {
      const inc = v.statusPage.declare({ title: 'Read path slow', severity: 'minor', components: ['read'], actor: 'sre' });
      assert.throws(() => v.statusPage.resolve(inc.id, { summary: 'fixed', actor: 'sre' }), /cause/);
      assert.throws(() => v.statusPage.resolve(inc.id, { cause: 'x', actor: 'sre' }), /summary/);
      assert.throws(() => v.statusPage.postMortem(inc.id, { whatHappened: 'a', whyItHappened: 'b', whatWeChanged: 'c', actor: 'sre' }), /resolved/);

      v.statusPage.resolve(inc.id, { cause: 'index rebuild', summary: 'Reads back to normal', actor: 'sre' });
      assert.throws(() => v.statusPage.postMortem(inc.id, {
        whatHappened: 'a', whyItHappened: 'b', whatWeChanged: 'c',
        actions: [{ what: 'add an index-size alert' }], actor: 'sre'
      }), /no owner/, 'an unowned action item is a wish');

      const pm = v.statusPage.postMortem(inc.id, {
        whatHappened: 'Reads slowed to 4s', whyItHappened: 'index rebuild ran in the foreground',
        whatWeChanged: 'rebuilds now run off the read path',
        actions: [{ what: 'add an index-size alert', owner: 'sam' }], actor: 'sre'
      });
      assert.equal(pm.actions[0].state, 'open');
      assert.equal(v.statusPage.internalView().openActionItems.length, 1);
    } finally { v.close(); }
  });

  test('an unwritten post-mortem shows as overdue rather than being quietly forgotten', () => {
    let clock = Date.parse('2026-03-01T00:00:00Z');
    setClock(() => clock);
    try {
      const v = keyed();
      const inc = v.statusPage.declare({ title: 'Ledger anchor delayed', severity: 'minor', components: ['ledger'], actor: 'sre' });
      v.statusPage.resolve(inc.id, { cause: 'witness timeout', summary: 'Anchoring resumed', actor: 'sre' });
      clock += 9 * DAY;

      const overdue = v.statusPage.internalView().overduePostMortems;
      assert.equal(overdue.length, 1);
      assert.ok(overdue[0].overdueDays >= 3);
      const pub = v.statusPage.publicView().history[0];
      assert.equal(pub.postMortem.overdue, true, 'the public record should show that we owe one');
      v.close();
    } finally { setClock(() => Date.now()); }
  });

  test('uptime with no incidents says so, rather than claiming 100%', () => {
    const v = keyed();
    try {
      const u = v.statusPage.uptime();
      assert.match(u.basis, /absence of a record, not a measurement/,
        'a quiet window is not evidence of availability, and quoting it as 100% is the lie status pages are known for');
      assert.match(u.caveat, /not synthetic external monitoring/);
      assert.equal(u.totalDownMinutes, 0);
    } finally { v.close(); }
  });

  test('uptime is computed from the incident record, and critical time counts as down', () => {
    let clock = Date.parse('2026-03-01T00:00:00Z');
    setClock(() => clock);
    try {
      const v = keyed();
      const inc = v.statusPage.declare({ title: 'Total ingest outage', severity: 'critical', components: ['ingest'], actor: 'sre' });
      clock += 90 * MINUTE;
      v.statusPage.resolve(inc.id, { cause: 'bad deploy', summary: 'Rolled back', actor: 'sre' });
      clock += 10 * DAY;

      const u = v.statusPage.uptime();
      const ingest = u.components.find((c) => c.component === 'ingest');
      assert.equal(ingest.downMinutes, 90);
      assert.equal(ingest.incidents, 1);
      assert.ok(ingest.availability < 1 && ingest.availability > 0.98, `availability ${ingest.availability}`);
      assert.equal(u.components.find((c) => c.component === 'read').downMinutes, 0, 'an incident only counts against the components it named');
      assert.match(u.basis, /computed from declared incidents/);
      v.close();
    } finally { setClock(() => Date.now()); }
  });

  test('an unknown component or severity is refused before it reaches a customer-visible page', () => {
    const v = keyed();
    try {
      assert.throws(() => v.statusPage.declare({ title: 'x', components: ['teleporter'], actor: 'sre' }), (e) => {
        assert.ok(e.meta.available.includes('ingest'));
        return true;
      });
      assert.throws(() => v.statusPage.declare({ title: 'x', severity: 'apocalyptic', actor: 'sre' }), /severity must be one of/);
      assert.throws(() => v.statusPage.declare({ title: 'x', actor: null }), /named actor/);
      assert.throws(() => v.statusPage.declare({ actor: 'sre' }), /needs a title/);
    } finally { v.close(); }
  });

  test('short-notice maintenance is labelled as such rather than averaged away', () => {
    const v = keyed();
    try {
      const soon = v.statusPage.scheduleMaintenance({ title: 'Emergency patch', startsAt: Date.now() + 60_000, endsAt: Date.now() + 3600_000, components: ['api'], actor: 'sre' });
      assert.equal(soon.shortNotice, true);
      const planned = v.statusPage.scheduleMaintenance({ title: 'Index migration', startsAt: Date.now() + 10 * DAY, endsAt: Date.now() + 10 * DAY + 3600_000, components: ['search'], actor: 'sre' });
      assert.equal(planned.shortNotice, false);
      assert.throws(() => v.statusPage.scheduleMaintenance({ title: 'Backwards', startsAt: Date.now() + 2000, endsAt: Date.now(), actor: 'sre' }), /start and an end/);
      assert.equal(v.statusPage.publicView().scheduledMaintenance.length, 2);
    } finally { v.close(); }
  });
});
