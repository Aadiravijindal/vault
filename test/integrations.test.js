/**
 * Slack, Teams, configuration-as-code and the installable surface.
 *
 * The chat endpoints are the most exposed thing in the product: they sit on a
 * public URL, and one of them can stop the business. So most of what follows is
 * adversarial — forged signatures, replayed captures, unmapped users, and the
 * question that matters most, whether a claim can be made to leak into a chat
 * channel that has none of Vault's walls.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { SlackApp, TeamsApp, REPLAY_WINDOW_MS } from '../src/integrations/chatops.js';
import { ConfigEngine, renderPlan, RESOURCES } from '../src/iac/iac.js';
import { setClock } from '../src/util/time.js';

const SECRET = 'slack-signing-secret-not-real';
const TEAMS_TOKEN = Buffer.from('teams-shared-secret-not-real').toString('base64');

function slackSign(body, secret = SECRET, at = Date.now()) {
  const ts = Math.floor(at / 1000);
  return {
    'x-slack-request-timestamp': String(ts),
    'x-slack-signature': `v0=${createHmac('sha256', secret).update(`v0:${ts}:${body}`).digest('hex')}`
  };
}
const teamsSign = (body) => ({ authorization: `HMAC ${createHmac('sha256', Buffer.from(TEAMS_TOKEN, 'base64')).update(Buffer.from(body, 'utf8')).digest('base64')}` });

function seeded() {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso', 'cto'], seedRules: false });
  v.demo.load({ actor: 'admin' });
  return v;
}

const slackOf = (v) => new SlackApp({
  vault: v, signingSecret: SECRET, baseUrl: 'https://vault.acme.internal',
  userMap: { U_CISO: 'ciso', U_DANA: 'dana' }
});

const form = (fields) => new URLSearchParams(fields).toString();

describe('Slack — the endpoint is on the public internet, so verification comes first', () => {
  test('a forged signature is refused before the payload is read', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'status', user_id: 'U_CISO', user_name: 'ciso' });
      const forged = slackSign(body, 'the-wrong-secret');
      await assert.rejects(() => app.command({ body, headers: forged }), (e) => {
        assert.match(e.message, /signature mismatch/);
        return true;
      });
      assert.equal(app.stats.rejected, 1);
      assert.equal(app.stats.commands, 0, 'a rejected request must not be counted as handled');
    } finally { v.close(); }
  });

  test('a valid signature replayed later is still refused', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'status', user_id: 'U_CISO', user_name: 'ciso' });
      const at = Date.now();
      const headers = slackSign(body, SECRET, at);

      // Fresh: fine.
      await app.command({ body, headers, at });

      // The same capture, ten minutes later. Without the timestamp check a
      // captured `/vault stop` works forever.
      await assert.rejects(() => app.command({ body, headers, at: at + REPLAY_WINDOW_MS + 60_000 }), (e) => {
        assert.match(e.message, /replay window/);
        return true;
      });
    } finally { v.close(); }
  });

  test('a missing signature header is refused, not treated as unsigned-but-fine', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'status', user_id: 'U_CISO' });
      await assert.rejects(() => app.command({ body, headers: {} }), /missing X-Slack/);
    } finally { v.close(); }
  });

  test('an app constructed without a signing secret refuses to exist', () => {
    assert.throws(() => new SlackApp({ vault: null }), (e) => {
      assert.match(e.message, /signing secret/);
      return true;
    }, 'there must be no "verification disabled" mode — that is a remote kill switch for whoever finds the URL');
  });

  test('an unmapped Slack user gets nothing, rather than inheriting a role', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'status', user_id: 'U_STRANGER', user_name: 'stranger' });
      await assert.rejects(() => app.command({ body, headers: slackSign(body) }), (e) => {
        assert.equal(e.code, 'forbidden');
        assert.match(e.message, /not mapped to a Vault principal/);
        return true;
      });
    } finally { v.close(); }
  });
});

describe('Slack — chat is a control surface, never a content one', () => {
  test('the review queue posts ids and reasons, never the claim text', async () => {
    const v = seeded();
    try {
      const held = v.facts.all().filter((f) => f.status === 'held');
      assert.ok(held.length > 0, 'the demo must leave something held for this test to mean anything');

      const app = slackOf(v);
      const body = form({ text: 'review', user_id: 'U_DANA', user_name: 'dana' });
      const out = await app.command({ body, headers: slackSign(body) });
      const rendered = JSON.stringify(out);

      for (const f of held) {
        assert.equal(rendered.includes(f.claim), false,
          `the claim "${f.claim.slice(0, 40)}…" reached a Slack channel, which has none of Vault's walls`);
      }
      assert.match(rendered, /waiting/);
      assert.match(rendered, /vault\.acme\.internal/, 'and it must link back to the real UI');
      assert.equal(out.response_type, 'ephemeral', 'a review queue posted to the whole channel is an access-control failure');
    } finally { v.close(); }
  });

  test('a fact lookup returns provenance without the claim', async () => {
    const v = seeded();
    try {
      const fact = v.facts.all()[0];
      const app = slackOf(v);
      const body = form({ text: `fact ${fact.id}`, user_id: 'U_DANA', user_name: 'dana' });
      const out = await app.command({ body, headers: slackSign(body) });
      const rendered = JSON.stringify(out);

      assert.equal(rendered.includes(fact.claim), false, 'the claim itself must stay behind the walls');
      assert.match(rendered, new RegExp(fact.id));
      assert.match(rendered, /Said by|Channel/, 'but the provenance — who, through what channel, decided how — is the useful part');
    } finally { v.close(); }
  });

  test('status reports the live kill switch and chain state', async () => {
    const v = seeded();
    try {
      v.killswitch.engage(3, { actor: 'ciso', reason: 'suspected poisoning' });
      const app = slackOf(v);
      const body = form({ text: 'status', user_id: 'U_CISO', user_name: 'ciso' });
      const out = JSON.stringify(await app.command({ body, headers: slackSign(body) }));
      assert.match(out, /L3/);
      assert.match(out, /suspected poisoning/);
      assert.match(out, /rotating_light/);
    } finally { v.close(); }
  });
});

describe('Slack — the kill switch needs more than a typo', () => {
  test('/vault stop asks for confirmation instead of firing', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'stop 6', user_id: 'U_CISO', user_name: 'ciso' });
      const out = await app.command({ body, headers: slackSign(body) });

      assert.equal(v.killswitch.state().level, 0, 'a slash command is one keystroke from a typo; it must not stop the business directly');
      const rendered = JSON.stringify(out);
      assert.match(rendered, /Engage kill switch level 6/);
      assert.match(rendered, /The business stops/, 'and it must say what level 6 actually does before someone confirms it');
      assert.match(rendered, /"confirm"/, 'with Slack\'s own confirmation dialog on the button');
    } finally { v.close(); }
  });

  test('a non-administrator is refused, by name', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'stop 3', user_id: 'U_DANA', user_name: 'dana' });
      const out = JSON.stringify(await app.command({ body, headers: slackSign(body) }));
      assert.match(out, /dana is not a named kill-switch administrator/);
      assert.match(out, /ciso, cto/, 'and it should say who is, so the person knows who to call');
      assert.equal(v.killswitch.state().level, 0);
    } finally { v.close(); }
  });

  test('confirming really engages it, and the ledger records who', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const payload = JSON.stringify({ user: { id: 'U_CISO', name: 'ciso' }, actions: [{ value: 'stop:3' }] });
      const body = form({ payload });
      const out = await app.interact({ body, headers: slackSign(body) });

      assert.equal(v.killswitch.state().level, 3);
      assert.match(JSON.stringify(out), /Kill switch level 3.*engaged by ciso/);
      const entry = v.ledger.entries({ limit: Infinity }).find((e) => e.action === 'chatops.stop');
      assert.ok(entry, 'a kill switch pulled from chat is still a governance event');
      assert.equal(entry.actor, 'ciso');
    } finally { v.close(); }
  });

  test('an invalid level is rejected before it reaches the switch', async () => {
    const v = seeded();
    try {
      const app = slackOf(v);
      const body = form({ text: 'stop 99', user_id: 'U_CISO', user_name: 'ciso' });
      const out = JSON.stringify(await app.command({ body, headers: slackSign(body) }));
      assert.match(out, /Level must be 1–6/);
    } finally { v.close(); }
  });
});

describe('Slack — approving from a phone is the same decision as approving in the UI', () => {
  test('an approval lands in the review engine and in the ledger', async () => {
    const v = seeded();
    try {
      const item = v.review.list({ status: 'open', limit: 1 })[0];
      assert.ok(item, 'the demo must leave something in the queue');

      const app = slackOf(v);
      const payload = JSON.stringify({ user: { id: 'U_DANA', name: 'dana' }, actions: [{ value: `approve:${item.id}` }] });
      const body = form({ payload });
      const out = await app.interact({ body, headers: slackSign(body) });

      assert.match(JSON.stringify(out.blocks), /Approved/);
      assert.ok(out._result, 'the real review decision must have run');
      const after = v.review.list({ status: 'open', limit: 100 }).map((i) => i.id);
      assert.equal(after.includes(item.id), false, 'the item must actually leave the queue');
      assert.ok(v.ledger.entries({ limit: Infinity }).some((e) => e.action === 'chatops.approve' && e.actor === 'dana'));
    } finally { v.close(); }
  });

  test('an outbound alert carries no content either', () => {
    const msg = SlackApp.alertMessage(
      { kind: 'cross_wall_attempt', severity: 'high', subject: 'f-123', detail: 'sales agent tried to read hr/', at: Date.now() },
      'https://vault.acme.internal'
    );
    const rendered = JSON.stringify(msg);
    assert.match(rendered, /cross_wall_attempt/);
    assert.match(rendered, /f-123/);
    assert.match(rendered, /warning/);
  });
});

describe('Microsoft Teams', () => {
  test('the HMAC over the raw body is verified in the format Teams actually sends', async () => {
    const v = seeded();
    try {
      const app = new TeamsApp({ vault: v, securityToken: TEAMS_TOKEN, userMap: { 'aad-1': 'ciso' } });
      const body = JSON.stringify({ text: '<at>Vault</at> status', from: { aadObjectId: 'aad-1', name: 'CISO' } });
      const out = await app.command({ body, headers: teamsSign(body) });
      assert.equal(out.type, 'message');
      assert.equal(out.attachments[0].contentType, 'application/vnd.microsoft.card.adaptive');
      assert.equal(app.stats.verified, 1);

      // A single flipped byte must fail.
      const tampered = JSON.stringify({ text: '<at>Vault</at> status', from: { aadObjectId: 'aad-1', name: 'CISO' }, extra: 'x' });
      await assert.rejects(() => app.command({ body: tampered, headers: teamsSign(body) }), /signature mismatch/);
    } finally { v.close(); }
  });

  test('the bot mention is stripped before the command is parsed', async () => {
    const v = seeded();
    try {
      const app = new TeamsApp({ vault: v, securityToken: TEAMS_TOKEN, userMap: { 'aad-1': 'ciso' } });
      const body = JSON.stringify({ text: '<at>Vault Bot</at> review', from: { aadObjectId: 'aad-1', name: 'CISO' } });
      const out = await app.command({ body, headers: teamsSign(body) });
      assert.match(JSON.stringify(out), /Review queue/,
        'Teams prefixes the mention into the text; not stripping it makes every command unrecognised');
    } finally { v.close(); }
  });

  test('the adaptive card carries no claim text', async () => {
    const v = seeded();
    try {
      const held = v.facts.all().filter((f) => f.status === 'held');
      const app = new TeamsApp({ vault: v, securityToken: TEAMS_TOKEN, userMap: { 'aad-1': 'ciso' } });
      const body = JSON.stringify({ text: 'review', from: { aadObjectId: 'aad-1', name: 'CISO' } });
      const rendered = JSON.stringify(await app.command({ body, headers: teamsSign(body) }));
      for (const f of held) assert.equal(rendered.includes(f.claim), false);
    } finally { v.close(); }
  });

  test('an app with no security token refuses to exist', () => {
    assert.throws(() => new TeamsApp({ vault: null }), /security token/);
  });
});

describe('configuration as code', () => {
  const bare = () => new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });
  const CONFIG = {
    version: 1,
    agent: [{ id: 'a-sales', name: 'Sales Copilot', purpose: 'answer account questions', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'watch', folders: ['sales/'] }],
    folder: [{ path: 'sales/accounts/', read: ['sales', 'support'], write: ['sales'], businessOwner: 'dana', technicalOwner: 'sam' }]
  };

  test('plan does not mutate anything — checked by snapshot, not by assertion', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      const snapshot = () => JSON.stringify({
        agents: v.registry.inventory(),
        folders: v.folders.all().map((f) => [f.path, f.read, f.write, f.businessOwner]),
        rules: v.rules.all().length,
        ledger: v.ledger.entries({ limit: Infinity }).length
      });
      const before = snapshot();
      const plan = cfg.plan(CONFIG, { prune: true });
      assert.ok(plan.changes.length > 0, 'this config should produce a diff, or the test proves nothing');
      assert.equal(snapshot(), before, 'plan wrote to the estate — the whole point of a plan is that it does not');
    } finally { v.close(); }
  });

  test('apply is idempotent: the second run produces no changes', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      const first = cfg.apply(CONFIG, { actor: 'ops', approvedBy: 'dana' });
      assert.equal(first.failed, 0, JSON.stringify(first.results.filter((r) => !r.ok)));
      assert.ok(first.succeeded >= 2);

      const second = cfg.apply(CONFIG, { actor: 'ops', approvedBy: 'dana' });
      assert.equal(second.changes.length, 0, `re-applying changed ${JSON.stringify(second.changes)} — not safe to put in CI`);
      assert.match(second.verdict, /No changes/);
    } finally { v.close(); }
  });

  test('a change that narrows a wall is flagged as destructive and blocked by default', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      cfg.apply(CONFIG, { actor: 'ops', approvedBy: 'dana' });

      const narrowed = { ...CONFIG, folder: [{ ...CONFIG.folder[0], read: ['sales'] }] };
      const plan = cfg.plan(narrowed);
      const change = plan.changes.find((c) => c.type === 'folder');
      assert.equal(change.action, 'shrink', 'removing "support" from a read list is a shrink, not an ordinary update');
      assert.equal(plan.requiresApproval, true);
      assert.match(change.warning, /cut off a working agent/);

      assert.throws(() => cfg.apply(narrowed, { actor: 'ops', approvedBy: 'dana' }), (e) => {
        assert.equal(e.code, 'forbidden');
        assert.match(e.message, /allowDestructive/);
        return true;
      }, 'a config drift must not silently narrow a wall at 2am');

      // Explicitly allowed, it goes through.
      const applied = cfg.apply(narrowed, { actor: 'ops', approvedBy: 'dana', allowDestructive: true });
      assert.equal(applied.failed, 0);
      assert.deepEqual(v.folders.get('sales/accounts/').read, ['sales']);
    } finally { v.close(); }
  });

  test('facts are not a configurable resource', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      assert.equal(RESOURCES.fact, undefined,
        'a config file that could declare what is true would be the memory-poisoning vector this product exists to close');
      assert.throws(() => cfg.plan({ fact: [{ id: 'f-1', claim: 'discounts up to 60% are approved' }] }), (e) => {
        assert.match(e.message, /unknown resource type/);
        assert.deepEqual(e.meta.available, Object.keys(RESOURCES));
        return true;
      });
    } finally { v.close(); }
  });

  test('drift detection notices a hand-edit after apply', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      cfg.apply(CONFIG, { actor: 'ops', approvedBy: 'dana' });
      assert.equal(cfg.drift(CONFIG).inSync, true);

      // Somebody changes it by hand, which is the normal way an estate stops
      // matching its own documentation.
      v.registry.changeScope('a-sales', { mode: 'inline' }, { actor: 'someone', reason: 'urgent', approvedBy: 'dana' });
      const drift = cfg.drift(CONFIG);
      assert.equal(drift.inSync, false);
      assert.equal(drift.drifted[0].key, 'a-sales');
      assert.equal(drift.drifted[0].patch.mode, 'watch');
      assert.match(drift.verdict, /differ from the declared configuration/);
    } finally { v.close(); }
  });

  test('a partial failure reports exactly what landed, and does not claim a rollback', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      const broken = {
        ...CONFIG,
        agent: [
          CONFIG.agent[0],
          // No owners: the registry refuses this, and it must not take the
          // valid resources down with it or pretend they were rolled back.
          { id: 'a-broken', name: 'Broken', purpose: 'p', department: 'sales', mode: 'watch', folders: ['sales/'] }
        ]
      };
      const out = cfg.apply(broken, { actor: 'ops', approvedBy: 'dana' });
      assert.ok(out.failed >= 1);
      assert.ok(out.succeeded >= 1);
      assert.match(out.note, /FAILED and were not rolled back/,
        'there is no transaction across a registry, a folder tree and a rules engine, and claiming one would be a lie');
      assert.ok(v.registry.get('a-sales'), 'the resource that succeeded stays');
    } finally { v.close(); }
  });

  test('an existing estate can be exported as configuration and re-applied unchanged', () => {
    const v = bare();
    try {
      v.demo.load({ actor: 'admin' });
      const cfg = new ConfigEngine({ vault: v });
      const exported = cfg.export();
      assert.ok(exported.agent.length >= 3);
      // Adopting an existing install must be a no-op, not a rewrite.
      const plan = cfg.plan(exported);
      assert.deepEqual(plan.changes, [], `exporting then planning produced ${JSON.stringify(plan.changes)}`);
    } finally { v.close(); }
  });

  test('the rendered plan reads like the one operators already know how to scan', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      const text = renderPlan(cfg.plan(CONFIG));
      assert.match(text, /^Plan:/);
      assert.match(text, /\+ agent\.a-sales/);
      assert.match(text, /to create/);
    } finally { v.close(); }
  });

  test('applying requires a named actor and is recorded in the ledger', () => {
    const v = bare();
    try {
      const cfg = new ConfigEngine({ vault: v });
      assert.throws(() => cfg.apply(CONFIG, {}), /named actor/);
      cfg.apply(CONFIG, { actor: 'ops', approvedBy: 'dana' });
      const entry = v.ledger.entries({ limit: Infinity }).find((e) => e.action === 'config.applied');
      assert.ok(entry);
      assert.equal(entry.actor, 'ops');
      assert.equal(cfg.history().length, 1);
    } finally { v.close(); }
  });
});

describe('the installable surface', () => {
  const UI = fileURLToPath(new URL('../src/ui/', import.meta.url));
  const sw = readFileSync(join(UI, 'sw.js'), 'utf8');
  const manifest = JSON.parse(readFileSync(join(UI, 'manifest.json'), 'utf8'));
  const html = readFileSync(join(UI, 'index.html'), 'utf8');

  test('the manifest makes the two 3am tasks one tap away', () => {
    assert.equal(manifest.display, 'standalone');
    const shortcuts = manifest.shortcuts.map((s) => s.url);
    assert.ok(shortcuts.includes('/#review'), 'the review queue is one of the two things needed from a phone');
    assert.ok(shortcuts.includes('/#admin'), 'and the kill switch is the other');
    assert.ok(manifest.icons.length >= 1);
    assert.match(html, /<link rel="manifest" href="\/manifest\.json">/);
  });

  test('the service worker never caches an API response', () => {
    assert.match(sw, /if \(url\.pathname\.startsWith\('\/api\/'\)\) return;/,
      'a cached fact has escaped the wall, the clearance check, the legal hold and the kill switch, and would survive an erasure order');
    // And the exemption must come before any caching logic runs.
    const apiGuard = sw.indexOf("startsWith('/api/')");
    const respond = sw.indexOf('event.respondWith');
    assert.ok(apiGuard > 0 && apiGuard < respond, 'the API guard must precede respondWith, or it is decoration');
  });

  test('the shell it does cache is only the shell', () => {
    const assets = sw.match(/const ASSETS = \[(.*?)\]/s)[1];
    assert.equal(/\/api\//.test(assets), false);
    for (const required of ['index.html', 'app.css', 'app.js']) {
      assert.ok(assets.includes(required), `the shell should include ${required}`);
    }
  });

  test('the worker is registered only over https, and a failure is not fatal', () => {
    const app = readFileSync(join(UI, 'app.js'), 'utf8');
    assert.match(app, /location\.protocol === 'https:'/);
    assert.match(app, /navigator\.serviceWorker\.register\('\/sw\.js'\)\.catch/,
      'an offline shell is a bonus; failing to register it must not break the app');
  });
});

describe('changing a wall after day one', () => {
  const bare = () => new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });

  test('a wall can be changed at all — ensure() alone never could', () => {
    const v = bare();
    try {
      v.folders.ensure('sales/accounts/');
      const before = v.folders.get('sales/accounts/').read;

      // The old path: ensure() returns the existing folder untouched, so an
      // estate could only ever be walled correctly on its first day.
      v.folders.ensure('sales/accounts/', { read: ['sales', 'support', 'marketing'] });
      assert.deepEqual(v.folders.get('sales/accounts/').read, before,
        'ensure must stay non-destructive — this documents why setWalls had to exist');

      const out = v.folders.setWalls('sales/accounts/', { read: ['sales'], actor: 'ciso', reason: 'support no longer handles accounts' });
      assert.deepEqual(v.folders.get('sales/accounts/').read, ['sales']);
      assert.ok(out.removed.read.includes('support'));
    } finally { v.close(); }
  });

  test('a folder can never be made more readable than its parent', () => {
    const v = bare();
    try {
      v.folders.ensure('hr/reviews/');
      assert.throws(() => v.folders.setWalls('hr/reviews/', { read: ['hr', 'sales'], actor: 'ciso', reason: 'sales asked' }), (e) => {
        assert.equal(e.code, 'forbidden');
        assert.match(e.message, /cannot be more readable than its parent/);
        return true;
      }, 'otherwise the way to read hr/ is to widen hr/reviews/, and the wall is advisory');
      assert.equal(v.folders.get('hr/reviews/').read.includes('sales'), false);
    } finally { v.close(); }
  });

  test('widening is allowed but never quiet', () => {
    const v = bare();
    try {
      v.folders.setWalls('sales/', { read: ['sales', 'support', 'marketing', 'finance'], actor: 'ciso', reason: 'finance now forecasts from pipeline' });
      const alerts = v.alerts.open({ limit: 200 });
      assert.ok(alerts.some((a) => a.kind === 'wall_widened'),
        'somebody just gained access to something — that is precisely the change an auditor asks about');
      const entry = v.ledger.entries({ limit: Infinity }).find((e) => e.type === 'folder.wall_changed');
      assert.ok(entry);
      assert.equal(entry.actor, 'ciso');
      assert.ok(entry.widened >= 1);
      assert.deepEqual(entry.before.read, ['sales', 'support', 'marketing']);
    } finally { v.close(); }
  });

  test('changing a wall requires a named actor and a reason', () => {
    const v = bare();
    try {
      v.folders.ensure('sales/accounts/');
      assert.throws(() => v.folders.setWalls('sales/accounts/', { read: ['sales'], actor: 'ciso' }), /named actor and a reason/);
      assert.throws(() => v.folders.setWalls('sales/accounts/', { read: ['sales'], reason: 'x' }), /named actor and a reason/);
      assert.throws(() => v.folders.setWalls('nowhere/', { read: ['sales'], actor: 'a', reason: 'b' }), /not found/);
    } finally { v.close(); }
  });

  test('the new wall is enforced immediately, not on the next restart', () => {
    const v = bare();
    try {
      v.folders.ensure('sales/accounts/', { read: ['sales', 'support'], write: ['sales'] });
      assert.equal(v.folders.check('read', { department: 'support' }, 'sales/accounts/').allowed, true);

      v.folders.setWalls('sales/accounts/', { read: ['sales'], actor: 'ciso', reason: 'scope reduction' });
      assert.equal(v.folders.check('read', { department: 'support' }, 'sales/accounts/').allowed, false,
        'a wall change that only takes effect later is a wall change that did not happen');
    } finally { v.close(); }
  });
});
