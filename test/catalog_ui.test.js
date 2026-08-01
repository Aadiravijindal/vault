/**
 * The connector catalog screen — browsing all 74, connecting one, managing what
 * is connected.
 *
 * The API half runs against a real server. The UI half is source inspection,
 * same as ui.test.js: there is no browser here, so what is checked is that the
 * screen is registered, role-gated, and calls endpoints that exist — never a
 * claim that it renders correctly.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { ApiServer } from '../src/api/server.js';
import { CONNECTORS } from '../src/connectors/catalog.js';

const UI = fileURLToPath(new URL('../src/ui/', import.meta.url));
const js = readFileSync(join(UI, 'app.js'), 'utf8');
const css = readFileSync(join(UI, 'app.css'), 'utf8');

const bare = () => new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });

async function withServer(v, fn) {
  const server = new ApiServer({ vault: v, port: 0 });
  const tok = server.issueToken({ name: 'ops', role: 'admin', clearance: 'secret' });
  await server.listen();
  const port = server.server.address().port;
  const call = (path, opts = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
    method: opts.method || 'GET',
    headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  try { return await fn(call); } finally { await server.close(); }
}

describe('the catalog endpoint serves every connector with its live state', () => {
  test('it returns the whole catalog, not just what is connected', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const r = await (await call('/api/connectors/catalog')).json();
      assert.equal(r.total, CONNECTORS.length);
      assert.equal(r.connected, 0);
      assert.ok(r.categories.length > 1, 'the screen needs categories to filter by');
    });
  });

  test('every entry carries the blind spots, not just what it can pull', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const r = await (await call('/api/connectors/catalog')).json();
      for (const e of r.entries) {
        assert.ok(Array.isArray(e.cannotPull), `${e.id} has no cannotPull — the honesty field is the point`);
        assert.ok(Array.isArray(e.modesSupported) && e.modesSupported.length, `${e.id} lists no usable mode`);
      }
    });
  });

  test('connecting one shows up as an instance on that catalog entry', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const res = await call('/api/connectors', {
        method: 'POST',
        body: { catalogId: 'slack-bot', mode: 'watch', owner: 'dana', technicalOwner: 'sam', backfillDays: 0 }
      });
      assert.equal(res.status, 200, await res.text());

      const r = await (await call('/api/connectors/catalog')).json();
      assert.equal(r.connected, 1);
      const slack = r.entries.find((e) => e.id === 'slack-bot');
      assert.equal(slack.connected, true);
      assert.equal(slack.instances.length, 1);
      assert.equal(slack.instances[0].mode, 'watch');
      assert.equal(slack.instances[0].owner, 'dana');
    });
  });

  test('connecting without both owners is refused — silence has to alert someone', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const res = await call('/api/connectors', {
        method: 'POST', body: { catalogId: 'slack-bot', mode: 'watch', owner: 'dana' }
      });
      assert.equal(res.status >= 400, true, 'a connector with no technical owner must not connect');
    });
  });

  test('one person may hold both owner roles — what is refused is neither being anybody', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const res = await call('/api/connectors', {
        method: 'POST',
        body: { catalogId: 'slack-bot', mode: 'watch', owner: 'sam', technicalOwner: 'sam', backfillDays: 0 }
      });
      assert.equal(res.status, 200, 'a one-admin company must still be able to connect a tool');
    });
  });

  test('kill, revive and disconnect are reachable and each demands a reason', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const conn = await (await call('/api/connectors', {
        method: 'POST',
        body: { catalogId: 'slack-bot', mode: 'watch', owner: 'dana', technicalOwner: 'sam', backfillDays: 0 }
      })).json();

      const noReason = await call(`/api/connectors/${conn.id}/kill`, { method: 'POST', body: {} });
      assert.equal(noReason.status >= 400, true, 'killing a connector with no stated reason must fail');

      assert.equal((await call(`/api/connectors/${conn.id}/kill`, { method: 'POST', body: { reason: 'incident' } })).status, 200);
      let cat = await (await call('/api/connectors/catalog')).json();
      assert.equal(cat.entries.find((e) => e.id === 'slack-bot').instances[0].killed, true);

      assert.equal((await call(`/api/connectors/${conn.id}/revive`, { method: 'POST', body: { reason: 'resolved' } })).status, 200);
      cat = await (await call('/api/connectors/catalog')).json();
      assert.equal(cat.entries.find((e) => e.id === 'slack-bot').instances[0].killed, false);

      assert.equal((await call(`/api/connectors/${conn.id}/disconnect`, { method: 'POST', body: { reason: 'no longer used' } })).status, 200);
      cat = await (await call('/api/connectors/catalog')).json();
      assert.equal(cat.entries.find((e) => e.id === 'slack-bot').instances[0].status, 'disconnected');
    });
  });

  test('the literal /catalog route is not swallowed by /:id/describe', async () => {
    const v = bare();
    await withServer(v, async (call) => {
      const r = await call('/api/connectors/catalog');
      assert.equal(r.status, 200);
      const body = await r.json();
      assert.ok(body.entries, 'catalog must not be routed as a connector id');
    });
  });
});

describe('the connectors screen is wired into the interface', () => {
  test('it is registered as a screen and role-gated to operators', () => {
    assert.match(js, /id: 'connectors'/);
    const decl = js.slice(js.indexOf("id: 'connectors'"), js.indexOf("id: 'connectors'") + 200);
    assert.match(decl, /roles: \['platform', 'admin', 'security'\]/);
  });

  test('it calls only endpoints the server actually registers', () => {
    const server = readFileSync(fileURLToPath(new URL('../src/api/server.js', import.meta.url)), 'utf8');
    for (const path of ['/api/connectors/catalog']) {
      assert.ok(server.includes(`'${path}'`), `the screen calls ${path} and the server does not serve it`);
    }
    for (const act of ['kill', 'revive', 'disconnect']) {
      assert.ok(server.includes(`/api/connectors/:id/${act}`), `the screen offers ${act} and the server does not serve it`);
    }
  });

  test('the detail panel is a real dialog, so focus trapping is the browser\'s job', () => {
    assert.match(js, /el\('dialog', 'sheet'\)/);
    assert.match(js, /showModal\(\)/);
    assert.ok(css.includes('.sheet::backdrop'), 'a modal with no backdrop style leaves the page behind it readable');
  });

  test('destructive actions ask for a reason before they are sent', () => {
    const openFn = js.slice(js.indexOf('function openConnector'), js.indexOf('// 🧠 MEMORY'));
    assert.match(openFn, /Reason for/, 'kill/disconnect must collect a reason — the ledger records it against a name');
    assert.match(openFn, /if \(!reason\) return;/, 'an empty reason must abort rather than send');
  });

  test('the connect form requires both owners in the markup, not just on the server', () => {
    const openFn = js.slice(js.indexOf('function openConnector'), js.indexOf('// 🧠 MEMORY'));
    assert.match(openFn, /name="owner"[^>]*required/);
    assert.match(openFn, /name="technicalOwner"[^>]*required/);
  });
});
