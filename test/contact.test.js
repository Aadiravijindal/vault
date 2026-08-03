/**
 * The contact endpoint.
 *
 * Two things here are security properties rather than features, and both get
 * their own cases: the destination address must never reach the browser, and
 * a stranger's form input must never become a mail header.
 *
 * The address is the whole reason this endpoint exists instead of a mailto:
 * link, so a test asserts the site cannot leak it — including from the zip
 * anybody downloads.
 */
import { test, describe, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, rmSync } from 'node:fs';
import { createContactServer, _internals } from '../bin/vault-contact.js';

const { header, dotStuff, validate, body, LIMITS, resetRateLimit } = _internals;

let server;
let base;
const SPOOL = new URL('../.contact-spool.jsonl', import.meta.url);

before(async () => {
  server = createContactServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
// Every request in this file comes from 127.0.0.1, so without this the
// limiter turns the suite into one long shared budget and whichever case runs
// last gets a 429 instead of the code it is testing.
beforeEach(() => resetRateLimit());
after(() => {
  server.close();
  // The tests spool real records; do not leave them in the working tree.
  if (existsSync(SPOOL)) rmSync(SPOOL);
});

const post = (payload, type = 'application/json') => fetch(`${base}/api/contact`, {
  method: 'POST',
  headers: { 'content-type': type },
  body: type.includes('json') ? JSON.stringify(payload) : new URLSearchParams(payload).toString()
});

const good = () => ({ name: 'Ada Lovelace', email: 'ada@example.com', message: 'Three agents, one memory.' });

describe('the address never reaches the browser', () => {
  test('nothing served to a visitor contains it', () => {
    // This is the entire reason the endpoint exists rather than a mailto:.
    // If it appears in any of these, the endpoint has bought nothing.
    const to = readFileSync(new URL('../bin/vault-contact.js', import.meta.url), 'utf8')
      .match(/CONTACT_TO \|\| '([^']+)'/)?.[1];
    assert.ok(to, 'the endpoint should have a configured destination');

    for (const file of ['index.html', 'styles.css', 'app.js', 'README.md']) {
      const src = readFileSync(new URL(`../site/${file}`, import.meta.url), 'utf8');
      assert.ok(!src.includes(to), `site/${file} leaks the destination address`);
    }
  });

  test('the page posts to a path, and offers no mailto anywhere', () => {
    const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
    assert.match(html, /action="\/api\/contact"/);
    // The comments explain why there is no mailto:; what matters is that no
    // element actually links to one.
    assert.ok(!/href="mailto:/i.test(html),
      'a mailto: link publishes the address to every scraper that reads the page');
  });

  test('it can be moved without a commit', () => {
    const src = readFileSync(new URL('../bin/vault-contact.js', import.meta.url), 'utf8');
    assert.match(src, /process\.env\.CONTACT_TO/,
      'the destination must be overridable by environment, for a public repository');
  });
});

describe('a stranger cannot write mail headers', () => {
  test('CR and LF never survive into a header', () => {
    // Without this, one message becomes two, and the second is addressed
    // wherever the attacker likes.
    const evil = 'Ada\r\nBcc: victim@example.com';
    assert.ok(!/[\r\n]/.test(header(evil)));

    const msg = body({
      from: 'site@example.com',
      to: 'dest@example.com',
      replyTo: evil,
      subject: `Vault — ${evil}`,
      text: 'hello'
    });
    // The text may survive folded into a value; what must not survive is a
    // LINE of its own, because that is what makes it a header.
    const headers = msg.split('\r\n\r\n')[0].split('\r\n');
    assert.ok(!headers.some((l) => /^Bcc:/i.test(l)), 'an injected Bcc header got through');
    assert.equal(headers.filter((l) => /^Subject:/.test(l)).length, 1);
  });

  test('a lone dot cannot end the message early', () => {
    // A line containing only "." terminates DATA. A body that contains one
    // would truncate the mail and leave the rest to be read as commands.
    const out = dotStuff('first\n.\nsecond');
    assert.match(out, /\r\n\.\.\r\n/);
  });

  test('every header value is length-capped', () => {
    assert.ok(header('x'.repeat(5000)).length <= 400);
  });
});

describe('what it accepts', () => {
  test('a real enquiry is taken', async () => {
    const res = await post(good());
    assert.equal(res.status, 200);
    assert.equal((await res.json()).ok, true);
  });

  test('a form post works with no JavaScript at all', async () => {
    // The form is a real <form> with a real action; the fetch in app.js is an
    // enhancement. If this breaks, the site stops working for anyone whose
    // script did not load.
    const res = await post(good(), 'application/x-www-form-urlencoded');
    assert.equal(res.status, 200);
    assert.equal((await res.json()).ok, true);
  });

  test('an address that is not one is refused, with a reason', async () => {
    const res = await post({ ...good(), email: 'not-an-address' });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /email/);
  });

  test('name and message are required', async () => {
    for (const missing of ['name', 'message']) {
      const payload = good();
      payload[missing] = '';
      const res = await post(payload);
      assert.equal(res.status, 400, `${missing} should be required`);
      assert.match((await res.json()).error, new RegExp(missing));
    }
  });

  test('over-long input is refused rather than silently truncated', async () => {
    const res = await post({ ...good(), message: 'x'.repeat(LIMITS.message + 1) });
    assert.equal(res.status, 400);
  });

  test('the honeypot is accepted and dropped', async () => {
    // Telling a bot it was caught teaches whoever wrote it which field to
    // leave alone next time, so this looks exactly like success.
    const res = await post({ ...good(), website: 'http://spam.example' });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  });

  test('validation trims before it checks, so spaces are not a message', () => {
    assert.ok(validate({ name: '  ', email: 'a@b.cc', message: '   ' }).errors.length >= 2);
  });
});

describe('it holds the line', () => {
  test('only POST', async () => {
    const res = await fetch(`${base}/api/contact`);
    assert.equal(res.status, 405);
  });

  test('a body that will not parse is a 400, not a crash', async () => {
    const res = await fetch(`${base}/api/contact`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not json'
    });
    assert.equal(res.status, 400);
  });

  test('the static server cannot be walked out of', async () => {
    // normalize() collapses the .. before the prefix check; without it this
    // reads any file the process can.
    for (const path of ['/../../etc/passwd', '/..%2f..%2fetc%2fpasswd', '/../package.json']) {
      const res = await fetch(base + path);
      assert.ok(res.status === 404 || res.status === 403, `${path} returned ${res.status}`);
    }
  });

  test('the same address cannot hammer it forever', async () => {
    const { max } = _internals.RATE;
    for (let i = 0; i < max; i++) {
      assert.equal((await post(good())).status, 200, `submission ${i + 1} should still be allowed`);
    }
    assert.equal((await post(good())).status, 429, `submission ${max + 1} should be refused`);
  });
});

describe('an enquiry is never lost', () => {
  test('it is spooled before the relay is attempted', async () => {
    // With no SMTP configured the send cannot happen, and the endpoint still
    // reports success — because the message is on disk. Losing somebody who
    // took the trouble to write is the expensive failure, not a 500.
    const src = readFileSync(new URL('../bin/vault-contact.js', import.meta.url), 'utf8');
    const spoolAt = src.indexOf('appendFileSync(SPOOL');
    const sendAt = src.indexOf('await sendMail(');
    assert.ok(spoolAt > 0 && sendAt > spoolAt,
      'the spool write must come before the send, or a dead relay loses the message');
    assert.match(src, /delivered: false/,
      'the reply should say whether it actually went out, not just that it was accepted');
  });
});
