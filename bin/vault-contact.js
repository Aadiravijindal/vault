#!/usr/bin/env node
/**
 * The contact endpoint for the marketing site — and, optionally, the static
 * server for the site itself, so one command stands the whole thing up.
 *
 *   node bin/vault-contact.js                    # serves site/ and /api/contact on :8090
 *   node bin/vault-contact.js --port 3000
 *   node bin/vault-contact.js --no-static        # endpoint only, behind your own CDN
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
 *
 * A `mailto:` link publishes the destination address to every scraper that
 * ever reads the page, and dumps the visitor into a mail client instead of
 * taking their message. A third-party form service fixes that by sending every
 * enquiry — names, companies, what they are worried about — to a company nobody
 * agreed to, and adds a script tag to a site whose whole claim is that it
 * fetches nothing from anyone.
 *
 * So the address lives here, in the server's configuration, and the page knows
 * only the path to POST to.
 *
 * ── ZERO DEPENDENCIES, INCLUDING THE MAIL ───────────────────────────────────
 *
 * SMTP is spoken directly over a TLS socket. It is a small, stable, text
 * protocol and the alternative was a dependency tree for something that is
 * ~120 lines. Implicit TLS on 465 rather than STARTTLS on 587, because
 * STARTTLS begins in plaintext and can be stripped by anything on the path.
 *
 * ── IF THE MAIL CANNOT GO ───────────────────────────────────────────────────
 *
 * Every message is appended to a spool file BEFORE the send is attempted, and
 * the spool line is marked once it succeeds. A misconfigured relay, an expired
 * password or a network blip therefore loses nothing — the enquiries are on
 * disk and can be replayed. Losing somebody who took the trouble to write to
 * you is the expensive failure here, not a 500.
 */
import { createServer } from 'node:http';
import { connect } from 'node:tls';
import { readFileSync, existsSync, appendFileSync, mkdirSync, statSync } from 'node:fs';
import { join, extname, dirname, resolve, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const flag = (name) => process.argv.includes(`--${name}`);

const PORT = Number(arg('port', process.env.PORT || 8090));
const SITE = resolve(arg('site', join(ROOT, 'site')));
const SPOOL = resolve(arg('spool', join(ROOT, '.contact-spool.jsonl')));
const SERVE_STATIC = !flag('no-static');

/**
 * Where enquiries go.
 *
 * This is the one place the address appears. It is NOT in index.html, not in
 * styles.css, not in app.js, and not in the zip anyone downloads of the site —
 * the page knows only `/api/contact`.
 *
 * Override it with CONTACT_TO if this repository is ever public, or if the
 * address should change without a commit.
 */
const TO = process.env.CONTACT_TO || 'aadijindal258@gmail.com';

const SMTP = {
  host: process.env.CONTACT_SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.CONTACT_SMTP_PORT || 465),
  user: process.env.CONTACT_SMTP_USER || '',
  pass: process.env.CONTACT_SMTP_PASS || '',
  from: process.env.CONTACT_FROM || process.env.CONTACT_SMTP_USER || ''
};

const LIMITS = { name: 120, email: 200, company: 120, message: 4000 };

// ── SMTP ────────────────────────────────────────────────────────────────────

/**
 * One conversation with the relay. Each step waits for the reply code it
 * expects rather than assuming order, because a server that refuses at RCPT
 * TO must not look like a success at QUIT.
 */
function sendMail({ from, to, subject, replyTo, text }) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: SMTP.host, port: SMTP.port, servername: SMTP.host });
    socket.setEncoding('utf8');
    socket.setTimeout(20000, () => { socket.destroy(); reject(new Error('SMTP timed out')); });

    let buffer = '';
    let step = 0;
    const b64 = (s) => Buffer.from(String(s), 'utf8').toString('base64');

    const script = [
      { expect: 220, send: `EHLO vault\r\n` },
      { expect: 250, send: `AUTH LOGIN\r\n` },
      { expect: 334, send: `${b64(SMTP.user)}\r\n` },
      { expect: 334, send: `${b64(SMTP.pass)}\r\n` },
      { expect: 235, send: `MAIL FROM:<${from}>\r\n` },
      { expect: 250, send: `RCPT TO:<${to}>\r\n` },
      { expect: 250, send: `DATA\r\n` },
      { expect: 354, send: `${body({ from, to, subject, replyTo, text })}\r\n.\r\n` },
      { expect: 250, send: `QUIT\r\n`, done: true }
    ];

    socket.on('data', (chunk) => {
      buffer += chunk;
      // A reply is complete when its last line has a space after the code
      // rather than a hyphen; multi-line greetings are normal.
      if (!/^\d{3} [^\n]*\r?\n$/m.test(buffer.split(/(?<=\n)/).at(-1) ?? '')) return;
      const code = Number(buffer.trim().split(/\r?\n/).at(-1).slice(0, 3));
      const stage = script[step];
      if (code !== stage.expect) {
        socket.destroy();
        return reject(new Error(`SMTP step ${step} wanted ${stage.expect}, got ${code}: ${buffer.trim().split(/\r?\n/).at(-1)}`));
      }
      buffer = '';
      step++;
      socket.write(stage.send);
      if (stage.done) { socket.end(); resolve(); }
    });

    socket.on('error', reject);
  });
}

/**
 * Header injection is the whole risk in this file. Every value that reaches a
 * header comes from a stranger's form, and a bare CR or LF in any of them
 * turns one message into two — the second addressed wherever they like. So
 * nothing is trusted: headers are stripped of CR and LF entirely, and the body
 * has its lone dots escaped because a line of "." ends DATA.
 */
const header = (v) => String(v ?? '').replace(/[\r\n]+/g, ' ').trim().slice(0, 400);
const dotStuff = (v) => String(v ?? '').replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');

function body({ from, to, subject, replyTo, text }) {
  const lines = [
    `From: Vault site <${header(from)}>`,
    `To: <${header(to)}>`,
    replyTo ? `Reply-To: ${header(replyTo)}` : null,
    `Subject: ${header(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    dotStuff(text)
  ].filter(Boolean);
  return lines.join('\r\n');
}

// ── validation ──────────────────────────────────────────────────────────────

function validate(data) {
  const errors = [];
  const clean = {};
  for (const [field, max] of Object.entries(LIMITS)) {
    const value = String(data[field] ?? '').trim();
    if (value.length > max) errors.push(`${field} is longer than ${max} characters`);
    clean[field] = value.slice(0, max);
  }
  if (!clean.name) errors.push('name is required');
  if (!clean.message) errors.push('message is required');
  // Deliberately loose. Anything stricter rejects real addresses, and the only
  // test that actually matters is whether a reply arrives.
  if (!/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(clean.email)) errors.push('email does not look like an address');
  return { clean, errors };
}

// ── rate limiting ───────────────────────────────────────────────────────────

/**
 * Per-address, in memory. Enough to stop a script hammering the relay; not a
 * substitute for whatever sits in front of this in production.
 */
const seen = new Map();
const RATE = {
  windowMs: Number(process.env.CONTACT_RATE_WINDOW_MS || 10 * 60 * 1000),
  max: Number(process.env.CONTACT_RATE_MAX || 5)
};
function overLimit(ip) {
  const now = Date.now();
  const hits = (seen.get(ip) ?? []).filter((t) => now - t < RATE.windowMs);
  hits.push(now);
  seen.set(ip, hits);
  if (seen.size > 5000) for (const [k, v] of seen) if (!v.some((t) => now - t < RATE.windowMs)) seen.delete(k);
  return hits.length > RATE.max;
}

// ── static files ────────────────────────────────────────────────────────────

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.webm': 'video/webm', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.woff2': 'font/woff2', '.md': 'text/plain; charset=utf-8'
};

function serveStatic(req, res) {
  const asked = decodeURIComponent((req.url || '/').split('?')[0]);
  // normalize() collapses ".." before the prefix check, so a request for
  // /../../etc/passwd cannot climb out of the site directory.
  const path = normalize(join(SITE, asked === '/' ? 'index.html' : asked));
  if (!path.startsWith(SITE)) { res.writeHead(403).end('forbidden'); return; }
  if (!existsSync(path) || !statSync(path).isFile()) { res.writeHead(404).end('not found'); return; }
  res.writeHead(200, {
    'content-type': TYPES[extname(path)] ?? 'application/octet-stream',
    'cache-control': extname(path) === '.html' ? 'no-cache' : 'public, max-age=3600'
  });
  res.end(readFileSync(path));
}

// ── the server ──────────────────────────────────────────────────────────────

const json = (res, code, obj) => {
  res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify(obj));
};

/**
 * The request handler, separately from the listening socket, so tests can
 * drive it without a port and so importing this file does not start a server.
 */
export const handler = async (req, res) => {
  if (req.method === 'OPTIONS') {
    return res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'content-type'
    }).end();
  }

  if (req.url?.split('?')[0] === '/api/contact') {
    if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });

    const ip = (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '?').trim();
    if (overLimit(ip)) return json(res, 429, { error: 'too many messages from here; try again later' });

    let raw = '';
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 64 * 1024) { req.destroy(); return; }
    }

    let data;
    try {
      // The page sends JSON; a no-JavaScript browser sends a urlencoded form.
      // Both have to work, because the form is meant to survive this file
      // never loading.
      data = /json/.test(req.headers['content-type'] || '')
        ? JSON.parse(raw)
        : Object.fromEntries(new URLSearchParams(raw));
    } catch { return json(res, 400, { error: 'could not read that' }); }

    // The honeypot: a field no human sees. Accept and drop, so whoever wrote
    // the bot learns nothing about which field gave it away.
    if (String(data.website ?? '').trim()) return json(res, 200, { ok: true });

    const { clean, errors } = validate(data);
    if (errors.length) return json(res, 400, { error: errors.join('; ') });

    const record = { at: new Date().toISOString(), ip, ...clean };
    // Spool BEFORE sending. If the relay is down, the enquiry still exists.
    mkdirSync(dirname(SPOOL), { recursive: true });
    appendFileSync(SPOOL, `${JSON.stringify(record)}\n`);

    const text = [
      `From:    ${clean.name} <${clean.email}>`,
      clean.company ? `Company: ${clean.company}` : null,
      `When:    ${record.at}`,
      '',
      clean.message
    ].filter(Boolean).join('\n');

    if (!SMTP.user || !SMTP.pass) {
      // Configuration is missing, not broken. Say so on the console, and still
      // tell the visitor their message landed — because it did, in the spool.
      console.warn(`[contact] spooled only — set CONTACT_SMTP_USER and CONTACT_SMTP_PASS to relay. (${SPOOL})`);
      return json(res, 200, { ok: true, delivered: false });
    }

    try {
      await sendMail({
        from: SMTP.from || SMTP.user,
        to: TO,
        replyTo: `${header(clean.name)} <${header(clean.email)}>`,
        subject: `Vault — ${clean.name}${clean.company ? ` (${clean.company})` : ''}`,
        text
      });
      appendFileSync(SPOOL, `${JSON.stringify({ at: new Date().toISOString(), sent: record.at })}\n`);
      return json(res, 200, { ok: true, delivered: true });
    } catch (err) {
      console.error(`[contact] relay failed: ${err.message} — the message is spooled at ${SPOOL}`);
      // The enquiry is safe on disk, so this is a 200 with the truth in it
      // rather than an error the visitor can do nothing about.
      return json(res, 200, { ok: true, delivered: false });
    }
  }

  if (SERVE_STATIC) return serveStatic(req, res);
  return json(res, 404, { error: 'not found' });
};

export const createContactServer = () => createServer(handler);

/** The parts worth pinning in a test. */
export const _internals = {
  header, dotStuff, validate, body, LIMITS, RATE,
  /* The limiter keeps state across requests by design, which makes any test
     that shares this process order-dependent unless it can be cleared. */
  resetRateLimit: () => seen.clear()
};

// Only listen when run directly. Imported — by a test, or by a larger server
// that wants to mount this handler — it does nothing on its own.
if (process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`) {
  createContactServer().listen(PORT, () => {
  console.log(`contact endpoint  http://localhost:${PORT}/api/contact  → ${TO.replace(/^(.).*(@.*)$/, '$1…$2')}`);
  if (SERVE_STATIC) console.log(`site              http://localhost:${PORT}/   (${SITE})`);
  if (!SMTP.user || !SMTP.pass) {
    console.log('\nNo relay configured — messages will be spooled to disk only.');
    console.log('  export CONTACT_SMTP_USER=you@gmail.com');
      console.log('  export CONTACT_SMTP_PASS=<a Google app password, not your login password>');
    }
  });
}
