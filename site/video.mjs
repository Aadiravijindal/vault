#!/usr/bin/env node
/**
 * Generates site/hero.webm — the looping background footage behind the hero.
 *
 *   node site/video.mjs                 # 1280x720, 24fps, 8s loop
 *   node site/video.mjs --w 960 --h 540 --seconds 6
 *
 * ── WHY THIS IS GENERATED AND NOT SHOT ──────────────────────────────────────
 *
 * A workstation at night, running Vault. Three screens: the terminal, the
 * folder map, the gate ticking through its ten checks. The desk catches their
 * light, racks blink somewhere behind, dust drifts through the glow.
 *
 * The terminal is the part that matters. Its text is not set dressing — this
 * script RUNS `demo/seed.js` at build time and puts its real output on the
 * screen, so every BLOCKED and HELD in the footage is an outcome the gate
 * actually produced. Licensed stock footage of somebody else's office says
 * nothing about this product and cannot be checked against it.
 *
 * It is also reproducible. The palette comes from the same tokens as the site,
 * so when the brand shifts the footage shifts with it — one edit, one command,
 * rather than a re-shoot.
 *
 * ── HOW ─────────────────────────────────────────────────────────────────────
 *
 * Frames are drawn in headless Chromium on a 2D canvas at a FIXED timestep, so
 * the result is deterministic and every animation closes its loop exactly at
 * the last frame. Each frame comes back as a JPEG and is piped straight into
 * ffmpeg's image2pipe, so nothing large is ever held in memory or written to
 * disk between the two.
 *
 * JPEG rather than PNG on purpose: the ffmpeg that ships with Playwright is a
 * minimal build with exactly two video decoders — mjpeg and libvpx. Hand it a
 * PNG and it exits before the first frame, and because the pipe then never
 * drains the render appears to hang rather than fail. Lossy intermediate
 * frames cost nothing here anyway; VP8 re-quantises everything downstream, and
 * the footage sits under a scrim.
 *
 * Requires: Playwright + ffmpeg. Neither is a runtime dependency of the site —
 * this runs once, at build time, and commits its output.
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? Number(process.argv[i + 1]) : fallback;
};

const W = arg('w', 1280);
const H = arg('h', 720);
const FPS = arg('fps', 24);
const SECONDS = arg('seconds', 8);
const FRAMES = FPS * SECONDS;
const OUT = join(HERE, 'hero.webm');
const FFMPEG = process.env.FFMPEG || '/opt/pw-browsers/ffmpeg-1011/ffmpeg-linux';
const require = createRequire(import.meta.url);

/**
 * The text on the centre screen is not invented — it is what `demo/seed.js`
 * prints when it runs, captured here at build time and stripped of its ANSI
 * colour codes. If the product's behaviour changes, the footage changes with
 * it; there is no separate script to keep in sync, and nothing on that screen
 * claims an outcome the gate does not actually produce.
 *
 * If the demo cannot run for any reason the render still proceeds, on a short
 * hand-written fallback, because a missing background video is a worse outcome
 * than a background video with less text on it.
 */
function realOutput() {
  const strip = (s) => s.replace(/\[[0-9;]*m/g, '');
  try {
    const { execFileSync } = require('node:child_process');
    const raw = execFileSync(process.execPath, [join(HERE, '..', 'demo', 'seed.js')], {
      encoding: 'utf8', timeout: 120000, maxBuffer: 8 << 20,
      env: { ...process.env, NO_COLOR: '1' }
    });
    const lines = strip(raw).split('\n').map((l) => l.replace(/\s+$/, '')).filter((l) => l.trim());
    if (lines.length > 24) return lines;
    process.stderr.write('demo output was unexpectedly short; using the fallback\n');
  } catch (e) {
    process.stderr.write(`could not run demo/seed.js (${e.message.split('\n')[0]}); using the fallback\n`);
  }
  return [
    'VAULT - gate armed', '', '> registering agents', '> sealing archive... OK',
    '  BLOCKED  indirect prompt injection', '  BLOCKED  golden-fact overwrite',
    '  HELD     drip-feed poisoning', '  BLOCKED  cross-wall write',
    '  ledger verified - chain intact'
  ];
}

const LINES = realOutput();

/** The walls, as the product actually names them. */
const FOLDERS = [
  ['_quarantine/', 'hard'], ['company/', 'read'], ['company/people/', 'read'],
  ['engineering/', 'read'], ['finance/', 'hard'], ['hr/', 'hard'],
  ['legal/', 'hard'], ['marketing/', 'read'], ['sales/', 'read'],
  ['sales/accounts/', 'read'], ['support/', 'read'], ['admin/', 'hard']
];


/**
 * The scene, as a string evaluated inside the page.
 *
 * A workstation at night: three screens running Vault, the desk catching their
 * light, the room falling away behind. The centre screen is the real terminal
 * output captured above; the side screens are the folder map and the gate.
 *
 * Everything is a function of `t` in [0,1) — never of a frame counter or a
 * clock — which is what makes the loop seamless: at t=1 every position, phase
 * and offset is back where it was at t=0. The camera drift uses a full sine
 * period for the same reason.
 */
const SCENE = `(W, H, t, LINES, FOLDERS) => {
  const c = document.getElementById('c').getContext('2d');
  const TAU = Math.PI * 2;
  const S = H / 720;                       // everything is authored at 720p
  const rnd = (i) => { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };

  // ---- the camera ------------------------------------------------------
  // A slow handheld drift. Small, and a whole sine period, so it closes.
  const camX = Math.sin(t * TAU) * 14 * S;
  const camY = Math.cos(t * TAU) * 7 * S;

  // ---- the room --------------------------------------------------------
  c.fillStyle = '#05030a';
  c.fillRect(0, 0, W, H);

  const deskY = H * 0.72;

  // back wall: server racks, far off and barely lit
  c.save();
  c.translate(camX * 0.25, camY * 0.25);
  for (let i = 0; i < 7; i++) {
    const x = (i / 7) * W * 1.15 - W * 0.06;
    const w = W * 0.085;
    c.fillStyle = 'rgba(18,10,20,.85)';
    c.fillRect(x, H * 0.06, w, deskY - H * 0.06);
    // rack status lights — the only thing alive back there
    for (let j = 0; j < 16; j++) {
      const y = H * 0.1 + j * (deskY - H * 0.14) / 16;
      const on = rnd(i * 40 + j) > 0.55;
      const blink = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin((t * (1 + rnd(i * 7 + j)) + rnd(j * 3 + i)) * TAU * 2));
      c.fillStyle = on
        ? 'rgba(255,140,43,' + (0.1 + 0.35 * blink) + ')'
        : 'rgba(90,110,130,' + (0.05 + 0.1 * blink) + ')';
      c.fillRect(x + w * 0.14, y, w * 0.1, 2.5 * S);
      c.fillRect(x + w * 0.34, y, w * 0.06, 2.5 * S);
    }
  }
  c.restore();

  // ---- a screen -------------------------------------------------------
  // Side screens are sheared rather than projected: canvas 2D is affine only,
  // and at background scale, under a scrim, a shear reads as an angled panel
  // while a true projective warp would cost a per-pixel pass per frame.
  function screen(x, y, w, h, shear, draw) {
    c.save();
    c.translate(x + camX, y + camY);
    c.transform(1, shear, 0, 1, 0, 0);

    // bezel, then a rim catching the glow of its own screen, then glass
    c.fillStyle = '#151020';
    c.fillRect(-7 * S, -7 * S, w + 14 * S, h + 14 * S);
    c.strokeStyle = 'rgba(255,150,70,.22)';
    c.lineWidth = 1 * S;
    c.strokeRect(-7 * S, -7 * S, w + 14 * S, h + 14 * S);
    c.fillStyle = '#0b0814';
    c.fillRect(0, 0, w, h);

    c.save();
    c.beginPath(); c.rect(0, 0, w, h); c.clip();
    // Shallow depth of field. Sharp, the terminal is legible right behind the
    // headline and competes with it; a background that reads as "screens with
    // work on them" rather than "text you try to read" is the whole job. The
    // blur is applied to the content only, so the bezels stay crisp and the
    // panels still read as hardware.
    c.filter = 'blur(' + (1.5 * S).toFixed(2) + 'px)';
    draw(w, h);
    c.filter = 'none';

    // scanlines and a faint CRT curve of light across the glass
    c.fillStyle = 'rgba(0,0,0,.22)';
    for (let yy = 0; yy < h; yy += 3 * S) c.fillRect(0, yy, w, 1 * S);
    const sheen = c.createLinearGradient(0, 0, w, h);
    sheen.addColorStop(0, 'rgba(180,200,255,.05)');
    sheen.addColorStop(0.5, 'rgba(180,200,255,0)');
    sheen.addColorStop(1, 'rgba(255,140,43,.04)');
    c.fillStyle = sheen; c.fillRect(0, 0, w, h);
    c.restore();

    c.restore();
  }

  // ---- centre screen: the real terminal --------------------------------
  const cw = W * 0.40, ch = H * 0.44;
  const cx = W * 0.5 - cw / 2, cy = H * 0.24;

  screen(cx, cy, cw, ch, 0, (w, h) => {
    c.fillStyle = '#08050d'; c.fillRect(0, 0, w, h);
    const lh = 13 * S;
    const rows = Math.ceil(h / lh) + 2;
    // scroll exactly one line per 1/LINES.length of the loop, so the text is
    // back where it started at t=1
    const scrolled = t * LINES.length;
    const first = Math.floor(scrolled);
    const frac = scrolled - first;

    c.font = (10.5 * S).toFixed(1) + 'px ui-monospace, monospace';
    c.textBaseline = 'top';
    for (let i = 0; i < rows; i++) {
      const line = LINES[(first + i) % LINES.length];
      const y = i * lh - frac * lh + 8 * S;
      // colour by what the line actually says — these are real outcomes
      let col = 'rgba(196,206,224,.42)';
      if (/BLOCKED|blocked|STOPPED|refused|✕/.test(line)) col = 'rgba(255,110,110,.62)';
      else if (/✓|OK|verified|written|stopped before/.test(line)) col = 'rgba(120,230,160,.55)';
      else if (/HELD|held|⚠|review/.test(line)) col = 'rgba(255,190,90,.6)';
      else if (/^[A-Z0-9 ·—-]+$/.test(line.trim()) && line.trim().length > 4) col = 'rgba(255,166,77,.66)';
      c.fillStyle = col;
      c.fillText(line.slice(0, 78), 10 * S, y);
    }
    // prompt caret, blinking on the loop
    if ((t * 8) % 1 < 0.55) {
      c.fillStyle = 'rgba(255,166,77,.9)';
      c.fillRect(10 * S, h - 16 * S, 7 * S, 11 * S);
    }
  });

  // ---- left screen: the folder map -------------------------------------
  const lw = W * 0.20, lh2 = H * 0.34;
  screen(W * 0.045, H * 0.30, lw, lh2, 0.05, (w, h) => {
    c.fillStyle = '#080610'; c.fillRect(0, 0, w, h);
    c.font = (8.5 * S).toFixed(1) + 'px ui-monospace, monospace';
    c.textBaseline = 'middle';
    c.fillStyle = 'rgba(255,166,77,.85)';
    c.fillText('FOLDERS & WALLS', 9 * S, 12 * S);
    const rowH = (h - 26 * S) / FOLDERS.length;
    for (let i = 0; i < FOLDERS.length; i++) {
      const y = 26 * S + i * rowH + rowH / 2;
      // one row highlights at a time, travelling down the list over the loop
      const hot = Math.floor(t * FOLDERS.length) === i;
      if (hot) { c.fillStyle = 'rgba(255,106,19,.14)'; c.fillRect(0, y - rowH / 2, w, rowH); }
      c.fillStyle = hot ? 'rgba(255,200,150,.95)' : 'rgba(180,190,210,.5)';
      c.fillText(FOLDERS[i][0], 9 * S, y);
      c.fillStyle = FOLDERS[i][1] === 'hard' ? 'rgba(255,110,110,.75)' : 'rgba(120,200,255,.45)';
      c.fillRect(w - 34 * S, y - 2.5 * S, 26 * S * (FOLDERS[i][1] === 'hard' ? 1 : 0.55), 5 * S);
    }
  });

  // ---- right screen: the gate ------------------------------------------
  const rw = W * 0.20, rh = H * 0.34;
  screen(W * 0.755, H * 0.30, rw, rh, -0.05, (w, h) => {
    c.fillStyle = '#080610'; c.fillRect(0, 0, w, h);
    c.font = (8.5 * S).toFixed(1) + 'px ui-monospace, monospace';
    c.textBaseline = 'middle';
    c.fillStyle = 'rgba(255,166,77,.85)';
    c.fillText('GATE · 10 CHECKS', 9 * S, 12 * S);

    const names = ['identity', 'channel', 'source', 'private', 'label',
                   'walls', 'instruction', 'policy', 'reconcile', 'consent'];
    for (let i = 0; i < 10; i++) {
      const y = 30 * S + i * (h - 40 * S) / 10;
      const lit = (Math.sin((t * 2 - i / 13) * TAU) + 1) / 2;
      c.fillStyle = 'rgba(170,180,200,' + (0.3 + 0.35 * lit) + ')';
      c.fillText(names[i], 9 * S, y);
      const bx = w * 0.52, bw = w * 0.38;
      c.fillStyle = 'rgba(255,255,255,.05)';
      c.fillRect(bx, y - 3 * S, bw, 6 * S);
      c.fillStyle = 'rgba(255,166,77,' + (0.3 + 0.65 * lit) + ')';
      c.fillRect(bx, y - 3 * S, bw * (0.35 + 0.65 * lit), 6 * S);
    }
  });

  // ---- the light the screens throw -------------------------------------
  // Screens are the only source in the room, so everything else is lit by
  // them: bloom in the air, a pool on the desk, and a reflection below.
  c.save();
  c.globalCompositeOperation = 'lighter';
  for (const [gx, gy, gr, a] of [
    [W * 0.5 + camX, H * 0.43 + camY, W * 0.42, 0.3],
    [W * 0.145 + camX, H * 0.47 + camY, W * 0.2, 0.15],
    [W * 0.855 + camX, H * 0.47 + camY, W * 0.2, 0.15]
  ]) {
    const g = c.createRadialGradient(gx, gy, 0, gx, gy, gr);
    g.addColorStop(0, 'rgba(255,140,43,' + a + ')');
    g.addColorStop(0.45, 'rgba(214,59,6,' + a * 0.3 + ')');
    g.addColorStop(1, 'rgba(255,106,19,0)');
    c.fillStyle = g; c.beginPath(); c.arc(gx, gy, gr, 0, TAU); c.fill();
  }
  c.restore();

  // ---- the desk --------------------------------------------------------
  const desk = c.createLinearGradient(0, deskY, 0, H);
  desk.addColorStop(0, 'rgba(26,14,10,.95)');
  desk.addColorStop(1, 'rgba(8,4,8,1)');
  c.fillStyle = desk;
  c.fillRect(0, deskY, W, H - deskY);
  // the edge catches the light
  c.fillStyle = 'rgba(255,140,43,.16)';
  c.fillRect(0, deskY, W, 1.5 * S);

  // Reflection: the frame above the desk, drawn back onto it flipped and
  // squashed. Cheaper and far more convincing than re-drawing each screen —
  // it picks up the bezels, the glow and the text without knowing about any
  // of them, and a real desk reflects all three.
  const reflTop = Math.max(0, cy - 20 * S);
  const reflH = deskY - reflTop;
  c.save();
  c.globalAlpha = 0.2;
  c.translate(0, deskY);
  c.scale(1, -0.5);
  // Destination y is negative: after scale(1,-0.5) a local y of Y lands at
  // deskY - 0.5*Y, so the strip has to be drawn at -reflH..0 to end up BELOW
  // the desk edge rather than back over the screens.
  c.drawImage(c.canvas, 0, reflTop, W, reflH, 0, -reflH, W, reflH);
  c.restore();
  // fade it out with distance, or it reads as a mirror rather than a desk
  const fade = c.createLinearGradient(0, deskY, 0, H);
  fade.addColorStop(0, 'rgba(8,4,8,.25)');
  fade.addColorStop(0.55, 'rgba(8,4,8,.85)');
  fade.addColorStop(1, 'rgba(8,4,8,1)');
  c.fillStyle = fade;
  c.fillRect(0, deskY, W, H - deskY);

  // a keyboard, catching the same light — the one object that says "somebody
  // works here" rather than "this is a render"
  c.save();
  c.translate(camX * 1.4, camY * 1.4);
  const kw = W * 0.26, kh = H * 0.055, kx = W * 0.5 - kw / 2, ky = deskY + H * 0.11;
  c.fillStyle = 'rgba(13,8,15,.92)';
  c.fillRect(kx, ky, kw, kh);
  c.strokeStyle = 'rgba(255,150,70,.1)'; c.lineWidth = 1 * S;
  c.strokeRect(kx, ky, kw, kh);
  for (let r = 0; r < 4; r++) for (let k = 0; k < 22; k++) {
    c.fillStyle = 'rgba(255,170,110,.035)';
    c.fillRect(kx + 6 * S + k * (kw - 12 * S) / 22, ky + 5 * S + r * (kh - 10 * S) / 4,
               (kw - 12 * S) / 22 - 2 * S, (kh - 10 * S) / 4 - 2 * S);
  }
  c.restore();

  // ---- dust in the light ------------------------------------------------
  for (let i = 0; i < 55; i++) {
    const drift = (t + rnd(i + 700)) % 1;
    const x = rnd(i) * W + Math.sin((drift + rnd(i + 30)) * TAU) * 26 * S;
    const y = (rnd(i + 200) + drift * 0.16) % 1 * H;
    const a = 0.05 + 0.16 * (0.5 + 0.5 * Math.sin((drift + rnd(i + 90)) * TAU));
    c.fillStyle = 'rgba(255,190,140,' + a + ')';
    c.beginPath(); c.arc(x, y, (0.7 + rnd(i + 400)) * S, 0, TAU); c.fill();
  }

  // ---- vignette ---------------------------------------------------------
  // Lighter than it looks like it should be: the page lays its own scrim over
  // this, and two stacked vignettes turn the footage into a brown smear.
  const v = c.createRadialGradient(W / 2, H / 2, H * 0.32, W / 2, H / 2, W * 0.78);
  v.addColorStop(0, 'rgba(4,2,7,0)');
  v.addColorStop(1, 'rgba(4,2,7,.8)');
  c.fillStyle = v;
  c.fillRect(0, 0, W, H);
}`;

/**
 * Resolve Playwright from wherever it is actually installed.
 *
 * A plain `import('playwright')` resolves relative to THIS file, which sits in
 * a repository with no node_modules by design — the site and the product both
 * ship with zero dependencies, and this build script is the one thing that
 * needs a browser. So resolution starts from the working directory, and falls
 * back to $PLAYWRIGHT, with an error that says what to do rather than a bare
 * ERR_MODULE_NOT_FOUND.
 */
const { chromium } = await (async () => {
  const { createRequire } = await import('node:module');
  const { pathToFileURL } = await import('node:url');
  const candidates = [process.env.PLAYWRIGHT, join(process.cwd(), 'x.js'), import.meta.url].filter(Boolean);
  for (const from of candidates) {
    try {
      const req = createRequire(from.startsWith('file:') ? from : pathToFileURL(from));
      const mod = await import(pathToFileURL(req.resolve('playwright')));
      // Playwright is CommonJS, so the namespace may expose it directly or
      // only under `default` depending on what the lexer detected.
      const chromium = mod.chromium ?? mod.default?.chromium;
      if (chromium) return { chromium };
    } catch { /* try the next one */ }
  }
  throw new Error(
    'Playwright is not resolvable from here. It is a build-time tool only — the site ships with no '
    + 'dependencies. Run this from a directory that has it installed, or set PLAYWRIGHT=/path/to/node_modules/x.js'
  );
})();
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'
});
const page = await browser.newPage({ viewport: { width: W, height: H } });
await page.setContent(`<body style="margin:0"><canvas id="c" width="${W}" height="${H}"></canvas></body>`);
await page.evaluate(`window.__scene = ${SCENE}`);
// The captured output crosses into the page once, not once per frame — 200
// lines of text serialised 192 times is the difference between a render that
// takes two minutes and one that takes ten.
await page.evaluate(([lines, folders]) => {
  window.__lines = lines;
  window.__folders = folders;
}, [LINES, FOLDERS]);

mkdirSync(dirname(OUT), { recursive: true });
const ff = spawn(FFMPEG, [
  '-y',
  // `pipe:0`, not `-`. This ffmpeg is built with --disable-everything and an
  // explicit protocol allowlist, so the usual `-` shorthand resolves to no
  // protocol at all and it exits with "Protocol not found" before reading a
  // byte. Naming the protocol is the whole fix.
  '-f', 'image2pipe', '-c:v', 'mjpeg', '-r', String(FPS), '-i', 'pipe:0',
  '-c:v', 'libvpx', '-b:v', '1400k', '-crf', '32',
  '-auto-alt-ref', '0',
  '-pix_fmt', 'yuv420p',
  OUT
], { stdio: ['pipe', 'ignore', 'pipe'] });

// Keep ffmpeg's last words. If it exits early — a codec it does not have, a
// frame format it cannot read, a protocol it was not built with — every
// subsequent write lands on a dead pipe and the render stalls forever with no
// explanation. Holding the tail of stderr turns that silent hang into a
// message worth reading.
let ffErr = '';
ff.stderr.on('data', (b) => { ffErr = (ffErr + b).slice(-4000); });
let ffDead = null;
let ffClosed = false;
let ffCode = null;
ff.on('error', (e) => { ffDead = e; ffClosed = true; });
ff.on('close', (code) => {
  ffClosed = true;
  ffCode = code;
  if (code !== 0 && !ffDead) ffDead = new Error(`ffmpeg exited ${code}`);
});
ff.stdin.on('error', () => { /* reported through ffDead instead */ });

process.stdout.write(`rendering ${FRAMES} frames at ${W}x${H}… `);
for (let f = 0; f < FRAMES; f++) {
  if (ffClosed) break;
  const t = f / FRAMES;                     // [0,1) — closes the loop exactly
  const dataUrl = await page.evaluate(([tt]) => {
    window.__scene(window.innerWidth, window.innerHeight, tt, window.__lines, window.__folders);
    return document.getElementById('c').toDataURL('image/jpeg', 0.92);
  }, [t]);
  const jpeg = Buffer.from(dataUrl.slice(dataUrl.indexOf(',') + 1), 'base64');
  if (!ff.stdin.write(jpeg) && !ffClosed) {
    // Race the drain against the exit. The `ffClosed` guard above matters:
    // `once('close')` on a process that has ALREADY closed never fires, so
    // without it a dead encoder parks this await forever — which is exactly
    // how the protocol bug above presented, as a hang rather than an error.
    // Both listeners come off whichever way it resolves; leaving the loser
    // attached leaks one per backpressured frame.
    await new Promise((resolve) => {
      const done = () => { ff.stdin.off('drain', done); ff.off('close', done); resolve(); };
      ff.stdin.once('drain', done);
      ff.once('close', done);
    });
  }
  if (f % 20 === 0) process.stdout.write('.');
}
ff.stdin.end();
if (!ffClosed) await new Promise((resolve) => ff.on('close', resolve));
await browser.close();

if (ffDead || ffCode !== 0) {
  console.error(`\nffmpeg failed: ${ffDead?.message ?? `exit ${ffCode}`}\n${ffErr}`);
  process.exit(1);
}
const { statSync } = await import('node:fs');
console.log(`\nwrote ${OUT} — ${(statSync(OUT).size / 1024).toFixed(0)} kB, ${FRAMES} frames, ${SECONDS}s loop`);
