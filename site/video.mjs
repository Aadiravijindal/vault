#!/usr/bin/env node
/**
 * Generates site/hero.webm — the looping background footage behind the hero.
 *
 *   node site/video.mjs                 # 1280x720, 24fps, 8s loop
 *   node site/video.mjs --w 960 --h 540 --seconds 6
 *
 * ── WHY THIS IS GENERATED AND NOT SHOT ──────────────────────────────────────
 *
 * The footage IS the product: packets of memory streaming in from the left,
 * hitting the gate, most passing and turning orange, a few flashing red and
 * dying at the wall. Stock footage of a server room says nothing. This says
 * exactly what Vault does, in eight seconds, with no narration.
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
import { writeFileSync, mkdirSync } from 'node:fs';
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

/**
 * The scene, as a string evaluated inside the page.
 *
 * Everything is a function of `t` in [0,1) — never of a frame counter or a
 * clock — which is what makes the loop seamless: at t=1 every position, phase
 * and offset is back where it was at t=0.
 */
const SCENE = `(W, H, t) => {
  const c = document.getElementById('c').getContext('2d');
  const TAU = Math.PI * 2;
  // The gate sits off-centre on purpose. Centred, it lands directly behind the
  // headline, where the scrim is darkest — the one element that carries the
  // whole idea would be the one element nobody can see.
  const GATE = W * 0.31;

  // deterministic pseudo-random, so every run produces the same footage
  const rnd = (i) => { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };

  c.fillStyle = '#050201';
  c.fillRect(0, 0, W, H);

  // ---- far field: a slow node lattice, breathing ----------------------
  c.save();
  c.globalAlpha = 0.5;
  for (let i = 0; i < 90; i++) {
    const x = rnd(i) * W;
    const y = rnd(i + 500) * H;
    const ph = rnd(i + 900);
    const pulse = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin((t + ph) * TAU * 2));
    c.fillStyle = 'rgba(255,120,40,' + (0.05 + 0.14 * pulse) + ')';
    c.beginPath();
    c.arc(x, y, 1.1 + 1.5 * pulse, 0, TAU);
    c.fill();
  }
  c.restore();

  // ---- perspective floor ----------------------------------------------
  c.save();
  c.strokeStyle = 'rgba(255,132,52,.34)';
  c.lineWidth = 1;
  const horizon = H * 0.62;
  for (let i = 0; i < 26; i++) {
    // rows accelerate towards the viewer; the +t makes them travel
    const p = ((i + t) % 26) / 26;
    const y = horizon + Math.pow(p, 2.6) * (H - horizon) * 1.9;
    if (y > H) continue;
    c.globalAlpha = Math.min(1, p * 2.2) * 0.8;
    c.beginPath(); c.moveTo(0, y); c.lineTo(W, y); c.stroke();
  }
  c.globalAlpha = 0.5;
  for (let i = -14; i <= 14; i++) {
    c.beginPath();
    c.moveTo(W / 2 + i * 18, horizon);
    c.lineTo(W / 2 + i * 210, H);
    c.stroke();
  }
  c.restore();

  // ---- the gate: a vertical wall of light ------------------------------
  const gateGlow = c.createLinearGradient(GATE - 130, 0, GATE + 130, 0);
  gateGlow.addColorStop(0, 'rgba(255,106,19,0)');
  gateGlow.addColorStop(0.5, 'rgba(255,140,43,' + (0.3 + 0.1 * Math.sin(t * TAU * 3)) + ')');
  gateGlow.addColorStop(1, 'rgba(255,106,19,0)');
  c.fillStyle = gateGlow;
  c.fillRect(GATE - 130, 0, 260, H);

  // the wall itself: a bright core with a soft bloom either side of it
  c.save();
  c.shadowColor = 'rgba(255,150,60,.95)'; c.shadowBlur = 26;
  c.strokeStyle = 'rgba(255,214,176,.95)';
  c.lineWidth = 2.5;
  c.beginPath(); c.moveTo(GATE, 0); c.lineTo(GATE, H); c.stroke();
  c.restore();

  // ten check marks along the gate, lighting in sequence — the ten checks
  for (let i = 0; i < 10; i++) {
    const y = (H / 11) * (i + 1);
    const lit = (Math.sin((t * 2 - i / 14) * TAU) + 1) / 2;
    c.save();
    c.shadowColor = 'rgba(255,166,77,.9)'; c.shadowBlur = 8 + 14 * lit;
    c.fillStyle = 'rgba(255,196,130,' + (0.35 + 0.65 * lit) + ')';
    c.fillRect(GATE - 15, y - 2, 30, 4);
    c.restore();
  }

  // ---- packets: memory arriving, being judged --------------------------
  const N = 58;
  for (let i = 0; i < N; i++) {
    const lane = rnd(i + 20);
    const y = 40 + lane * (H - 80);
    const speed = 0.55 + rnd(i + 40) * 0.75;
    const phase = rnd(i + 60);
    // position cycles once per loop, so the field is seamless
    const p = ((t * speed + phase) % 1);
    const x = p * (W + 260) - 130;

    // one in six is refused at the wall
    const blocked = rnd(i + 80) > 0.83;
    const crossed = x > GATE;

    if (blocked && crossed) {
      // died at the gate: a red flare and an expanding ring, gone within 90px
      const d = (x - GATE) / 90;
      if (d > 1) continue;
      const a = (1 - d) * 0.95;
      c.save();
      c.shadowColor = 'rgba(255,60,60,.95)'; c.shadowBlur = 26;
      c.fillStyle = 'rgba(255,96,96,' + a + ')';
      c.beginPath(); c.arc(GATE, y, 3 + 10 * d, 0, TAU); c.fill();
      c.strokeStyle = 'rgba(255,120,120,' + a * 0.7 + ')';
      c.lineWidth = 1.5;
      c.beginPath(); c.arc(GATE, y, 6 + 26 * d, 0, TAU); c.stroke();
      c.restore();
      continue;
    }

    const len = 16 + rnd(i + 100) * 30;
    const g = c.createLinearGradient(x - len, y, x, y);
    if (crossed) {
      g.addColorStop(0, 'rgba(255,140,43,0)');
      g.addColorStop(1, 'rgba(255,190,120,.95)');
    } else {
      g.addColorStop(0, 'rgba(190,190,200,0)');
      g.addColorStop(1, 'rgba(225,225,235,.6)');
    }
    c.fillStyle = g;
    c.fillRect(x - len, y - 1.1, len, 2.2);

    c.fillStyle = crossed ? 'rgba(255,205,150,.95)' : 'rgba(240,240,248,.75)';
    c.shadowColor = crossed ? 'rgba(255,140,43,.9)' : 'rgba(200,210,255,.5)';
    c.shadowBlur = crossed ? 14 : 8;
    c.beginPath(); c.arc(x, y, crossed ? 2.4 : 1.9, 0, TAU); c.fill();
    c.shadowBlur = 0;
  }

  // ---- a scan sweep, and scanlines -------------------------------------
  const sweepY = ((t * 2) % 1) * (H + 300) - 150;
  const sweep = c.createLinearGradient(0, sweepY - 150, 0, sweepY + 150);
  sweep.addColorStop(0, 'rgba(255,140,43,0)');
  sweep.addColorStop(0.5, 'rgba(255,166,77,.10)');
  sweep.addColorStop(1, 'rgba(255,140,43,0)');
  c.fillStyle = sweep;
  c.fillRect(0, sweepY - 150, W, 300);

  c.fillStyle = 'rgba(0,0,0,.16)';
  for (let y = 0; y < H; y += 3) c.fillRect(0, y, W, 1);

  // ---- vignette, so the type on top always has ground ------------------
  // Lighter than it looks like it should be: the page lays its own scrim over
  // this, and two stacked vignettes turn the footage into a brown smear.
  const v = c.createRadialGradient(W / 2, H / 2, H * 0.3, W / 2, H / 2, W * 0.78);
  v.addColorStop(0, 'rgba(5,2,1,0)');
  v.addColorStop(1, 'rgba(5,2,1,.7)');
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
    window.__scene(window.innerWidth, window.innerHeight, tt);
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
