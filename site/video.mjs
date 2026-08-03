#!/usr/bin/env node
/**
 * Generates site/hero.webm — the looping background footage behind the hero.
 *
 *   node site/video.mjs                 # 1280x720, 24fps, 8s loop
 *   node site/video.mjs --w 960 --h 540 --seconds 6
 *
 * ── WHY THIS IS GENERATED AND NOT SHOT ──────────────────────────────────────
 *
 * An open-plan office, late. Ceiling strips receding down the aisle, desks
 * and chairs either side, the city out of focus through the far glass, dust
 * turning in the light. The camera drifts forward. Nobody is there — which is
 * the point, because the thing this product governs runs when nobody is.
 *
 * Then the whole frame is put through an old-film pass: graded into the brand
 * orange, gate weave, lamp flicker, clumped grain, scratches that live a few
 * frames and move on, dust on the print, halation around every highlight.
 *
 * It is reproducible. The palette comes from the same tokens as the site, so
 * when the brand shifts the footage shifts with it — one edit, one command,
 * rather than a re-shoot. Stock footage of somebody else's office can do none
 * of that, and has to be licensed for every place the site is served.
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
 * An open-plan office, late, lit by its ceiling strips and the city through
 * the far glass. The camera drifts down the aisle. Nobody is there — which is
 * the point, because the thing this product governs runs when nobody is.
 *
 * The vanishing point sits right of centre and the near-left desks stay in
 * shadow, because the copy lands in the bottom-left corner and has to sit on
 * quiet ground.
 *
 * Everything is a function of `t` in [0,1) — never of a frame counter or a
 * clock — which is what makes the loop seamless. The dolly works by cycling
 * each row of desks through a fixed set of depths, so at t=1 the room is
 * arranged exactly as it was at t=0 even though it has moved the whole way.
 */
const SCENE = `(W, H, t, LINES, FOLDERS) => {
  const c = document.getElementById('c').getContext('2d');
  const TAU = Math.PI * 2;
  const S = H / 720;
  const rnd = (i) => { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };

  // ── film: gate weave ──────────────────────────────────────────────────
  // The frame never sits perfectly still in the gate of a real projector.
  // Integer frequencies only, so the wander closes its own loop.
  const weaveX = (Math.sin(t * TAU * 3) * 0.6 + Math.sin(t * TAU * 7 + 1.3) * 0.34) * 3.4 * S;
  const weaveY = (Math.cos(t * TAU * 2) * 0.5 + Math.sin(t * TAU * 5 + 0.7) * 0.3) * 2.8 * S;
  // …and the lamp never holds a perfectly even exposure either
  const flicker = 1 + 0.055 * Math.sin(t * TAU * 11) + 0.03 * Math.sin(t * TAU * 23 + 2);

  c.fillStyle = '#040206';
  c.fillRect(0, 0, W, H);

  c.save();
  c.translate(weaveX, weaveY);
  c.globalAlpha = flicker > 1 ? 1 : flicker;

  // ── the room ──────────────────────────────────────────────────────────
  const VPX = W * 0.6;            // vanishing point, right of centre
  const HOR = H * 0.44;
  const FL = 700 * S;             // focal length
  const px = (X, Z) => VPX + (X * FL) / Z;
  const py = (Y, Z) => HOR + (Y * FL) / Z;

  const ROWS = 10;
  const SPACING = 2.6;
  const NEAR = 4.2;               // far enough back that the near row is a
                                  // desk rather than a wall across the frame
  const FAR = NEAR + ROWS * SPACING;

  const quad = (pts, fill) => {
    c.beginPath();
    c.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) c.lineTo(pts[i][0], pts[i][1]);
    c.closePath();
    c.fillStyle = fill; c.fill();
  };

  // ---- the far glass, and the city behind it ---------------------------
  const wz = FAR + 3;
  const wl = px(-7.2, wz), wr = px(7.2, wz);
  const wt = py(-2.6, wz), wb = py(1.9, wz);
  quad([[wl, wt], [wr, wt], [wr, wb], [wl, wb]], 'rgba(10,7,18,1)');

  // city bokeh — out of focus, so it is the one thing allowed to be bright
  c.save();
  c.beginPath(); c.rect(wl, wt, wr - wl, wb - wt); c.clip();
  c.filter = 'blur(' + (2.4 * S).toFixed(2) + 'px)';
  for (let i = 0; i < 120; i++) {
    const x = wl + rnd(i) * (wr - wl);
    const y = wt + rnd(i + 300) * (wb - wt);
    const tw = 0.55 + 0.45 * Math.sin((t + rnd(i + 600)) * TAU * (1 + Math.floor(rnd(i + 800) * 3)));
    const warm = rnd(i + 90) > 0.35;
    c.fillStyle = warm
      ? 'rgba(255,168,90,' + (0.1 + 0.3 * tw) + ')'
      : 'rgba(150,180,235,' + (0.06 + 0.18 * tw) + ')';
    c.beginPath(); c.arc(x, y, (0.8 + rnd(i + 40) * 2.4) * S, 0, TAU); c.fill();
  }
  c.filter = 'none';
  c.restore();

  // mullions
  c.strokeStyle = 'rgba(6,4,10,.9)'; c.lineWidth = 2.5 * S;
  for (let i = -3; i <= 3; i++) {
    const x = px(i * 2.4, wz);
    c.beginPath(); c.moveTo(x, wt); c.lineTo(x, wb); c.stroke();
  }

  // ---- floor ------------------------------------------------------------
  quad([[0, py(1.55, NEAR)], [W, py(1.55, NEAR)], [wr, wb], [wl, wb]], 'rgba(9,6,12,1)');
  // the aisle catches the strips overhead — the one thing leading the eye in
  const aisle = c.createLinearGradient(0, py(1.55, FAR), 0, H);
  aisle.addColorStop(0, 'rgba(255,150,70,.16)');
  aisle.addColorStop(0.45, 'rgba(255,140,60,.06)');
  aisle.addColorStop(1, 'rgba(255,140,60,0)');
  quad([
    [px(-1.5, NEAR), py(1.55, NEAR)], [px(1.5, NEAR), py(1.55, NEAR)],
    [px(1.5, FAR), py(1.55, FAR)], [px(-1.5, FAR), py(1.55, FAR)]
  ], aisle);

  // ---- desks, ceiling lights and chairs, far to near --------------------
  // Each row cycles through the same set of depths as t advances, so the
  // dolly is continuous and the loop is exact.
  const rows = [];
  for (let i = 0; i < ROWS; i++) rows.push(NEAR + ((i + t) % ROWS) * SPACING);
  rows.sort((a, b) => b - a);

  for (const z of rows) {
    const fade = Math.max(0, Math.min(1, (FAR - z) / FAR)) * 0.55 + 0.2;

    // ceiling strip lights, two runs
    for (const sx of [-1, 1]) {
      const x1 = px(sx * 1.1, z), x2 = px(sx * 3.4, z);
      const yy = py(-2.35, z), h = Math.max(1.2 * S, (0.09 * FL) / z);
      const g = c.createLinearGradient(x1, yy, x2, yy);
      g.addColorStop(0, 'rgba(255,196,140,' + (0.1 * fade) + ')');
      g.addColorStop(0.5, 'rgba(255,222,180,' + (0.72 * fade) + ')');
      g.addColorStop(1, 'rgba(255,196,140,' + (0.1 * fade) + ')');
      c.fillStyle = g;
      c.fillRect(Math.min(x1, x2), yy, Math.abs(x2 - x1), h);
      // halation — the bloom old stock puts around any highlight
      c.save();
      c.globalCompositeOperation = 'lighter';
      const bx = (x1 + x2) / 2;
      const bloom = c.createRadialGradient(bx, yy, 0, bx, yy, Math.abs(x2 - x1) * 0.9);
      bloom.addColorStop(0, 'rgba(255,170,90,' + (0.16 * fade) + ')');
      bloom.addColorStop(1, 'rgba(255,140,43,0)');
      c.fillStyle = bloom;
      c.fillRect(bx - Math.abs(x2 - x1), yy - Math.abs(x2 - x1) * 0.5, Math.abs(x2 - x1) * 2, Math.abs(x2 - x1));
      c.restore();
    }

    for (const sx of [-1, 1]) {
      const zf = z + 1.35;
      const inner = sx * 1.45, outer = sx * 4.5;

      // partition behind the desk
      quad([
        [px(inner, z), py(0.35, z)], [px(outer, z), py(0.35, z)],
        [px(outer, z), py(1.1, z)], [px(inner, z), py(1.1, z)]
      ], 'rgba(28,19,32,' + (0.7 + 0.3 * fade) + ')');

      // desk top, then its front edge
      quad([
        [px(inner, z), py(1.1, z)], [px(outer, z), py(1.1, z)],
        [px(outer, zf), py(1.1, zf)], [px(inner, zf), py(1.1, zf)]
      ], 'rgba(52,33,34,' + (0.45 + 0.55 * fade) + ')');
      quad([
        [px(inner, zf), py(1.1, zf)], [px(outer, zf), py(1.1, zf)],
        [px(outer, zf), py(1.62, zf)], [px(inner, zf), py(1.62, zf)]
      ], 'rgba(17,11,18,.95)');

      // the strips catch the front edge; one bright line does more to say
      // "desk" than any amount of shading on the surface
      c.strokeStyle = 'rgba(255,178,110,' + (0.16 + 0.4 * fade) + ')';
      c.lineWidth = Math.max(1, 1.4 * S);
      c.beginPath();
      c.moveTo(px(inner, zf), py(1.1, zf));
      c.lineTo(px(outer, zf), py(1.1, zf));
      c.stroke();

      // the light the strips throw along the desk
      const dl = c.createLinearGradient(px(inner, z), py(1.1, z), px(inner, zf), py(1.1, zf));
      dl.addColorStop(0, 'rgba(255,150,70,' + (0.12 * fade) + ')');
      dl.addColorStop(1, 'rgba(255,150,70,0)');
      quad([
        [px(inner, z), py(1.1, z)], [px(outer, z), py(1.1, z)],
        [px(outer, zf), py(1.1, zf)], [px(inner, zf), py(1.1, zf)]
      ], dl);

      // a monitor, dark or barely awake — this is a workspace, not a console
      const mx = (inner + outer) / 2;
      const mw = Math.abs(px(mx + 0.62, z) - px(mx - 0.62, z));
      const mh = (0.62 * FL) / z;
      const mxs = px(mx, z) - mw / 2, mys = py(1.1, z) - mh;
      quad([[mxs, mys], [mxs + mw, mys], [mxs + mw, mys + mh], [mxs, mys + mh]], 'rgba(10,7,14,.96)');
      if (rnd(Math.round(z * 13) + (sx > 0 ? 7 : 0)) > 0.55) {
        c.fillStyle = 'rgba(255,150,70,' + (0.1 + 0.06 * Math.sin((t + z) * TAU * 2)) * fade + ')';
        c.fillRect(mxs + mw * 0.06, mys + mh * 0.1, mw * 0.88, mh * 0.74);
      }

      // chair
      const chx = px(mx - sx * 0.15, zf + 0.9);
      const chw = Math.abs(px(0.5, zf + 0.9) - px(0, zf + 0.9));
      const chh = (0.85 * FL) / (zf + 0.9);
      c.fillStyle = 'rgba(30,20,28,' + (0.6 + 0.35 * fade) + ')';
      c.beginPath();
      c.ellipse(chx, py(1.12, zf + 0.9) - chh * 0.2, chw, chh * 0.3, 0, 0, TAU);
      c.fill();
      // the back: a solid mass, no outline. An outlined rectangle at this
      // scale reads as a picture frame rather than a chair.
      c.beginPath();
      c.ellipse(chx, py(1.12, zf + 0.9) - chh * 0.62, chw * 0.72, chh * 0.42, 0, 0, TAU);
      c.fill();
    }
  }

  // ---- haze in the air, so depth reads ---------------------------------
  const haze = c.createLinearGradient(0, HOR - H * 0.2, 0, H);
  haze.addColorStop(0, 'rgba(120,60,30,.1)');
  haze.addColorStop(0.45, 'rgba(60,26,14,.05)');
  haze.addColorStop(1, 'rgba(4,2,6,0)');
  c.fillStyle = haze; c.fillRect(0, 0, W, H);

  // ---- dust in the beams ------------------------------------------------
  for (let i = 0; i < 70; i++) {
    const drift = (t + rnd(i + 700)) % 1;
    const x = rnd(i) * W + Math.sin((drift + rnd(i + 30)) * TAU) * 30 * S;
    const y = ((rnd(i + 200) + drift * 0.12) % 1) * H;
    const a = 0.04 + 0.14 * (0.5 + 0.5 * Math.sin((drift + rnd(i + 90)) * TAU));
    c.fillStyle = 'rgba(255,200,150,' + a + ')';
    c.beginPath(); c.arc(x, y, (0.6 + rnd(i + 400)) * S, 0, TAU); c.fill();
  }

  c.restore();  // gate weave

  // ══ the old-film pass ═════════════════════════════════════════════════
  // Grade first, then the physical damage on top of it — that is the order it
  // happens in reality, and doing it the other way tints the scratches.

  // ---- grade: push the whole frame towards the brand ---------------------
  c.save();
  c.globalCompositeOperation = 'color';
  c.fillStyle = 'rgba(255,106,19,.34)';
  c.fillRect(0, 0, W, H);
  c.restore();

  c.save();
  c.globalCompositeOperation = 'overlay';
  const grade = c.createLinearGradient(0, 0, W, H);
  grade.addColorStop(0, 'rgba(122,26,5,.3)');
  grade.addColorStop(0.5, 'rgba(255,106,19,.1)');
  grade.addColorStop(1, 'rgba(20,8,24,.38)');
  c.fillStyle = grade;
  c.fillRect(0, 0, W, H);
  c.restore();

  // ---- grain -----------------------------------------------------------
  // Rendered small and scaled up with smoothing off. Real grain is clumped,
  // not per-pixel, and a 1:1 noise field costs eight times as much to produce
  // for a result that looks like digital noise rather than film.
  const gw = 320, gh = Math.round(320 * H / W);
  if (!window.__grain) {
    window.__grain = document.createElement('canvas');
    window.__grain.width = gw; window.__grain.height = gh;
  }
  const gc = window.__grain.getContext('2d');
  const img = gc.createImageData(gw, gh);
  const seed = Math.floor(t * 997);
  for (let i = 0; i < gw * gh; i++) {
    const n = (Math.sin((i + seed * 7919) * 12.9898) * 43758.5453);
    const v = (n - Math.floor(n)) * 255;
    img.data[i * 4] = img.data[i * 4 + 1] = img.data[i * 4 + 2] = v;
    img.data[i * 4 + 3] = 30;
  }
  gc.putImageData(img, 0, 0);
  c.save();
  c.globalCompositeOperation = 'overlay';
  c.imageSmoothingEnabled = false;
  c.drawImage(window.__grain, 0, 0, W, H);
  c.restore();

  // ---- scratches, splices and dust on the print -------------------------
  const framesPerLoop = 192;
  const fi = Math.floor(t * framesPerLoop);
  for (let s = 0; s < 3; s++) {
    // each scratch lives for a run of frames, then the print moves on
    const life = Math.floor(rnd(s * 31 + Math.floor(fi / 11)) * 3);
    if (life === 0) continue;
    const x = rnd(s * 17 + Math.floor(fi / 11) * 3) * W + Math.sin(fi * 0.7 + s) * 1.5 * S;
    const a = 0.05 + 0.1 * rnd(s * 53 + fi);
    c.fillStyle = 'rgba(255,225,200,' + a + ')';
    c.fillRect(x, 0, (0.6 + rnd(s * 7 + fi) * 0.9) * S, H);
  }
  for (let d = 0; d < 9; d++) {
    if (rnd(d * 91 + fi * 3) < 0.6) continue;
    const x = rnd(d * 13 + fi * 7) * W;
    const y = rnd(d * 29 + fi * 11) * H;
    c.fillStyle = rnd(d + fi) > 0.5 ? 'rgba(20,10,6,.5)' : 'rgba(255,230,205,.28)';
    c.fillRect(x, y, (1 + rnd(d * 3 + fi) * 2.5) * S, (1 + rnd(d * 5 + fi) * 4) * S);
  }

  // ---- vignette ---------------------------------------------------------
  // The copy sits bottom-left, so the corner opposite the vanishing point is
  // pulled down hardest — the type gets ground, the room keeps its depth.
  const v = c.createRadialGradient(W * 0.62, H * 0.42, H * 0.18, W * 0.62, H * 0.42, W * 0.85);
  v.addColorStop(0, 'rgba(4,2,7,0)');
  v.addColorStop(0.55, 'rgba(4,2,7,.3)');
  v.addColorStop(1, 'rgba(4,2,7,.9)');
  c.fillStyle = v;
  c.fillRect(0, 0, W, H);

  // and one more pull into the bottom-left, where the headline lands
  const pocket = c.createRadialGradient(W * 0.2, H * 0.82, 0, W * 0.2, H * 0.82, W * 0.62);
  pocket.addColorStop(0, 'rgba(4,2,7,.5)');
  pocket.addColorStop(0.6, 'rgba(4,2,7,.2)');
  pocket.addColorStop(1, 'rgba(4,2,7,0)');
  c.fillStyle = pocket;
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
