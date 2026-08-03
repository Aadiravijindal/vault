/**
 * The marketing site.
 *
 * No browser here on purpose — Playwright is not a dependency of this project
 * and `npm test` has to run from a fresh clone with nothing installed. So this
 * checks what can be checked from the source: that the approved copy is on the
 * page, that the brand colours clear WCAG AA by calculation rather than by eye,
 * that the mark in the HTML is still the one the generator produces, and that
 * every animated background stays behind the content and can be switched off.
 *
 * Two things here need pixels, and were measured in a real browser rather than
 * asserted from source:
 *
 *   · white on the bare hero footage fell to 2.24:1 behind the right of the
 *     headline — under the 3:1 that AA asks of large text — which is why the
 *     scrim exists. With it, the worst of 135 samples across three viewports
 *     is 8.93:1.
 *   · the mark's proportions were measured off the supplied artwork's 437x477
 *     bounding box, which pins R_HEX and R_OUTER exactly; see mark.mjs.
 *
 * Both are recorded here because they are the reason the hero and the logo
 * look the way they do, and because nothing in a source-only test can catch
 * them regressing.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { MARK_PATH } from '../site/mark.mjs';

const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../site/styles.css', import.meta.url), 'utf8');
const js = readFileSync(new URL('../site/app.js', import.meta.url), 'utf8');
/** Copy as a reader sees it: tags gone, whitespace collapsed. */
const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

// --- WCAG contrast, computed rather than eyeballed --------------------------
const hex = (h) => { const s = h.replace('#', ''); return [0, 2, 4].map((i) => parseInt(s.slice(i, i + 2), 16)); };
const lum = (c) => {
  const s = hex(c).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * s[0] + 0.7152 * s[1] + 0.0722 * s[2];
};
const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

function tokens() {
  const root = css.slice(css.indexOf(':root{'), css.indexOf('}', css.indexOf(':root{')));
  const out = {};
  for (const m of root.matchAll(/--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})/g)) out[m[1]] = m[2];
  return out;
}

/** The opening tag that carries a given class, for checking its attributes. */
function tagWithClass(cls) {
  const at = html.indexOf(`class="${cls}"`);
  if (at < 0) return null;
  return html.slice(html.lastIndexOf('<', at), html.indexOf('>', at) + 1);
}

describe('the page says what it promises to say', () => {
  test('the headline and the three sentences under it are exact', () => {
    // Matched against the rendered text, not the markup, so a line break or a
    // wrapping span cannot silently change the approved copy.
    assert.match(text, /The governed memory layer for enterprise AI\./);
    assert.match(text, /Every AI agent in your company reads from one memory\./);
    assert.match(text, /Nothing enters without being checked\./);
    assert.match(text, /Everything is traced, sealed, and provable\./);
  });

  test('the headline reads as one sentence even though it is broken over two lines', () => {
    // <br> is a line break, not a word break. Without the glitch layer's
    // data-text carrying the unbroken sentence the effect would render the
    // wrap as part of the copy.
    const h1 = html.slice(html.indexOf('<h1'), html.indexOf('</h1>'));
    assert.match(h1, /data-text="The governed memory layer for enterprise AI\."/,
      'the glitch layers are drawn from data-text; it must hold the approved line verbatim');
  });

  test('the numbers on the page match the product', () => {
    // A marketing claim nobody re-checks is wrong the first time the product
    // changes. These are the ones with a number in them.
    assert.match(text, /\b74\b/, '74 connectors');
    assert.match(text, /576 adversarial cases/);
    assert.match(text, /\b932\b/, 'the test count');
    assert.match(text, /p50 80ms/);
    assert.match(text, /ten checks|10 checks/i);
  });

  test('the honest section is still on the page', () => {
    assert.match(text, /What Vault does not do/i,
      'the limits section is the most persuasive thing here; it must not get quietly dropped');
    assert.match(text, /does not prove a fact is true/);
    assert.match(text, /does not catch every attack/);
  });

  test('the partner is named, not implied', () => {
    assert.match(text, /The University of Hong Kong/);
    assert.match(html, /id="partners"/);
    assert.match(text, /HKU/);
  });

  test('every section the nav points at exists', () => {
    const targets = [...html.matchAll(/href="#([a-z-]+)"/g)].map((m) => m[1]);
    for (const id of new Set(targets)) {
      assert.match(html, new RegExp(`id="${id}"`), `nav points at #${id}, which is not on the page`);
    }
  });
});

describe('the header', () => {
  test('menu on one side, mark in the middle, contact on the other', () => {
    const bar = html.slice(html.indexOf('<header'), html.indexOf('</header>'));
    const order = ['menu-btn', 'brandmark', 'contact-btn'].map((c) => bar.indexOf(c));
    assert.ok(order.every((i) => i >= 0), 'all three header items must be present');
    assert.deepEqual([...order].sort((a, b) => a - b), order,
      'source order is menu, mark, contact — the grid centres the middle column');

    // Three columns with the outer two equal is what actually centres the mark
    // on the viewport rather than between two items of different widths.
    const rule = css.slice(css.indexOf('.topbar{'), css.indexOf('}', css.indexOf('.topbar{')));
    assert.match(rule, /grid-template-columns:1fr auto 1fr/,
      'equal outer columns, or the mark sits off-centre by half the width difference');
  });

  test('the menu button says what it controls', () => {
    const btn = html.slice(html.indexOf('<button class="menu-btn"'), html.indexOf('</button>'));
    assert.match(btn, /aria-expanded="false"/);
    assert.match(btn, /aria-controls="drawer"/);
    assert.match(html, /id="drawer"/);
  });

  test('nothing sits above the headline but the status badge', () => {
    // Explicitly asked for: no logo over "The governed memory layer…".
    const heroInner = html.slice(html.indexOf('<div class="hero-inner">'), html.indexOf('<h1'));
    assert.ok(!/<use href="#mark">/.test(heroInner),
      'the mark must not reappear above the headline — it is in the header and nowhere else up there');
    assert.match(heroInner, /class="kicker"/);
  });
});

describe('brand colour clears WCAG AA by calculation', () => {
  test('every text token passes against every section ground', () => {
    const t = tokens();
    const failures = [];
    for (const ground of ['black', 'black-2', 'black-3']) {
      for (const name of ['ink', 'ink-2', 'muted', 'orange', 'orange-2']) {
        const r = contrast(t[name], t[ground]);
        if (r < 4.5) failures.push(`--${name} ${t[name]} on --${ground} ${t[ground]} is ${r.toFixed(2)}:1`);
      }
    }
    assert.deepEqual(failures, [], 'a brand colour that fails AA is a brand colour that has to change');
  });

  test('cyan is chrome, never real text', () => {
    // It is the one colour here that would pass a contrast check and still be
    // wrong: two saturated colours competing means neither leads. It is allowed
    // on the glitch layer, which is a chromatic-aberration copy on a
    // pseudo-element, clipped out of sight for all but a few frames in five
    // seconds — and never the copy a reader or a screen reader gets.
    const t = tokens();
    assert.ok(t.cyan, '--cyan should exist');
    for (const m of css.matchAll(/([^{}]+)\{[^{}]*color:var\(--cyan\)/g)) {
      assert.match(m[1], /::(before|after)/,
        `--cyan sets the colour of "${m[1].trim()}", which is a real element — `
        + 'cyan is for grid lines and machine chrome only');
    }
  });

  test('the stylesheet documents the ratios it claims', () => {
    assert.match(css, /18\.9:1/);
    assert.match(css, /6\.9:1/);
    assert.match(css, /2\.24:1/, 'the measured hero failure is why the scrim exists');
  });
});

describe('the mistake this palette invites', () => {
  test('button text on orange is dark, never white', () => {
    const t = tokens();
    assert.ok(contrast('#ffffff', t.orange) < 3,
      'white on this orange is about 2.9:1 — the reason the rule below exists');
    const btn = css.slice(css.indexOf('.btn{'), css.indexOf('}', css.indexOf('.btn{')));
    const colour = btn.match(/color:(#[0-9a-fA-F]{6})/)?.[1];
    assert.ok(colour, 'the primary button must set its own text colour');
    assert.ok(contrast(colour, t.orange) >= 4.5, `button text ${colour} on --orange is too low`);
  });
});

describe('the mark', () => {
  test('the path in the page is the one the generator produces', () => {
    // The geometry is solved in site/mark.mjs. If somebody nudges the path by
    // hand the two drift apart silently, and the favicon, the header and the
    // footer stop being the same shape.
    assert.ok(html.includes(MARK_PATH), 'site/index.html no longer matches `node site/mark.mjs`');
  });

  test('the favicon is the same geometry, not a redraw', () => {
    const icon = html.match(/rel="icon" href="([^"]+)"/)?.[1];
    assert.ok(icon, 'there should be an inline favicon — one request fewer, and no 404 in the log');
    assert.ok(decodeURIComponent(icon).includes(MARK_PATH),
      'the favicon must carry the generated path, or the tab shows a different logo from the page');
  });

  test('the geometry lives in exactly one place', () => {
    assert.equal((html.match(/<symbol id="mark"/g) ?? []).length, 1);
    assert.ok((html.match(/<use href="#mark">/g) ?? []).length >= 2, 'every other use references it');
  });

  test('it inherits colour instead of hard-coding white', () => {
    const symbol = html.slice(html.indexOf('<symbol id="mark"'), html.indexOf('</symbol>'));
    assert.match(symbol, /fill="currentColor"/);
    assert.ok(!/#fff/i.test(symbol), 'the mark must recolour on hover and in any context');
  });

  test('the necks are concave — the fillets are real arcs, not straight bars', () => {
    // A metaball neck is an arc sweeping the opposite way to the blob it joins.
    // If somebody replaces the path with circles and rectangles this fails, and
    // the mark stops being the brand.
    // 16 for this topology: a 2-blob chain is 4 arcs (two necks, two outer
    // caps), a 3-blob chain is 8, and there are two of the former and one of
    // the latter.
    const arcs = MARK_PATH.match(/A[\d.]+ [\d.]+ 0 [01] [01]/g) ?? [];
    assert.equal(arcs.length, 16, 'the outline should be made of arcs throughout');
    assert.ok(arcs.some((a) => a.endsWith('0')) && arcs.some((a) => a.endsWith('1')),
      'both sweep directions must appear, or nothing is concave');
    assert.ok(!/[LlHhVv]/.test(MARK_PATH), 'no straight segments — every join is a fillet');
  });

  test('the proportions are the ones measured from the artwork', () => {
    // Derived, not tuned: the supplied logo's 437x477 bounding box pins R_HEX
    // and R_OUTER for a hexagon with a vertex at twelve o'clock, and its neck
    // is ~11% of an outer blob's diameter, which pins the fillet.
    const src = readFileSync(new URL('../site/mark.mjs', import.meta.url), 'utf8');
    const konst = (name) => src.match(new RegExp(`const ${name}\\s*=\\s*([\\d.]+)`))?.[1];
    assert.equal(konst('R_HEX'), '33.5');
    assert.equal(konst('R_OUTER'), '12.45');
    assert.equal(konst('R_CENTRE'), '14.9');
    assert.equal(konst('FILLET'), '5.75', 'the fillet is solved from the artwork, not a tuning knob');
  });

  test('no neck self-intersects — the failure that shipped once', () => {
    // For blobs rA, rB at distance d the fillet centre sits `off` from the
    // centre line and the waist is 2*(off - F). At off <= F the two fillet
    // arcs cross and the outline tears. R_OUTER 11.6 with FILLET 6.0 gave
    // -1.19 on every outer join and went out looking like a broken logo.
    const src = readFileSync(new URL('../site/mark.mjs', import.meta.url), 'utf8');
    const konst = (name) => Number(src.match(new RegExp(`const ${name}\\s*=\\s*([\\d.]+)`))[1]);
    const [hex, outer, centre, F] = ['R_HEX', 'R_OUTER', 'R_CENTRE', 'FILLET'].map(konst);

    const waist = (rA, rB, d) => {
      const ra = rA + F; const rb = rB + F;
      const along = (d * d + ra * ra - rb * rb) / (2 * d);
      const off2 = ra * ra - along * along;
      assert.ok(off2 > 0, `no fillet solution for ${rA}/${rB} at ${d}`);
      return 2 * (Math.sqrt(off2) - F);
    };

    // Every join in the mark: outer-to-outer along a hexagon edge, and
    // centre-to-outer along a radius. Both spans are R_HEX.
    for (const [label, w] of [
      ['outer↔outer', waist(outer, outer, hex)],
      ['centre↔outer', waist(outer, centre, hex)]
    ]) {
      assert.ok(w > 0, `${label} waist is ${w.toFixed(2)} — the neck self-intersects`);
    }

    // And the outer neck is genuinely pinched, which is what makes it this
    // logo rather than a string of sausages.
    const ratio = waist(outer, outer, hex) / (2 * outer);
    assert.ok(ratio > 0.08 && ratio < 0.16,
      `outer neck is ${(ratio * 100).toFixed(1)}% of a blob — the artwork's is about 11%`);
  });
});

describe('it moves, and it can be told not to', () => {
  test('the hero carries real footage over a live canvas', () => {
    // The brief asked for a background video. The canvas is not a substitute
    // for it — it is what stands in during the seconds before the video can
    // play, and for anyone who never gets it.
    assert.match(html, /<video class="hero-video"/);
    assert.match(html, /<canvas class="hero-canvas"/);
    assert.match(html, /preload="none"/,
      'the video must not be on the critical path — it is fetched by script, on purpose');
    assert.ok(!/<video[^>]*\bsrc=/.test(html),
      'no src in the markup, or the browser fetches it before anyone has decided it is wanted');
    assert.match(js, /video\.src = 'hero\.webm'/);
  });

  test('the footage is gated on motion, data and connection', () => {
    assert.match(js, /prefers-reduced-motion/);
    assert.match(js, /saveData/);
    assert.match(js, /effectiveType/);
    // Revealed only once it can genuinely play, so the worst case is the
    // canvas rather than a black rectangle.
    assert.match(js, /'canplay'/);
    assert.match(css, /\.hero-video\{opacity:0/);
    assert.match(css, /\.hero-video\.ready\{opacity:1\}/);
  });

  test('the theme colour is laid over the footage, not baked into it', () => {
    const scrim = css.slice(css.indexOf('.hero-scrim{'), css.indexOf('}', css.indexOf('.hero-scrim{')));
    assert.match(scrim, /rgba\(255,106,19/, 'the brand orange must burn through the gradient over the film');
    assert.match(scrim, /radial-gradient/);
    assert.match(scrim, /linear-gradient/);
    assert.match(html, /<div class="hero-scrim"/);
  });

  test('every band has an animated ground', () => {
    for (const cls of ['bg-scan', 'bg-flow', 'bg-lines', 'bg-dots', 'bg-chain', 'bg-horizon']) {
      assert.match(html, new RegExp(`class="${cls}"`), `${cls} is missing from the page`);
      assert.match(css, new RegExp(`\\.${cls}\\{`), `${cls} has no rule`);
    }
    const keyframes = (css.match(/@keyframes/g) ?? []).length;
    assert.ok(keyframes >= 10, `only ${keyframes} animations — the brief was motion in every section`);
  });

  test('no decorative layer can be read by a screen reader or catch a click', () => {
    for (const cls of ['hero-canvas', 'hero-video', 'hero-scrim', 'grain', 'scanlines',
      'bg-scan', 'bg-flow', 'bg-lines', 'bg-dots', 'bg-chain', 'bg-horizon']) {
      const tag = tagWithClass(cls);
      assert.ok(tag, `${cls} is not on the page`);
      assert.match(tag, /aria-hidden="true"/, `${cls} must be hidden from assistive technology`);
    }
  });

  test('one switch stops all of it', () => {
    assert.match(css, /@media \(prefers-reduced-motion:reduce\)/);
    const block = css.slice(css.indexOf('@media (prefers-reduced-motion:reduce)'));
    assert.match(block, /animation-duration:\.001ms !important/,
      'a per-animation opt-out gets forgotten the moment somebody adds the sixteenth animation');
    assert.match(block, /animation-iteration-count:1 !important/);
    // The canvas is script, not CSS, so the media query cannot reach it.
    assert.match(js, /if \(reduced\) \{ frame\(t0\); cancelAnimationFrame\(raf\); raf = null; \}/,
      'reduced motion must paint one still frame, not loop and not go blank');
  });

  test('the background stops when nobody is looking at it', () => {
    // A requestAnimationFrame loop running behind eight sections of content, or
    // in a hidden tab, is a battery bug rather than a design decision.
    assert.match(js, /IntersectionObserver/);
    assert.match(js, /visibilitychange/);
    assert.match(js, /cancelAnimationFrame/);
  });
});

describe('it degrades', () => {
  test('content that hides itself has a deadline and a print path', () => {
    // Reveal-on-scroll hid the entire page below the hero in a renderer that
    // never scrolls. All three of these are the fix.
    assert.match(js, /setTimeout\(\(\) => targets\.forEach\(\(el\) => el\.classList\.add\('in'\)\), 4000\)/,
      'an observer that never fires must not mean content that never appears');
    assert.match(js, /beforeprint/);
    assert.match(css, /@media print\{/);
    const print = css.slice(css.indexOf('@media print{'));
    assert.match(print, /\.reveal\{opacity:1 !important/);
    assert.match(print, /\.hero-canvas,\.hero-video/, 'the film must not be part of a printed page');
  });

  test('the reveal is additive, so no JavaScript means visible, not blank', () => {
    assert.ok(!/class="[^"]*\breveal\b/.test(html),
      'nothing may ship with the hidden state in the markup — the class is added by script or not at all');
    assert.match(js, /el\.classList\.add\('reveal'\)/);
  });

  test('the drawer is genuinely hidden when closed, not merely transparent', () => {
    // A menu that is only opacity:0 is still in the tab order, and a keyboard
    // user tabs into eight invisible links.
    assert.match(html, /<div class="drawer" id="drawer" hidden>/);
    assert.match(js, /panel\.hidden = true/);
    assert.match(js, /e\.key === 'Escape'/, 'Escape must close it');
  });

  test('nothing is fetched from a third party', () => {
    const remote = [...html.matchAll(/(?:src|href)="(https?:)?\/\/[^"]+"/g)].map((m) => m[0]);
    assert.deepEqual(remote, [], 'no CDN fonts, no analytics by default — the page loads with no network but its own');
    assert.ok(!/https?:\/\//.test(js.replace(/^\s*(\/\/|\*|\/\*).*$/gm, '')),
      'the script must not reach off-origin either');
  });

  test('the FAQ opens without JavaScript', () => {
    assert.match(html, /<details>/, 'native disclosure, so it works before and without script');
    assert.ok(!/details/.test(js) && !/summary/.test(js),
      'nothing may script the disclosure open — <details> already works with no JS and with a keyboard');
  });

  test('the whole site is still four files and no build step', () => {
    // The product ships with zero dependencies; a marketing site that needs a
    // toolchain to change a headline would be the first crack in that.
    assert.ok(!/type="module"[^>]*src="[^"]*\/node_modules/.test(html));
    assert.ok(!/import .* from ['"][^./]/.test(js), 'app.js must not import a package');
    assert.match(html, /<script type="module" src="app\.js"><\/script>/);
  });
});

describe('the footage that ships', () => {
  const webm = new URL('../site/hero.webm', import.meta.url);

  test('it is committed, or the hero silently falls back forever', { skip: !existsSync(webm) && 'hero.webm not built' }, () => {
    const kb = statSync(webm).size / 1024;
    assert.ok(kb > 20, `hero.webm is ${kb.toFixed(0)} kB — that is a truncated render, not a video`);
    // A hero background that costs more than a megabyte is a hero background
    // that people on a train never see.
    assert.ok(kb < 1400, `hero.webm is ${kb.toFixed(0)} kB — too heavy for a decorative loop`);
  });

  test('the terminal in the footage shows real product output', () => {
    // The screen says BLOCKED and HELD. If that text were hand-written it
    // would be a marketing claim nobody re-checks; instead the generator runs
    // demo/seed.js and puts its actual stdout on the screen, so the footage
    // cannot outlive the behaviour it depicts.
    const gen = readFileSync(new URL('../site/video.mjs', import.meta.url), 'utf8');
    assert.match(gen, /demo['"/\s,\]]*['"]?\s*,?\s*['"]seed\.js['"]|'seed\.js'/,
      'the footage must be driven by demo/seed.js, not by a copy of its output');
    assert.match(gen, /execFileSync/);
    // …and it must not take the whole build down when the demo cannot run.
    assert.match(gen, /fallback/i, 'a demo that fails must degrade, not fail the render');
  });

  test('the generator is build-time only and says so', () => {
    const gen = readFileSync(new URL('../site/video.mjs', import.meta.url), 'utf8');
    assert.match(gen, /build time/i);
    // The frames go through ffmpeg's mjpeg decoder because the ffmpeg that
    // ships with Playwright has no PNG decoder — hand it a PNG and the render
    // hangs on a dead pipe rather than failing.
    assert.match(gen, /'mjpeg'/);
    assert.match(gen, /image\/jpeg/);
    assert.ok(!/require\('playwright'\)|from 'playwright'/.test(gen),
      'Playwright must stay optional — resolved at run time, never a static import');
  });
});
