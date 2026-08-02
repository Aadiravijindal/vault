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
 * The gradient needs pixels to measure, and it was measured: white on the bare
 * hero bloom fell to 2.24:1 behind the headline before a shadow pocket was
 * added under the content, and 5.03:1 after. That number is recorded here
 * because it is the reason the hero looks the way it does.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MARK_PATH } from '../site/mark.mjs';

const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../site/styles.css', import.meta.url), 'utf8');
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

describe('the page says what it promises to say', () => {
  test('the headline and the three sentences under it are exact', () => {
    // Matched against the rendered text, not the markup, so a line break or a
    // wrapping span cannot silently change the approved copy.
    assert.match(text, /The governed memory layer for enterprise AI\./);
    assert.match(text, /Every AI agent in your company reads from one memory\./);
    assert.match(text, /Nothing enters without being checked\./);
    assert.match(text, /Everything is traced, sealed, and provable\./);
  });

  test('the numbers on the page match the product', () => {
    // A marketing claim nobody re-checks is wrong the first time the product
    // changes. These are the ones with a number in them.
    assert.match(text, /\b74\b/, '74 connectors');
    assert.match(text, /576 adversarial cases/);
    assert.match(text, /\b908\b/, 'the test count');
    assert.match(text, /p50 80ms/);
    assert.match(text, /ten checks|10 checks/i);
  });

  test('the honest section is still on the page', () => {
    assert.match(text, /What Vault does not do/i,
      'the limits section is the most persuasive thing here; it must not get quietly dropped');
    assert.match(text, /does not prove a fact is true/);
    assert.match(text, /does not catch every attack/);
  });

  test('every section the nav points at exists', () => {
    const targets = [...html.matchAll(/href="#([a-z-]+)"/g)].map((m) => m[1]);
    for (const id of new Set(targets)) {
      assert.match(html, new RegExp(`id="${id}"`), `nav points at #${id}, which is not on the page`);
    }
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

  test('the stylesheet documents the ratios it claims', () => {
    assert.match(css, /18\.9:1/);
    assert.match(css, /6\.9:1/);
    assert.match(css, /2\.24:1/, 'the measured hero failure is why the shadow pocket exists');
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
    // hero stop being the same shape.
    assert.ok(html.includes(MARK_PATH), 'site/index.html no longer matches `node site/mark.mjs`');
  });

  test('the geometry lives in exactly one place', () => {
    assert.equal((html.match(/<symbol id="mark"/g) ?? []).length, 1);
    assert.ok((html.match(/<use href="#mark">/g) ?? []).length >= 3, 'every other use references it');
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
});

describe('it moves, and it can be told not to', () => {
  test('every band has an animated ground', () => {
    for (const cls of ['bloom', 'bg-scan', 'bg-flow', 'bg-lines', 'bg-dots', 'bg-chain', 'bg-horizon']) {
      assert.match(html, new RegExp(`class="${cls}"`), `${cls} is missing from the page`);
      assert.match(css, new RegExp(`\\.${cls}\\{`), `${cls} has no rule`);
    }
    const keyframes = (css.match(/@keyframes/g) ?? []).length;
    assert.ok(keyframes >= 10, `only ${keyframes} animations — the brief was motion in every section`);
  });

  test('no decorative layer can be read by a screen reader or catch a click', () => {
    for (const cls of ['bloom', 'grain', 'bg-scan', 'bg-flow', 'bg-lines', 'bg-dots', 'bg-chain', 'bg-horizon']) {
      const at = html.indexOf(`class="${cls}"`);
      const tag = html.slice(html.lastIndexOf('<', at), html.indexOf('>', at));
      assert.match(tag, /aria-hidden="true"/, `${cls} must be hidden from assistive technology`);
    }
  });

  test('one switch stops all of it', () => {
    assert.match(css, /@media \(prefers-reduced-motion:reduce\)/);
    const block = css.slice(css.indexOf('@media (prefers-reduced-motion:reduce)'));
    assert.match(block, /animation-duration:\.001ms !important/,
      'a per-animation opt-out gets forgotten the moment somebody adds the sixteenth animation');
    assert.match(block, /animation-iteration-count:1 !important/);
  });

  test('none of it is a video file', () => {
    assert.ok(!/<video|\.mp4|\.webm/i.test(html),
      'a background video is megabytes per loop, decodes on the main thread, cannot be recoloured, '
      + 'and cannot honour prefers-reduced-motion without JavaScript that has to load first');
  });
});

describe('it degrades', () => {
  test('content that hides itself has a deadline and a print path', () => {
    // Reveal-on-scroll hid the entire page below the hero in a renderer that
    // never scrolls. Both of these are the fix.
    assert.match(html, /setTimeout\(\(\) => \{ for \(const el of hidden\) el\.classList\.add\('in'\); \}/,
      'an observer that never fires must not mean content that never appears');
    assert.match(html, /beforeprint/);
    assert.match(css, /@media print\{/);
    const print = css.slice(css.indexOf('@media print{'));
    assert.match(print, /\.reveal\{opacity:1 !important/);
  });

  test('the reveal is additive, so no JavaScript means visible, not blank', () => {
    assert.ok(!/class="[^"]*\breveal\b/.test(html),
      'nothing may ship with the hidden state in the markup — the class is added by script or not at all');
    assert.match(html, /el\.classList\.add\('reveal'\)/);
  });

  test('nothing is fetched from a third party', () => {
    const remote = [...html.matchAll(/(?:src|href)="(https?:)?\/\/[^"]+"/g)].map((m) => m[0]);
    assert.deepEqual(remote, [], 'no CDN fonts, no analytics by default — the page loads with no network but its own');
  });

  test('the FAQ opens without JavaScript', () => {
    assert.match(html, /<details>/, 'native disclosure, so it works before and without script');
    assert.ok(!/querySelectorAll\('[^']*details/.test(html) && !/summary[^]{0,80}addEventListener/.test(html),
      'nothing may script the disclosure open — <details> already works with no JS and with a keyboard');
  });
});
