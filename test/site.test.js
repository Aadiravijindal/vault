/**
 * The marketing site.
 *
 * No browser here on purpose — Playwright is not a dependency of this project
 * and `npm test` has to run from a fresh clone with nothing installed. So this
 * checks the things that can be checked from the source: that the promised copy
 * is actually on the page, that the brand colours clear WCAG AA by calculation
 * rather than by eye, and that the one mistake this palette invites — white text
 * on the brand orange — has not been made.
 *
 * The gradient itself needs pixels to measure, and it was measured: white on the
 * bare bloom fell to 2.24:1 behind the headline before a shadow pocket was added
 * under the content, and 5.03:1 after. That is recorded here because the number
 * is the reason the hero looks the way it does.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../site/styles.css', import.meta.url), 'utf8');

// --- WCAG contrast, computed rather than eyeballed --------------------------
const hex = (h) => { const s = h.replace('#', ''); return [0, 2, 4].map((i) => parseInt(s.slice(i, i + 2), 16)); };
const lum = (c) => {
  const s = hex(c).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * s[0] + 0.7152 * s[1] + 0.0722 * s[2];
};
const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

/** Read the :root custom properties out of the stylesheet. */
function tokens() {
  const root = css.slice(css.indexOf(':root{'), css.indexOf('}', css.indexOf(':root{')));
  const out = {};
  for (const m of root.matchAll(/--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})/g)) out[m[1]] = m[2];
  return out;
}

describe('the page says what it promises to say', () => {
  test('the headline and the three sentences under it are exact', () => {
    assert.match(html, /The governed memory layer for enterprise AI\./);
    assert.match(html, /Every AI agent in your company reads from one memory\./);
    assert.match(html, /Nothing enters\s+without being checked\./);
    assert.match(html, /Everything is traced, sealed, and provable\./);
  });

  test('the numbers on the page match the product', () => {
    // A marketing claim nobody re-checks becomes wrong the first time the
    // product changes. These are the ones with a number in them.
    assert.match(html, />74</, '74 connectors');
    assert.match(html, />576</, '576 adversarial cases');
    assert.match(html, /45 detectors/);
    assert.match(html, /p50\s*80ms/);
    assert.match(html, /Node 22\+/);
  });

  test('the honest section is still on the page', () => {
    assert.match(html, /What Vault does not do/i,
      'the limits section is the most persuasive thing here; it must not get quietly dropped');
    assert.match(html, /does not prove a fact is true/);
  });
});

describe('brand colour clears WCAG AA by calculation', () => {
  test('every text token passes against both section grounds', () => {
    const t = tokens();
    const failures = [];
    for (const ground of ['black', 'black-2', 'black-3']) {
      for (const [name, need] of [['ink', 4.5], ['ink-2', 4.5], ['muted', 4.5], ['orange', 4.5], ['orange-2', 4.5]]) {
        const r = contrast(t[name], t[ground]);
        if (r < need) failures.push(`--${name} ${t[name]} on --${ground} ${t[ground]} is ${r.toFixed(2)}:1`);
      }
    }
    assert.deepEqual(failures, [], 'a brand colour that fails AA is a brand colour that has to change');
  });

  test('the stylesheet documents the ratios it claims', () => {
    // The comment block is not decoration: it is what stops the next person
    // nudging a hex value two shades and silently dropping below the line.
    assert.match(css, /18\.9:1/);
    assert.match(css, /6\.9:1/);
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
    const r = contrast(colour, t.orange);
    assert.ok(r >= 4.5, `button text ${colour} on --orange is ${r.toFixed(2)}:1`);
  });
});

describe('the mark', () => {
  test('the geometry lives in exactly one place', () => {
    assert.equal((html.match(/<symbol id="mark"/g) ?? []).length, 1);
    assert.ok((html.match(/<use href="#mark">/g) ?? []).length >= 2, 'every other use references it');
  });

  test('node radius stays under half the shortest link, or the graph stops reading', () => {
    const symbol = html.slice(html.indexOf('<symbol id="mark"'), html.indexOf('</symbol>'));
    const nodes = [...symbol.matchAll(/<circle cx="(\d+)"\s+cy="(\d+)"\s+r="([\d.]+)"/g)]
      .map((m) => ({ x: +m[1], y: +m[2], r: +m[3] }));
    assert.equal(nodes.length, 7);

    let shortest = Infinity;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        shortest = Math.min(shortest, Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y));
      }
    }
    const biggest = Math.max(...nodes.map((n) => n.r));
    assert.ok(biggest * 2 < shortest,
      `radius ${biggest} against a shortest link of ${shortest.toFixed(1)} — at r=5 on the first attempt the circles `
      + 'merged into a blob and the connections disappeared');
  });

  test('it inherits colour instead of hard-coding white', () => {
    const symbol = html.slice(html.indexOf('<symbol id="mark"'), html.indexOf('</symbol>'));
    assert.match(symbol, /fill="currentColor"/);
    assert.ok(!/#fff/i.test(symbol), 'the mark must recolour on hover and in any context');
  });
});

describe('it degrades', () => {
  test('motion is optional', () => {
    assert.match(css, /@media \(prefers-reduced-motion:reduce\)/);
    const blocks = css.match(/@media \(prefers-reduced-motion:reduce\)/g) ?? [];
    assert.ok(blocks.length >= 2, 'the drifting gradient and the entrance animations both have to stop');
  });

  test('the reveal-on-scroll is additive, so no JavaScript means visible, not blank', () => {
    assert.ok(!/class="[^"]*\breveal\b/.test(html),
      'nothing may ship with the hidden state in the markup — the class is added by script or not at all');
    assert.match(html, /el\.classList\.add\('reveal'\)/);
  });

  test('nothing is fetched from a third party', () => {
    const remote = [...html.matchAll(/(?:src|href)="(https?:)?\/\/[^"]+"/g)].map((m) => m[0]);
    assert.deepEqual(remote, [], 'no CDN fonts, no analytics by default — the page loads with no network but its own');
  });
});
