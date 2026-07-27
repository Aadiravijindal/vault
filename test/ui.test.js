/**
 * Interface language, direction and accessibility (§23).
 *
 * There is no browser here, so these do not claim to be a WCAG audit — a real
 * conformance statement needs assistive technology driven by a person, and
 * saying otherwise would be the kind of unearned claim this product exists to
 * prevent. What they do check is every accessibility property that is decidable
 * from the source: that the markup carries the attributes screen readers need,
 * that contrast ratios clear AA by calculation, that nothing interactive is
 * unreachable by keyboard, and that the translation layer reports its own gaps
 * instead of silently serving English.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { I18n, LOCALES, STRINGS, coverage, negotiate } from '../src/ui/i18n.js';

const UI = fileURLToPath(new URL('../src/ui/', import.meta.url));
const html = readFileSync(join(UI, 'index.html'), 'utf8');
const css = readFileSync(join(UI, 'app.css'), 'utf8');
const js = readFileSync(join(UI, 'app.js'), 'utf8');

// --- contrast, computed from the WCAG formula rather than eyeballed ---------
function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};
function vars(block) {
  const out = {};
  for (const [, name, value] of block.matchAll(/--([a-z0-9]+)\s*:\s*(#[0-9a-f]{6})/gi)) out[name] = value;
  return out;
}

describe('colour contrast clears WCAG AA by calculation', () => {
  test('every foreground colour in the dark theme is legible on its background', () => {
    const root = css.slice(0, css.indexOf('}'));
    const c = vars(root);
    assert.ok(c.bg && c.ink, 'the palette must define bg and ink');
    const failures = [];
    for (const name of ['ink', 'dim', 'dimmer', 'accent', 'green', 'amber', 'red', 'purple']) {
      if (!c[name]) continue;
      const ratio = contrast(c[name], c.bg);
      // 4.5:1 is the AA threshold for normal-size text, which is what every one
      // of these is used for.
      if (ratio < 4.5) failures.push(`--${name} ${c[name]} on --bg ${c.bg} is ${ratio.toFixed(2)}:1`);
    }
    assert.deepEqual(failures, [], `these fail AA for normal text:\n  ${failures.join('\n  ')}`);
  });

  test('the light theme is held to the same standard, not left as an afterthought', () => {
    const start = css.indexOf('prefers-color-scheme:light');
    assert.ok(start > 0, 'there must be a light theme at all');
    const c = vars(css.slice(start, css.indexOf('}', css.indexOf(':root', start))));
    assert.ok(c.bg, 'the light theme must define its own palette');
    const failures = [];
    for (const name of ['ink', 'dim', 'dimmer', 'accent', 'green', 'amber', 'red', 'purple']) {
      if (!c[name]) continue;
      const ratio = contrast(c[name], c.bg);
      if (ratio < 4.5) failures.push(`--${name} ${c[name]} is ${ratio.toFixed(2)}:1`);
    }
    assert.deepEqual(failures, [], `light theme fails AA:\n  ${failures.join('\n  ')}`);
  });
});

describe('the markup carries what assistive technology needs', () => {
  test('the document declares its language and direction', () => {
    assert.match(html, /<html lang="en" dir="ltr">/,
      'a document with no lang attribute is read by a screen reader in the wrong voice');
  });

  test('there is a skip link, and it is the first focusable element', () => {
    assert.match(html, /class="skip"/);
    const skipAt = html.indexOf('class="skip"');
    const firstInput = html.search(/<(?:input|button|select|a )/);
    assert.ok(skipAt <= html.indexOf('<a href="#view"') + 40);
    assert.ok(skipAt < html.indexOf('<input'), 'the skip link must come before the form it skips');
    assert.ok(firstInput >= 0);
    // And it must move focus, not merely scroll.
    assert.match(js, /skipLink[\s\S]{0,320}\.focus\(\)/,
      'a skip link that scrolls without moving focus leaves the keyboard user still in the nav');
  });

  test('there are live regions, and urgent messages have their own', () => {
    assert.match(html, /aria-live="polite"/);
    assert.match(html, /aria-live="assertive"/);
    assert.match(html, /role="alert"/);
    assert.match(js, /function announce\(message, urgent/);
    // The two things a person must not miss.
    assert.match(js, /announce\(t\('chain\.broken'\), true\)/);
    assert.match(js, /announce\(`\$\{t\('killswitch\.label'\)\}: \$\{state\}`, true\)/);
  });

  test('every form control has a label bound to it by id', () => {
    const ids = [...html.matchAll(/<(?:input|select|textarea)[^>]*\bid="([^"]+)"/g)].map((m) => m[1]);
    assert.ok(ids.length >= 2, 'expected at least the token and locale controls');
    for (const id of ids) {
      assert.ok(new RegExp(`<label[^>]*for="${id}"`).test(html),
        `#${id} has no <label for>, so a screen reader announces it as an unlabelled edit box`);
    }
  });

  test('decorative emoji are hidden from screen readers, and meaningful ones are not', () => {
    // "🔒 VAULT" read as "lock VAULT" is noise; the lock adds nothing.
    assert.match(html, /<span class="lock" aria-hidden="true">🔒<\/span>/);
    assert.match(js, /<span aria-hidden="true">\$\{s\.icon\}<\/span>/,
      'nav icons duplicate the adjacent label and should not be announced twice');
  });

  test('the busy state and the main region are announced during navigation', () => {
    assert.match(html, /id="view" tabindex="-1" aria-busy="false"/);
    assert.match(js, /setAttribute\('aria-busy', 'true'\)/);
    assert.match(js, /setAttribute\('aria-busy', 'false'\)/);
    assert.match(js, /document\.title = /,
      'in a single-page app there is no page load, so the title must change for a screen change to be noticeable');
  });
});

describe('generated markup is accessible too', () => {
  test('tables get a caption, column scopes and a row header', () => {
    assert.match(js, /<caption class="sr-only">/);
    assert.match(js, /<th scope="col">/);
    assert.match(js, /<th scope="row">/,
      'without a row header every cell is read as a bare value with no idea which row it belongs to');
  });

  test('scrollable table containers are keyboard-reachable', () => {
    assert.match(js, /class="scroll" tabindex="0" role="region"/,
      'a container that scrolls but cannot take focus is unreachable without a mouse');
  });

  test('stat tiles read label-then-value, not a bare number', () => {
    assert.match(js, /const accessible = `\$\{label\}: \$\{val\}`/);
    assert.match(js, /role="group" aria-label="\$\{esc\(accessible\)\}"/);
  });

  test('tabs implement the real tab pattern, including roving tabindex', () => {
    assert.match(js, /setAttribute\('role', 'tablist'\)/);
    assert.match(js, /setAttribute\('role', 'tabpanel'\)/);
    assert.match(js, /'role', 'tab'/);
    assert.match(js, /aria-selected/);
    assert.match(js, /tab\.tabIndex = i === 0 \? 0 : -1/,
      'fourteen tab stops for fourteen tabs is the pattern that makes keyboard users give up');
    assert.match(js, /ArrowRight: 1, ArrowLeft: -1, Home: -Infinity, End: Infinity/);
    // Arrow keys must follow reading direction, or RTL users navigate backwards.
    assert.match(js, /rtl \? -step : step/);
  });

  test('navigation items are buttons with aria-current, not clickable divs', () => {
    assert.match(js, /<button type="button" class="navbtn"/);
    assert.match(js, /setAttribute\('aria-current', 'page'\)/,
      'a CSS highlight is invisible to anyone not looking at it');
    assert.match(js, /aria-disabled="true"/);
    assert.match(js, /not available to the \$\{esc\(me\.role\)\} role/,
      'a locked screen should say why, not just look faded');
    assert.equal(/<li data-id=/.test(js), false, 'the clickable-div nav must be gone, not merely supplemented');
  });

  test('the login is a real form, so Enter and password managers work', () => {
    assert.match(html, /<form class="login-card" id="loginForm"/);
    assert.match(html, /<button id="signin" type="submit"/);
    assert.match(js, /\$\('#loginForm'\)\.addEventListener\('submit'/);
    assert.match(js, /setAttribute\('aria-invalid', 'true'\)/);
  });
});

describe('the stylesheet supports the people who need it most', () => {
  test('focus is visible, and not left to the browser default on a dark panel', () => {
    assert.match(css, /:focus-visible\{[\s\S]{0,120}outline:3px solid var\(--focus\)/);
    assert.match(css, /--focus:/);
  });

  test('reduced motion, forced colours and print are all handled', () => {
    assert.match(css, /@media \(prefers-reduced-motion:reduce\)/);
    assert.match(css, /@media \(forced-colors:active\)/);
    assert.match(css, /@media print/);
    assert.match(css, /@media \(prefers-color-scheme:light\)/);
  });

  test('touch targets meet the 24px minimum', () => {
    assert.match(css, /min-height:24px/);
    assert.match(css, /nav li\{min-height:36px\}/);
  });

  test('.sr-only hides visually without leaving the accessibility tree', () => {
    const rule = css.slice(css.indexOf('.sr-only{'), css.indexOf('}', css.indexOf('.sr-only{')));
    assert.match(rule, /position:absolute/);
    assert.equal(/display:none/.test(rule), false,
      'display:none removes it from the accessibility tree, which defeats the whole purpose');
  });

  test('layout uses logical properties, so dir=rtl really flips it', () => {
    for (const prop of ['border-inline-end', 'border-inline-start', 'inset-inline-start', 'inset-inline-end', 'text-align:start']) {
      assert.ok(css.includes(prop), `missing ${prop} — physical properties do not flip in RTL`);
    }
    // The specific ones that would look broken in Arabic if left physical.
    assert.equal(/nav\{[^}]*border-right/.test(css), false);
    assert.equal(/th\{[^}]*text-align:left/.test(css), false);
  });
});

describe('translation is honest about its own coverage', () => {
  test('every locale in the picker reports how complete it actually is', () => {
    const cov = coverage();
    assert.equal(cov.length, Object.keys(LOCALES).length);
    for (const l of cov) {
      assert.ok(l.status, `${l.locale} has no status`);
      if (l.percent < 100) {
        assert.match(l.status, /partial|not started/,
          `${l.locale} is ${l.percent}% translated but its status does not say so`);
      }
    }
    assert.equal(cov.find((l) => l.locale === 'en').percent, 100);
  });

  test('a locale with no string table falls back to English and says it is not started', () => {
    const es = coverage().find((l) => l.locale === 'es');
    assert.equal(Boolean(STRINGS.es), false, 'this test is about the untranslated case');
    assert.equal(es.percent, 0);
    assert.match(es.status, /not started — selecting this shows English/,
      'offering a language that does nothing, without saying so, is the failure this reports');

    const i = new I18n({ locale: 'es' });
    assert.equal(i.t('auth.signin'), 'Sign in');
  });

  test('missing keys are recorded, and can be made visible for QA', () => {
    const quiet = new I18n({ locale: 'de' });
    assert.equal(quiet.t('screen.map'), 'Übersicht');
    quiet.t('a.key.that.does.not.exist');
    assert.ok(quiet.missed.has('a.key.that.does.not.exist'));
    assert.deepEqual(quiet.report().missingKeysSeenThisSession, ['a.key.that.does.not.exist']);

    const loud = new I18n({ locale: 'de', markMissing: true });
    // German has this key, so it renders normally...
    assert.equal(loud.t('screen.map'), 'Übersicht');
    // ...and a key German lacks is marked, so a half-translated screen looks
    // half-translated rather than looking finished.
    STRINGS.de['temp.only.english'] = undefined;
    STRINGS.en['temp.only.english'] = 'English only';
    assert.equal(loud.t('temp.only.english'), '⟦English only⟧');
    delete STRINGS.en['temp.only.english'];
  });

  test('RTL locales set the document direction, not a mirrored stylesheet', () => {
    const ar = new I18n({ locale: 'ar' });
    assert.equal(ar.dir, 'rtl');
    assert.equal(new I18n({ locale: 'he' }).dir, 'rtl');
    assert.equal(new I18n({ locale: 'de' }).dir, 'ltr');
    assert.match(js, /document\.documentElement\.dir = dir/,
      'direction belongs on the document; setting it in CSS misses scroll gutters and selection');
    assert.match(js, /document\.documentElement\.lang = i18n\.locale/);
  });

  test('Arabic is genuinely translated, not a stub with the direction flipped', () => {
    const ar = new I18n({ locale: 'ar' });
    assert.equal(ar.t('auth.signin'), 'تسجيل الدخول');
    assert.equal(ar.t('screen.review'), 'بحاجة إلى مراجعة');
    const cov = coverage().find((l) => l.locale === 'ar');
    assert.ok(cov.percent > 90, `Arabic is only ${cov.percent}% — an RTL locale that is mostly English tests nothing`);
  });

  test('numbers and dates go through Intl, because 1.234 means different things', () => {
    const de = new I18n({ locale: 'de' });
    const en = new I18n({ locale: 'en' });
    assert.notEqual(de.number(1234.5), en.number(1234.5),
      'German uses . for thousands and , for decimals — showing the English form is showing a different number');
    assert.equal(en.number(null), '—', 'a missing number is not zero');
    assert.match(en.date(Date.parse('2027-03-14T09:00:00Z')), /UTC|GMT/,
      'a retention deadline without a timezone is a date somebody will get wrong by a day');
  });

  test('interpolation leaves an unfilled placeholder visible rather than rendering undefined', () => {
    const i = new I18n();
    STRINGS.en['temp.count'] = '{count} facts were blocked';
    assert.equal(i.t('temp.count', { count: 3 }), '3 facts were blocked');
    assert.equal(i.t('temp.count', {}), '{count} facts were blocked',
      '"undefined facts were blocked" is a false statement on a governance screen');
    delete STRINGS.en['temp.count'];
  });

  test('Accept-Language negotiation picks a supported locale, including by base tag', () => {
    assert.equal(negotiate('de-DE,de;q=0.9,en;q=0.8'), 'de');
    assert.equal(negotiate('ar-EG'), 'ar');
    assert.equal(negotiate('en-GB,en;q=0.9'), 'en');
    assert.equal(negotiate('xx-YY'), 'en', 'an unsupported language falls back rather than failing');
    assert.equal(negotiate(''), 'en');
    assert.equal(negotiate(null), 'en');
    // Quality values decide, not order of appearance.
    assert.equal(negotiate('en;q=0.2,fr;q=0.9'), 'fr');
  });

  test('the report states plainly that content is never machine-translated', () => {
    const r = new I18n({ locale: 'de' }).report();
    assert.match(r.note, /never machine-translated/,
      'translating a fact would be a governance failure, and the UI should say it does not');
    assert.equal(r.locale, 'de');
    assert.equal(r.dir, 'ltr');
  });
});
