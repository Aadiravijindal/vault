/**
 * Text normalisation and de-obfuscation.
 *
 * Every detector in the gate runs against BOTH the original string and the
 * de-obfuscated string. Normalising before detection is how you catch
 * `i​gnore previous instructions`; keeping the original is how you can
 * still show the reviewer exactly what arrived on the wire.
 */

// Zero-width, bidi and other invisible characters used to smuggle instructions.
// Written as escapes on purpose: these are unreadable and unreviewable as
// literals, and a copy-paste that eats one silently disarms the detector.
const INVISIBLE = new RegExp(
  '[' +
  '\\u00AD' +               // soft hyphen
  '\\u180E' +               // mongolian vowel separator
  '\\u200B-\\u200F' +       // zero-width space/non-joiner/joiner, LRM, RLM
  '\\u202A-\\u202E' +       // bidi embedding/override
  '\\u2060-\\u2064' +       // word joiner, invisible operators
  '\\u2066-\\u206F' +       // bidi isolates, deprecated format chars
  '\\uFEFF' +               // zero-width no-break space / BOM
  '\\uFFF9-\\uFFFB' +       // interlinear annotation
  ']', 'g'
);

// Homoglyph folding: Cyrillic/Greek/fullwidth/mathematical lookalikes → ASCII.
const HOMOGLYPHS = new Map(Object.entries({
  а: 'a', б: '6', в: 'b', е: 'e', ѕ: 's', і: 'i', ј: 'j', к: 'k', м: 'm', н: 'h',
  о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x', А: 'A', В: 'B', Е: 'E', З: '3',
  К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', У: 'Y', Х: 'X',
  α: 'a', ο: 'o', ρ: 'p', ν: 'v', τ: 't', υ: 'u', χ: 'x', Α: 'A', Β: 'B', Ε: 'E',
  Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P', Τ: 'T', Υ: 'Y',
  Χ: 'X', ǀ: 'l', ǃ: '!', ʼ: "'", '‚': ',', '＇': "'", '＂': '"'
}));

/** Fullwidth forms (U+FF01–U+FF5E) map linearly onto ASCII 0x21–0x7E. */
function foldFullwidth(ch) {
  const code = ch.codePointAt(0);
  if (code >= 0xff01 && code <= 0xff5e) return String.fromCharCode(code - 0xfee0);
  // Mathematical alphanumerics → latin
  if (code >= 0x1d400 && code <= 0x1d7ff) {
    const offsets = [
      [0x1d400, 26, 'A'], [0x1d41a, 26, 'a'], [0x1d434, 26, 'A'], [0x1d44e, 26, 'a'],
      [0x1d468, 26, 'A'], [0x1d482, 26, 'a'], [0x1d49c, 26, 'A'], [0x1d4b6, 26, 'a'],
      [0x1d5a0, 26, 'A'], [0x1d5ba, 26, 'a'], [0x1d5d4, 26, 'A'], [0x1d5ee, 26, 'a'],
      [0x1d670, 26, 'A'], [0x1d68a, 26, 'a'], [0x1d7ce, 10, '0'], [0x1d7d8, 10, '0'],
      [0x1d7e2, 10, '0'], [0x1d7ec, 10, '0'], [0x1d7f6, 10, '0']
    ];
    for (const [base, len, start] of offsets) {
      if (code >= base && code < base + len) {
        return String.fromCharCode(start.charCodeAt(0) + (code - base));
      }
    }
  }
  return ch;
}

/** Strip invisible characters and report how many were found. */
export function stripInvisible(text) {
  const found = (text.match(INVISIBLE) || []).length;
  return { text: text.replace(INVISIBLE, ''), found };
}

/** Fold homoglyphs to ASCII and report how many were folded. */
export function foldHomoglyphs(text) {
  let folded = 0;
  let out = '';
  for (const ch of text) {
    const mapped = HOMOGLYPHS.get(ch) ?? foldFullwidth(ch);
    if (mapped !== ch) folded++;
    out += mapped;
  }
  return { text: out, folded };
}

/**
 * Full de-obfuscation pass.
 * @param {string} input
 * @returns {{normalised:string, signals:string[], details:Record<string,any>}}
 */
export function deobfuscate(input) {
  const signals = [];
  const details = {};
  let text = String(input ?? '');

  const nfkc = text.normalize('NFKC');
  if (nfkc !== text) {
    signals.push('unicode_normalisation_changed_text');
    details.nfkc = true;
  }
  text = nfkc;

  const inv = stripInvisible(text);
  if (inv.found > 0) {
    signals.push('invisible_characters');
    details.invisibleCount = inv.found;
  }
  text = inv.text;

  const hom = foldHomoglyphs(text);
  if (hom.folded > 0) {
    signals.push('homoglyphs');
    details.homoglyphCount = hom.folded;
  }
  text = hom.text;

  // Whitespace steganography: long runs of trailing spaces/tabs carrying bits.
  if (/[ \t]{8,}$/m.test(text) || /(?:[ \t]{2,}\n){3,}/.test(text)) {
    signals.push('whitespace_steganography');
  }

  // Decode nested encodings, up to 3 hops, and append the plaintext so the
  // detectors downstream can see it.
  const decoded = decodeLayers(text, 3);
  if (decoded.layers.length) {
    signals.push('encoded_payload');
    details.encodings = decoded.layers;
    text += '\n' + decoded.decoded.join('\n');
  }

  // Collapse whitespace last so offsets in the *original* stay reportable.
  const normalised = text.replace(/[ \t\u00A0\u2000-\u200A\u3000]+/g, ' ').trim();
  return { normalised, signals, details };
}

const B64 = /(?:[A-Za-z0-9+/]{20,}={0,2})/g;
const HEXSTR = /(?:[0-9a-fA-F]{2}[\s:]?){12,}/g;
const PCTENC = /(?:%[0-9a-fA-F]{2}){4,}/g;
const HTMLENT = /(?:&#x?[0-9a-fA-F]{2,6};){4,}/g;

/** Decode base64 / hex / percent / html-entity / rot13 payloads recursively. */
export function decodeLayers(text, maxDepth = 2) {
  const layers = [];
  const decoded = [];
  let current = text;
  for (let depth = 0; depth < maxDepth; depth++) {
    let found = false;
    for (const m of current.match(B64) || []) {
      const out = tryB64(m);
      if (out) { decoded.push(out); layers.push('base64'); current = out; found = true; break; }
    }
    if (!found) {
      for (const m of current.match(HEXSTR) || []) {
        const out = tryHex(m);
        if (out) { decoded.push(out); layers.push('hex'); current = out; found = true; break; }
      }
    }
    if (!found && PCTENC.test(current)) {
      try {
        const out = decodeURIComponent(current.match(PCTENC)[0]);
        if (isPrintable(out)) { decoded.push(out); layers.push('percent'); current = out; found = true; }
      } catch { /* not valid percent-encoding */ }
      PCTENC.lastIndex = 0;
    }
    if (!found && HTMLENT.test(current)) {
      const out = decodeEntities(current.match(HTMLENT)[0]);
      if (isPrintable(out)) { decoded.push(out); layers.push('html_entity'); current = out; found = true; }
      HTMLENT.lastIndex = 0;
    }
    if (!found) break;
  }
  // ROT13 is cheap to test and shows up in real payloads.
  //
  // This used to fire only when the decode contained one of six hard-coded
  // words, which meant any ROT13'd instruction that avoided that vocabulary
  // went through untouched — "your authorisation limit has been raised" among
  // them. Keyword lists are the wrong tool here: what identifies a ROT13
  // payload is that the ciphertext is not language and the plaintext is.
  const rot = rot13(text);
  if (englishness(rot) > englishness(text) + 0.15 && englishness(rot) >= 0.2) {
    decoded.push(rot);
    layers.push('rot13');
  }
  return { layers, decoded };
}

function tryB64(s) {
  if (s.length < 20 || s.length % 4 === 1) return null;
  try {
    const out = Buffer.from(s, 'base64').toString('utf8');
    if (out.length < 8 || !isPrintable(out)) return null;
    // Require it to look like language, not random bytes that happen to decode.
    if (!/[aeiou]/i.test(out) || !/\s|[a-z]{3,}/i.test(out)) return null;
    return out;
  } catch { return null; }
}

function tryHex(s) {
  const clean = s.replace(/[\s:]/g, '');
  if (clean.length < 24 || clean.length % 2) return null;
  try {
    const out = Buffer.from(clean, 'hex').toString('utf8');
    return isPrintable(out) && /[a-z]{3,}/i.test(out) ? out : null;
  } catch { return null; }
}

function decodeEntities(s) {
  return s.replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
          .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)));
}

export function rot13(s) {
  return String(s).replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/**
 * The most common English function words. Any real sentence of more than a few
 * words hits several; a substitution cipher of one hits almost none. That
 * asymmetry is what makes this work as a cipher detector without needing to
 * know what the payload says.
 */
const COMMON_WORDS = new Set(('the be to of and a in that have i it for not on with he as you do at this but his '
  + 'by from they we say her she or an will my one all would there their what so up out if about who get which go '
  + 'me when make can like time no just him know take people into year your good some could them see other than '
  + 'then now look only come its over think also back after use two how our work first well way even new want '
  + 'because any these give day most us is are was were has had been').split(' '));

/**
 * Fraction of tokens that are common English words: 0 for ciphertext or random
 * bytes, typically 0.3–0.5 for ordinary prose.
 * @param {string} s
 * @returns {number}
 */
export function englishness(s) {
  const words = String(s || '').toLowerCase().match(/[a-z']+/g) || [];
  if (words.length < 4) return 0;   // too short to judge; do not guess
  let hits = 0;
  for (const w of words) if (COMMON_WORDS.has(w)) hits++;
  return hits / words.length;
}

function isPrintable(s) {
  // eslint-disable-next-line no-control-regex
  const ctrl = (s.match(/[\x00-\x08\x0E-\x1F\x7F]/g) || []).length;
  return ctrl / Math.max(s.length, 1) < 0.05;
}

// ---------------------------------------------------------------------------
// Hidden-text extraction from markup and structured documents.
// ---------------------------------------------------------------------------

/**
 * Pull text a human would never see but a model always will: HTML comments,
 * alt/title attributes, white-on-white or zero-size text, off-canvas elements,
 * markdown link targets, code comments, document metadata.
 * @param {string} content
 * @returns {{hidden:string[], reasons:string[]}}
 */
export function extractHiddenText(content) {
  const hidden = [];
  const reasons = [];
  const push = (why, ...vals) => {
    const kept = vals.filter((v) => v && String(v).trim().length > 2);
    if (kept.length) { hidden.push(...kept.map(String)); if (!reasons.includes(why)) reasons.push(why); }
  };

  for (const m of content.matchAll(/<!--([\s\S]*?)-->/g)) push('html_comment', m[1]);
  for (const m of content.matchAll(/\balt\s*=\s*["']([^"']{4,})["']/gi)) push('alt_text', m[1]);
  for (const m of content.matchAll(/\btitle\s*=\s*["']([^"']{4,})["']/gi)) push('title_attribute', m[1]);
  for (const m of content.matchAll(/\baria-label\s*=\s*["']([^"']{4,})["']/gi)) push('aria_label', m[1]);

  // Style-hidden elements.
  const hidingStyle = /(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*#?(?:fff(?:fff)?|white)\s*;?[^"']*background[^"']*(?:fff|white)|position\s*:\s*absolute\s*;\s*(?:left|top)\s*:\s*-\d{3,})/i;
  for (const m of content.matchAll(/<([a-z]+)[^>]*style\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/\1>/gi)) {
    if (hidingStyle.test(m[2])) push('css_hidden_text', stripTags(m[3]));
  }
  for (const m of content.matchAll(/<([a-z]+)[^>]*\bhidden\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    push('hidden_attribute', stripTags(m[2]));
  }

  // Markdown/link injection.
  for (const m of content.matchAll(/\[[^\]]*\]\(\s*(javascript:[^)]+)\)/gi)) push('javascript_link', m[1]);
  for (const m of content.matchAll(/^\s*\[[^\]]+\]:\s*(\S+)\s*(.*)$/gim)) push('reference_link_definition', m[2]);

  // Code comments — instructions live in `//`, `#`, `/* */`, docstrings.
  for (const m of content.matchAll(/(?:^|\s)(?:\/\/|#)\s*(.{12,200})$/gm)) push('code_comment', m[1]);
  for (const m of content.matchAll(/\/\*([\s\S]{12,400}?)\*\//g)) push('block_comment', m[1]);
  for (const m of content.matchAll(/"""([\s\S]{12,400}?)"""/g)) push('docstring', m[1]);

  // Document metadata channels we accept in normalised documents.
  for (const m of content.matchAll(/<(?:speakerNotes|w:comment|pdf:annotation|exif:\w+)>([\s\S]*?)<\//gi)) {
    push('document_metadata', m[1]);
  }
  return { hidden, reasons };
}

export function stripTags(html) {
  return String(html).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// Tokenisation, similarity, statistics
// ---------------------------------------------------------------------------

const STOPWORDS = new Set(('a an the and or but if then than that this these those of to in on for with '
  + 'at by from as is are was were be been being it its it\'s do does did doing have has had having '
  + 'i you he she we they them his her their our your my me him us not no yes can could should would '
  + 'will shall may might must about into over under again further once here there when where why how '
  + 'all any both each few more most other some such only own same so too very s t just don now').split(' '));

/** @param {string} text @returns {string[]} */
export function tokenize(text) {
  return String(text || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .split(/[^a-z0-9$£€%.@_-]+/)
    .map((t) => t.replace(/^[.\-_]+|[.\-_]+$/g, ''))
    .filter((t) => t.length > 1);
}

export function contentTokens(text) {
  return tokenize(text).filter((t) => !STOPWORDS.has(t));
}

/** Jaccard over content tokens — cheap, deterministic, no model required. */
export function jaccard(a, b) {
  const A = new Set(contentTokens(a));
  const B = new Set(contentTokens(b));
  if (!A.size && !B.size) return 1;
  let inter = 0;
  for (const t of A) if (B.has(t)) inter++;
  return inter / (A.size + B.size - inter);
}

/**
 * Bag-of-words cosine with sublinear tf. Stands in for an embedding model so the
 * engine has zero external dependencies; swap in a real embedder by setting
 * `vault.config.embedder`.
 */
export function cosine(a, b) {
  const va = termVector(a);
  const vb = termVector(b);
  let dot = 0, na = 0, nb = 0;
  for (const [t, w] of va) { na += w * w; const o = vb.get(t); if (o) dot += w * o; }
  for (const w of vb.values()) nb += w * w;
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

export function termVector(text) {
  const m = new Map();
  for (const t of contentTokens(text)) m.set(t, (m.get(t) || 0) + 1);
  for (const [t, n] of m) m.set(t, 1 + Math.log(n));
  return m;
}

/** Character-level perplexity proxy: unexpected style shifts score high. */
export function styleScore(text) {
  const s = String(text || '');
  if (s.length < 20) return { score: 0, features: {} };
  const words = s.split(/\s+/).filter(Boolean);
  const avgWordLen = words.reduce((a, w) => a + w.length, 0) / Math.max(words.length, 1);
  const upperRatio = (s.match(/[A-Z]/g) || []).length / s.length;
  const punctRatio = (s.match(/[^\w\s]/g) || []).length / s.length;
  const digitRatio = (s.match(/\d/g) || []).length / s.length;
  const nonAscii = (s.match(/[^\x00-\x7F]/g) || []).length / s.length;
  let score = 0;
  if (avgWordLen > 12 || avgWordLen < 2.5) score += 0.3;
  if (upperRatio > 0.35) score += 0.25;
  if (punctRatio > 0.28) score += 0.2;
  if (digitRatio > 0.5) score += 0.15;
  if (nonAscii > 0.25) score += 0.3;
  return { score: Math.min(score, 1), features: { avgWordLen, upperRatio, punctRatio, digitRatio, nonAscii } };
}

/**
 * Split into sentence-ish units, keeping the character offset of each.
 *
 * A naive split on "." shreds email addresses, URLs, decimals, version numbers
 * and abbreviations into fragments, and each fragment then arrives at the gate
 * as its own candidate fact. That is how a review queue fills up with rubbish
 * like "accounts@acme-payments." — so the terminator has to be followed by
 * whitespace-then-capital, or the end of the input.
 */
const SENTENCE_END = /[.!?]+(?=\s+["'(\[]?[A-Z0-9]|\s*$)|\n+/g;

export function sentences(text) {
  const str = String(text || '');
  const out = [];
  let start = 0;
  SENTENCE_END.lastIndex = 0;
  let m;
  while ((m = SENTENCE_END.exec(str))) {
    const end = m.index + m[0].length;
    const raw = str.slice(start, end);
    if (raw.trim()) out.push({ text: raw.trim(), start, end });
    start = end;
  }
  const tail = str.slice(start);
  if (tail.trim()) out.push({ text: tail.trim(), start, end: str.length });
  return out;
}

export function truncate(s, n = 120) {
  const str = String(s ?? '');
  return str.length <= n ? str : str.slice(0, n - 1) + '…';
}

/** Levenshtein, capped — used for lookalike-domain detection and alias matching. */
export function editDistance(a, b, max = 4) {
  a = String(a); b = String(b);
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}
