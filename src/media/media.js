/**
 * Images and audio as injection vectors (§5 Check 7).
 *
 * Attachments were sealed into the archive and then never looked at, so a PNG
 * carrying "ignore previous instructions" as pale grey text reached extraction
 * with the gate never having seen the words. Text is checked; pixels were not.
 * This closes that, with real codecs and real signal processing rather than a
 * stub that returns an empty string and lets everything through.
 *
 * WHAT THE OCR HERE ACTUALLY IS, precisely, because overstating it would be
 * worse than not having it:
 *
 *   It reads text that was RENDERED — drawn into a bitmap by software, in a
 *   regular grid-aligned bitmap font. That is exactly the shape of the attack
 *   it exists to stop: an attacker generating an image with hidden instructions
 *   uses a renderer, not a pen. Segmentation is by connected component and
 *   recognition is by template match against a built-in 5x7 font, scale-
 *   normalised, so the same glyphs at different sizes are read.
 *
 *   It does NOT read photographed text, handwriting, arbitrary typefaces, or
 *   rotated and warped text. A production deployment should put a real OCR
 *   engine behind `imageText` — the interface is one function — and this
 *   implementation is the zero-dependency floor, not a ceiling. `analyseImage`
 *   reports `engine` so a reviewer can see which one ran.
 *
 * The part that matters most is not the recognition at all: it is the contrast
 * normalisation in front of it. The attack is white-on-white, or #FEFEFE on
 * #FFFFFF — invisible to a human reviewing the document, perfectly ordinary
 * once the histogram is stretched. Anything thresholding at a fixed level
 * misses it entirely. And low contrast is itself reported as evidence, because
 * text nobody was meant to see is a stronger signal than the words.
 *
 * The audio side is unambiguously real DFT. An ultrasonic carrier is found by
 * measuring band energy above 16 kHz against the total, and a splice is found
 * from the discontinuity it leaves: an amplitude step no physical source
 * produces, plus a change in the noise floor either side of it.
 */
import { inflateSync, deflateSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { VaultError } from '../util/errors.js';

// ---------------------------------------------------------------------------
// A 5x7 bitmap font. Both the renderer and the recogniser use it, which is
// honest about what this reads: text drawn by software in a regular font.
// ---------------------------------------------------------------------------
const GLYPHS = {
  A: ['01110', '10001', '10001', '11111', '10001', '10001', '10001'],
  B: ['11110', '10001', '11110', '10001', '10001', '10001', '11110'],
  C: ['01111', '10000', '10000', '10000', '10000', '10000', '01111'],
  D: ['11110', '10001', '10001', '10001', '10001', '10001', '11110'],
  E: ['11111', '10000', '11110', '10000', '10000', '10000', '11111'],
  F: ['11111', '10000', '11110', '10000', '10000', '10000', '10000'],
  G: ['01111', '10000', '10000', '10011', '10001', '10001', '01111'],
  H: ['10001', '10001', '11111', '10001', '10001', '10001', '10001'],
  I: ['11111', '00100', '00100', '00100', '00100', '00100', '11111'],
  J: ['00111', '00010', '00010', '00010', '00010', '10010', '01100'],
  K: ['10001', '10010', '11100', '10100', '10010', '10010', '10001'],
  L: ['10000', '10000', '10000', '10000', '10000', '10000', '11111'],
  M: ['10001', '11011', '10101', '10101', '10001', '10001', '10001'],
  N: ['10001', '11001', '10101', '10101', '10011', '10001', '10001'],
  O: ['01110', '10001', '10001', '10001', '10001', '10001', '01110'],
  P: ['11110', '10001', '10001', '11110', '10000', '10000', '10000'],
  Q: ['01110', '10001', '10001', '10001', '10101', '10010', '01101'],
  R: ['11110', '10001', '10001', '11110', '10100', '10010', '10001'],
  S: ['01111', '10000', '10000', '01110', '00001', '00001', '11110'],
  T: ['11111', '00100', '00100', '00100', '00100', '00100', '00100'],
  U: ['10001', '10001', '10001', '10001', '10001', '10001', '01110'],
  V: ['10001', '10001', '10001', '10001', '10001', '01010', '00100'],
  W: ['10001', '10001', '10001', '10101', '10101', '11011', '10001'],
  X: ['10001', '10001', '01010', '00100', '01010', '10001', '10001'],
  Y: ['10001', '10001', '01010', '00100', '00100', '00100', '00100'],
  Z: ['11111', '00010', '00100', '01000', '10000', '10000', '11111'],
  0: ['01110', '10001', '10011', '10101', '11001', '10001', '01110'],
  1: ['00100', '01100', '00100', '00100', '00100', '00100', '01110'],
  2: ['01110', '10001', '00001', '00110', '01000', '10000', '11111'],
  3: ['11111', '00010', '00100', '00010', '00001', '10001', '01110'],
  4: ['00010', '00110', '01010', '10010', '11111', '00010', '00010'],
  5: ['11111', '10000', '11110', '00001', '00001', '10001', '01110'],
  6: ['00110', '01000', '10000', '11110', '10001', '10001', '01110'],
  7: ['11111', '00001', '00010', '00100', '01000', '01000', '01000'],
  8: ['01110', '10001', '10001', '01110', '10001', '10001', '01110'],
  9: ['01110', '10001', '10001', '01111', '00001', '00010', '01100'],
  '.': ['00000', '00000', '00000', '00000', '00000', '01100', '01100'],
  ',': ['00000', '00000', '00000', '00000', '01100', '01100', '11000'],
  '-': ['00000', '00000', '00000', '11111', '00000', '00000', '00000'],
  ':': ['00000', '01100', '01100', '00000', '01100', '01100', '00000'],
  '!': ['00100', '00100', '00100', '00100', '00100', '00000', '00100'],
  '?': ['01110', '10001', '00010', '00100', '00100', '00000', '00100'],
  "'": ['00100', '00100', '00000', '00000', '00000', '00000', '00000'],
  '/': ['00001', '00010', '00100', '00100', '01000', '10000', '10000']
};
const GLYPH_W = 5;
const GLYPH_H = 7;

// ---------------------------------------------------------------------------
// Rendering — used by tests and by anything that needs to produce a fixture.
// ---------------------------------------------------------------------------

/**
 * Draw text into an 8-bit greyscale bitmap.
 * @param {string} text
 * @param {{scale?:number, ink?:number, paper?:number, pad?:number}} [o]
 */
export function renderText(text, { scale = 1, ink = 0, paper = 255, pad = 2 } = {}) {
  const chars = [...String(text).toUpperCase()];
  const advance = (GLYPH_W + 1) * scale;
  const width = pad * 2 + chars.length * advance;
  const height = pad * 2 + GLYPH_H * scale;
  const pixels = new Uint8Array(width * height).fill(paper);
  chars.forEach((ch, i) => {
    const rows = GLYPHS[ch];
    if (!rows) return;                       // space and unknowns leave a gap
    for (let y = 0; y < GLYPH_H; y++) {
      for (let x = 0; x < GLYPH_W; x++) {
        if (rows[y][x] !== '1') continue;
        for (let sy = 0; sy < scale; sy++) {
          for (let sx = 0; sx < scale; sx++) {
            const px = pad + i * advance + x * scale + sx;
            const py = pad + y * scale + sy;
            pixels[py * width + px] = ink;
          }
        }
      }
    }
  });
  return { width, height, pixels };
}

// ---------------------------------------------------------------------------
// PNG — real, using node:zlib for the IDAT stream
// ---------------------------------------------------------------------------
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function crc32(buf) {
  let c = ~0;
  for (const b of buf) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (~c) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** @param {{width:number,height:number,pixels:Uint8Array}} img */
export function encodePng(img, { text = null } = {}) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(img.width, 0);
  ihdr.writeUInt32BE(img.height, 4);
  ihdr[8] = 8;      // bit depth
  ihdr[9] = 0;      // greyscale
  const raw = Buffer.alloc((img.width + 1) * img.height);
  for (let y = 0; y < img.height; y++) {
    raw[y * (img.width + 1)] = 0;                       // filter: none
    for (let x = 0; x < img.width; x++) raw[y * (img.width + 1) + 1 + x] = img.pixels[y * img.width + x];
  }
  const chunks = [PNG_SIG, chunk('IHDR', ihdr)];
  for (const [k, v] of Object.entries(text ?? {})) {
    chunks.push(chunk('tEXt', Buffer.concat([Buffer.from(k, 'latin1'), Buffer.from([0]), Buffer.from(String(v), 'latin1')])));
  }
  chunks.push(chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0)));
  return Buffer.concat(chunks);
}

function decodePng(buf) {
  let off = 8;
  let width = 0; let height = 0; let depth = 8; let colour = 0;
  const idat = [];
  const meta = {};
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.subarray(off + 4, off + 8).toString('ascii');
    const data = buf.subarray(off + 8, off + 8 + len);
    if (type === 'IHDR') {
      width = data.readUInt32BE(0); height = data.readUInt32BE(4); depth = data[8]; colour = data[9];
    } else if (type === 'IDAT') idat.push(data);
    else if (type === 'tEXt' || type === 'iTXt') {
      const nul = data.indexOf(0);
      if (nul > 0) {
        const key = data.subarray(0, nul).toString('latin1');
        // iTXt has compression flag/method and language tags between the key
        // and the text; skipping to the last NUL lands on the value either way.
        const rest = data.subarray(nul + 1);
        const start = type === 'iTXt' ? rest.lastIndexOf(0) + 1 : 0;
        meta[key] = rest.subarray(start).toString('utf8');
      }
    } else if (type === 'IEND') break;
    off += 12 + len;
  }
  if (!width || !height) throw new VaultError('invalid', 'unrecognised image: PNG has no usable IHDR');
  if (depth !== 8 || (colour !== 0 && colour !== 2 && colour !== 6)) {
    throw new VaultError('unsupported', `this PNG is bit depth ${depth} colour type ${colour}, which this decoder does not read`, { depth, colour });
  }
  const channels = colour === 0 ? 1 : colour === 2 ? 3 : 4;
  const stride = width * channels;
  const raw = inflateSync(Buffer.concat(idat));
  const out = new Uint8Array(width * height);
  const line = Buffer.alloc(stride);
  const prior = Buffer.alloc(stride);
  let p = 0;
  for (let y = 0; y < height; y++) {
    const filter = raw[p++];
    raw.copy(line, 0, p, p + stride);
    p += stride;
    // The five PNG filters, undone. Skipping these would decode most real
    // images as noise, and noise is what an attacker would hide behind.
    for (let i = 0; i < stride; i++) {
      const a = i >= channels ? line[i - channels] : 0;
      const b = prior[i];
      const c = i >= channels ? prior[i - channels] : 0;
      switch (filter) {
        case 1: line[i] = (line[i] + a) & 0xff; break;
        case 2: line[i] = (line[i] + b) & 0xff; break;
        case 3: line[i] = (line[i] + ((a + b) >> 1)) & 0xff; break;
        case 4: {
          const pa = Math.abs(b - c); const pb = Math.abs(a - c); const pc = Math.abs(a + b - 2 * c);
          line[i] = (line[i] + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c)) & 0xff;
          break;
        }
        default: break;
      }
    }
    line.copy(prior);
    for (let x = 0; x < width; x++) {
      const i = x * channels;
      out[y * width + x] = channels === 1 ? line[i]
        : Math.round(0.299 * line[i] + 0.587 * line[i + 1] + 0.114 * line[i + 2]);
    }
  }
  return { width, height, pixels: out, metadata: meta, format: 'png' };
}

// ---------------------------------------------------------------------------
// BMP — uncompressed 8-bit and 24-bit, bottom-up
// ---------------------------------------------------------------------------
export function encodeBmp(img) {
  const rowSize = Math.ceil(img.width / 4) * 4;
  const pixelBytes = rowSize * img.height;
  const paletteSize = 256 * 4;
  const offset = 14 + 40 + paletteSize;
  const buf = Buffer.alloc(offset + pixelBytes);
  buf.write('BM', 0, 'ascii');
  buf.writeUInt32LE(buf.length, 2);
  buf.writeUInt32LE(offset, 10);
  buf.writeUInt32LE(40, 14);
  buf.writeInt32LE(img.width, 18);
  buf.writeInt32LE(img.height, 22);
  buf.writeUInt16LE(1, 26);
  buf.writeUInt16LE(8, 28);
  buf.writeUInt32LE(pixelBytes, 34);
  buf.writeUInt32LE(256, 46);
  for (let i = 0; i < 256; i++) {
    const p = 54 + i * 4;
    buf[p] = i; buf[p + 1] = i; buf[p + 2] = i; buf[p + 3] = 0;
  }
  for (let y = 0; y < img.height; y++) {
    const srcY = img.height - 1 - y;             // BMP rows run bottom-up
    for (let x = 0; x < img.width; x++) buf[offset + y * rowSize + x] = img.pixels[srcY * img.width + x];
  }
  return buf;
}

function decodeBmp(buf) {
  const offset = buf.readUInt32LE(10);
  const width = buf.readInt32LE(18);
  const height = Math.abs(buf.readInt32LE(22));
  const topDown = buf.readInt32LE(22) < 0;
  const bpp = buf.readUInt16LE(28);
  if (bpp !== 8 && bpp !== 24 && bpp !== 32) {
    throw new VaultError('unsupported', `this BMP is ${bpp} bits per pixel, which this decoder does not read`, { bpp });
  }
  const bytes = bpp / 8;
  const rowSize = Math.ceil((width * bytes) / 4) * 4;
  const out = new Uint8Array(width * height);
  for (let y = 0; y < height; y++) {
    const srcRow = topDown ? y : height - 1 - y;
    for (let x = 0; x < width; x++) {
      const p = offset + srcRow * rowSize + x * bytes;
      out[y * width + x] = bpp === 8 ? buf[p]
        : Math.round(0.114 * buf[p] + 0.587 * buf[p + 1] + 0.299 * buf[p + 2]);
    }
  }
  return { width, height, pixels: out, metadata: {}, format: 'bmp' };
}

/** @returns {{width:number,height:number,pixels:Uint8Array,metadata:object,format:string}} */
export function decodeImage(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length >= 8 && buf.subarray(0, 8).equals(PNG_SIG)) return decodePng(buf);
  if (buf.length >= 54 && buf[0] === 0x42 && buf[1] === 0x4d) return decodeBmp(buf);
  throw new VaultError('unsupported',
    'unrecognised image format — only PNG and BMP are decoded here, and an attachment that cannot be read cannot be cleared',
    { magic: buf.subarray(0, 4).toString('hex') });
}

// ---------------------------------------------------------------------------
// OCR
// ---------------------------------------------------------------------------

/**
 * Read text out of a bitmap.
 *
 * The order matters: measure contrast first (because low contrast is evidence),
 * then stretch the histogram, then binarise, then segment, then recognise. A
 * fixed threshold applied first would erase the attack before anything looked
 * at it.
 */
export function imageText(img) {
  const { width, height, pixels } = img;
  if (!width || !height) return { text: '', confidence: 0, lowContrast: false, contrastRatio: 1, glyphs: 0 };

  let min = 255; let max = 0;
  for (const v of pixels) { if (v < min) min = v; if (v > max) max = v; }
  const spread = max - min;
  // WCAG-style ratio on the two extremes present in the image.
  const lum = (v) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
  const contrastRatio = (lum(max) + 0.05) / (lum(min) + 0.05);
  // A single level of difference is not a rounding artefact, it is the
  // attack: #FEFEFE on #FFFFFF. Only a genuinely uniform image has no text.
  if (spread < 1) return { text: '', confidence: 0, lowContrast: false, contrastRatio: 1, glyphs: 0 };

  // Stretch, then split at the midpoint. Ink is whichever side is rarer —
  // that makes light-on-dark work without a special case.
  const norm = new Uint8Array(pixels.length);
  for (let i = 0; i < pixels.length; i++) norm[i] = Math.round(((pixels[i] - min) / spread) * 255);
  let dark = 0;
  for (const v of norm) if (v < 128) dark++;
  const inkIsDark = dark <= norm.length / 2;
  const on = (i) => (inkIsDark ? norm[i] < 128 : norm[i] >= 128);

  // Column-profile segmentation: a rendered line of text has blank columns
  // between glyphs. Cheap, and exactly right for the rendered case.
  const colHas = new Array(width).fill(false);
  const rowHas = new Array(height).fill(false);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (!on(y * width + x)) continue;
      colHas[x] = true; rowHas[y] = true;
    }
  }
  const top = rowHas.indexOf(true);
  const bottom = rowHas.lastIndexOf(true);
  if (top < 0) return { text: '', confidence: 0, lowContrast: false, contrastRatio, glyphs: 0 };

  const boxes = [];
  let start = -1;
  for (let x = 0; x <= width; x++) {
    if (x < width && colHas[x]) { if (start < 0) start = x; continue; }
    if (start >= 0) { boxes.push([start, x - 1]); start = -1; }
  }

  // A gap wider than a glyph is a space.
  const glyphWidth = boxes.length ? median(boxes.map(([a, b]) => b - a + 1)) : GLYPH_W;
  let text = '';
  let matched = 0;
  for (const [i, [x0, x1]] of boxes.entries()) {
    if (i > 0 && x0 - boxes[i - 1][1] - 1 > Math.max(2, glyphWidth * 0.8)) text += ' ';
    const guess = recognise(norm, width, x0, x1, top, bottom, on);
    if (guess) { text += guess; matched++; } else text += '?';
  }
  return {
    text: text.trim(),
    confidence: boxes.length ? matched / boxes.length : 0,
    glyphs: boxes.length,
    // 3:1 is the WCAG floor for large text. Below that, in an image that
    // contains words, someone was hiding something.
    lowContrast: contrastRatio < 3,
    contrastRatio: Math.round(contrastRatio * 100) / 100,
    engine: 'builtin-5x7-template'
  };
}

/** Scale the candidate to the 5x7 cell and pick the best-matching glyph. */
function recognise(norm, width, x0, x1, y0, y1, on) {
  const w = x1 - x0 + 1;
  const h = y1 - y0 + 1;
  const cell = new Array(GLYPH_H);
  for (let gy = 0; gy < GLYPH_H; gy++) {
    cell[gy] = new Array(GLYPH_W);
    for (let gx = 0; gx < GLYPH_W; gx++) {
      // Area-average the source region for this cell, so a glyph drawn at 3x
      // reduces to the same 5x7 pattern as one drawn at 1x.
      const sx0 = x0 + Math.floor((gx * w) / GLYPH_W);
      const sx1 = x0 + Math.max(Math.floor(((gx + 1) * w) / GLYPH_W), Math.floor((gx * w) / GLYPH_W) + 1);
      const sy0 = y0 + Math.floor((gy * h) / GLYPH_H);
      const sy1 = y0 + Math.max(Math.floor(((gy + 1) * h) / GLYPH_H), Math.floor((gy * h) / GLYPH_H) + 1);
      let lit = 0; let total = 0;
      for (let y = sy0; y < sy1; y++) {
        for (let x = sx0; x < sx1; x++) { total++; if (on(y * width + x)) lit++; }
      }
      cell[gy][gx] = total && lit / total >= 0.4 ? 1 : 0;
    }
  }
  let best = null; let bestScore = 0;
  for (const [ch, rows] of Object.entries(GLYPHS)) {
    let same = 0;
    for (let y = 0; y < GLYPH_H; y++) {
      for (let x = 0; x < GLYPH_W; x++) if ((rows[y][x] === '1' ? 1 : 0) === cell[y][x]) same++;
    }
    const score = same / (GLYPH_W * GLYPH_H);
    if (score > bestScore) { bestScore = score; best = ch; }
  }
  return bestScore >= 0.8 ? best : null;
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)] : 0;
}

/**
 * Everything an image can say, run through Check 7.
 *
 * Pixels AND metadata: a tEXt chunk is never rendered, is invisible in any
 * viewer, and is therefore a better hiding place than the image itself.
 */
export function analyseImage(bytes, { detector, name = 'image' } = {}) {
  const sources = [];
  let img;
  try {
    img = decodeImage(bytes);
  } catch (e) {
    // An attachment that cannot be read cannot be cleared. Holding is the only
    // safe answer; waving it through is how a format the decoder does not know
    // becomes the bypass.
    return {
      name, hold: true, score: 1, text: '', sources: [], engine: null,
      reasons: [`the attachment "${name}" could not be decoded (${e.message}) — an image that cannot be read cannot be checked for hidden instructions`]
    };
  }

  const ocr = imageText(img);
  const parts = [];
  if (ocr.text) { parts.push(ocr.text); sources.push('pixels'); }
  for (const [k, v] of Object.entries(img.metadata ?? {})) {
    if (!String(v).trim()) continue;
    parts.push(String(v));
    sources.push(`metadata:${k}`);
  }
  const text = parts.join('\n');
  const verdict = text ? detector.analyse(text, { source: 'attachment' }) : { verdict: 'pass', score: 0 };

  const reasons = [...(verdict.reasons ?? verdict.explanation ? [verdict.explanation].filter(Boolean) : [])];
  let score = verdict.score ?? 0;
  let hold = verdict.verdict === 'hold' || verdict.verdict === 'block';
  if (text && ocr.lowContrast) {
    // Hidden text is evidence in itself, independent of what it says: nobody
    // renders a legitimate caption at a 1.05:1 contrast ratio.
    score = Math.min(1, score + 0.5);
    hold = hold || score >= 0.5;
    reasons.push(`text in "${name}" is rendered at a contrast ratio of ${ocr.contrastRatio}:1 — effectively invisible, which is not how legitimate captions are drawn`);
  }
  if (text && sources.includes('pixels')) {
    reasons.push(`text recovered from the pixels of "${name}" was checked as if it had been typed into the conversation`);
  }
  return {
    name, hold, score, text, sources, engine: ocr.engine,
    contrastRatio: ocr.contrastRatio, lowContrast: ocr.lowContrast,
    confidence: ocr.confidence, reasons,
    sha256: createHash('sha256').update(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)).digest('hex')
  };
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

/** Synthesise PCM. Used for fixtures; also the reference for what "clean" is. */
export function synthesise({ seconds, sampleRate, tones = [], noise = 0, phase = 0 }) {
  const n = Math.floor(seconds * sampleRate);
  const out = new Float32Array(n);
  // A fixed LCG rather than Math.random, so a "noisy" fixture is reproducible
  // and a flaky detector cannot hide behind a lucky seed.
  let seed = 12345;
  const rand = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return (seed / 0x7fffffff) * 2 - 1; };
  for (let i = 0; i < n; i++) {
    let v = 0;
    for (const t of tones) v += t.amp * Math.sin(2 * Math.PI * t.hz * (i / sampleRate) + phase);
    if (noise) v += rand() * noise;
    out[i] = Math.max(-1, Math.min(1, v));
  }
  return out;
}

export function encodeWav(samples, sampleRate) {
  const n = samples.length;
  const buf = Buffer.alloc(44 + n * 2);
  buf.write('RIFF', 0, 'ascii');
  buf.writeUInt32LE(36 + n * 2, 4);
  buf.write('WAVE', 8, 'ascii');
  buf.write('fmt ', 12, 'ascii');
  buf.writeUInt32LE(16, 16);
  buf.writeUInt16LE(1, 20);            // PCM
  buf.writeUInt16LE(1, 22);            // mono
  buf.writeUInt32LE(sampleRate, 24);
  buf.writeUInt32LE(sampleRate * 2, 28);
  buf.writeUInt16LE(2, 32);
  buf.writeUInt16LE(16, 34);
  buf.write('data', 36, 'ascii');
  buf.writeUInt32LE(n * 2, 40);
  for (let i = 0; i < n; i++) buf.writeInt16LE(Math.round(Math.max(-1, Math.min(1, samples[i])) * 32767), 44 + i * 2);
  return buf;
}

export function decodeWav(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length < 44 || buf.subarray(0, 4).toString('ascii') !== 'RIFF' || buf.subarray(8, 12).toString('ascii') !== 'WAVE') {
    throw new VaultError('unsupported', 'not a RIFF/WAVE file');
  }
  let off = 12; let fmt = null; let data = null;
  while (off + 8 <= buf.length) {
    const id = buf.subarray(off, off + 4).toString('ascii');
    const size = buf.readUInt32LE(off + 4);
    if (id === 'fmt ') {
      fmt = { format: buf.readUInt16LE(off + 8), channels: buf.readUInt16LE(off + 10), sampleRate: buf.readUInt32LE(off + 12), bits: buf.readUInt16LE(off + 22) };
    } else if (id === 'data') {
      data = buf.subarray(off + 8, Math.min(off + 8 + size, buf.length));
    }
    off += 8 + size + (size % 2);
  }
  if (!fmt || !data) throw new VaultError('unsupported', 'the WAVE file has no fmt or data chunk');
  if (fmt.format !== 1 || fmt.bits !== 16) {
    throw new VaultError('unsupported', `only 16-bit PCM is decoded here; this is format ${fmt.format} at ${fmt.bits} bits`, fmt);
  }
  const frames = Math.floor(data.length / 2 / fmt.channels);
  const samples = new Float32Array(frames);
  for (let i = 0; i < frames; i++) samples[i] = data.readInt16LE(i * 2 * fmt.channels) / 32768;
  return { sampleRate: fmt.sampleRate, channels: fmt.channels, samples };
}

/** Goertzel: energy at one frequency, without a full FFT. */
function goertzel(samples, sampleRate, hz, from, to) {
  const k = (2 * Math.PI * hz) / sampleRate;
  const coeff = 2 * Math.cos(k);
  let s1 = 0; let s2 = 0;
  for (let i = from; i < to; i++) {
    const s = samples[i] + coeff * s1 - s2;
    s2 = s1; s1 = s;
  }
  return s1 * s1 + s2 * s2 - coeff * s1 * s2;
}

/**
 * Ultrasonic detection.
 *
 * Energy in the band above 16 kHz measured against energy in the audible band,
 * so the threshold is a ratio rather than an absolute level — a loud recording
 * and a quiet one give the same answer. Reported as `inspectable: false` when
 * the sample rate is too low to contain the band at all, because "clean" would
 * be a false assurance for 8 kHz telephony audio.
 */
function detectUltrasonic(samples, sampleRate) {
  const nyquist = sampleRate / 2;
  if (nyquist <= 16000) {
    return {
      detected: false, inspectable: false, energyRatio: 0, peakHz: null,
      note: `the sample rate is ${sampleRate} Hz, so there is no content above 16 kHz to inspect — this audio is not evidence of absence`
    };
  }
  const n = Math.min(samples.length, sampleRate);      // one second is plenty

  // A Hann window before the transform. Without it, the discontinuity at the
  // ends of the analysis block smears energy across every bin, and a loud
  // 300 Hz tone shows up as substantial "ultrasonic" content — which is
  // exactly the false positive that would get this control switched off.
  const windowed = new Float32Array(n);
  let total = 0;
  for (let i = 0; i < n; i++) {
    const w = 0.5 * (1 - Math.cos((2 * Math.PI * i) / (n - 1)));
    windowed[i] = samples[i] * w;
    total += windowed[i] * windowed[i];
  }
  if (total <= 0) return { detected: false, inspectable: true, energyRatio: 0, peakHz: null };

  // Goertzel gives |X(k)|^2 for a length-n block; dividing by n^2/4 converts it
  // to the squared amplitude of a sinusoid at that frequency, which is
  // comparable with the mean square of the signal.
  const scale = (n * n) / 4;
  let ultra = 0; let peak = 0; let peakHz = null;
  for (let hz = 16500; hz < nyquist - 500; hz += 250) {
    const e = goertzel(windowed, sampleRate, hz, 0, n) / scale;
    ultra += e;
    if (e > peak) { peak = e; peakHz = hz; }
  }
  const meanSquare = total / n;
  const ratio = meanSquare > 0 ? ultra / (2 * meanSquare) : 0;
  return {
    // 1% of audible-band energy. A real microphone's ultrasonic noise floor is
    // far below this; a carrier loud enough to survive transcoding is far above.
    detected: ratio > 0.01,
    inspectable: true,
    energyRatio: Math.round(ratio * 10000) / 10000,
    peakHz: ratio > 0.01 ? peakHz : null
  };
}

/**
 * Splice detection.
 *
 * A cut leaves two signatures at the same instant: the waveform steps by more
 * than a physical source could in one sample period, and the noise floor
 * changes either side. Requiring both is what keeps ordinary silence, plosives
 * and clipping from firing it.
 */
function detectSplices(samples, sampleRate) {
  const win = Math.max(64, Math.floor(sampleRate * 0.02));       // 20 ms
  const at = [];
  const rmsOf = (from, to) => {
    let s = 0; let n = 0;
    for (let i = Math.max(0, from); i < Math.min(samples.length, to); i++) { s += samples[i] * samples[i]; n++; }
    return n ? Math.sqrt(s / n) : 0;
  };

  const overall = rmsOf(0, samples.length);
  if (overall < 1e-6) return { detected: false, at: [], count: 0 };

  // The reference step size is taken from the ACTIVE part of the recording.
  // Measuring it across the whole file lets leading and trailing silence
  // collapse the median to zero, after which every ordinary waveform slope
  // looks like a discontinuity — which is how silence-padded voicemail gets
  // reported as an edit.
  const steps = [];
  for (let i = 1; i < samples.length; i++) {
    if (Math.abs(samples[i]) < overall * 0.1 && Math.abs(samples[i - 1]) < overall * 0.1) continue;
    steps.push(Math.abs(samples[i] - samples[i - 1]));
  }
  const typical = median(steps);
  const jumpThreshold = Math.max(0.05, typical * 6);

  for (let i = win; i < samples.length - win; i++) {
    const jump = Math.abs(samples[i] - samples[i - 1]);
    if (jump < jumpThreshold) continue;
    const before = rmsOf(i - win, i);
    const after = rmsOf(i, i + win);
    // Speech starting or stopping is not a splice. A splice joins two pieces
    // of audio that both have content; a recording that fades to silence and
    // back is the ordinary shape of a voicemail.
    if (before < overall * 0.2 || after < overall * 0.2) continue;
    const floorChange = Math.abs(after - before) / Math.max(before, after, 1e-6);
    // Both signals, at the same place. Either alone is ordinary audio.
    if (floorChange > 0.35) {
      const t = Math.round((i / sampleRate) * 1000) / 1000;
      if (!at.some((x) => Math.abs(x - t) < 0.05)) at.push(t);
    }
  }
  return { detected: at.length > 0, at, count: at.length };
}

/** Everything an audio attachment can be checked for before its transcript is trusted. */
export function analyseAudio(bytes, { name = 'audio' } = {}) {
  let decoded;
  try {
    decoded = decodeWav(bytes);
  } catch (e) {
    return {
      name, hold: true, reasons: [`the attachment "${name}" could not be decoded (${e.message}) — audio that cannot be inspected cannot be cleared for transcription`],
      ultrasonic: { detected: false, inspectable: false }, splices: { detected: false, at: [] }, notes: []
    };
  }
  const { samples, sampleRate } = decoded;
  const ultrasonic = detectUltrasonic(samples, sampleRate);
  const splices = detectSplices(samples, sampleRate);
  const reasons = [];
  const notes = [];
  if (ultrasonic.note) notes.push(ultrasonic.note);
  if (ultrasonic.detected) {
    reasons.push(`"${name}" carries ultrasonic content at ${ultrasonic.peakHz} Hz holding ${(ultrasonic.energyRatio * 100).toFixed(1)}% of the audible-band energy — inaudible to anyone in the room, but present in what a transcription model hears`);
  }
  if (splices.detected) {
    reasons.push(`"${name}" contains ${splices.count} discontinuit${splices.count === 1 ? 'y' : 'ies'} at ${splices.at.join('s, ')}s where both the waveform and the noise floor step — the signature of an edit, so the transcript is not a record of one continuous conversation`);
  }
  return {
    name, hold: ultrasonic.detected || splices.detected,
    ultrasonic, splices, reasons, notes,
    durationSeconds: Math.round((samples.length / sampleRate) * 1000) / 1000,
    sampleRate
  };
}

/** Route an attachment to the right analyser. */
export function analyseAttachment(attachment, { detector }) {
  const { name = 'attachment', mime = '', content } = attachment ?? {};
  if (content == null) return null;
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const isImage = /^image\//.test(mime) || /\.(png|bmp|jpe?g|gif|webp)$/i.test(name);
  const isAudio = /^audio\//.test(mime) || /\.(wav|mp3|m4a|ogg|flac)$/i.test(name);
  if (isImage) return { kind: 'image', ...analyseImage(bytes, { detector, name }) };
  if (isAudio) return { kind: 'audio', ...analyseAudio(bytes, { name }) };
  return null;
}
