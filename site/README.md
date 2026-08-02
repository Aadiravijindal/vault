# The marketing site

Three files. No build step, no framework, no dependency, nothing fetched from a third
party — open `index.html` and it works, including offline.

```bash
python3 -m http.server -d site 4000
```

Deploy by copying `site/` anywhere that serves static files.

---

## The page

| | |
|---|---|
| Hero | mark, headline, the three sentences, two calls to action |
| Ticker | the claims, on a loop |
| The problem | four numbered failures of ungoverned agent memory |
| Introducing Vault | the write pipeline, drawn; four properties |
| Our approach | three steps, then where the time actually goes |
| Capabilities | six, numbered; four numbers underneath |
| Engineered evidence | the five proof layers, and a terminal showing eight attacks stopped |
| What Vault does not do | the limits |
| FAQ | six, native `<details>`, works with no JavaScript |
| Closer | the ask, over a perspective horizon |

---

## The brand

| | | |
|---|---|---|
| `--black` | `#070402` | the field the mark sits in |
| `--black-2` | `#0d0603` | section ground, a shade warmer |
| `--black-3` | `#150a05` | raised surfaces |
| `--ember` | `#7a1a05` | where black meets fire |
| `--flame` | `#d63b06` | mid burn |
| **`--orange`** | **`#ff6a13`** | **the brand orange** |
| `--orange-2` | `#ff8c2b` | highlight |
| `--glow` | `#ffa64d` | the hottest edge |

**One rule worth knowing:** white text on `--orange` is **2.87:1** and fails WCAG AA.
Every orange surface carries near-black text (`#1a0a02`, 6.9:1). `npm test` enforces it,
along with every other text colour against every section ground.

---

## Motion, and why none of it is a video

Every section has its own animated ground: a drifting bloom, a surveillance sweep, a
rotating ember field, creeping rules, a breathing dot field, a travelling chain, and a
perspective horizon. Fifteen animations, all CSS.

A background video would be 5–20MB per loop, decode on the main thread on cheap phones,
need a poster frame for first paint, could not be recoloured when the brand shifts, and
**could not honour `prefers-reduced-motion`** without JavaScript that has to load first.
This is a few kilobytes, paints immediately, tints from the brand tokens, and stops dead
for anyone who has asked it to — one media query at the end of the stylesheet, using the
universal selector so the sixteenth animation is covered the day it is added.

Every animated layer is absolutely positioned, `aria-hidden`, behind its content and at
low opacity, so none of it can reduce the contrast of any text. There is a test.

### The hero, measured

The first gradient in the bloom stack is a shadow pocket under the content. It is not
decoration. Measured in a browser with the text hidden, white on the bare bloom fell to
**2.24:1** at the right end of the headline — under the 3:1 AA asks of large text, and it
*looked* fine, which is the point. With the pocket it is **5.03:1** at the worst of three
viewports. If you move the bloom, measure it again.

---

## The mark

Seven blobs joined by concave necks — a metaball. The joins are circular fillets tangent
to both blobs, which is what gives the shape its pinched, liquid quality.

`site/mark.mjs` **solves** those fillets rather than drawing them:

```bash
node site/mark.mjs         # the path data
node site/mark.mjs --svg   # a whole SVG, for checking
```

Eyeing the tangents gets something that looks nearly right at poster size and visibly
wrong at 24px, because a fraction of a degree of error puts a kink in the neck. Both SVG
arc flags are derived from the geometry too — the first attempt guessed them and produced
crescents, because the blob arcs took the short way between tangent points and cut
straight through the blob.

The alternative was an `feGaussianBlur` + `feColorMatrix` "gooey" filter, which fakes the
same effect. Rejected: a filter cannot go in a favicon data URI, costs a compositing pass
on every paint, and renders differently across browsers.

**If you change the geometry, re-run the generator and paste the path into
`index.html`.** A test compares the two and fails if they drift — which it did, the first
time, catching a stale path that had been left behind after the generator was fixed.

This is still a **reconstruction** from the supplied render. Drop the original in over the
`<symbol>` contents when you have it; nothing else needs to change.

---

## What is checked

`test/site.test.js` runs with the rest of the suite and needs no browser:

- the headline and its three sentences are exactly as approved, matched against the
  *rendered text* so a line break cannot change them
- every number on the page matches the product
- every nav link points at a section that exists
- every text colour clears WCAG AA against every ground, by calculation
- button text on orange is dark, never white
- the mark in the page is byte-identical to the generator's output, is made only of
  arcs, and uses both sweep directions (so the necks are actually concave)
- every band has an animated ground, and every decorative layer is `aria-hidden`
- one media query stops all the motion, and nothing is a `<video>`
- content that hides itself for scroll-reveal has a **deadline and a print path** — it
  once rendered the whole page blank below the hero in a renderer that never scrolls
- the FAQ opens with no JavaScript, and nothing loads from a third-party host
