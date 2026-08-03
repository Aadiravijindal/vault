# The marketing site

Five files: `index.html`, `styles.css`, `app.js`, `hero.webm`, and the mark generator.
No build step, no framework, no dependency, nothing fetched from a third party — open
`index.html` and it works, including offline.

```bash
python3 -m http.server -d site 4000
```

Deploy by copying `site/` anywhere that serves static files.

`mark.mjs` and `video.mjs` are **build-time tools**. They are not shipped, not imported by
the page, and not needed to serve it. They regenerate two committed artefacts: the logo
path and the hero footage.

---

## The page

| | |
|---|---|
| Header | menu left, mark centred, contact right |
| Hero | generated footage, the headline, the three sentences, two calls to action |
| Ticker | the claims, on a loop |
| The problem | four numbered failures of ungoverned agent memory |
| Introducing Vault | the write pipeline, drawn; four properties |
| Our approach | three steps, then where the time actually goes |
| Capabilities | six, numbered; four counters underneath |
| Engineered evidence | the five proof layers, and a terminal showing eight attacks stopped |
| Partners | HKU |
| What Vault does not do | the limits |
| FAQ | six, native `<details>`, works with no JavaScript |
| Closer | the ask, over a perspective horizon |

The menu is a full-screen drawer. Closed, it is genuinely `hidden` rather than
transparent — a menu that is only `opacity:0` still puts eight links in the tab order.

---

## The brand

| | | |
|---|---|---|
| `--black` | `#07040a` | the field the mark sits in |
| `--black-2` | `#0b0509` | section ground |
| `--black-3` | `#140a10` | raised surfaces |
| `--ember` | `#7a1a05` | where black meets fire |
| `--flame` | `#d63b06` | mid burn |
| **`--orange`** | **`#ff6a13`** | **the brand orange** |
| `--orange-2` | `#ff8c2b` | highlight |
| `--glow` | `#ffa64d` | the hottest edge |
| `--cyan` | `#3ff2ff` | grid lines and machine chrome **only** |

**Two rules worth knowing.**

White text on `--orange` is **2.87:1** and fails WCAG AA. Every orange surface carries
near-black text (`#1a0a02`, 6.9:1).

Cyan never sets the colour of a real element. It is for hairlines, grid lines and HUD
chrome, plus the glitch layer's chromatic-aberration copy — which lives on a
pseudo-element and is clipped out of sight for all but a few frames in five seconds. Two
saturated colours competing means neither leads.

`npm test` enforces both, along with every text colour against every section ground.

---

## Cyberpunk, but not costume

The vocabulary is a system you are watching run: mono type for anything a machine would
say, hairline rules, HUD readouts, corner ticks, scan sweeps, and glitch on exactly two
headlines — the hero and the closer. Two, because a page where everything glitches reads
as broken rather than deliberate.

Square corners throughout. The orange stays the only saturated colour.

---

## Motion

The hero carries real footage. **Everything below it is CSS**: a surveillance sweep,
creeping rules, a breathing dot field, a travelling chain, a perspective horizon.

Per-section video would be tens of megabytes, decode on the main thread on cheap phones,
could not be recoloured when the brand shifts, and **could not honour
`prefers-reduced-motion`** without JavaScript that has to load first. CSS stops dead for
anyone who has asked it to — one media query at the end of the stylesheet, using the
universal selector, so the sixteenth animation is covered the day it is added.

Every animated layer is absolutely positioned, `aria-hidden`, behind its content and at
low opacity, so none of it can reduce the contrast of any text. There is a test.

Scroll reveal, the counters and the progress bar are additive: the classes are added by
script or not at all, so no JavaScript means visible, not blank.

---

## The hero footage

```bash
node site/video.mjs                                  # 1280x720, 24fps, 8s
node site/video.mjs --w 960 --h 540 --seconds 6
```

**An open-plan office, late.** Ceiling strips receding down the aisle, desks and chairs
either side, the city out of focus through the far glass, dust turning in the light. The
camera drifts forward. **Nobody is there** — which is the point, because the thing this
product governs runs when nobody is.

The vanishing point sits right of centre and the near-left desks stay in shadow, because
the copy lands in the bottom-left corner and has to sit on quiet ground. The composition
and the layout are one decision, not two.

Licensed stock footage of somebody else's office was the alternative. It cannot be
recoloured when the brand shifts, cannot be composed around the copy, and has to be
licensed for every place the site is served.

### The old-film pass

Applied to the whole frame after the room is drawn, in the order it happens in reality —
**grade first, damage second**, because the other way round tints the scratches:

| | |
|---|---|
| Grade | a `color` composite into the brand orange, then an `overlay` gradient ember→orange→violet |
| Gate weave | the frame wanders in the gate; integer frequencies only, so the wander closes its own loop |
| Lamp flicker | the exposure is never perfectly even |
| Grain | rendered at 320px wide and scaled up with smoothing off — real grain is clumped, and a 1:1 noise field costs eight times as much to look like digital noise instead |
| Scratches | vertical, alive for a run of frames, then the print moves on |
| Dust | specks on the print, light and dark, new every frame |
| Halation | the bloom old stock puts around every highlight |

Frames are drawn in headless Chromium on a 2D canvas at a fixed timestep and piped
straight into ffmpeg, so nothing large is ever held in memory or written between the two.
Everything in the scene is a function of `t ∈ [0,1)` rather than of a frame counter, which
is what makes the loop seamless: at `t=1` every position and phase is back where it
started.

Two things about the encoder are worth knowing before you change the pipeline, because
both presented as a **hang rather than an error**:

- frames go in as **JPEG**, because the ffmpeg that ships with Playwright is built
  `--disable-everything` and has exactly two video decoders, `mjpeg` and `libvpx`. Hand it
  a PNG and it exits before the first frame.
- the input is **`pipe:0`**, not `-`. The same build has an explicit protocol allowlist,
  and the `-` shorthand resolves to no protocol at all.

In both cases ffmpeg dies immediately, every subsequent write lands on a dead pipe, and
the render parks forever. `video.mjs` now keeps the tail of ffmpeg's stderr and treats an
already-closed encoder as a reason to stop, so the next such failure prints instead.

### How the page loads it

`preload="none"` and no `src` in the markup — the browser must not fetch it before anyone
has decided it is wanted. `app.js` sets the source only when motion is not reduced, the
connection is not metered, and `effectiveType` is not 2g; it reveals the video only on
`canplay`.

Underneath, a canvas draws the same room live — the aisle, the ceiling strips, the desks
and the far glass, without the chairs, the monitors, the scratches or the grain, because it
has to paint in a single frame on a phone. It is a stand-in for the two seconds before the video plays, not a second
implementation of it, and the composition matches so the crossfade is not a cut. There is
never a black rectangle and never a stalled first frame. It stops when the hero scrolls out of view or the tab is
hidden — a `requestAnimationFrame` loop running behind eight sections of content is a
battery bug, not a design decision. Under reduced motion it paints exactly one frame: the
composition is still there, it simply holds still.

### The hero, measured

The copy sits in the **bottom-left corner**, and the scrim's dark pocket sits there with
it, while the brand burns in from the top right — which is where the footage's vanishing
point and its brightest thing, the far windows, happen to be.

The scrim is not decoration. Measured in a browser with the text hidden, white on the bare
footage fell to **2.24:1** behind the headline — under the 3:1 AA asks of large text, and
it *looked* fine, which is the point. With the scrim in place and the copy in the quiet
corner, the worst of 135 samples across three viewports is **14.08:1**. If you move the
copy, the scrim, or the composition, measure it again.

The hero's grid uses `align-content:end` and `justify-items:start` rather than absolute
positioning, so a right-to-left locale mirrors the whole layout for free.

---

## The mark

Seven blobs joined by concave necks — a metaball. The joins are circular fillets tangent to
both blobs, which is what gives the shape its pinched, liquid quality.

`site/mark.mjs` **solves** those fillets rather than drawing them:

```bash
node site/mark.mjs         # the path data
node site/mark.mjs --svg   # a whole SVG, for checking
```

Eyeing the tangents gets something that looks nearly right at poster size and visibly wrong
at 24px, because a fraction of a degree of error puts a kink in the neck. Both SVG arc
flags are derived from the geometry too — an early attempt guessed them and produced
crescents, because the blob arcs took the short way between tangent points and cut straight
through the blob.

### The proportions are measured, not chosen

The supplied artwork is 437 x 477 at its bounding box, and for a hexagon with a vertex at
twelve o'clock those two numbers pin everything down:

```
height = 2·R_HEX + 2·R_OUTER  = 477   →  R_HEX   ≈ 173.5 px
width  = √3·R_HEX + 2·R_OUTER = 437      R_OUTER ≈  64.5 px
```

which is `R_OUTER/R_HEX = 0.372`, with the centre blob at ~1.20x an outer one. In a
100-unit viewBox: **R_HEX 33.5, R_OUTER 12.45, R_CENTRE 14.9**.

**And the fillet is not free either.** For two blobs at distance `d` the fillet centre sits
`off` from the line joining them and the visible waist is `2·(off − F)`. If `off ≤ F` the
two fillet arcs cross and *the outline self-intersects* — the neck stops being a neck and
becomes a torn spike. This shipped once: `R_OUTER 11.6` with `FILLET 6.0` gives a waist of
**−1.19** on every outer join, which is why the mark looked wrong rather than merely
slightly off. `fillets()` refuses that case now, and a test computes the waist for both
join types.

The artwork's neck is ~11% of an outer blob's diameter; solving for that gives
**`FILLET = 5.75`**.

The alternative was an `feGaussianBlur` + `feColorMatrix` "gooey" filter, which fakes the
same effect. Rejected: a filter cannot go in a favicon data URI, costs a compositing pass
on every paint, and renders differently across browsers.

**If you change the geometry, re-run the generator and paste the path into `index.html` —
and into the favicon data URI.** Tests compare all three and fail if they drift, which they
did the first time, catching a stale path left behind after the generator was fixed.

---

## What is checked

`test/site.test.js` runs with the rest of the suite and needs no browser:

- the headline and its three sentences are exactly as approved, matched against the
  *rendered text* so a line break cannot change them — and the glitch layer's `data-text`
  carries the unbroken sentence
- every number on the page matches the product
- every nav link points at a section that exists, and HKU is named
- the header is menu / mark / contact in that order over three grid columns with equal
  outer columns, which is what actually centres the mark on the viewport
- nothing sits above the headline but the status badge
- every text colour clears WCAG AA against every ground, by calculation
- button text on orange is dark, never white; cyan never colours a real element
- the mark in the page and in the favicon is byte-identical to the generator's output, is
  made only of arcs, uses both sweep directions, and keeps its fillet radius
- the video is never in the critical path: no `src` in the markup, `preload="none"`,
  gated on reduced motion, save-data and connection, revealed on `canplay`
- the brand gradient is laid over the footage rather than baked into it
- every band has an animated ground, and every decorative layer is `aria-hidden`
- one media query stops all the CSS motion, and reduced motion paints one still frame
  rather than looping or going blank
- the canvas stops when off-screen or in a hidden tab
- content that hides itself for scroll-reveal has a **deadline and a print path** — it once
  rendered the whole page blank below the hero in a renderer that never scrolls
- the drawer is genuinely `hidden` when closed, and Escape closes it
- the FAQ opens with no JavaScript, nothing loads from a third-party host, and `app.js`
  imports no package
