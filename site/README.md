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

**The footage is the product.** Memory streams in from the left, hits the gate, most of it
passes and turns orange, about one in six flares red and dies at the wall. Stock footage of
a server room says nothing; this says what Vault does in eight seconds with no narration.
It is also reproducible — the palette comes from the same tokens as the site, so a brand
shift is one edit and one command rather than a re-shoot.

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

Underneath, a canvas draws the same scene live, so there is never a black rectangle and
never a stalled first frame. It stops when the hero scrolls out of view or the tab is
hidden — a `requestAnimationFrame` loop running behind eight sections of content is a
battery bug, not a design decision. Under reduced motion it paints exactly one frame: the
composition is still there, it simply holds still.

### The hero, measured

The scrim is not decoration. Measured in a browser with the text hidden, white on the bare
footage fell to **2.24:1** at the right of the headline — under the 3:1 AA asks of large
text, and it *looked* fine, which is the point. With the scrim in place, the worst of 135
samples across three viewports is **11.5:1**. If you move the scrim, or brighten the
footage, measure it again.

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

**`FILLET = 6.0` is a brand decision, not a tuning knob.** It was chosen by rendering 6.0,
7.0, 8.0 and 9.2 side by side against the supplied artwork. Anything larger fattens the
joins until the whole thing reads as one blob — recognisably a different logo. A test pins
it.

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
