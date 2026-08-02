# The marketing site

Two files. No build step, no framework, no dependency, nothing fetched from a third
party — open `index.html` and it works, including offline.

```bash
# any static server will do
python3 -m http.server -d site 4000
```

Deploy by copying `site/` anywhere that serves static files.

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
Every orange surface on this site carries near-black text (`#1a0a02`, 6.9:1). `npm test`
enforces it, along with every other text colour against every section ground.

## The background

It is CSS, not a video. Five radial gradients drifting over each other on a 26-second
loop, plus an inline `feTurbulence` grain. That gets the same living quality as a render
while staying a few kilobytes, working offline, costing nothing on mobile data, and —
the thing a video file cannot do — holding perfectly still for anyone who has asked for
reduced motion.

The first gradient in the stack is a shadow pocket under the hero content. It is not
decoration. Measured in a browser with the text hidden, white on the bare bloom fell to
**2.24:1** at the right end of the headline, under the 3:1 AA asks of large text — and
it looked fine, which is the point. With the pocket it is **5.03:1** at the worst
viewport tested. If you move the bloom, measure it again.

## The mark

Seven nodes, nine links, defined once as an SVG `<symbol>` and referenced with `<use>`.
It paints with `currentColor`, so it recolours on hover and in any context.

Node radius is deliberately held under half the shortest link. On the first attempt it
was not, the circles merged into a solid blob, and the connections — the entire idea of
the mark — disappeared. There is a test for it.

This is a **reconstruction** from the supplied render. Drop the original in over the
`<symbol>` contents when you have it; nothing else needs to change.

## What is checked

`test/site.test.js` runs with the rest of the suite and needs no browser:

- the headline and the three sentences under it are exactly as approved
- every number on the page matches the product (74 connectors, 576 cases, p50 80ms…)
- every text colour clears WCAG AA against every ground, by calculation
- button text on orange is dark, never white
- the mark's geometry still reads as a graph
- reduced motion is honoured, no-JavaScript leaves the page visible rather than blank,
  and nothing loads from a third-party host
