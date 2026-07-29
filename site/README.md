# Vault marketing site

One self-contained file: `index.html`. No build step, no dependencies, no external
requests of any kind — no CDN, no web fonts, no analytics, no third-party script. Open it
directly or serve the folder.

```bash
npx http-server site -p 8123     # or: python3 -m http.server -d site 8123
```

Deploy by copying `index.html` to any static host (Pages, Netlify, Vercel, S3, nginx).

- `RESEARCH.md` — the competitive research the copy was built from, including which
  sources could not be verified and were therefore not used.
- `POSITIONING.md` — the positioning decision, the information architecture and the
  reason for each section's placement, and the investor-content confirmation.

## Forms — what is wired, and the one thing that isn't

Both forms deliver to **aadijindal258@gmail.com**: the demo form in the CTA section and
the *Investors & partnerships* form in the footer.

**Working right now, with no backend:** on submit, the page validates the fields, composes
the full message and opens it in the visitor's mail client addressed to
`aadijindal258@gmail.com`. The confirmation also renders an explicit `mailto:` link and a
*copy the message* button, so the visitor can still send it if no mail handler is
configured or a browser blocks the automatic open. Nothing is faked and no submit button
is a dead end.

**To deliver server-side instead** — recommended before launch, because `mailto:` depends
on the visitor having a mail client — set one constant near the top of the `<script>` in
`index.html`:

```js
var FORM_TO       = "aadijindal258@gmail.com";
var FORM_ENDPOINT = "";   // ← set this
```

Put a form-relay POST URL in `FORM_ENDPOINT` (Formspree, Web3Forms, Basin, or your own
handler) and both forms switch to a native `POST` to it, carrying the same named fields.
A native form POST is used rather than `fetch` so it works under strict Content-Security
Policies.

**The one piece this page cannot do for you:** the relay account itself has to be created
and configured to forward to `aadijindal258@gmail.com`. `FORM_TO` is used for the
`mailto:` path and is displayed next to both buttons; it does not control where a
third-party relay delivers — that is set in the relay's own dashboard. Providers differ
(Formspree binds the destination to the form ID; Web3Forms binds it to an access key), so
no hidden `_to` field is emitted, because for both of those providers it would be ignored
and would only create a false impression that delivery was configured.

## The scene

The hero, problem, gate, memory and ledger sections share one continuous WebGL2 scene,
written by hand — no three.js, nothing fetched. The concept: **the scroll is the write
path.** A cohort of facts travels with the camera down a corridor of ten gate rings; at
each ring some are held (amber, pushed aside) or blocked (red, they fall out of the
stream); what survives settles into the memory lattice, which folds into the ledger chain.

Every particle's position is a pure function of `(instanceId, scrollProgress)` evaluated
in the vertex shader, so scrubbing backwards is exact, the CPU does no per-particle work,
and there is no simulation state to drift. Three uniforms drive the whole thing.

The frustum is deliberately off-centre (`perspective(..., shift)`): the vanishing point
sits in the right-hand column so the camera still flies straight through the rings while
the left column stays clean for type.

Fallbacks: `prefers-reduced-motion` hides the canvas entirely and renders the ten checks
as a plain vertical list; if WebGL2 is unavailable the canvas is removed and the page is
unaffected; on screens under 900px the scene drops to 700 particles at low opacity behind
a scrim.

## Colour

The page is black and white except where the gate makes a decision. Pass green, hold
amber, block red, and golden are the only four colours on the site, and all four are
semantic. There is no brand accent colour, on purpose.
