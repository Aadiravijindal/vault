# Positioning, information architecture, and the cold read

## 1. The positioning decision, in one sentence

> **Vault is the shared memory every AI agent in the company reads and writes — and the
> only one that checks what goes in, with a record of every decision that the customer,
> not Vault, holds the keys to.**

### Why the research forces this sentence

Every direct competitor competes on **recall**. Mem0 leads with benchmark scores. Zep
leads with sub-200ms retrieval. Letta leads with agents that learn. Cognee leads with six
lines of code. Supermemory leads with developer velocity. MemoryLake leads with
memory-centric infrastructure. Hyper, GBrain and Savant lead with assembling the company's
scattered knowledge. Across all of them, memory is an asset to be made better.

Not one of them competes on **admission** — on what is allowed to become a durable fact.
The category has an entirely unclaimed axis, and it happens to be the axis Vault was
actually built on.

**Closest to:** Zep. "Agent memory at enterprise scale," SOC 2 Type II, and an explicit
claim that governance is in the substrate. Vault sits beside Zep in seriousness and
audience, and takes the same enterprise register rather than the developer register.

**Directly against:** Mem0 and Zep both, on the same word. Mem0 is documented as having
no audit model at all. Zep's governance is authorization, retention and audit *of a
store* — Zep's own audit trail, verified by trusting Zep. Vault's differentiator is that
the ten checks run *before* the write and that the ledger is verifiable **without
trusting Vault**: customer-held signing keys, external witnesses, and a standalone
verifier that imports nothing from Vault's codebase. That is not a stronger version of
Zep's claim; it is a different claim.

**Against the hyperscalers** (AgentCore, Memory Bank, Foundry) by being cross-vendor.
They govern their own agents on their own platform. No enterprise runs one platform.

**Against the control planes** (Agent 365, ServiceNow AI Control Tower) by governing the
memory rather than the agent. A correctly registered, correctly permissioned agent can
still write a falsehood; nothing in either product notices.

**Against the archivers, search vendors, observability vendors and governance platforms**
by not fighting them at all. Every one of them is a module Vault ships built-in and can
switch off in favour of the incumbent — with the single exception of the gate, which has
no toggle. That resolves the loudest real objection ("we already own Smarsh / Glean /
Langfuse / OneTrust") by agreeing with it.

### The headline this produces

> **One memory for every AI agent. Ten checks before anything gets in.**

Twelve words, two sentences. The first states the category so a CIO knows what it is; the
second states the differentiator, and states it as a *number* rather than an adjective —
"ten checks" is concrete and checkable in a way "unchecked" was not. (v1 used "Nothing
enters it unchecked," which was accurate but vaguer, and gave the reader nothing to
count.) It keeps the category's own cadence — short declarative clauses, the convention
across Zep, Mem0, Letta and Microsoft — while making a claim none of them makes.

---

## 2. Information architecture, and why this order

**Revised after the first version was rejected as too long and too wordy.** v1 ran
3,460 words over 16 sections and ~20,000px. A YC-style landing page runs 400–700 words.
v2 is 1,351 words over 10 sections and ~9,900px — and, following Paul Graham's rule to
"put the impressive thing on the front page," the product now *runs* in the first screen
instead of being described.

| # | Section | Why it sits here |
|---|---|---|
| 1 | **Hero + the live gate** | Headline, one line, two CTAs — and a working gate card beside them. Four real write attempts cycle through the ten checks and land a verdict with the actual reasons: a lookalike-domain invoice that contradicts a golden fact, a clean sales note that passes, an injected instruction in a GitHub comment, a leaked connection string. This is the demo, in the first five seconds, instead of a `curl` block 6,000px down. |
| 2 | **The problem** — "A lie only has to get written once." | Four short lines. The punch is the Tuesday/Friday sentence; Unit 42 and OWASP ASI06 sit under it as fine print rather than as the argument. |
| 3 | **The gate** — ten checks, scroll-driven | The differentiator, shown. Each check is now a question as a heading and one ~25-word answer, down from a paragraph each. |
| 4 | **Proof** — sealed ledger on your keys + four capability cards | The second differentiator, and the slot where a competitor would put logos. Vault has none and invents none, so verifiable proof substitutes for social proof. |
| 5 | **Golden facts** | One band. Kept because "no agent can create one, and there is no API path that does" is the most quotable line on the site. |
| 6 | **Connect** — three modes, 74 connectors, the coverage map | Where the technical evaluator lands. Publishing what Vault *can't* see is a differentiator because nobody in the category does it. |
| 7 | **Modules** — "You already own half of this. Keep it." | Answers the loudest real objection by conceding it, then shows the one row with no toggle. |
| 8 | **The boring questions** | v1 spent four separate sections on deployment, law, privacy and exit. They are now one scannable 8-cell grid. Same facts, a quarter of the words, and far better for the buyer who is scanning for one answer. |
| 9 | **Where to start** — five stages + the pricing model | Turns a large product into a small first step. |
| 10 | **Demo CTA**, then footer + investor form | One ask. |

Cut entirely from v1: the standalone archive section, the separate privacy and law
sections, the emergency-controls section, the exit section, the value-reporting
paragraph, and the `curl` block. Everything that survived was compressed into the spec
grid or into the live card.

---

## 3. The cold read

Read back as someone who has never heard of Vault.

**Do I know what this does?** Yes, and faster than in v1 — because the page no longer
*tells* you, it shows you. The headline names the category and the count; the card beside
it runs a real write through the ten checks and blocks it with three specific reasons.

**Do I believe it?** The evidence discipline from v1 is unchanged and still the reason to:
the shadow-AI statistics found in research (79% of IT leaders, "50% ungoverned", 340% YoY)
all traced back to content farms and were cut. What is cited is Unit 42's memory-poisoning
proof of concept, OWASP ASI06, the FINRA notices, and the post-Digital-Omnibus EU AI Act
dates — Article 50 from 2 Aug 2026, high-risk moved to 2 Dec 2027, which most vendor pages
still get wrong. The CTA still says out loud that Vault is early.

**Do I want it?** This is what v1 got wrong and what changed. v1 buried the want in
3,460 words; the reader never reached it. The desire now comes from two places, both in
the first two screens: the card blocking a fake-invoice write that *contradicts a golden
fact signed by the CFO*, and the line "a guess an AI made on Tuesday gets read back on
Friday as company policy." A CIO recognises the second from their own week, and has just
watched the first get stopped.

**What else changed in v2:** words cut 61% (3,460 → 1,351); sections 16 → 10; page height
halved (20,124px → ~9,900px); every ten-check paragraph rewritten as a question plus one
short answer; four sections collapsed into one scannable spec grid; and a real measure bug
fixed — `.head{max-width:34ch}` sat on a 17px `div`, so `ch` resolved against 17px and
clamped every section heading to ~290px instead of the intended measure.

---

## 4. Investor content — confirmation

- The **only** investor-facing element on the entire site is the contact form in the
  footer, labelled *"Investors & partnerships"*, with three fields: name, email, message.
- It sits below the product CTA and is visually separate from it.
- There is **no** investor page, no traction section, no market-size claim, no funding
  narrative, no team/founder section, no metrics, and no investor-specific copy anywhere
  else in the document. The site an investor reads is exactly the site a customer reads.
- **Both** forms — the demo form and the investor form — deliver to
  **aadijindal258@gmail.com**. See `README.md` for exactly what is wired and what one
  line has to change before launch.
