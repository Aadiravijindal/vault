# Positioning, information architecture, and the cold read

## 1. The positioning decision, in one sentence

> **Every AI agent keeps its memory to itself; Vault is the one memory they all share, so
> connecting a new agent means it already knows what the others learned — with ten checks
> on every write and a record the customer, not Vault, holds the keys to.**

**This replaced an earlier, worse positioning.** v1 and v2 led with the gate — with
*security*. That was the wrong order. Governance is the reason a buyer keeps Vault; it is
not the reason they want it in the first place. The reason they want it is that their
company's memory is scattered across a dozen tools and every new agent starts from zero.
Leading with the gate sold insurance for the bad day. Leading with connection sells the
thing that gets used every day, and the gate then arrives as the answer to the obvious
follow-up question: *if everything shares one memory, how do I trust what's in it?*

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

> **Every AI agent remembers alone. Vault gives them one memory.**

Ten words, two sentences. The first names the problem in four words that anyone
running more than one AI tool recognises immediately. The second names the fix. Neither
clause mentions security, because security is not why anyone shows up.

Earlier headlines and why they were worse: *"One memory for every AI agent. Nothing enters
it unchecked."* (v1) and *"...Ten checks before anything gets in."* (v2) both spent the
second half of the headline on the gate. Both described a guard rather than a benefit, and
both asked a reader who had not yet felt the problem to care about the solution to it.

---

## 2. Information architecture, and why this order

Rebuilt twice. v1: 3,460 words, 16 sections, ~20,000px — rejected as yapping. v2: cut to
1,351 words and 10 sections, gate-first. v3 (current) keeps the compression but **reverses
the argument**: connection first, security second.

| # | Section | Why it sits here |
|---|---|---|
| 1 | **Hero — the handoff, running live** | `claude-code`, `cursor` and `vapi-sales-agent` have written 47 facts to `engineering/atlas`. Then `emergent` connects and the panel fills in what it now knows: the schema, that auth is session cookies and why the token plan died, that Redis went in March. Ends on "Nobody re-explained anything." This is the whole pitch, demonstrated, in the first screen. |
| 2 | **The problem** — memory locked inside twelve tools | Three cards on three timescales: *every day* (re-explaining), *every week* (two agents, two answers), *the bad day* (something false gets remembered). The bad day is third on purpose — it's real, but it isn't the reason anyone buys. |
| 3 | **Connect** — Watch / Inline / Gateway, 74 connectors | Answers "will it work with what I actually run?" while the reader still cares. Voice, chat, code, API. Includes what Vault *can't* see, which nobody else publishes. |
| 4 | **Structure** — folders build themselves | A real folder tree: `sales/acme/`, `engineering/atlas/backend/`, `hr/` marked walled. Answers "so where does it all go?" without a paragraph about taxonomy. |
| 5 | **One company, four teams** | Tabbed: Sales, Engineering, Support, Legal. Each shows the agents actually running, what lands, **what changes**, and **what gets stopped**. This is the concrete department-by-department walkthrough — the same company, four teams that don't talk to each other. |
| 6 | **Security** — the ten checks, scroll-driven, with the live verdict card | Arrives as the answer to the question section 5 just raised: if all four teams write to one memory, how do I trust it? Four write attempts cycle — a lookalike-domain invoice, a clean sales note, an injected PR comment, an unapproved support promise. |
| 7 | **What it does, in plain words** | Four grouped Feature / Plain meaning tables — Keeping it clean, Proving what happened, Emergency and legal, Showing the value. 33 features, one short sentence each, no jargon. Dense and scannable rather than prose. |
| 8 | **Modules** — you already own half of this | Concedes the loudest objection, then shows the one row with no toggle. |
| 9 | **The boring questions** | Deployment, keys, records, employees, identity, dates, leaving, pricing — one 8-cell grid. |
| 10 | **Where to start** → **CTA** → footer + investor form | Discover / Connect / Govern / Prove / Sovereign. The CTA is "Connect one agent. Then connect a second," because the second one *is* the demo. |

The reorder is the substantive change. Everything security-related still exists and is
still specific — it just stopped being the opening argument.

---

## 3. The cold read

**Do I know what this does?** In four words: agents remember alone. The panel beside the
headline then shows a new agent connecting and inheriting a project it has never seen.

**Do I believe it?** Evidence discipline is unchanged from v1: the shadow-AI statistics
found in research (79% of IT leaders, "50% ungoverned", 340% YoY) all traced to content
farms and were cut. The department scenarios are labelled as what this looks like in one
company — no invented customer is presented as real, and no incident is cited that wasn't
verified. Dates are the checked ones: EU AI Act Article 50 from 2 Aug 2026, high-risk moved
to 2 Dec 2027; India DPDP Consent Manager 13 Nov 2026, full compliance 13 May 2027. The CTA
still says plainly that Vault is early.

**Do I want it?** This is what v1 and v2 both got wrong. They led with a guard. A guard is
something you accept; a team that stops re-explaining its own project to every new tool is
something you want. The engineering tab is the strongest thing on the page: Team A builds
with Claude Code, Team B connects Emergent, and Emergent starts already knowing the
project. Anyone who has run two coding agents on one codebase recognises that instantly.

**Bugs fixed this pass:** the folder tree collapsed into one line because HTML eats
newlines in a `div` (needed `white-space: pre`); and the fixed WebGL canvas bled through
the sections above the gate, because the render loop returned early on "not visible"
without clearing the buffer, leaving the last frame painted.

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
