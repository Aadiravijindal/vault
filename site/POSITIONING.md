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

> **One memory for every AI agent. Nothing enters it unchecked.**

Nine words. First clause states the category so a CIO knows what it is. Second clause
states the differentiator so they know why it isn't the other nine. It matches the
category's own cadence — short declarative noun phrase, the convention across Zep, Mem0,
Letta and Microsoft — while making a claim none of them makes.

---

## 2. Information architecture, and why this order

One page. The order is derived from what enterprise-infrastructure sites actually do
(Zep, Smarsh, ServiceNow, Microsoft) rather than what developer-tool sites do (Mem0,
Cognee, Supermemory) — because the buyers are CIO, CISO, GC, CFO and CCO, not an
individual developer. The developer-credibility signals the memory category expects
(integration modes, connectors, a real API response) are kept, but placed after the
enterprise argument rather than at the top.

The first five sections are a single continuous 3D scene. Everything after is flat,
fast and dense.

| # | Section | Why it sits here |
|---|---|---|
| 1 | **Hero** — headline, subhead, two CTAs | Five-second test. The category and the differentiator in one line. Two CTAs is the universal convention; the secondary one ("See what it can and can't see") is deliberately an admission, which no competitor offers. |
| 2 | **The problem** — the write path is unguarded | Enterprise sites state the problem; developer sites skip it. This is a category that does not yet exist in the buyer's head, so it must be named. Three short paragraphs, two of them citable (Unit 42, OWASP ASI06), and one that lands the quieter and more expensive version: *a guess an AI made on Tuesday gets read back on Friday as though it were policy.* |
| 3 | **The gate** — ten checks, pinned, scroll-driven | The differentiator, shown rather than described. Placed third because everything else on the page depends on the reader believing this one thing. The scroll *is* the write path. |
| 4 | **What survives** — folders, entities, provenance at read time | The payoff of the gate. Short, because the visual carries it. |
| 5 | **The record** — sealed ledger, customer keys, external witnesses, standalone verifier | The second differentiator and the one a CISO/GC actually buys. It also occupies the slot where a competitor site would put customer logos — Vault has none and invents none, so verifiable proof substitutes for social proof. That substitution is the honest one. |
| 6 | **Trace / Undo / Contagion / Incident bundle** | Four concrete capabilities, in flat cards, immediately after the abstract claim they make real. |
| 7 | **Golden facts** | Short, distinct, memorable. Its own beat because "no agent can create one and there is no API path that does" is the single most quotable thing on the site. |
| 8 | **Connect** — Watch / Inline / Gateway, 74 connectors, coverage map, a real API response | Where the technical evaluator lands. The `curl` block does in ten lines what three paragraphs cannot. The coverage-map paragraph — publishing what Vault *cannot* see, including personal AI accounts — is a differentiator precisely because nobody in the category does it. |
| 9 | **The archive** | The regulated buyer's section. Verbatim retention, WORM, eDiscovery, privilege, and the rule mappings. FINRA 24-09/25-07 context in fine print rather than as a scare. |
| 10 | **Modules** | Answers the loudest objection — "we already own half of this" — by conceding it, then noting the one row with no toggle. |
| 11 | **People** — employee privacy mode | Works-council and DPO risk kills deployments. Placed before the legal section because it is the objection raised in the room, not in the contract. |
| 12 | **Law** — the retention/deletion conflict, erasure, holds, dated obligations | GC and Privacy. Leads with the conflict rather than pretending it away. Dates are the verified ones. |
| 13 | **Run it / Leave** — nine deployments, encryption, identity; then exit and continuity | Paired deliberately: how to run it and how to leave it, side by side. For an early company, "leaving should be boring" is a stronger trust signal than any certification badge. |
| 14 | **When it goes wrong** — graduated kill switch, slow-attack detectors, break-glass | The CISO's last question. |
| 15 | **Where to start** — Discover → Unify → Govern → Prove → Sovereign, and the pricing model | Converts a large product into a small first step. Priced per agent, not per seat. |
| 16 | **Demo CTA** | One ask, with a form. |
| 17 | **Footer + investor form** | Below everything, separate from the product CTA. |

Total reading time at the intended skim depth is roughly ninety seconds; the scene adds
scroll distance but no reading obligation, and the ten checks are one short paragraph each.

---

## 3. The cold read

Read back as someone who has never heard of Vault.

**Do I know what this does?** Yes. "One memory for every AI agent. Nothing enters it
unchecked," plus a subhead naming the mechanism (ten checks, any agent, any platform) and
the receipt (a sealed ledger on your keys).

**Do I believe it?** This is where the first draft failed, and what changed:

- The first draft opened the problem with shadow-AI statistics — *79% of IT leaders*,
  *50% of agents ungoverned*, *340% year over year*. Every one traced back to vendor
  blogs and content farms. All were **cut**. What replaced them is one documented attack
  (Unit 42), one standards-body classification (OWASP ASI06), and a plain description of
  the failure mode. Fewer numbers, all of them checkable.
- The EU AI Act paragraph originally used the August 2026 high-risk deadline, which the
  Digital Omnibus superseded in June 2026. Corrected to: Article 50 transparency from
  2 August 2026, high-risk to 2 December 2027. A GC who knows this file will notice.
- The closing CTA now says out loud that Vault is early, and offers to say on the call
  what isn't ready. A page this dense with capability claims reads as vapour without it.

**Do I want it?** The line that does the work isn't in the hero — it's in the problem
section: *"a guess an AI made on Tuesday gets read back on Friday as though it were
company policy, and nobody can tell the difference."* That is the sentence a CIO
recognizes from their own week. The gate is the answer to it, and section 4 closes the
loop by saying every returned fact is labelled with whether a person signed it or an AI
guessed it.

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
