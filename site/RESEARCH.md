# Competitive research — what the landscape actually says

Research method and its limit, stated up front: **outbound `WebFetch` was blocked at
the session's egress proxy for every host** (CONNECT returned 403 for `mem0.ai`,
`getzep.com`, `letta.com`, `supermemory.ai` and even `wikipedia.org`). Web *search*
was available and was the channel used throughout. So the positioning lines below are
taken from search-surfaced page titles, meta descriptions and indexed page copy rather
than from a rendered visit to each homepage. Wording is quoted where the source
carried it verbatim and paraphrased where it did not. Anything below marked
**unverified** could not be pinned down and was not used to build the site.

---

## 1. Direct — agent memory and context layers

| Company | Positioning line | Structure | The gap it leaves |
|---|---|---|---|
| **Mem0** | "Drop-in memory infrastructure for AI agents and apps. Context that persists. Built for production." | Developer-first. Benchmark-led (92.5% LoCoMo, 94.4% LongMemEval). Public pricing ladder — Hobby free → Starter $19 → Growth $79 → Pro $249 → Enterprise. Open source + hosted. SOC 2 Type I, HIPAA-ready, Type II in progress. | Comparison writeups state plainly that Mem0 "has no audit model." Memory is a store to be made accurate and cheap. Nothing decides what is allowed to enter it. |
| **Zep** (+ Graphiti) | "Agent memory at enterprise scale. Memory of users, the business, and work done." Also: enterprise-grade memory via context graphs — sub-200ms retrieval, SOC 2 compliant. | The most enterprise-shaped of the group. Product split into agent-memory / agent-context / context-engineering pages. Leads on latency, temporal knowledge graphs, SOC 2 Type II, a public trust page. | Closest competitor. Says "governance lives in the substrate" — but that governance is authorization, retention and audit *of a store*. There is no write-path gate, no channel-trust model, no authority-based contradiction resolution, and the audit trail is Zep's own, not the customer's to verify. |
| **Letta** (ex-MemGPT) | "Machines that learn." / "Stateful agents that remember everything, learn continuously, and improve themselves over time." | Research-led, founder-credentialed (UC Berkeley Sky Lab). Blog-heavy. Agent-centric, not memory-store-centric. | Positioned on agent capability, not on enterprise control. No compliance surface. |
| **Cognee** | "Model your agent's world." / "memory in 6 lines of code." | Open-source, graph-first, time-to-first-value framing. | As of mid-2026 advertises no SOC 2 or HIPAA — explicitly limits regulated deployment. |
| **Supermemory** | "The memory layer for AI agents." Developers page: "Built for developers who ship." | Fast, dev-tool aesthetic. API-first. | Consumer/prosumer gravity. No governance story. |
| **LangMem** | Long-term memory SDK for LangGraph agents — semantic, episodic, procedural. | A library inside LangChain's docs, not a product site. | Not a competitor for an enterprise buyer; it's a component. Last PyPI release 0.0.30 (Oct 2025) despite active repo. |
| **MemoryLake** (Zhibian / 质变科技, launched 9 Feb 2026) | "The Memory Lake for Every AI." Framed as *AI infrastructure entering a memory-centric era* — "memory is the second brain of AI." | Materially different from the Western players: positioned as **infrastructure and a data platform**, not an SDK. Full stack — MemoryLake-D1 model + memory engine + multimodal storage/compute (Relyt). Claims 1.5M professional users, 15k enterprise customers. | Confirms "memory as infrastructure, not a library" is a live global frame — and that the infrastructure framing is available and largely unclaimed in the West. Still a *storage and understanding* story; no gate, no ledger. |
| **Hyper** (YC), **GBrain**, **Savant** | The "Company Brain" cohort. Hyper: "Company brain that powers your AI employees." GBrain: Garry Tan's open-sourced typed-knowledge-graph memory (23.6k GitHub stars in two months). | Racing YC's own RFS category (see §6). Fast, developer-led, knowledge-graph shaped. | All three answer "how does the company's knowledge get *in*." None answers "what happens when something false, hostile or unlawful tries to get in." |

**What the whole direct category conspicuously leaves out:** every one of them competes
on *recall* — accuracy, latency, benchmark scores, lines of code. Not one competes on
*admission*. Memory is uniformly presented as an asset to improve, never as a liability
to control.

---

## 2. Hyperscaler memory — the real commoditization threat

- **AWS Bedrock AgentCore Memory** — GA. Short-term (raw session events) and long-term
  (async-extracted facts). 2026 additions: metadata on long-term records with a
  `STRICTLY_CONSISTENT` mode, streaming notifications on memory writes.
- **Google Vertex AI Agent Engine Memory Bank** — public preview Jul 2025, **GA
  17 Dec 2025**. Customizable extraction, multimodal, managed storage/retrieval.
- **Microsoft Foundry Agent Service** — long-term memory in the same shape.

**Gap:** all three govern only their own agents, on their own platform. None spans a
company that is simultaneously running Cursor, ChatGPT Enterprise, a Vapi voice agent
and a LangGraph pipeline. This is the strongest available argument that memory-as-recall
is not a durable business and memory-as-control is — and it is also the honest form of
the biggest objection (see §7).

## 3. Agent control planes

- **Microsoft Agent 365** — "The control plane for AI agents." Announced Ignite Nov 2025,
  **GA 1 May 2026**, $15/user/month, part of M365 E7. Entra Agent ID for identity,
  Purview for data, Defender for threats.
- **ServiceNow AI Control Tower** — "a centralized command center to govern, manage,
  secure, and realize value from any AI agent, model and workflow." Built on an AI Inventory.

**Gap:** these govern *the agent* — its identity, its permissions, its lifecycle. Neither
governs *the memory the agent writes*. A fully registered, correctly permissioned,
Entra-identified agent can still write a lie into shared memory and nothing in either
product stops it or records that it happened.

## 4. AI governance platforms

**Credo AI** — "Credo AI created the AI governance category, and is defining it for the
agentic era"; discover AI, enforce policy, manage risk, "Measurable Trust," intake to
runtime. Alongside IBM watsonx.governance, OneTrust AI Governance, Holistic AI, ModelOp,
Trustible, Monitaur, Saidot, Cranium, Relyance, Truyo.

**Gap:** these are registries, policy documents, risk classifications and evidence
binders. They describe controls. They are not in the write path and cannot stop anything
at the moment it happens. Vault's compliance module is deliberately positioned as
swappable *for* these — the site does not fight them.

## 5. Adjacent categories, and precisely what each one misses

- **Enterprise search** (Glean "Work AI that works" / "Context for it all"; Guru, GoSearch,
  Dust, Onyx "open-source AI chat connected to your docs, apps and people", Sinequa, Coveo,
  Lucidworks, Moveworks) — permissions-aware retrieval over documents that already exist.
  They index; they don't adjudicate writes.
- **Regulated archiving** (Smarsh — "Digital communications governance and archiving,"
  2025 Gartner MQ Leader, 6,500+ customers, 18 of the 20 largest financial institutions;
  Global Relay; Theta Lake — capture/archive/supervise UCC with an AI-assistant inspection
  suite; Proofpoint, Veritas, Mimecast, Shield) — capture *human* communications. AI agent
  conversations are a record type they are only beginning to reach, and they hold no facts.
- **Agent observability** (Langfuse — most-deployed open source, acquired by ClickHouse
  Jan 2026; Braintrust — "a quality management system for AI products"; Arize AX/Phoenix;
  LangSmith; Datadog LLM Observability; Honeycomb; W&B Weave; Galileo; Fiddler) — traces
  and evals, read-only and after the fact.
- **Data governance** (Atlan, Alation, Collibra, BigID, Varonis) — catalogues and DSPM for
  data at rest. Agent memory is neither a warehouse table nor a SharePoint file.
- **AI/agent runtime security** (Zenity — "Secure AI Agents with Confidence," unified
  observability, governance and real-time threat protection; Lakera — acquired by Check
  Point; Aim Security; Wiz AI-SPM; Cyera) — block prompt injection at the *prompt*. They do
  not decide what becomes a durable, re-readable fact.
- **Non-human identity** (CyberArk, Okta, Ping, Astrix, Oasis, Entro) — identity and secrets
  for machines. Identity is Vault's check #1, not the whole gate.

---

## 6. YC, Gartner, and the real objections

**YC Request for Startups — "Company Brain" (Summer 2026, Tom Blomfield).** The single
genuinely relevant entry. The argument: the blocker to AI automation inside companies is
domain knowledge, scattered across heads, Slack, tickets, pricing exceptions and
undocumented habits. The asked-for primitive is "a living map of how the company works,"
turned into something AI can execute against. Explicitly *not* a search tool, *not* a
chatbot over documents. "AI cannot automate a company it cannot understand."
YC's Fall 2026 RFS separately asks for AI-native compliance infrastructure.

**Gartner.** First-ever *Hype Cycle for Agentic AI* published 2 Apr 2026, with agentic AI
at the Peak of Inflated Expectations: **only 17% of organizations have deployed AI agents,
while more than 60% expect to within two years.** Gartner defines **guardian agents** —
governance plus runtime controls under AI TRiSM — as a category. Gartner coined **"agent
washing"** for rebranded automation. Worldwide AI spending forecast $2.5T for 2026.

**The real objections** (found, not invented):
1. *Hyperscalers commoditize this at near-zero incremental cost.* Genuine — AgentCore and
   Memory Bank are both GA. Answer: they are single-platform; Vault is cross-vendor and
   sells control, not storage.
2. *Context windows growing toward 1M–10M tokens absorb short-horizon memory back into
   inference.* Genuine — and it argues **against** recall-based memory startups and
   **for** governance, which a longer context window does not provide.
3. *Open-source commoditization compresses margins for software-only memory vendors.*
   Genuine. The defensible surface is the sealed record and the regulated archive, not
   the embedding store.

## 7. Documented incidents and verified regulatory dates

Only facts that could be corroborated were used on the site.

- **Unit 42 (Palo Alto Networks)** demonstrated indirect prompt injection silently
  poisoning an AI agent's long-term memory (proof of concept on Amazon Bedrock Agent):
  malicious web content manipulates session summarization so injected instructions persist
  into all future sessions. *Used on the site.*
- **OWASP** formalized Memory and Context Poisoning as **ASI06** in the 2026 Agentic AI
  Top 10. *Used on the site.*
- **FINRA Notice 24-09** (Jun 2024) — technology-neutral; existing supervisory,
  recordkeeping and governance obligations already apply to generative and agentic AI, with
  no carve-outs. **Notice 25-07** (14 Apr 2025) asks whether AI-generated chatbot
  communications and transcripts are records "as such" under Exchange Act Rule 17a-4(b)(4).
  *Used on the site.*
- **EU AI Act.** Article 50 transparency obligations apply **from 2 August 2026**, and were
  *not* delayed. The **Digital Omnibus** — Parliament 16 Jun 2026, Council 29 Jun 2026 —
  postponed high-risk obligations to **2 December 2027** (stand-alone Annex III) and
  2 August 2028 (Annex I embedded). A limited grace period runs to 2 Dec 2026 for
  Art. 50(2) marking on systems already on the market. *Used on the site — most vendor
  sites still cite the superseded Aug 2026 high-risk date, so getting this right is itself
  a credibility signal.*
- **India DPDP Rules 2025**, notified 13 Nov 2025, 18-month phased rollout: Consent Manager
  framework operative **13 Nov 2026**; full substantive compliance **13 May 2027**. *Used.*
- **Cyber insurance.** ISO standard general-liability AI exclusion forms effective January
  2026; carriers filing AI exclusions across GL, E&O and D&O; AI questions being added to
  underwriting applications. *Informs the insurance-evidence module framing; no statistic
  quoted on the site.*
- **Shadow-AI prevalence statistics** (79% of IT leaders, "50% of agents ungoverned",
  "340% YoY") — **unverified**, sourced only to low-quality secondary blogs. **Deliberately
  not used.** The site relies on Gartner's 17%/60% instead, and otherwise describes the
  problem without a number.

## 8. Craft reference (form, not content)

Linear, Vercel, Stripe, Ramp, Modal, Neon, Supabase, Cloudflare, Cursor, Anthropic. The
invariants that transfer: ruthless positioning above the fold; real product visualization
rather than stock illustration; a single accent colour used with restraint; motion that
demonstrates the product's defining quality rather than decorating the page; typography as
the brand; size-as-hierarchy applied consistently; and a page that loads fast.

Applied here as: no web fonts and no external requests at all; one hand-written WebGL2
scene with no library; and the strictest possible colour rule — **the site is black and
white except where the gate makes a decision.** Pass green, hold amber, block red and
golden are the only four colours on the page, and each is semantic rather than decorative.
