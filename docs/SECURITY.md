# Security

## Threat model

Named attack classes the gate and the detectors are built against:

| Class | What it is |
|---|---|
| Direct injection | instruction typed straight at the agent |
| Indirect injection | instruction hidden in content the agent reads |
| Stored / persistent injection | the instruction becomes durable memory and fires later |
| Memory poisoning | a false *fact* planted, not an instruction — subtler |
| Sleeper poisoning | written, dormant for months, triggered by a keyword |
| Drip-feed poisoning | small increments, each innocuous, summing to a policy change |
| Slow-boil | a threshold nudged upward over weeks |
| Coordinated poisoning | multiple sources asserting one falsehood to fake corroboration |
| Derived-fact contamination | the lie is corrected but the summaries built on it aren't |
| Cross-session leakage | data from one session surfacing in another |
| Cross-wall exfiltration | memory used as a covert channel between departments |
| Tool poisoning (MCP) | malicious instruction inside a tool's *description* |
| Schema / tool shadowing | a rogue tool impersonating a legitimate one |
| Agent impersonation | unregistered agent writing under a stolen identity |
| Confused deputy | tricking a high-privilege agent into acting for a low-privilege one |
| Model swap | the underlying model silently changed and nobody was told |
| Retrieval manipulation | gaming ranking so the poisoned fact is always returned first |
| Denial by volume | flooding the review queue so real threats get rubber-stamped |
| Denial by cost | runaway loops burning budget |
| Supply chain | compromised connector, dependency, or MCP server |
| Insider | a legitimate employee writing false golden facts |

---

## Layer 0 — Trust boundary architecture

The foundational move: **outside data and trusted internal state are physically
different things in the system, not two labels on the same table.**

Untrusted content lands in `_quarantine/`, which has `noAgentRead` set — no agent may
read it, at any clearance, including under break-glass. Promotion into the fact store
requires passing the gate, and **there is no code path from quarantine to fact store
that skips it.** Not a permission. A structural absence.

Golden facts live behind a separate, human-only write path. No agent API reaches them.

## Layer 1 — Instruction detection

**Facts describe the world. Instructions try to change behaviour. Vault stores facts
only.** This check runs *independently* of the channel check — both must pass.

Seven layers, and **any single one firing holds the write**. Not a majority vote:
recall over precision, with the review queue absorbing the false positives, which is
exactly why the queue has anti-graveyard machinery.

```
1. DETERMINISTIC   pattern lists, regex, character-class rules
2. STRUCTURAL      where in the document did this appear?
                   (a footer instruction is not a fact)
3. STATISTICAL     perplexity, entropy, style discontinuity
4. CLASSIFIER      trained instruction-vs-fact model (naive Bayes, shipped trained)
5. SEMANTIC        does this text attempt to change behaviour?
6. CROSS-REFERENCE does it contradict a golden fact?
7. ENSEMBLE        any layer fires → hold
```

De-obfuscation runs before all seven: zero-width and bidi characters, homoglyphs
(Cyrillic/Greek/fullwidth/mathematical), base64/hex/URL/ROT13/entity encodings
including nested ones, HTML comments and alt/title attributes, hidden text
(white-on-white, `font-size:0`, `display:none`, off-canvas), whitespace steganography,
split payloads assembled across turns, code-comment injection, and markdown/link
injection.

Detection also runs on the **read** side: a query crafted to surface a specific
poisoned fact is itself a signal, and it is logged.

## Layer 2 — MCP and tool security

Tool *descriptions* are untrusted content and get the full instruction scan. Plus:
allowlist with version pinning, provenance for who added a server and who approved it,
schema-change detection, tool-shadowing detection, tool output always treated as an
untrusted channel, per-tool RBAC, and full invocation logging. Mapped to the OWASP MCP
Top 10 and the CoSAI MCP threat categories.

## Layer 3 — Golden facts

| Property | Detail |
|---|---|
| Human-only creation | no agent can create one. No API path exists. |
| Named authority | only a human with a defined authority role |
| Four-eyes | two named humans above a sensitivity threshold |
| Cryptographically attested | signed by the approver's key, independently verifiable |
| Unoverwritable | any agent write contradicting one is blocked and alerted |
| Expiry-dated | a review date, so they prompt re-attestation instead of rotting |
| Contradiction radar | quiet conflicts are raised even without a direct overwrite |
| Read-time precedence | ranked first, and labelled as golden to the agent |
| Blast-radius report | see every affected fact and agent *before* you commit a change |

## Layer 4 — Temporal & behavioural detection

Single-write checks miss patient attackers. `src/security/temporal.js` watches over
time for: drip-feed (fragments assembled semantically across sessions), slow-boil
(a threshold trending upward: $50k → $60k → $75k), coordinated assertion within a
window, sleeper facts (written, untouched for months, suddenly hot), trigger-word
watch, volume anomaly, novel channel, cross-wall probing, timing anomaly, semantic
drift from an agent's stated purpose, confidence laundering (a `guessed` fact
re-asserted until it looks corroborated), reviewer fatigue — **flagging the reviewer,
not just the write** — and queue flooding.

Each agent gets a behavioural baseline: write rate, folders, claim types, hours,
channels. It is persisted, not held in process memory, because a baseline that resets
on restart detects nothing.

## Layer 5 — Blast-radius containment

Walls limit lateral movement · per-namespace keys mean one compromise doesn't open the
rest · quarantine is unreadable by agents · automatic scope reduction on anomaly (an
agent behaving oddly gets narrowed, not just alerted) · rate limits per agent, folder
and channel · circuit breaker on repeated blocks from one source · the graduated kill
switch · derived-fact tracking so a correction propagates to everything built on the
bad fact.

## Layer 6 — Detection & response

Real-time alerting with severity and deduplication (don't page someone 200 times),
case management, one-click incident bundle, contagion trace, undo, and automated
playbooks: "on drip-feed detection → freeze folder, notify owner, open case."

## Layers 7–12

**Platform posture**, **identity**, **data**, **model**, **compliance** and **customer
assurance** are specified in full in the product specification. In this build the
enforceable parts are code: no content in logs or error messages (there is a test for
it), tiered read logging, model pinning with silent-swap alerts, break-glass requiring
two approvers plus a time box plus a loud log, and a security scorecard the customer
runs against their own posture.

---

## The kill switch — graduated, not binary

Freezing all writes stops the business. That is never the only option.

| Level | Effect | Business impact |
|---|---|---|
| 1 Warn | everything works, everything flagged | none |
| 2 Review all | every write goes to the queue | slow, still working |
| 3 Read-only | no writes accepted, reads continue | agents work, stop learning |
| 4 Scoped freeze | one agent, folder, channel or department | contained |
| 5 Read-block on scope | that scope can't be read either | contained, harder |
| 6 Full freeze | no reads, no writes, anywhere | business stops |

Named administrator role. In-flight writes are **queued, not lost**. Agents are told
"memory read-only" so they degrade gracefully instead of hallucinating. Auto-expiry
with forced re-authorisation, so nobody forgets it's on. Tested quarterly with the
result recorded — insurers ask. `vault killswitch test` measures activation and writes
the result to the ledger.

---

## What we do not claim

- The gate has false positives, roughly 4% in backtests. Deliberate.
- Watch mode cannot block. A fact captured in Watch mode was never gated, and the
  Trace screen says so in red on every such fact.
- Vault does not stop an agent doing harm inside a single session it never records.
- A hash chain we control proves nothing to an adversary — which is why customer keys,
  external anchoring and the standalone verifier exist. See [FORMATS.md](FORMATS.md).
- No emotion, sentiment, stress, honesty or productivity scoring exists anywhere in
  this codebase. Not a config option — attempting it raises `wall_violation`.
