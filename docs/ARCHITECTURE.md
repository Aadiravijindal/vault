# Architecture

Twelve layers. The order is the design.

```
AGENTS  voice · chat · coding · custom API · SaaS bots · orchestrators
   │ WRITE                                              │ READ
   ▼                                                    ▼
L1   CONNECTION LAYER     Watch (logs) · Inline (API/MCP/SDK) · Gateway (proxy)
L2   RAW ARCHIVE          sealed FIRST, before any check
L3   EXTRACTION           conversation → candidate facts
L4   THE GATE             ★ 10 checks · always on · never toggleable ★
L5   FACT STORE           folders · entities · versions · walls
L6   HYGIENE ENGINE       dedup · expiry · conflicts · decay
L7   READ PATH            authorise · filter · label · rank · log
L8   LEDGER               sealed chain of every event
L9   OBSERVABILITY        spans · evals · issues · regressions
L10  GOVERNANCE           register · risk · controls · evidence
L11  STORAGE              hot/warm/cold/WORM · BYOK · BYO-bucket
L12  CONTROL SURFACE      14 screens + API + MCP + CLI + webhooks
```

**Why L2 comes before L3 and L4.** The raw archive is sealed *before* extraction and
*before* any check runs. So even a write that gets blocked leaves a record that it was
attempted. Nobody can ever claim "nothing arrived." Reverse those two layers and the
product loses its only unfakeable claim.

---

## L1 — Connection layer

Three modes, and the difference between them is the whole honesty of the product:

| Mode | Setup | Power | Use for |
|---|---|---|---|
| **Watch** | minutes–hours, one credential | forensics, inventory, contagion trace. **Cannot block.** | SaaS agents you don't control, and everything on day one |
| **Inline** | ~20 min per agent (SDK, MCP, webhook) | **full** — hold, block, mask, escalate, before a fact exists | anything you built or control |
| **Gateway** | network/DNS change, days | sees everything by construction, **including agents nobody registered** | shadow-agent discovery, custom bots at scale |

**Watch finds things. Inline stops things. Gateway finds things you didn't know
existed.** Never let a customer think they bought the second when they installed the
first — `vault coverage` prints the difference per tool, and the Map shows it in red.

74 connectors ship in the catalog across voice (7), chat (7), coding (11), customer-
facing (6), internal (3), orchestration frameworks (12), existing memory layers (9),
systems of record (12) and generic transports (7). Every one carries the same seven
facts: auth method, modes supported, what it pulls, **what it cannot pull**, setup
time, scopes required, rate-limit profile.

Non-negotiable per connector: least-privilege scopes · credentials never logged and
never in error messages · backfill on connect · idempotent reconnect · gap detection
with alarm · health monitor with a named owner · **disconnect ≠ delete** · per-connector
kill switch and cost meter.

## L2 — Raw archive

Whole transcript, both sides, verbatim. Attachments as original bytes. Tool calls with
arguments and results. Model and version. System prompt in effect, versioned.
Millisecond timestamps. Participants resolved to identity. Channel and its trust
classification. Cost and latency. Errors and retries.

Immutable by construction: `Collection` marked `worm: true` throws on `update()` — not
"no permission", **no code path**. Erasure exists only through the receipted path, and
on a WORM collection it requires crypto-shredding rather than deletion.

## L3 — Extraction

Conversation → candidate facts. Nothing is a fact yet. Each candidate carries claim,
claim type, speaker, source pointer (`conv-9921 @ 22:14`, clickable forever), entities,
proposed folder, time sensitivity, sensitivity guess, confidence, language, and a
structured form.

Conservative by design: unsure → don't extract, or extract and hold. Never invents —
every candidate points at a byte range in the archive. Instructions are never extracted
as facts. Negation and hedging are preserved, because "Acme does *not* want Q2" and
"Acme *might* want Q3" are different facts. Unattributable claims are held.

**Routing:** agent's project scope → entity match → classifier → default department.
Uncertain → review, never a guess. A misfiled fact crosses a wall, and that's a breach.

### The claim-type taxonomy

| Type | Meaning | Can it be authoritative? |
|---|---|---|
| `heard` | someone outside said it | only after verification |
| `stated` | an employee said it | yes |
| `guessed` | the AI inferred it; nobody said it | **never** |
| `verified` | a human confirmed it | yes |
| `approved` | a human with authority signed it | yes, and unoverwritable by any AI |

## L4 — The gate

See [SECURITY.md](SECURITY.md) for the checks in detail. The structural points:

- It runs in **every** module configuration. Built-in, Connected, or Both.
- It reads the **raw conversation**, not only the tidy extracted claim — that closes
  the obvious bypass where the poison lives in a part the extractor discarded.
- Latency budget p50 <80ms · p95 <250ms · p99 <600ms. Fast path for trusted channel
  with no policy match; slow path goes async and the agent is told "queued", never
  silently passed.

## L5 — Fact store

Folders build themselves as facts arrive, each with a named business **and** technical
owner — an unowned folder is a finding, reported on the Map. Walls are enforced at read
*and* write; a cross-wall attempt is blocked, logged and alerted, never silently
dropped, because silent failure hides attacks. Walls survive reorganisation, and they
apply to derived facts, summaries, search results, entity views and exports — a summary
that would leak across a wall is itself walled.

Entities resolve across systems: "Acme Corp" in a call, a ticket and a bug report is
one entity, with alias handling and a confidence floor below which it goes to review
rather than auto-merging.

## L6 — Hygiene

Runs continuously: deduplicate (sources preserved, confidence rises) · expire by claim
class · resolve contradictions by authority order · decay confidence without deleting ·
re-summarise (summaries inherit the strictest wall and label of their inputs) · detect
drift against golden facts · orphans · staleness · single-source risk · golden
re-attestation · compact · **three-way consistency check across ledger, fact store and
archive**. Every action is logged and reversible. The engine never silently deletes.

## L7 — Read path

```
identify → authorise → rate check → retrieve → filter → rank → label
        → redact → return → log → detect retrieval manipulation
```

Ranking is golden > verified > trusted-channel > corroborated > specific > recent.
Read logging is tiered on purpose, because excessive logging is itself a liability:
full fidelity for `secret`/`confidential`, golden facts, legal holds and cross-wall
attempts; aggregate counts for `public`.

## L8 — Ledger

65 event types, hash-chained, append-only, no edit path. Entries store ids, verdicts,
counts and hashes — never content — so the ledger can be handed to an auditor without
a privacy review. Content-bearing keys are hashed and length-recorded instead.

Signed with customer-held Ed25519 keys, anchored to independent witnesses, and
verifiable by `bin/vault-verify.js`, which imports nothing from `src/`. See
[FORMATS.md](FORMATS.md).

## L9–L12

**L9 Vault Trace** — memory-aware spans: every trace shows which facts were read,
withheld, written, held or blocked, inline with the reasoning. OTel GenAI semantic
conventions in and out. Evals with memory-specific scorers ("did it use the golden
fact? did it repeat a `guessed` fact as truth?").

**L10 Vault Comply** — AI register, 16 controls mapped across frameworks, crosswalk
engine (evidence once, satisfies many), gap analysis, board pack, auditor workspace.
Evidence is pulled from the ledger and the gate, not from screenshots.

**L11 Storage** — hot/warm/cold/archive/WORM tiers with per-class lifecycle, envelope
encryption, per-namespace keys, BYOK/CMK/HYOK/HSM/split-key, and crypto-shredding as
the only honest way to prove deletion from immutable backups.

**L12 Control surface** — 14 screens, HTTP API, MCP server, CLI, webhooks, SIEM and
OTel export.

---

## Cross-cutting

- 🔒 **Employee Privacy Mode** with 12 jurisdiction presets — see [PRIVACY.md](PRIVACY.md)
- 🚪 **Exit & Continuity** — see [CONTINUITY.md](CONTINUITY.md)
- 🛡️ **Security**, 12 layers — see [SECURITY.md](SECURITY.md)

## The injectable clock

`setClock()` in `src/util/time.js` makes "45 days later" real to retention, decay,
credential expiry, SLA ageing and the temporal detectors. The tests use it to run
months of history in milliseconds, and so does the demo. Nothing in the engine reads
`Date.now()` directly.
