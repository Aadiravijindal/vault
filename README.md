# 🔒 VAULT

**The company's shared AI memory — with a guard at the door, a recorder that never
stops, and a complete built-in stack you can swap for your own.**

Every AI tool in the company reads from and writes to one memory instead of keeping
its own private notepad. Nothing enters that memory without being checked. Everything
that enters or leaves is recorded, sealed, traceable, reversible, and deletable with
proof.

---

## Run it

Node 22+. No dependencies, no build step, no `npm install`.

```bash
node demo/seed.js            # the whole product, narrated, in ~10 seconds
node demo/seed.js --serve    # same, then opens the 16-screen UI
node bin/vault.js serve      # empty vault, UI + API on :8080
npm test                     # 908 tests
```

`demo/seed.js` seeds a fictional company, runs normal traffic through it, then runs
eight real attacks — indirect injection, a golden-fact overwrite, a credential leak,
drip-feed poisoning, a cross-wall write, an unregistered agent, a homoglyph domain,
and hidden white-on-white text — and shows each one being stopped, with the reason.

### From the command line

```bash
vault agent register --name "Sales Copilot" --owner dana --tech-owner sam \
                     --department sales --folder sales/     # prints a credential
vault ingest conversation.json --credential vlt_…
vault ask "what do we know about Acme?"
vault review                       # the queue
vault rules backtest "no payment authority above $50k"
vault ledger verify
vault doctor
vault export ./out                 # everything, open format, verifiable without us
node bin/vault-verify.js ./out     # standalone verifier — imports nothing from src/
```

`vault help` lists the rest.

### Optional: a model, on your own hardware

```bash
ollama pull mistral:7b-instruct     # ~4GB, no GPU required
export VAULT_MODEL_PROVIDER=ollama  # no API key — nothing leaves the building

npm run model -- --probe            # configured, and actually reachable?
npm run organize -- --watch         # keep the file room tidy, no button pressing
npm run journal -- --subject f-123  # everything that ever happened to one record
```

With no model configured, filing uses deterministic rules and answers are composed from
retrieved facts. Both say which path produced their result. An air-gapped install loses
wording, never correctness — see [docs/AI.md](docs/AI.md).

---

## The one principle

**Everything is built in. Anything can be swapped for theirs with a toggle. The gate
can never be toggled off.**

Every module has three states — 🟢 Built-in (Vault's own engine, default on),
🔵 Connected (use their tool, Vault's engine goes dormant), 🟣 Both (Vault's engine
runs *and* pushes to theirs). Twelve modules ship this way: archive, search, tracing,
compliance, registry, identity, SIEM, KMS, storage, DLP, memory, insurance.

Switching never loses data, degrades gracefully when their tool is down, and works in
both directions. **The gate runs in every configuration.** That one is not a setting.

The same principle governs the model, in one line:

> **A folder is a wall. A tag is an index.**
>
> The model invents tags freely — client names, projects, risk markers — because a tag
> decides what is easy to *find*, and every read through one is still resolved against
> the folder wall underneath. It cannot invent a folder, because a folder decides who
> can *read*. It proposes one instead, and a named administrator approves it. "Who
> approved this category, and when" is the question an auditor asks, and *"the model
> decided"* is not an answer.

---

## The gate — 10 checks on every write, from every agent, forever

| # | Check | Stops |
|---|---|---|
| 1 | Identity & authorisation | unregistered agents, expired/wrong-origin credentials, out-of-scope writes |
| 2 | Channel trust | deny-by-source: email, web forms, scraped pages, other agents' output |
| 3 | Source verification | unauthenticated senders, lookalike and homoglyph domains, first contact |
| 4 | Private information | 45 detectors — credentials blocked outright, never masked-and-stored |
| 5 | Sensitivity labelling | never guesses downward; unsure → higher label, then review |
| 6 | Walls | cross-department writes, blocked *and* alerted, never silently dropped |
| 7 | Instruction detection | 7 layers; **any one firing holds the write** |
| 8 | Policy rules | plain language → policy-as-code, backtested before enabling |
| 9 | Reconciliation | contradictions resolve by **authority, not recency** |
| 10 | Consent & lawful basis | no personal data without a recorded basis |

Outcomes: `pass` · `hold` · `mask` · `escalate` · `block` · `quarantine` ·
`require-4-eyes`. **Every outcome is logged identically** — a blocked write is as much
a record as an accepted one, and it's the one the auditor and the insurer want.

There is no fail-open. The fail-safe posture is queue-and-drain or reject; *pass
unchecked* is not a configuration option, because no code path exists for it.

### Why "authority, not recency"

```
1. approved (golden)         beats everything
2. verified by human         beats unverified
3. trusted channel           beats untrusted
4. higher org authority      beats lower
5. more specific             beats general
6. corroborated              beats single-source
7. ONLY THEN: newer          beats older
```

"Newer wins" was the bug. A stranger's email is always newer than your CFO's approval.

---

## What the agent actually gets back

```
9 facts returned · 2 withheld (above your clearance) · 1 held in review

★ GOLDEN · approved by CFO · 12 Mar 2026 · signed
    "Maximum discount without Finance approval: 20%"
✓ VERIFIED · Marcus Chen (Acme CTO) · phone call · 12d ago
    "Acme wants a Q3 start date"
⚠ GUESSED BY AI · unverified · single source · 5d ago
    "Acme may be evaluating a competitor"
    → DO NOT STATE AS FACT
```

The agent sees the labels. That is the difference between an AI that says "Acme is
evaluating a competitor" and one that says "there's an unconfirmed signal."

---

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The 12 layers, and why the order matters |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, the 12 defence layers, what we don't claim |
| [docs/COVERAGE.md](docs/COVERAGE.md) | Per tool, exactly what Vault can and cannot see |
| [docs/API.md](docs/API.md) | HTTP API, MCP server, CLI, roles and who sees what |
| [docs/PRIVACY.md](docs/PRIVACY.md) | Employee Privacy Mode and the jurisdiction packs |
| [docs/CONTINUITY.md](docs/CONTINUITY.md) | Proof your memory survives even if we don't |
| [docs/FORMATS.md](docs/FORMATS.md) | The export schema and the standalone verifier |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Deploy, storage, keys, backup, kill switch, doctor |
| [docs/AI.md](docs/AI.md) | The model layer — local models, the memory file, what it may never do |
| [docs/JOURNAL.md](docs/JOURNAL.md) | The complete audit record, and why it is separate from the ledger |
| [site/README.md](site/README.md) | The marketing site — brand colours, the mark, and what is enforced |

---

## The proof problem

A hash chain you control proves nothing to an adversary — opposing counsel will say
you own the server and you own the chain. So the chain is only the first of five
layers:

1. **Internal hash chain** — tamper-evidence for you
2. **Customer-held signing keys** — the customer proves integrity, not us
3. **External anchoring** — periodic digests to independent append-only witnesses
4. **Witness diversity** — more than one, so one witness can't be leaned on
5. **Standalone verifier** — `bin/vault-verify.js` imports nothing from `src/`.
   Your auditor runs it against an export and needs to trust neither of us.

---

## What Vault does NOT do

A CISO trusts the fence more than the promise.

- **Vault governs what agents *believe*, not what they can *reach*.** Reach is your
  identity tool's job.
- **If an agent does something harmful in-session and never writes it down, Vault
  didn't stop it.** It governs durable memory. It will show you the conversation after.
- **Watch mode finds. Inline mode stops.** Never confuse the two.
- **Vault is not a model.** It doesn't fix a bad model. It fixes a bad memory.
- **Vault reduces hallucination; it doesn't eliminate it.** It stops the invention
  from persisting.
- **Personal accounts are invisible.** That's policy, not product.
- **Vault does not monitor employees, and does not score people.** No mood, stress,
  honesty, or productivity scoring — in Privacy Mode the code does not exist.
- **The gate has false positives**, around 4% in backtests. That's deliberate: recall
  over precision, absorbed by a review queue built not to become a graveyard.

---

## Layout

```
src/
  api/        HTTP API + the 16-screen UI server        ui/       the UI itself
  ai/         optional model layer — local or hosted provider, semantic filing,
              the librarian (tags, folder proposals, notices), the .vmem memory file
  audit/      the journal — the complete record of who did what, beside the ledger
  archive/    L2 sealed raw archive (WORM)              connectors/  74-tool catalog
  extract/    L3 conversation → candidate facts
  gate/       L4 the 10 checks — gate, instructions, pii, rules, reconcile, classifier
  facts/      L5 fact store, folders and walls, entity resolution
  hygiene/    L6 dedup, expiry, decay, contradiction, three-way consistency
  read/       L7 authorise → filter → rank → label → log
  ledger/     L8 hash chain, signing, anchoring, witnesses
  trace/      contagion, undo, incident bundles         observability/  L9 Vault Trace
  comply/     L10 register, controls, crosswalks        registry/  L1 agent registry
  storage/    L11 db, tiers, kms                        modules/   built-in ↔ connected
  privacy/    Employee Privacy Mode + jurisdiction packs
  legal/      holds, erasure, DSAR, consent, receipts   security/  detectors, killswitch
  insure/     the carrier evidence pack                 value/     cost, health, patterns
  continuity/ mirror, escrow, self-host                 search/    L7 Vault Search
bin/          vault.js (CLI) · vault-verify.js (standalone verifier)
              vault-model.js · vault-organize.js · vault-journal.js · vault-redteam.js
site/         the marketing site — two files, no build step, no dependencies
demo/         seed.js — the whole product, narrated
test/         908 tests
```

Zero dependencies is a deliberate constraint, not a flex: the product has to run
on-prem and air-gapped from a fresh clone, where "just add a database" is a six-week
procurement.

---

## Licence

See [LICENSE](LICENSE).
