# Surfaces — HTTP API, MCP, CLI

Everything in the UI is in the API. 131 routes.

## Authentication

Bearer tokens. `ApiServer#issueToken({ name, role, clearance, department })` mints
one; `vault serve` prints three at boot (admin, security, legal) for the process it
started. Every request without a valid token gets `401`; every request from a role that
may not reach a route gets `403` naming the roles that may.

```bash
curl -H "Authorization: Bearer vlt_…" http://localhost:8080/api/status
```

## Who sees what (§24)

Least privilege applies to our own product too — an admin who can silently read
everything is the objection that kills the deal.

| Role | Sees |
|---|---|
| `end_user` | nothing but their own **My Data** portal |
| `folder_owner` | their folder, their queue, their health score, their golden facts |
| `department_head` | their department's memory, agents, value. **No individual employee views in Privacy Mode.** |
| `platform` | connectors, modules, health, scale, cost, storage. **Not content.** |
| `security` | map, rules, walls, blocks, alerts, incidents, own posture. Content only via break-glass. |
| `legal` | cases, holds, erasure, archive, receipts, privileged folders, consent |
| `compliance` | comply, supervision queues, evidence, attestations |
| `finance` | value, cost attribution, chargeback. **No content.** |
| `risk` | insure, incident register, inventory |
| `works_council` | privacy settings, retention, access matrix, change notifications, objection channel. **No content, no individual data.** |
| `admin` | configuration. **Not content** — that needs break-glass with two approvers. |
| `auditor` | read-only, scoped, time-boxed, verification tools, its own access log |

Three capabilities are tracked **separately** from the role's screen list, because they
protect different things and the people who need them are not the same people:

| Capability | Grants | Held by |
|---|---|---|
| `privilegeCleared` | attorney-client material | `legal` |
| `administrator` | administrator-only folders (`admin/`) | `admin` |
| `canAsk` | natural-language questions over the **whole** memory | `admin` `legal` `compliance` `security` |

`canAsk` is narrower than "may read facts" on purpose. An ordinary read returns the
handful of facts somebody is cleared for; an ask ranges over everything at once and
returns prose — a larger disclosure and a much easier one to paste somewhere it should
not go. A lawyer needs `canAsk` and must not get `administrator`; collapsing them into one
seniority flag is exactly how a lawyer ends up reading the board folder.

## Route groups

| Prefix | Screen | Notable |
|---|---|---|
| `/api/map` `/api/coverage` `/api/connectors` | 🗺️ Map | `/connectors/gaps` — expected-but-absent data |
| `/api/facts` `/api/folders` `/api/entities` `/api/golden` | 🧠 Memory | `/golden/:id/blast-radius` before you commit a change |
| `/api/review` | ⏳ Needs Review | `/review/:id/decide`, `/review/bulk`, `/review/ooo`, `/review/suggestions` |
| `/api/rules` | 📜 Rules | **`POST /api/rules/backtest`** — the procurement closer |
| `/api/facts/:id/trace` `/contagion` `/incident-bundle` | 🔍 Trace | who believed the lie, and what did they do about it |
| `/api/archive` | 📚 Archive | supervision queues, production sets, eDiscovery export |
| `/api/observability` `/api/traces` `/api/evals` `/api/otel/v1/traces` | 🔭 Observability | OTel GenAI conventions in and out |
| `/api/legal` `/api/consent` | ⚖️ Cases | holds, erasure plan, DSAR, receipts, privilege log |
| `/api/security` | 🛡️ Security | alerts, detectors, scorecard, cases, **undo** |
| `/api/comply` | 📋 Comply | register, controls, crosswalk, gaps, board pack, audit session |
| `/api/insure` | 🏛️ Insure | pack, gaps, questionnaire, renewals |
| `/api/value` | 📈 Value | health, patterns, chargeback, kill candidates, knowledge map |
| `/api/my-data` | 👤 My Data | the employee portal — export and object |
| `/api/librarian` `/api/facts/:id/tag` `/lock` | 🗂️ Librarian | `POST /librarian/organize`, folder **proposals** (approve/reject), notices |
| `/api/journal` `/api/memory` | 📓 Journal | `/journal/:subject` dossier, `/journal/refusals`, signed `/journal/export` |
| `/api/admin` `/api/killswitch` `/api/ledger` | ⚙️ Admin | modules, keys, storage, privacy, continuity, works council |

Writes go through `POST /api/ingest`; reads through `POST /api/read` and
`POST /api/search`. `POST /api/ask` is gated twice — by role at the router, and by
`vault.mayAsk()` in the vault, which also covers MCP and the CLI. `GET /api/ask/permitted`
tells a caller whether it may ask before it tries.

`POST /api/librarian/proposals/:id/approve` is `admin` only, whatever else a role can
see: reading the audit record does not imply deciding what the folders are. The wall
comes from the request (`read`, `write`, `adminOnly`) and never from the model's
suggestion. `POST /api/journal/export` attributes the export to the **session**, never to
an `exportedBy` in the body.

### Routing rule

A literal path segment always beats a parameter at the same position, regardless of
registration order — so `/api/review/suggestions` is never swallowed by
`/api/review/:id`. There is a test for it.

### Connecting a module over the API

An adapter is live functions and cannot cross the wire, so a module is connected with
a declarative endpoint instead — which is what makes the toggle usable by someone who
is not deploying code:

```
POST /api/admin/modules/archive
{ "state": "connected", "vendor": "Smarsh",
  "endpoint": { "url": "https://smarsh.example/api", "token": "…",
                "paths": { "push": "/ingest" } } }
```

Each required operation becomes one POST to that endpoint. A partial adapter is
allowed — push-only to an archive is a real integration — and the operations it does
not implement are listed in `missingOps`, with Vault's own engine still covering them.
Non-2xx queues the work and flips the module unhealthy; it drains when theirs returns.

### Errors

`{ "error": "<code>", "message": "<plain language>", …context }`. **No error body ever
contains fact content** — there is a test asserting it, because an error message is
the classic accidental exfiltration channel.

---

## MCP server

```bash
npm run mcp          # JSON-RPC 2.0 over stdio
```

Four tools, and no parameter on any of them can skip the checks — asserted by test:

| Tool | Does |
|---|---|
| `vault_remember` | write a candidate fact through the full gate |
| `vault_recall` | read, with every returned fact wearing its provenance label |
| `vault_check` | dry run — returns the verdict, **writes nothing** |
| `vault_status` | what this agent is scoped to, and what it has been doing |

The agent gets the gate's plain-language reason back. Instruction-shaped content comes
back as `HOLD` with which layers fired, not as a silent success.

---

## CLI

```
vault serve [--port 8080] [--data ./data]
vault status | doctor | map | coverage
vault agent register --name N --owner O --tech-owner T [--department d] [--folder f/]
vault agent [list|show|credential|revoke|suspend|retire|attest] <id>
vault golden add "<claim>" --folder f --actor who --role CFO [--approver b]
vault golden [list|due|verify|blast-radius|reattest] <id>
vault ingest <file.json> [--credential vlt_…]
vault ask "<query>" [--agent a-…]
vault review [--folder sales/]
vault rules [list|backtest "<plain>"|export yaml|conflicts]
vault ledger verify | export [file]
vault privacy [status|preview <jur>|apply <jur>|pack]
vault killswitch [status|engage <level>|release|test]
vault hygiene [--dry-run]
vault insure | comply | value
vault export <dir>
```

Standalone tools, each with `--json`:

```
node bin/vault-model.js    [--probe]                       is a model configured, and actually there?
node bin/vault-organize.js [--watch] [--proposals] [--notices] [--memory]
                           [--approve <id> --by <who> --reason "…" [--read a,b] [--admin-only]]
                           [--reject  <id> --by <who> --reason "…"]
node bin/vault-journal.js  [--subject <id>] [--actor <who>] [--refusals] [--verify]
                           [--export <file> --by <who> --reason "…"]
node bin/vault-redteam.js  [--watch] [--interval-ms …]     576 attacks, on a schedule
node bin/vault-sync.js     [--watch]                       poll the connectors that cannot push
```

`npm run model` / `organize` / `journal` / `redteam` / `sync` are the same commands.

`--data` selects the data directory (default `./data`). The ledger signing key is
generated into `<data>/signing-key.json` on first run, mode `0600`, **before** the
first ledger entry is written — otherwise the opening entries would be signed by a key
nobody can produce again and `ledger verify` would call the chain tampered.

### Registering an agent

Folder walls are keyed on **department**, not on the agent's own scope list. An agent
registered without `--department` is legal but mute, so the CLI says so at registration
time rather than letting you discover it through a queue full of held writes.

---

## Other outputs

- **Webhooks** — outbound on gate verdicts, alerts and review decisions
- **SIEM** — `GET /api/siem/events`, plus registered sinks via `addSiemSink()`
- **OTel** — spans out to any collector; `POST /api/otel/v1/traces` accepts them in
- **Mirror** — continuous export to customer-owned storage, see [CONTINUITY.md](CONTINUITY.md)
