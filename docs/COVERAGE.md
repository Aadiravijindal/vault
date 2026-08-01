# The coverage map

**Say this out loud in every sale.** Publishing the holes is what makes a CISO trust
you; vagueness here is what makes them distrust every other vendor in the room.

Vault publishes, per tool, exactly what it can and cannot see. Run it yourself:

```bash
vault coverage
```

or read it from the API at `GET /api/coverage`, or open the Map screen.

## What the columns mean

| Column | Meaning |
|---|---|
| **CONVOS** | can Vault see the conversation content? `✗*` means "not in this mode" — the footnote says which mode fixes it |
| **MEMORIES** | can Vault see the memories the tool stores for itself? |
| **BLOCK?** | can Vault *stop* a write, or only observe it after the fact? |
| **MODE** | which connection modes this tool supports |
| **NOTES** | the specific blind spot, named |

## The shape of it

```
TOOL                  CONVOS  MEMORIES  BLOCK?  MODE          NOTES
ChatGPT Enterprise      ✓        ✓        ✓     Watch+Inline
Claude Enterprise       ✗*       ✗*       ✓     Inline/GW     *audit log excludes
                                                               content by design
Claude Code (MCP)       ✓        ✓        ✓     Inline
Vapi calling agent      ✓        ✓        ✓     Watch+Inline  cannot see: audio before
                                                               the assistant answered
Intercom Fin            ✓        —        ✗     Watch
Copilot Agent (CI)      ✓      partial    ✗     Watch
Custom API bot          ✓        ✓        ✓     Inline+GW
Personal ChatGPT        ✗        ✗        ✗     —             NOT REACHABLE
                                                              → policy problem,
                                                                not product
```

74 connectors ship in the catalog. Every one carries the same seven facts: auth method,
modes supported, what it pulls, **what it cannot pull**, setup time, scopes required,
and rate-limit profile.

## Four different meanings of "verified"

```bash
vault conformance          # or: node bin/vault-conformance.js
```

**74 of 74 pass conformance.** Each one builds a real request against a synthetic
vendor and is checked on what it actually sent: the credential is attached under the
header that vendor reads, every `{placeholder}` is substituted, the URL is absolute
and HTTPS, a token-exchange scheme knows where to exchange the token, and a signed
webhook rejects a forged signature.

**3 of 74 are checked against the vendor's own published OpenAPI document.**

```bash
vault contract             # or: node bin/vault-contract.js
```

GitHub, Slack and Twilio publish machine-readable API descriptions. Every endpoint
Vault calls on those three is confirmed to exist in the vendor's own spec, with an
allowed method, at a host the vendor declares. That is the provider-driven contract
test the industry uses for third-party integrations, and it needs no credential —
only the spec, which is public. It catches the invented path and the renamed
endpoint, which conformance cannot.

Only three, because the rest publish no machine-readable description or publish one
only as YAML, and Vault ships no YAML parser. Those are listed as unverifiable-here
rather than quietly dropped.

**3 of 74 are continuously polled and ingested through the gate today**, with nobody
calling `vault_remember` by hand.

```bash
vault sync                 # or: node bin/vault-sync.js [--watch]
```

The connector layer already had everything downstream of a fetch: idempotency, cursors,
schema-drift detection, gap alarms, the kill switch, the cost meter. What it never had
was anything upstream that actually called the vendor on a schedule. `src/connectors/
sync.js` is that: it polls, and feeds the vendor's answer into the SAME gate as an
inline write — filing, sensitivity, department walls and instruction detection included,
because there is only one ingest path in this codebase.

Wired for exactly Slack, GitHub and Twilio — the same three the contract check covers,
because that is where the response shape is actually confirmed rather than guessed.
A normalizer against an unconfirmed shape for the other 71 would be exactly the overclaim
this map exists to prevent, so every other connected connector is reported skipped, by
name, with why, rather than silently doing nothing. Each one gets wired the same way once
its real response shape is confirmed.

**4 of 74 have been run against the vendor's real API.** That number has not moved.
Conformance rules out a malformed request; only a credential rules out a vendor whose
API differs from its own documentation, an undocumented required header, or a response
shape nobody published. Passing conformance does not earn `status: 'live'`.

Conformance is worth running because it found real defects that a live run would have
hit on its first request:

- Every URL placeholder was percent-encoded, including the ones holding a whole
  origin. Salesforce learns its `instanceUrl` from its own token exchange, so every
  request became `https%3A%2F%2Facme.my.salesforce.com/…`. That connector could not
  have worked against a real tenant.
- `gemini-enterprise` used the JWT bearer flow with no token endpoint defined, so the
  signed assertion had nowhere to go. It was marked `live` on the strength of its
  JWKS endpoint, which needs no credential — exactly the overclaim this map exists to
  prevent.

## The three honest sentences

1. **Watch finds things. Inline stops things. Gateway finds things you didn't know
   existed.** A customer who installed Watch mode did not buy prevention. The Trace
   screen marks every fact captured in Watch mode with *"gate NOT run — this agent was
   in Watch mode"*, and the suggested fix is one click: move it to Inline.

2. **Some vendors' audit logs deliberately exclude message content.** Those tools
   cannot be covered in Watch mode at all. They need Inline or Gateway. The map says so
   per tool rather than averaging it away.

3. **Personal accounts are not reachable.** That is a policy problem, not a product
   one. Vault's job is to make the sanctioned path better than the unsanctioned one,
   not to pretend it can see a personal ChatGPT session.

## Retention on the upstream APIs

Several chat platforms expose only ~30 days of history through their compliance APIs.
Vault must export continuously or the history is simply gone. That is itself a reason
to buy, and it is why every connector does backfill on connect plus incremental after,
with **gap detection**: *"we should have seen data between 14:00 and 16:00 and didn't."*
A gap raises an alarm to a named owner within 15 minutes rather than being discovered
at audit.

## Where coverage gaps show up in the product

- **Map screen** — coverage per tool, with unowned agents and shadow findings
- **`vault doctor`** — Watch-mode agents listed as a medium finding with the fix
- **Insurance pack** — "N agents are in Watch mode — observable but not preventable",
  ranked by likely premium impact
- **Trace** — per fact, whether the gate ran at all
- **`vault sync`** — which connectors are actually being polled right now, and which
  are named as skipped and why

## Adding a 75th connector

```bash
vault add-connector my-new-tool.json      # or: node bin/vault-add-connector.js
```

`src/connectors/scaffold.js` takes the handful of facts specific to a new vendor —
auth scheme, base URL, endpoints, what it pulls, and **what it cannot pull** — and
returns two paste-ready snippets, one for the catalog and one for the client
definition. Before printing either, it runs the same class of check conformance.js
runs against the 74 already shipped: the auth scheme is a real one, the base URL
resolves to absolute HTTPS, every endpoint is a rooted path, a token-exchange scheme
names where the token comes from, and the auth scheme actually builds a header. A
new connector fails here, offline, in seconds, rather than shipping broken — and it
refuses to let `cannotPull` be silently empty, because a blank blind-spot list is
worse than an honest "not known yet".

What it cannot do: decide the vendor's real auth scheme or endpoints for you, or
promote a new connector past conformance. Run `vault conformance` after pasting, and
`vault contract` if the vendor publishes a machine-readable OpenAPI spec — the same
path every existing connector went through.
