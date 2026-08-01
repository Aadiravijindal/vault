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

## Two different meanings of "verified"

```bash
vault conformance          # or: node bin/vault-conformance.js
```

**74 of 74 pass conformance.** Each one builds a real request against a synthetic
vendor and is checked on what it actually sent: the credential is attached under the
header that vendor reads, every `{placeholder}` is substituted, the URL is absolute
and HTTPS, a token-exchange scheme knows where to exchange the token, and a signed
webhook rejects a forged signature.

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
