# Known limits

Published rather than discovered. Each entry is a deliberate trade-off or a
measured ceiling, stated here so that a buyer, an auditor or a security
researcher finds it in the documentation instead of in an incident.

This file is part of the shipped product. It is not a session report.

---

## 1. Terraform: a REST provider, not a compiled Go provider

**What ships:** server-side plan/apply/drift over the configuration API, and
real `.tf` files driven through the community `restapi` provider. `terraform
plan` produces a genuine diff against live Vault state, and `terraform apply`
converges it.

**What does not ship:** a compiled Go provider published to the Terraform
Registry.

**Why this is a deliberate trade-off.** A compiled provider is a binary that has
to be fetched from a registry at `terraform init`. The air-gapped and on-premise
deployment models are a large part of why this product has zero runtime
dependencies, and a provider that requires a registry fetch reintroduces exactly
the dependency those models exist to avoid. The `restapi` route works in an
air-gapped network with a vendored provider binary and no Vault-specific
supply chain.

**What a customer gives up:** registry discoverability, `terraform import` of
pre-existing resources without a mapping file, and the typed plan output a
first-party provider gives. If a customer requires a first-party provider, say
so during procurement — it is a build, not a research problem.

---

## 2. Mobile: an installable PWA, not a native app

**What ships:** an installable progressive web app with an offline shell,
home-screen shortcuts to the review queue and the kill switch, and full
functionality on a phone browser.

**What does not ship:** a native iOS or Android application in the App Store or
Play Store.

**Why.** The mobile requirement in the specification is "review and kill switch,
minimum". Both work in the PWA. A native app buys push notifications through
the OS notification service, biometric unlock through the platform keychain, and
app-store distribution — none of which changes whether an administrator can
reach the kill switch from a phone.

**What a customer gives up:** OS-level push (the PWA uses web push, which is
supported on current iOS and Android but requires the user to install the PWA
first), and any MDM policy that requires managed apps to come from a store.
**If your MDM blocks PWAs or mandates store distribution, this is a genuine
blocker and should be raised in procurement.**

---

## 3. Search: connected-source federation, not bespoke crawlers

**What ships:** a hybrid retrieval engine over Vault's own memory (BM25 +
semantic + entity + graph + structured filters), permissions-aware at query
time; plus a federation interface that queries a connected search tool and
merges its results, re-filtered by Vault's walls.

**What does not ship:** bespoke crawlers that independently index Google
Workspace, SharePoint, Confluence, Notion, Jira, Slack, Salesforce, Zendesk,
GitHub and file shares while replicating each source's native ACL model.

**Why.** Native ACL replication is the hard part and the part that fails
quietly. A crawler that indexes SharePoint and gets its permission model
slightly wrong produces a search index that returns documents to people who
cannot open them — an access-control failure created by the search feature.
Federating to a tool that already holds the source's ACLs, and then re-filtering
through Vault's walls, is strictly safer.

**What a customer gives up:** single-index latency across memory and documents,
and search over sources for which they have no existing search tool. Vault's own
memory is fully indexed either way.

---

## 4. Scale: proven to 17.3M records per collection; 100M is extrapolated

**Measured, on a 15 GiB machine:**

| | |
|---|---|
| Records in one collection | **17,277,216** (proven by running past the old 16,777,216 ceiling) |
| Write throughput | 312,128 records/sec |
| Read latency | p50 0.00134 ms · p95 0.00283 ms · p99 0.00515 ms |
| Heap per record | 247–533 bytes depending on record size |
| Architectural capacity, one collection | 1,073,741,824 records (64 shards × 2²⁴) |

**The old ceiling was real and is gone.** `Collection.records` was a JavaScript
`Map`; V8 backs a Map with a single FixedArray and throws
`RangeError: Map maximum size exceeded` at exactly 2²⁴ = 16,777,216 entries,
regardless of available memory. It is now sharded.

**What is extrapolated rather than measured:** 100M facts requires
approximately 32 GiB of heap at the measured 341 bytes/record. That is an
ordinary production machine and well inside the sharded capacity, but it has
**not been run on this hardware**, which has 15 GiB. The extrapolation is linear
because a sharded map is O(1) per entry with fixed per-entry overhead and no
rebalancing; the error bar is the 341–533 bytes/record range observed across
scales.

**Ledger, measured at 20,000,000 entries in the real export format:** 406
bytes/entry, verification at 89,267 entries/sec single-threaded and 313,534/sec
across 4 cores (3.51× speedup).

**Full-corpus chain verification against the stated "under one hour" target:**

| Cores | 10B entries | Verdict |
|---|---|---|
| 4 | 8.9 h | **FAIL** |
| 16 | 2.2 h | **FAIL** |
| 32 | 1.1 h | **FAIL** |
| **36** | **0.99 h** | **PASS** |
| 64 | 0.6 h | PASS |

**36 cores are required to meet the one-hour target at 10B entries.** That is a
normal production instance size, but it is a hardware requirement and it is
stated rather than assumed. On a 4-core box the target is missed by 8.9×.

**50 TB archive:** not tested. This environment has 30 GiB of disk. At the
measured 406 bytes per ledger entry, 10B entries alone would need 2.91 TiB.
Verifying the 50 TB claim requires 50 TB of disk; no extrapolation substitutes
for that, and the claim should not be made in a sales context until it is run.

---

## 5. Connector verification: 4 live, the rest against documentation

74 connector clients and 81 module vendor adapters ship with real
vendor-specific authentication, real endpoints, real rate limiting and real
webhook signature verification.

**Verified live** (a real request to the real endpoint producing a real,
documented response): GitHub `/rate_limit`, GitHub App JWT, Google JWKS,
Anthropic `authentication_error`.

**Everything else is contract-verified**: the exact request is asserted against
the vendor's published documentation — method, path, auth header format, body
shape, pagination parameters and terminating condition — and driven through a
real HTTP conformance server that answers as the documentation specifies,
including every documented error status.

**Why not live:** the build environment's egress policy permits five hosts. Every
other vendor host returns 403 from the policy proxy. That is an organisational
network policy, not a missing implementation, and it is not routed around.

**What closes the gap:** a network path to the vendor and one credential per
vendor. `vendorStatus(id)` and `clientStatus()` name the exact credential, the
exact scopes and the exact steps for each one.

**What a customer should assume:** that a connector may need a small correction
on first live use — a header name, a field name, a pagination cursor. The
contract tests make that correction a one-line change with a failing test
attached, rather than an investigation.

---

## 6. Erasure: per-person crypto-shredding covers single-subject records only

A record concerning **exactly one** identifiable person is sealed under a key
unique to that person. Destroying it makes every copy unreadable — live store,
every backup generation, archive tier — in one operation.

A record concerning **more than one** person falls back to a namespace key
shared with other people's records. That key cannot be destroyed without erasing
those other people, so for such records the erasure receipt states plainly that
backups were **not** crypto-shredded, names the scope, and identifies retention
expiry as the actual mechanism.

The live copy is hard-deleted with a segment rewrite in both cases.

This is a real limitation, not a defect, and the receipt is the place it is
disclosed. The MSA carries the same disclosure at Clause 10.5 so the contract
and the artefact agree.

---

## 7. Ledger pseudonymisation is not anonymisation

Person-shaped identifiers in the audit ledger are pseudonymised with an HMAC
under a salt derived from the persisted root key. This defeats `grep` over a
data directory and defeats an auditor handed an export.

It does **not** defeat an attacker who already holds the root key: with the salt,
a guessed identifier can be confirmed by recomputing the HMAC. The identifier
space for email addresses is small enough that this is a practical attack for
someone with the key.

The ledger is the one collection deliberately left readable, because
independent verification with the standalone verifier requires reading it with
no key and no Vault code. Operator-authored audit prose (`reason`, `note`,
`matter`, `purpose`) is also left readable on purpose — an audit log an auditor
cannot read is not an audit log.

---

## 8. Independent assurance: not yet obtained

| | Status |
|---|---|
| SOC 2 Type II | Readiness package generated with ledger-linked evidence. **No audit engaged.** Requires an observation window of at least 3 months. |
| ISO 27001 | Readiness package with a full 93-control Statement of Applicability. **No certification body engaged.** |
| ISO 42001 | Readiness package with the full Annex A mapping. **No certification body engaged.** |
| Third-party penetration test | Engagement package written and ready to issue. **No test performed.** |
| Independent code review | **Not performed.** The code and its review documents share an author, which is a disqualifying conflict for a security review. |

The readiness packages report their own coverage honestly: SOC 2 41/51 controls
evidenced from the ledger, ISO 27001 47/93, ISO 42001 17/38, with every
remaining control listed as a gap and what closes it. A package reporting full
coverage has not been read carefully.

---

*Every number in this document was measured on the date of the commit that
introduced it, and is reproducible with `npm test`, `bin/vault-scale.js` and the
scripts referenced in `docs/drills/`.*
