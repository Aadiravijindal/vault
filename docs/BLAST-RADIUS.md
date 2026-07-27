# Breach blast radius

What an attacker gets, for each thing they might compromise. Written as an
adversary would write it, because the version written by the defender is always
more flattering than the truth.

Every row states what is reached, what is **not**, and why not — where "why not"
is an architectural property rather than a policy, that is said explicitly,
because policies are what fail during an incident.

---

## The short answer

The worst single compromise is **the Vault process with the KMS scopes already
primed** — that reads everything the running instance can decrypt. The
architecture's job is to make sure that is *still not everything*: the customer
holds the ledger signing key, external witnesses hold the anchors, and split-key
namespaces need a quorum the process does not have.

The most *likely* compromise is a connector credential, and that one is bounded
by design.

---

## 1. A connector credential (OAuth token, API key)

**Reached:** the source system, at the scopes that connector was granted, and
whatever Vault has already ingested through it.

**Not reached:** anything in another folder. A connector writes into the folder
its agent is scoped to; the wall is enforced at write, not just at read.

**Not reached:** the ability to make an assertion stick. This is the important
one. A stolen connector credential lets an attacker *submit* content. It does
not let them make that content become a trusted fact — it still goes through
channel-trust weighting, instruction detection and reconciliation, and content
arriving from a low-trust channel asserting something novel and authoritative is
exactly the shape the gate holds.

**Detection:** rate deviation from the connector's baseline, gap detection, and
schema-drift detection all fire on anomalous connector behaviour.

**Containment:** `vault.connectors.kill(id, { actor, reason })` — immediate, and
disconnect ≠ delete, so the evidence survives.

**Rotation:** credentials are never stored in the collection, the ledger or an
error message; only a fingerprint, so rotation is provable.

---

## 2. An agent credential

**Reached:** read access to that agent's folders at its clearance, and the
ability to write as it.

**Not reached:** other folders. Not with any header, parameter or trick — the
wall check runs on the resolved folder, and there is no admin bypass in the read
path.

**Bounded by:** credentials are short-lived (12h default) and origin-bound. A
credential lifted from a log is expired before most attackers use it.

**Detection:** the temporal detector notices a credential used from a new origin,
at an unusual rate, or asserting outside its historical pattern.

---

## 3. An administrator account

**Reached:** configuration — module toggles, rate limits, connectors, folder
walls, agent registration. The Map, the Admin screen, the kill switch.

**Not reached, by construction:** memory *content*. The `admin` role's content
access is `break-glass only`, and break-glass requires two named humans, a stated
reason and a time box. An administrator cannot silently read a fact.

**Not reached:** the ability to make the record say something different. Every
administrative action appends to a hash-chained, signed ledger. An administrator
can change the future; they cannot change the past without breaking a chain the
customer's own key signs and external witnesses have anchored.

**Not reached:** deletion of the archive. There is no update or delete code path
on a WORM collection — not a permission check, an absent function.

**This is the compromise the design most explicitly anticipates.** "The admin is
the attacker" is the assumption the ledger, the walls and break-glass exist to
survive.

---

## 4. The Vault process itself (RCE, container escape into the app)

**Reached:** everything the running process can currently decrypt. With
Vault-managed keys, that is the store. With a cloud KMS and primed scopes, that
is the primed scopes.

**Not reached:** un-primed namespaces. `RemoteKeyBridge` caches a KEK per scope
with a TTL; a scope that was never primed cannot be opened, and a cached one
expires.

**Not reached:** split-key namespaces without a quorum. M-of-N shares are held by
people, not by the process.

**Not reached:** the ability to forge the record. The ledger is signed with the
customer's private key. In the intended deployment that key is not on the Vault
host — it signs at the customer's side. An attacker inside the process can
*append* what the process could append, but cannot rewrite history and cannot
produce entries that verify against an anchor already published to witnesses.

**Detected by:** the standalone verifier, run by the customer against their own
export, using their own key. That check does not trust the process at all — which
is the entire reason it imports nothing from `src/`.

**Honest limit:** if the signing key IS on the compromised host — which is the
default single-host deployment — an attacker with the process can sign. The
mitigation is external anchoring: entries published to witnesses before the
compromise cannot be retroactively altered without the witnesses' copies
disagreeing. Anchor frequently, and keep the key off the host.

---

## 5. The storage layer (S3 bucket, database volume, backup tape)

**Reached:** ciphertext. Envelope encryption means objects are encrypted under a
per-object DEK, wrapped by a per-scope KEK.

**Not reached:** plaintext, without the KMS. In BYOK/CMK/HYOK modes the key
material is the customer's and the unwrap happens at their service.

**Not reached:** undetected modification. Every write is verified round-trip by
hash at put time; the ledger holds an independent hash of every record; a
modified object fails verification.

**Crypto-shredding:** destroying a KEK makes every object under that scope
undecryptable in one step — including the copies in backups and the archive
tier. It is the only honest way to prove deletion from immutable media, and the
erasure receipt names it explicitly rather than claiming backups were "deleted".

---

## 6. The customer's signing key

**Reached:** the ability to produce ledger entries that verify.

**Not reached:** the ability to change entries already anchored. An anchor is a
digest published to independent witnesses at a point in time; rewriting history
before that point makes the local chain disagree with copies we do not hold.

**Response:** rotate the key, re-anchor, and treat every entry after the last
verified anchor as unproven until independently corroborated. This is a Sev 1.

---

## 7. A works council or auditor account

**Reached:** configuration transparency — retention settings, access matrix, the
list of re-identifications, the privacy screen.

**Not reached:** content. `works_council` has `content: 'none'` and
`noIndividualViews: true`; `auditor` is `read-only scoped`. Both are enforced at
the route, not documented in a policy.

This matters in the other direction too: these roles exist so oversight does not
require handing someone the ability to read everything.

---

## 8. A supply-chain compromise of a dependency

**Reached:** nothing, by construction. There are no runtime dependencies. The
product imports `node:` builtins and nothing else, so dependency confusion,
typosquatting and transitive CVEs have no surface here.

**Still in scope:** Node.js itself, the operating system, the container image,
and the machine that produces the artefact. `bin/vault-supplychain.js` inventories
these and produces an SBOM and provenance statement — and states plainly that the
provenance is SLSA L1 at best because it is generated on the same machine as the
build.

---

## What would actually hurt most

Ranked by damage, not by likelihood:

1. **The signing key on a compromised host, with infrequent anchoring.** The
   record becomes forgeable and the forgery is not detectable. Everything else in
   the product depends on this not happening. Keep the key off the host; anchor
   often.
2. **A poisoned golden fact.** Golden facts are the authority reconciliation
   defers to. Poisoning one propagates. This is why they require two named humans
   and cannot be written through any agent path.
3. **A wall misconfiguration that widens quietly.** Which is why widening a wall
   raises an alert and appears in the ledger with before and after — it is not
   possible to widen access without leaving a mark.
4. **A connector credential.** Most likely, least damaging. Bounded by scope,
   caught by the gate, killable in one call.

## What this document is not

It is not a penetration test. It is the design's own account of its containment
boundaries, and a competent attacker's job is to find the place this account is
wrong. Where a claim above rests on a policy rather than a structure, it is
labelled as such — those are the places to look first.
