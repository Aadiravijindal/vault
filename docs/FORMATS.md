# Export format and independent verification

The point of this document: **your memory is portable and your proof survives us.**

```bash
vault export ./out               # free, any time, any volume, no throttling
node bin/vault-verify.js ./out   # exit 0 = verified, exit 1 = tampered
```

## `vault.export.v1`

| File | Contents |
|---|---|
| `facts.jsonl` | one fact per line, the complete fact model |
| `golden.jsonl` | golden facts with attestations and signatures |
| `conversations.jsonl` | the raw archive — whole transcripts with seal hashes |
| `ledger.jsonl` | the hash-chained ledger, verifiable standalone |
| `rules.yaml` | policy rules as code |
| `rules.tf` | the same rules as Terraform, for the platform team |
| `folders.json` | folder tree with walls, owners, retention and residency |
| `entities.json` | resolved entities, aliases, cross-system ids |
| `agents.json` | the registry — owners, scopes, pinned models |
| `receipts.jsonl` | deletion, consent and hold receipts with proofs |
| `manifest.json` | file hashes, counts, schema version, chain head, public key |
| `SCHEMA.md` | the field-by-field schema, written into every export |
| `SELFHOST.md` | how to stand the whole thing up from this directory, without us |

JSONL, one object per line, UTF-8. Not a proprietary blob — portable to a competitor,
and the migration tooling goes both ways (import from Mem0, Zep, Letta, Glean, Smarsh;
export to any of them).

## The fact model

Every fact carries five blocks. Nothing in them is optional — a fact without provenance
isn't a fact, it's a rumour.

```
IDENTITY     id · version · created/updated · status
CONTENT      claim · structured form · original strings · language · entities
PROVENANCE   claim type · said by · captured by · connector mode · channel ·
             channel trust · source verification · source ref (clickable, forever) ·
             model + version · extraction confidence
GOVERNANCE   sensitivity · folder · namespace · owner · region · rules evaluated ·
             gate outcome · reviewed by · legal hold · privileged ·
             regulatory record · consent basis
LIFECYCLE    expires · confidence + decay · last confirmed · review due ·
             supersedes · superseded by
USAGE        read count · read by · derived facts · influenced actions
SECURITY     instruction score · PII findings · anomaly flags · corroborating sources
INTEGRITY    content hash · ledger position · prev hash · signature
```

## The ledger

65 event types, hash-chained. Each entry:

```json
{
  "id": "l-000000000042", "seq": 42, "type": "fact.written",
  "at": 1785312000000, "actor": "a-114", "subject": "f-88214",
  "folder": "sales/accounts/acme-corp/", "outcome": "pass",
  "claimHash": "sha256:…", "claimLen": 34,
  "contentHash": "…", "prevHash": "…", "hash": "…", "signature": "…"
}
```

**Content never appears in the ledger.** Content-bearing keys are replaced by
`<key>Hash` and `<key>Len`, so the whole chain can be handed to an auditor without a
privacy review. Payload keys that would collide with the envelope's own fields are
namespaced to `payload_*` rather than overwriting them — otherwise a payload with an
`id` field would silently corrupt the chain it is being sealed into.

## Verification, in five layers

A hash chain the vendor controls proves nothing to an adversary. Opposing counsel will
say: you own the server, you own the chain. So:

| Layer | What it gives |
|---|---|
| Internal hash chain | tamper-**evidence**, for you |
| **Customer-held signing keys** | the *customer* proves integrity, independent of us |
| **External anchoring** | periodic digests to an independent append-only witness |
| **Witness diversity** | more than one witness, so no single one can be leaned on |
| **Standalone verifier** | `bin/vault-verify.js` — imports nothing from `src/` |

The verifier recomputes canonical-JSON content hashes, chain links, sequence continuity
(a missing entry is as much a tamper signal as an altered one), Ed25519 signatures
against the public key in the export, anchor digests, and the manifest's file hashes.
Exit code 0 or 1. Your auditor runs it and needs to trust neither of us.

It also says what it does *not* prove:

> What this proves: no entry was altered, removed or reordered after it was written,
> and every signed entry was signed by the holder of the private key matching the
> public key in this export.
>
> What it does not prove: that the facts recorded are true. It proves what was
> recorded, and that the record has not been changed since.

## Storage format on disk

One JSONL file per collection, each line an operation:

```
{"o":"i","id":"f-1","t":1690000000000,"d":{…}}   insert
{"o":"u","id":"f-1","t":…,"d":{…}}               new full revision
{"o":"x","id":"f-1","t":…,"r":"erasure REQ-1"}   physical erasure tombstone
```

Append-only by construction, so "editing" a fact writes a new revision and the old one
survives. WORM collections reject `update` and `delete` **at the code level** — there
is no path. Erasure physically rewrites the segment, so a deleted transcript is gone
from the bytes, not merely from an index. Records can be envelope-encrypted per key
scope, which is what lets crypto-shredding reach backups.

---

## `vault.journal.v1` — the audit bundle

The complete record of who did what, exported for a regulator or an investigator. See
[JOURNAL.md](JOURNAL.md) for what it is and why it is separate from the ledger.

```json
{
  "format": "vault.journal.v1",
  "exportedAt": "…", "exportedBy": "ciso", "reason": "FCA request 2026-114",
  "filters":      { "subject": null, "actor": null, "folder": null, "from": null, "to": null, "action": "fact.written" },
  "completeness": { "entriesInBundle": 3, "entriesInJournal": 9, "excluded": 6, "full": false, "statement": "This is a FILTERED extract: …" },
  "chain":        { "head": "…", "verified": { "ok": true, "checked": 9, "problems": [] } },
  "entries":      [ … ],
  "bundleHash": "…", "signature": "…", "publicKeyPem": "…"
}
```

Two properties make it evidence rather than a dump. **It states its own completeness** —
a selective export presented as a complete one is the oldest way to mislead an auditor
using nothing but true statements. And it is **signed over its own content hash**, so the
recipient can prove it is the bundle that was handed over.

Each entry carries `who / what / when / where / why / how`, a field-by-field `changed`
list, `allowed`, and the sealed-ledger `ledgerSeq` it corresponds to — so the chain and
the detail can be checked against each other.

---

## `VMEM v1` — the AI memory file

`data/ai-memory.vmem`. What the *filing* has learned about this company, as distinct from
the facts themselves. Gzipped JSON with a `VMEM` magic header; a mature file over a busy
estate is tens of kilobytes.

```json
{
  "magic": "VMEM", "format": 1, "tenant": "default", "writtenAt": …,
  "head": "…",
  "revisions": [ { "seq": 1, "at": …, "actor": "…", "reason": "…", "stateHash": "…", "prevHash": "GENESIS", "hash": "…" } ],
  "tokens":   { "invoice":   { "n": 12, "folders": { "finance/": 12 }, "sens": { "confidential": 12 }, "seen": … } },
  "clients":  { "acme-corp": { "n": 12, "type": "organisation", "folders": { "finance/": 12 }, … } },
  "corrections": [ { "at": …, "factId": "f-1", "from": "sales/", "to": "legal/", "by": "human", "terms": [ … ] } ],
  "uncertain":   [ … ],
  "counters":    { "learned": 40, "recalls": 12, "human": 3, "model": 9, "rules": 28 },
  "signature": "…", "publicKeyPem": "…"
}
```

**No claim text, ever.** Only vocabulary, ids and counts — and tokens carrying three or
more consecutive digits are dropped on the way in, so a salary or an account number
cannot survive as vocabulary. The file is built to be boring enough that it is not worth
stealing.

Revisions are hash-chained and the head is signed, so an edit that retrains the filing
breaks the chain and `verify()` names the revision that broke. Usage counters sit
*outside* the sealed hash, exactly as read counts sit outside a fact's content hash —
reading the memory must never make it look tampered with.

A wrong magic, a non-gzip payload or a future format version is **refused as such**
rather than parsed into nonsense. Deleting the file costs speed and nothing else.
