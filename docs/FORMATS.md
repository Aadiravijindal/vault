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
