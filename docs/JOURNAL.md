# The journal — the complete record

**"Show me everything that ever happened to this record, and who did it."**

That is the question a regulator actually asks. It is not "did sequence 4,812 hash
correctly", and it is not answerable from the ledger alone.

---

## Why there are two records, not one

They have opposite requirements, and merging them means losing one of them.

| | **Ledger** (`src/ledger/ledger.js`) | **Journal** (`src/audit/journal.js`) |
|---|---|---|
| Purpose | prove nothing was altered | say what happened |
| Content | **stripped** — ids, hashes, counts | excerpts, queries, before-and-after values |
| Size | small, forever | proportional to activity |
| Storage | WORM | ordinary collection |
| Hand to an auditor | with no privacy review | after the usual review |
| Chain | hash-chained, signed, externally anchored | hash-chained, signed |

The ledger is content-free **by design** — that is what lets it be handed over
unreviewed. The journal holds exactly what the ledger refuses. Every journal entry
carries the ledger sequence it corresponds to, so an auditor can verify the chain, read
the detail, and check the two agree.

---

## What an entry carries

| | |
|---|---|
| **who** | actor id, kind, department, clearance, on whose behalf, session, credential, source address |
| **what** | the action, the subject, its kind and version |
| **when** | wall clock and a monotonic sequence, so ordering survives a clock that jumps |
| **where** | folder, namespace, region, storage tier |
| **why** | the stated reason, the purpose of access, the legal basis |
| **how** | channel, connector, connector mode, API route, whether a model was involved and which |
| **changed** | field by field — `from` → `to`, not two blobs to diff by eye |
| **result** | allowed or refused, and the reason either way |

A write additionally records every gate check that ran and its verdict, every rule
evaluated, the PII findings, the reconciliation outcome, the instruction score, the seal
hash of the conversation it came from, the content hash at the time, and the latency.
Captured **at the moment it happens**, while the context is still in scope — afterwards,
reassembling that costs a join across four collections and loses the parts nobody
persisted.

Actions are an explicit list, like the ledger's. An unknown action throws. A free-text
action field means three people log the same event under three names and no query ever
finds all of it.

---

## Refusals are recorded as loudly as successes

A log of things that worked describes a system nobody attacked.

The entries that matter in an investigation are the ones where somebody asked for
something and did not get it: wall hits, refused asks, blocked writes, reads that
returned less than was there. They carry the same detail as a successful write, and
`refusals()` collects them so nobody has to grep.

```bash
npm run journal -- --dir ./data --refusals
```

A read records **both halves** — what came back and what was held back. A read returning
three of eleven facts is a different event from one returning three of three, and only
one of them is worth investigating.

Each disclosed record also gets its own entry against **the record itself**, so *"who has
read this fact"* is answerable from the fact rather than by scanning every query anyone
ever ran and checking whether the id was in the result set. That is what a subject access
request asks. Above 100 facts in one query, per-fact attribution is truncated and the
truncation is itself recorded — never silently dropped.

---

## The dossier

```bash
npm run journal -- --dir ./data --subject f-abc123
```

Narrative first, structure underneath. An auditor should be able to read the first screen
and understand what happened without knowing anything about how this system is built —
then check every sentence of it against the entries below.

```
  f-msay023h003dbb5   (fact)
  Acme signed the renewal at 48 seats.
  sales/  ·  internal  ·  v3  ·  live  ·  client:acme corp  ·  🔒 locked

  This record was first touched 6s ago (fact.written) and last touched 6s ago
  (model.flagged). 5 action(s) are recorded against it by 4 distinct actor(s):
  1 read(s), 2 change(s), 0 refusal(s), and 1 action(s) involving a model. Every
  line below is individually hash-linked to the one before it, and carries the
  sealed-ledger sequence it corresponds to.

  WHEN                      WHO           WHAT               WHERE
  2026-08-01 22:36:47   sales-bot     fact.written       sales/
  2026-08-01 22:36:48   dana          fact.read          sales/
  2026-08-01 22:36:48   dana          fact.tagged        sales/
                              ↳ account review
                              ↳ tags: [] → [client:acme corp, topic:renewal]
  2026-08-01 22:36:48   admin         fact.locked        sales/
                              ↳ confirmed with the customer
                              ↳ locked: false → true
```

An unknown subject is a **not-found**, never an empty dossier — "nothing is recorded
against this" and "this does not exist" are different answers.

---

## Handing it over

```bash
npm run journal -- --dir ./data --export bundle.json \
                   --by ciso --reason "FCA information request 2026-114"
```

Two things make this evidence rather than a dump.

**It states its own completeness.** The filters that produced it, how many entries are in
it, how many exist that are not, and whether it is the whole journal:

> This is a **FILTERED extract**: 3 of 9 entries. 6 entries exist that are not in this
> bundle. The filters that produced it are stated above so the recipient can ask for the
> rest.

A selective export presented as a complete one is the oldest way to mislead an auditor
using nothing but true statements.

**It is signed over its own content hash**, so the recipient can prove it is the bundle
that was handed over and not one edited afterwards.

An export must name **who is taking it and why** — an unattributed copy of the audit
record is not evidence, it is a leak. Over the API, `exportedBy` comes from the session
and never from the request body.

Taking a copy of the record is itself an event in the record.

---

## Verifying it

```bash
npm run journal -- --dir ./data --verify
```

Each entry hash-links to the one before it. Editing an entry breaks its own content hash;
deleting one leaves a sequence gap. This is a **weaker** chain than the ledger's — the
collection is not WORM — but a chain that makes deletion visible is still worth having,
and gaps are reported rather than smoothed over.

---

## Who can read it

`admin`, `platform`, `security`, `compliance`, `auditor`, `legal`.

Wider than most routes on purpose: the complete record of who did what is the thing all
of those roles are separately accountable for, and **an audit trail only auditors can see
is one nobody checks**. It is not open to everyone — `finance` gets a 403.

Reading the record does not imply deciding what the folders are. Approving a new access
boundary is administrators only, whatever else a role can see.

### Metadata is wide. Content is still walled.

Six roles can read the record, and the journal deliberately holds what the ledger
refuses — excerpts of claims, queries, transcripts. Those are not the same permission:

> **"May see the audit record" is not "may read every fact in the company."**

So every journal route applies the ordinary folder wall to the *content* of an entry.
Who did what, when, where, why, and whether it was refused stays visible — that is the
record, and it is what an investigation runs on. The sentence itself is walled exactly as
the fact is. Without this, an external auditor refused a payroll fact on the read path
could recover its text verbatim from the trail of it having been written.

It fails closed: an entry carrying content with no folder attached — a sealed
conversation, before anything was extracted from it — cannot be checked against a wall,
so it is withheld rather than guessed at.

Redactions are **marked and counted**, never silently blanked. `GET /api/journal` returns
`redacted: n`; a dossier says so in its narrative; and an export that withheld content
reports `contentRedacted` and refuses to describe itself as complete:

> `n` entry(ies) are present but had their CONTENT withheld… An export containing
> everything requires somebody cleared for everything to take it.

`legal` is exempt, because its row in the role table already reads `content: 'full'`.
Narrowing that would be a separate decision about the role, not about the journal.
