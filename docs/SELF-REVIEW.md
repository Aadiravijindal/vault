# Structured Self-Review for a Human Reviewer

**Version:** 2.0 — 2026-07-28 (second pass).

---

## 0. Read this part first

**This document was written by the same agent that wrote the code it reviews.**

That is a disqualifying conflict of interest for a security review, and nothing
below changes it. A reviewer who reads only this document has not had the code
reviewed; they have had it described by its author. The purpose here is narrow
and specific: to make an independent review *faster and better targeted* by
saying where the author already knows the ground is soft.

There is a concrete reason to distrust this document's confident passages. Over
five working sessions on this codebase, the same author reported **eighteen**
mechanisms as complete and working which were subsequently proven, by execution,
not to be. Several were written minutes before being declared done. One was
introduced *during the writing of this document*, by the author, while fixing
another entry on the list — see the end of §5. The full register is §5, and it
is the most useful section here.

The pattern in every case was identical: **the code existed, was well-structured,
had tests, and did not do what it said.** The tests asserted against the code's
own account of itself rather than against the underlying state. So the specific
question worth asking of any claim below is not "does this look right?" but
"what would this test still pass if the mechanism were removed?"

---

## 1. Critical-path walkthrough, in reading order

A reviewer with limited time should read these, in this sequence. Roughly a day.

### 1.1 `src/index.js` — the constructor (≈400 lines)

Everything is wired here. Two things deserve attention out of proportion to
their size:

- **`PLAINTEXT_COLLECTIONS`** (top of file). The allowlist of collections that
  may sit on disk unencrypted. It has one entry. Every collection not listed is
  sealed by default. **Judgement call for you:** is `ledger` correctly exempted?
  The reasoning is that independent verification requires reading it without a
  key. The counter-argument is that it is the one file guaranteed to be readable.
- **`nsOf`** — the key scope function. Decides what a crypto-shred can destroy.
  Records naming exactly one person key to that person; everything else keys to
  the namespace. This boundary is load-bearing for the erasure receipt's
  truthfulness and is discussed at §3.2.

### 1.2 `src/gate/gate.js` — the ten checks

The product's central claim. Read the order the checks run in and ask what
happens when one throws.

### 1.3 `src/ledger/ledger.js` — `append`, `stripContent`, `reduceValue`

The reduction rules that decide what may enter the audit chain. Rewritten this
session after the chain was found to contain SCIM usernames, consent subjects
and participant names behind a docstring claiming it contained no content.
Read `AUDIT_PROSE` critically — see §4.1.

### 1.4 `src/legal/legal.js` — `erase()`

The erasure receipt. A document a regulator reads. Has been factually wrong
twice. Read the `sealedUnder` map and the `notReached` branch.

### 1.5 `src/continuity/backup.js` — `_rehydrateFromStore`, `recordSuppression`

Rewritten this session after the discovery that a backup could not be restored
at all once the primary was gone.

### 1.6 `src/storage/db.js` — `Db.collection`

Where encryption-by-default is applied.

### 1.7 `test/adversarial.test.js`

Read last, and read it as evidence about the *author*, not only about the code.
It records what was already got wrong.

---

## 2. Every mechanism mutation-tested this session

For each: the mutation applied, and what caught it. A mutation test proves the
test has teeth. **It does not prove the mechanism is correct** — only that it is
genuinely exercised. Do not read this table as assurance of correctness.

| # | Mechanism | Mutation applied | Caught by | Result |
|---|---|---|---|---|
| 1 | Encryption at rest, default-on | `encryptByDefault: false` in the Vault constructor | Whole-directory canary grep (A1) + per-collection assertion (A2) | 3 tests failed; restored → green |
| 2 | Ledger content reduction | Reverted `reduceValue` to pass all strings verbatim, i.e. the original denylist behaviour | Canary grep of `ledger.jsonl` + shape unit tests | 3 tests failed; restored → green |
| 3 | Ledger identity pseudonymisation | Removed the pseudonymise call from `_reduceIdentity` | Canary grep + the email round-trip test | 2 tests failed; restored → green |
| 4 | Backup manifest persistence | Removed the `store.put(manifest…)` call | DR restore with the primary destroyed | 2 tests failed; restored → green |
| 5 | Erasure suppression persistence | Removed `_persistSuppression` | Pre-erasure backup restore returned the erased canary | 1 test failed; restored → green |
| 6 | Erasure key-scope selection | Shredded `subject:<name>` as the old code did, without consulting the record | Assertion that the guessed scope ≠ the real scope and the real key survives | Reproduced the original bug exactly |
| 7 | MFA enrolment persistence | Detached the collection (`v.mfa.col = null`) | Restart round-trip | Enrolment vanished, as required |
| 8 | Sharding past the V8 Map ceiling | `ShardedMap(1)` — one shard | Capacity assertion collapses to 16,777,216 | Caught; the ceiling returns with one shard |
| 9 | Parallel chain verification | Byte-level tamper at 0.2%, 50% and 99.8% of a 3,000,000-entry file, in place, same-length | `verifyParallel` reported the exact seq each time; clean after restore | Caught at all three positions, including across worker seams |
| 10 | Vendor adapter error handling | A conforming server returning 401/403/404/409/422/429/500/503 | Every status surfaced with `vendorStatus` and `Retry-After` read | Caught; none swallowed |
| 11 | Readiness evidence integrity | Re-read all 92 cited ledger entries and compared hashes | Any mismatch fails the package test | 0 mismatched |

**What is NOT mutation-tested, and should be:** the gate's ten checks
individually, the wall enforcement, break-glass two-person control, and Employee
Privacy Mode's architectural absences. Those are §6 questions.

---

## 3. Known risk areas, ranked

### 3.1 The gate-bypass claim rests on tests written by the claimant — **highest**

"The gate cannot be turned off" is the product. It is asserted programmatically,
but by the same author. There is no independent confirmation. This is the single
most valuable thing to hand to an external tester, and it is scoped as priority
one in `docs/PENTEST-PACKAGE.md` §4.1.

### 3.2 Multi-person records cannot be crypto-shredded per person — **high**

A record naming two or more people falls back to a namespace key. Destroying it
would erase the other people. So for those records the erasure receipt states
plainly that backups were **not** reached, and names retention expiry as the
actual mechanism.

**This is a real, unresolved limitation, not a bug.** It is reported honestly.
Whether "reported honestly" is commercially sufficient for a GDPR Art 17
response is a judgement a lawyer and a customer must make, not the engineer who
chose the boundary. **Flagged for you to overrule.**

### 3.3 Ledger pseudonymisation is not anonymisation — **high**

Person-shaped identifiers in the ledger are HMAC'd under a salt derived from the
persisted root key. Anyone holding the root key can confirm a guessed identifier
by recomputing. It defeats `grep` and it defeats an auditor handed the export.
It does not defeat an attacker who already has the root key.

Stated in the code, in the bounty policy, and here. **Do not let it be described
as anonymisation in any sales material.**

### 3.4 `AUDIT_PROSE` fields stay readable in the ledger — **medium**

`reason`, `note`, `matter`, `purpose`, `name`, `title`, `description` and
similar pass into the chain verbatim, because an audit log an auditor cannot
read is not an audit log. These are operator-authored fields, not content lifted
from customer conversations.

**The residual risk is an operator typing a person's name into a `reason`
field.** That cannot be solved by hashing without destroying the field's
purpose. `name` is the widest of these and is the one I would most expect a
reviewer to want narrowed. **Flagged for you to overrule.**

### 3.5 70 of 74 connector clients are unverified against live services — **medium**

Verified against published vendor documentation, not a live account, because the
build environment cannot resolve those hosts. A contract test proves we send
what the docs specify; it cannot prove the docs are current or that the vendor
behaves as documented.

### 3.6 The scale ceiling is real and unfixed — **medium**

`Collection.records` is a JavaScript `Map`. V8 throws "Map maximum size
exceeded" at exactly 16,777,216 entries. The stated target is 100M facts and 10B
ledger entries. **The current architecture cannot reach either.** Not addressed
this session; see §7.

### 3.7 Ledger `entries()` and `verify()` are linear in the corpus — **medium**

`this.col.all()` materialises every entry. Fine at the tested scale, and a
problem well before 10B. Related to 3.6 and unaddressed.

### 3.8 The suite runs single-threaded by choice — **low**

`--test-concurrency=1`. A previously-found flake (execFileSync truncating stdout
under parallel load) was addressed by removing the parallelism rather than the
race. That is a legitimate trade, but it means concurrency bugs are not being
looked for.

---

## 4. Judgement calls a human should confirm or overrule

Each of these is a decision I made where a reasonable person could decide
differently. I have stated my reasoning and my confidence.

### 4.1 Keeping operator prose readable in the ledger

**Decision:** `reason`, `matter`, `purpose`, `note`, `name` and similar are
written verbatim into the audit chain.
**Reasoning:** these are precisely the fields an auditor reads. Hashing them
yields a chain that verifies and answers no question.
**Against:** they are free text and an operator may type anything into them.
**Confidence:** medium. **I would not be surprised to be overruled on `name`.**

### 4.2 Exempting only the ledger from encryption at rest

**Decision:** one entry in `PLAINTEXT_COLLECTIONS`.
**Reasoning:** independent verification with no Vault code and no key is a core
product claim; sealing it would end that.
**Against:** it is the one guaranteed-readable file.
**Confidence:** high, given the reduction rules — but the reduction rules are
the thing being trusted, and they are new.

### 4.3 Keying records by subject when exactly one person is named

**Decision:** exactly one person → `subject:` scope; zero or several →
namespace.
**Reasoning:** it is the boundary at which a per-person shred is meaningful
without destroying a third party's data.
**Against:** it is a sharp cliff. A record that names one person plus a passing
mention of another loses per-person shreddability entirely.
**Confidence:** medium. **This is the decision I would most like reviewed.**

### 4.4 Not revoking a session when a group is added that does not change the role

**Decision:** adding a lower-privileged group to an admin does not revoke.
**Reasoning:** revoking on every IdP group sync is its own outage.
**Against:** a strict reading says any entitlement change should re-mint.
**Confidence:** high.

### 4.5 Unrecognised roles rank last in SCIM precedence

**Decision:** a role name not on Vault's precedence list ranks below every known
role.
**Reasoning:** the alternative — which was the actual behaviour — had `indexOf`
returning −1, sorting unknown roles *ahead of* `admin`.
**Against:** a customer mapping a genuinely superior custom role now finds it
outranked.
**Confidence:** high that the old behaviour was wrong; medium that "last" beats
"error on an unmapped role".

### 4.6 Storing TOTP seeds at all

**Decision:** MFA enrolments are persisted, sealed, because they previously
vanished on every restart.
**Against:** the seeds are now on disk, where they were not before. Mitigated by
default encryption and asserted by a test that greps for the issued seed.
**Confidence:** high that persisting is right; **this deserves a second opinion
on key handling specifically.**

### 4.7 Plaintext portability exports

**Decision:** `continuity.export()` writes readable JSON/JSONL.
**Reasoning:** it is the customer's own data going to customer-owned storage,
and §19 promises an open documented schema with no lock-in.
**Against:** it is the largest plaintext surface the product creates, written to
a caller-supplied path.
**Confidence:** medium. **A reviewer may reasonably require an encryption
option and a destination policy.** I did not add one.

---

## 5. Every prior "done" that turned out to be false

This is the most useful section for a reviewer, because it locates the pattern.

### Found in earlier sessions (8)

| # | Claim | Reality | Root cause |
|---|---|---|---|
| 1 | SCIM PATCH replace substitutes group membership | Appended, so a demotion left the old entitlement | RFC misread; `replace` treated as `add` |
| 2 | Crypto-shredding is durable | KEK re-derived from the root on restart, undoing the shred | Destruction recorded in memory only |
| 3 | Erasure destroys the record's key | Destroyed `conversation:<id>` for a record keyed `ns:unfiled` | Scope guessed, not read from the record |
| 4 | No identifiers leak to disk | `lastRevocation` echoed a userName back into a sealed record | Return value carried more than the caller needed |
| 5 | Request URLs are built after token exchange | Built before, so the URL used a stale token | Ordering bug hidden by async |
| 6 | Identity files store no employee names | Names, emails and departments in plaintext | Field encryption not applied to that collection |
| 7 | Encryption at rest is on | No collection was ever constructed with `encrypted: true` | Capability implemented, never enabled |
| 8 | Crypto-shredding reaches backups | Backups held plaintext | Backup path bypassed the seal |

### Found this session (5)

| # | Claim | Reality | Root cause | Status |
|---|---|---|---|---|
| 9 | "Content is never stored here… the ledger can be handed to an auditor without a privacy review" | SCIM usernames, consent subjects, DSAR subjects, participant names and folder owners in plaintext in the chain | `stripContent` was a **denylist of nine key names**; every other key passed verbatim, and `subject` was copied in before the filter ran | Fixed, mutation-tested |
| 10 | Encryption at rest covers content | 33 of 45 collections unencrypted, including the DSAR register, saved searches, case notes and the agent inventory | Encryption was **opt-in**; only the collections somebody remembered were sealed | Fixed — now opt-out, with a justified allowlist |
| 11 | Backups are restorable; the quarterly restore drill passes | `restore()` threw "there are no backups to restore from" whenever the primary was gone. The manifest chain lived only in the memory of the process that took the backup | **Every restore test restored from the same live process that took the backup.** The process boundary — which is what a disaster *is* — was never crossed | Fixed, mutation-tested |
| 12 | "Backups crypto-shredded — the ciphertext is unrecoverable" (on the erasure receipt) | Restoring a pre-erasure backup returned the record verbatim. The shred destroyed `subject:<name>`, a scope created by the shred call itself, which had encrypted nothing | Same root cause as #3, in a second place: the scope was **guessed rather than read from the record** | Fixed, mutation-tested |
| 13 | MFA, device bindings and SCIM groups persist | All three were bare `Map`s. Every restart unenrolled every second factor, forgot every bound device, and emptied the group directory | In-memory state in the security-critical layer | Fixed, mutation-tested |

### Found in this session's second pass (5)

| # | Claim | Reality | Root cause | Status |
|---|---|---|---|---|
| 14 | "100M facts" was a target the architecture could reach | `Collection.records` was a JS `Map`; V8 throws at exactly 16,777,216 entries. Proven by filling one until it died | A hard platform limit nobody had run into, because nobody had run it | Fixed — sharded, 17,277,216 records proven in one collection |
| 15 | "Full-corpus chain verification under one hour" at 10B entries | Measured 17 hours single-threaded. A 17× miss | The target was written without a measurement behind it | Partly fixed — parallel verification, 3.51× on 4 cores; needs 36 cores to hit the target, and that is now stated |
| 16 | The Built-in/Connected/Both toggle can reach the named vendors | 81 vendors were listed with only a generic `POST /{op}` adapter. No named vendor implements that | A catalogue was mistaken for an integration | Fixed — 81 bespoke adapters, contract- and conformance-tested |
| 17 | The backup path works | `Buffer.toString()` on a whole collection chunk throws past V8's ~512 MB string cap. Taking a backup of a large collection crashed the backup | Never run at a size where it mattered | Fixed — buffer-based throughout |
| 18 | Ingest throughput is 84,000/sec | That was a storage-layer benchmark, not the gated write path. End-to-end ingest measured 250/sec at 200 facts falling to 16/sec at 8,000 — quadratic | Two bounds that grew with the corpus, and one recomputation per comparison | Improved 5× to 79/sec at 8,000; still not flat, and stated in KNOWN-LIMITS.md |

### And one I introduced, mid-session, while fixing #18

Capping the temporal detector's token window, I indexed its buckets like
arrays. They are `Set`s. `bucket.length` is `undefined`, the loop never ran, and
**the drip-feed and coordinated-source detectors silently stopped firing** —
while 795 of 797 tests still passed.

Two did not. That is the suite doing its job, and it is the reason the suite
exists. But it is worth recording as its own entry, because it is this
session's failure class committed by the person writing about this session's
failure class: a mechanism that is present, reports nothing wrong, and does
nothing.

### The pattern, stated plainly

Of eighteen, **fifteen** are one of three shapes:

1. **A capability implemented and never enabled** (#7, #10). The code is correct.
   Nothing calls it. Every unit test of the mechanism passes.
2. **A scope, key or identifier guessed rather than read from the thing it
   describes** (#3, #12, and #4 in mirror image). The guess and the truth agree
   in the test fixture and diverge in production.
3. **State that must outlive the process, kept in the process** (#2, #11, #13).
   Tests pass because they never cross the boundary.

And a fourth shape emerged in the second pass, which earlier sessions had no
way to see because they never ran anything to failure:

4. **A number that was never measured** (#14, #15, #18). The 100M target, the
   one-hour verification target and the 84,000/sec figure were all written
   down, carried forward, and repeated. Two were false and one was measuring
   something other than what it was quoted for. Running the system to
   destruction is the only thing that found them.

A reviewer looking for #19 should look for those four shapes first.

### One correction to my own method, this session

While testing SCIM revocation I initially reported **all thirteen routes failing
to revoke**. That was wrong, and the fault was in my harness: `verify()` returns
`{valid: false, reason}`, and truthiness-testing an object is always true. The
finding was withdrawn before it went anywhere.

It is recorded here because the failure mode cuts both ways — a harness can
manufacture a false alarm as easily as it can miss a real one, and both come
from asserting against the wrong thing.

Related, and worth knowing: the first version of the canary scan used
whitespace-free tokens. Those look like identifiers to the ledger's shape test
and passed through, so the scan **reported a clean ledger that was not clean**.
It was rewritten to use realistic, space-containing values. *The harness
flattering the result is the same failure as the product flattering it.*

---

## 6. Specific questions for the reviewer

Not "please review". These are the questions I cannot answer myself.

1. **Is the gate actually unbypassable?** I assert it. I wrote both the assertion
   and the thing asserted. What did I not think to test?
2. **Is §3.2 commercially acceptable?** A per-person erasure cannot reach backup
   copies of multi-person records. The receipt says so. Is honest disclosure of
   that limit sufficient for a GDPR Art 17 response, or does it need solving
   before sale?
3. **Should `name` be removed from `AUDIT_PROSE`?** (§4.1) It is the widest
   readable field in the audit chain.
4. **Is the exactly-one-person keying boundary right?** (§4.3) It is a sharp
   cliff and I am least confident about it.
5. **Do the portability exports need an encryption option?** (§4.7) I did not add
   one. They are the largest plaintext surface the product creates.
6. **Is persisting TOTP seeds under the default collection key adequate**, or
   should they be under a separate scope with a distinct rotation policy? (§4.6)
7. **What in `test/adversarial.test.js` is measuring the code's account of
   itself rather than the underlying state?** This is the question I am
   structurally worst placed to answer, because if I could see it, it would not
   be there.
8. **Given three recurring failure shapes (§5), where else do they occur?** I
   found instances by looking. That is not the same as having looked everywhere.
9. **Is single-threaded testing hiding concurrency bugs?** (§3.8)
10. **Is the sharding approach for §3.6 sound**, and should it block a first
    sale or not?

---

## 7. What the second pass reached, and what it did not

**Reached, with measurements:** the scale ceiling (fixed and proven past),
parallel chain verification, 81 vendor adapters, the three readiness packages
generated from real ledger evidence, the attack corpus with 24 seam variants,
the drills, the MSA/DPA and escrow as final text, and KNOWN-LIMITS.md as a
shipped document.

**Still not reached, and blocked on things code cannot supply:**

- **Live verification of any vendor.** Re-probed from scratch: hosts now
  resolve, and all but five return 403 from the egress proxy. That is an
  organisation policy denial which the proxy documentation says to report
  rather than route around, so it was reported. Needs a network path and one
  credential per vendor.
- **An executed penetration test, audit, or certification.** All three need a
  contract, a budget and a counterparty.
- **Independent human code review.** Still the one thing that cannot be
  self-certified, and the reason this document opens the way it does.
- **100M facts and 50 TB** run for real. 100M needs ~32 GiB of heap against
  this machine's 15 GiB; 50 TB needs 50 TB. Both are extrapolated with the
  method and the error bars stated, and neither should be claimed in a sales
  context until run.
- **A7–A10 re-verification** (token-exchange ordering across all two-step
  connectors, the programmatic gate-bypass assertion, break-glass attacks,
  Employee Privacy Mode attacks). The attack corpus covers a great deal of the
  gate, but the specific claim that *no code path* reaches the fact store
  without the gate is still asserted only by its author.

## 7b. What the first pass did not reach

Stated plainly, because an incomplete list is its own form of over-claiming.

- **Part A partially:** A1–A5, A11 and A12 were re-proven by execution. **A6
  (token-exchange ordering across all two-step connectors), A7 (the full attack
  corpus plus 20 new seam-targeting variants), A8 (programmatic gate-bypass
  assertion across every module configuration), A9 (break-glass attacks) and A10
  (Employee Privacy Mode attacks) were NOT re-verified this session.** They carry
  a ✅ from a prior session, and on this session's evidence a prior ✅ is not
  evidence.
- **Part B entirely.** No connector reachability re-probe, no contract tests, no
  module vendor adapters.
- **Part C entirely.** The 16,777,216 Map ceiling stands, unfixed and unmitigated.
- **Part D:** this document, the bug bounty policy, the vulnerability disclosure
  policy and the pen-test package are complete. **D1–D3 (SOC 2, ISO 27001, ISO
  42001 readiness packages), D6 (MSA/DPA), D7 (escrow agreement), D10 (the DR
  exercise at scale) and D11 (the drills) are not started.**
- **Parts E and F entirely.**

---

*If you read one section, read §5. If you read two, read §5 and §6.*
