# Business continuity and vendor disclosure

The question this answers is the one procurement actually asks: *what happens to
our AI memory if you go out of business next Tuesday?*

Most vendors answer it with a promise. This answer is architectural, and can be
checked today without asking us anything.

---

## 1. The short answer

**Your memory does not depend on us being alive.**

- The export is complete, documented and self-describing.
- It verifies with a program that imports none of our code, using a key you hold.
- The product runs on Node with **zero runtime dependencies** and **no build
  step**, so the source you hold is the artefact you run.
- A continuous mirror can write to storage you own, so the current state is
  already on your infrastructure before anything goes wrong.

You can test all four of these in an afternoon, and the product will run the test
for you: `vault.drill.run({ actor })`.

---

## 2. What "export" actually means

`vault.exportAll({ actor, dir, reason })` writes:

| File | Contents |
|---|---|
| `facts.jsonl` | Every fact, with full provenance |
| `golden.jsonl` | Approved facts, separately |
| `conversations.jsonl` | The raw archive, verbatim |
| `ledger.jsonl` | The complete hash-chained event log |
| `agents.json` | The registry |
| `manifest.json` | Counts, chain head, your public key, and a SHA-256 of every file |
| `SCHEMA.md` | What each file contains, field by field |
| `SELFHOST.md` | Runnable steps to stand it back up |

There is no proprietary container, no licence check on read, and no format that
requires our software to interpret. It is newline-delimited JSON.

---

## 3. Verification without us

```
node bin/vault-verify.js <export-dir>
```

That program imports nothing from `src/`. It is licensed Apache-2.0 (see
LICENSE-verifier) specifically so you, your auditor or your regulator can read
it, run it and fork it. It checks the chain against the public key travelling in
the manifest — a key whose private half you hold.

If we disappeared, this still works. If we turned hostile, this still works.
That is the point.

---

## 4. The mirror

Configured with `mirrorDir` or a customer bucket, every ledger event is written
continuously to storage you own — not nightly, not on request. `mirrorStatus()`
reports events mirrored and failures, and `doctor()` raises a **high** finding
when no mirror is configured, because a continuity story that is switched off is
not a continuity story.

---

## 5. Restore drills

`vault.drill.run({ actor })` performs the whole thing end to end: export, verify
with the standalone verifier, restore into a brand-new instance from the export
alone, and compare the restored data against the source record by record — not
by row count, because a restore producing the right number of wrong facts passes
a count check and fails a customer.

It reports:

- **RPO** — the age of the most recent record that did not survive. Zero loss is
  reported as a result for that drill and explicitly not as a guaranteed RPO,
  because a guarantee depends on your export schedule, which is yours to set.
- **RTO** — wall-clock time, reported **with the volume restored** and the
  throughput, so you can scale it to your own store rather than quoting a number
  measured on a demo.

A drill that has never run is reported as a high finding. A drill that fails is
recorded as a failure, not retried until it passes.

---

## 6. Vendor-failure runbook

If we stop existing, in order:

1. **Take a final export.** `vault.exportAll(...)`. If the service is already
   gone, use your mirror — it is current.
2. **Verify it.** `node bin/vault-verify.js <dir>`. Do this before relying on it.
3. **Stand it up.** Follow `SELFHOST.md` from the export. Node, the source, your
   key. No build, no package install, no network.
4. **Point your agents at it.** The API surface is unchanged; it is the same
   software.
5. **Decide about the future.** You now have a running system and a complete
   record. You can operate it, migrate off it at your own pace, or hand the
   export to another vendor — the schema is documented for exactly that.

Nothing in that list requires our cooperation, our licence server, or our
existence.

---

## 7. What we do not claim

This document is about *your* continuity, not ours. Specifically:

- **We do not claim a tested disaster-recovery capability for our own hosted
  infrastructure.** That would require a production estate, a second region and
  documented failover exercises. Where Vault is self-hosted — the intended
  deployment — this is your DR plan, not ours, and the drill above is the part
  we can hand you.
- **We do not claim an RTO or RPO as a contractual number.** The harness measures
  both at your scale on your hardware. Quoting ours would be quoting a number
  from a machine you do not own.
- **We do not claim key escrow.** You hold your key. If you lose it, the ledger's
  signatures cannot be verified and encrypted namespaces cannot be opened. That
  is the cost of us not being able to read your data either, and it is the right
  trade — but it means your key management is a real obligation, not a formality.
- **Financial resilience of the vendor is not addressed here at all.** Runway,
  insurance and ownership are commercial disclosures for the copyright holder to
  make; the architecture above is designed so that you do not have to rely on
  them.
