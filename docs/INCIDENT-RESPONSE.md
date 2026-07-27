# Incident response

This is the plan Vault operates under, and the plan it is built to support a
customer in operating. It is written to be executed at 3am by someone who did
not write it.

**What makes an incident here different from an ordinary outage:** in most
systems, the worst case is that data is unavailable. Here the worst case is that
data is *available and wrong* — a poisoned memory that agents are acting on right
now, believing it. So the first move is almost never "restore service". It is
"stop the spread, then find out what was believed."

---

## 0. The one-page version

| | |
|---|---|
| **Declare** | Anyone may declare. Nobody needs permission. Over-declaring costs an hour; under-declaring costs the record. |
| **First action** | Contain before you diagnose. `vault.killswitch.engage(level, { actor, reason })`. |
| **Never** | Never delete to clean up. Never edit a fact to correct it. Both destroy the evidence and neither is reversible in the way you want. |
| **Always** | Always name yourself. Every containment action takes an actor and a reason, and both appear in the ledger. |
| **Clock starts** | GDPR/UK 72h, HIPAA 60d, DPDP as notified, SEC 8-K 4 business days. `vault.legal.breachClock()` tracks them. |

---

## 1. Severity, and what each one means in practice

| Sev | Definition | Example | Response |
|---|---|---|---|
| **1** | Memory integrity is compromised, or the ledger does not verify | Chain break; a confirmed poisoning that reached golden facts; a wall bypass | Page immediately, 24/7. Containment inside 15 minutes. |
| **2** | Confidentiality or availability is materially affected | A cross-wall read succeeded; the gate is down and writes are queueing; a KMS outage blocks all reads | Page during business hours, on-call out of hours. Containment inside 1 hour. |
| **3** | Degraded, contained, or affecting one tenant/folder | One connector silently failing; review queue SLA breached; elevated hold rate | Next business day. |
| **4** | No customer impact | An internal alert with no external effect | Ticket. |

A ledger verification failure is **always Sev 1**, even if nothing else looks
wrong. The chain is the thing every other claim rests on; if it is broken, every
statement the product makes is unsupported until proven otherwise.

---

## 2. Roles

Fill these in with names before you need them. An unassigned role in an incident
is a role nobody performs.

- **Incident Commander** — decides. Does not investigate. Rotates.
- **Operations Lead** — executes containment and recovery.
- **Communications Lead** — customer notice, status page, regulator clock.
- **Scribe** — timestamps everything. The post-mortem is written from this.
- **Legal/DPO** — decides whether a notification obligation exists. Engaged at
  declaration for any Sev 1 or 2, not after triage.

The Commander is not the most senior person in the room. It is whoever declared,
until they hand over explicitly and the handover is logged.

---

## 3. Containment: what to press

Containment is graduated on purpose. The instinct under pressure is to reach for
the biggest switch; the correct move is usually two levels below it.

| Level | Effect | Use when |
|---|---|---|
| 1 | Everything works, everything flagged | You suspect but do not know |
| 2 | Every write goes to review | Suspicious writes, but the source is unclear |
| 3 | No writes; reads continue | **The default for a suspected poisoning.** Agents keep working, they stop learning |
| 4 | One agent/folder/channel/department frozen | You know the blast radius |
| 5 | That scope cannot be read either | The bad data is already written and is being read |
| 6 | No reads, no writes, anywhere | Confirmed active compromise of the memory itself |

```
vault.killswitch.engage(3, { actor: 'your.name', reason: 'suspected injection via zendesk connector' })
```

Level 6 stops the business. It is correct exactly when continuing to serve
memory is worse than stopping — which is rarer than it feels at 3am.

**Per-connector kill:** if the source is known, kill the connector rather than
the system. `vault.connectors.kill(id, { actor, reason })`.

---

## 4. Diagnosis

The product is built so that this step is a query, not an investigation.

```js
// What did this agent believe, and when did it start believing it?
vault.trace.trace(factId)

// What else did this fact influence? Everything downstream of a bad fact.
vault.trace.contagion(factId)

// What arrived from this source in the window?
vault.archive.search(term, { from, to })

// Does the record hold?
vault.verifyLedger()          // the whole chain
vault.verifyLedgerTail()      // since the last external anchor — run this first
```

Start with `contagion`. The question that decides the size of the incident is
not "what got in" but "what did it touch" — a single poisoned fact that was
summarised into a rolling summary and read by four agents is a different
incident from one nobody ever read.

---

## 5. Eradication — and the thing not to do

**Do not delete. Do not edit.**

The correct remedy is `vault.trace.undo({ ... })`, which supersedes the affected
facts and records the reversal as its own event. The bad fact remains in the
record, marked, with the decision to reverse it attributed and timestamped.

Deleting it removes the only evidence of what happened. Editing it makes the
record say something that was never true at the time it claims. Both make the
next question — "what did the system believe when it took that action?" —
permanently unanswerable, which is the exact question a regulator, an insurer or
a court will ask.

If content must genuinely be destroyed (an erasure order, a credential in the
archive), that is the erasure workflow with its own two-approver path and
receipt, not incident cleanup.

---

## 6. Recovery

1. Confirm the source is closed. Re-opening into an unfixed source repeats the incident.
2. `vault.verifyLedger()` — full, not tail. It must pass before service resumes.
3. `vault.facts.verifyIntegrity()` — every fact re-hashed.
4. Release the kill switch in stages: 6 → 3 → 1 → 0, verifying at each step.
   Releasing straight to 0 means any residual problem arrives at full volume.
5. Run `vault.doctor()` and clear the findings before declaring resolution.
6. Watch the hold rate for 24h. A gate that is now holding everything is not a
   healthy gate; a gate that is holding nothing after an injection incident is
   worse.

---

## 7. Notification clocks

Legal decides whether an obligation exists. Operations makes sure the clock is
not discovered late.

| Regime | Clock | Trigger |
|---|---|---|
| GDPR Art 33 / UK | 72h to the supervisory authority | Awareness of a personal-data breach |
| GDPR Art 34 / UK | Without undue delay, to data subjects | High risk to rights and freedoms |
| HIPAA | 60 days | Discovery of a PHI breach |
| DPDP (India) | As specified by the Board | Awareness |
| SEC Item 1.05 | 4 business days | Determination of materiality |
| Customer contract | Usually 24–72h | Per the MSA; see docs/legal/MSA-TERMS.md |

`vault.legal.breachClock()` starts, tracks and reports these. The clock starts at
**awareness**, not at confirmation — a common and expensive misreading.

---

## 8. Post-mortem

Within five working days, blameless, and published to the status page for any
incident with customer impact. `vault.statusPage.postMortem(id, {...})` requires
what happened, why, what changed, and follow-up actions **with named owners** —
an unowned action item is a wish, and the API refuses one.

The status page marks an overdue post-mortem as overdue rather than letting it
be quietly forgotten.

---

## 9. Exercising this

A plan first executed during an incident is a document, not a plan.

- **Quarterly:** a restore drill — `vault.drill.run({ actor })`. Automated, and
  it fails loudly. A never-run drill is reported as a high finding.
- **Quarterly:** a kill-switch test. `vault.killswitch.test()` records the date
  the insurance evidence pack cites.
- **Twice yearly:** a tabletop on a Sev 1, with the Commander rotating.
- **Annually:** a full exercise including a simulated regulator notification,
  timed against the 72-hour clock.

## What this document is not

It is not a claim that these procedures have been executed against a production
estate, or that response times have been measured under load. Those are
operational facts an organisation earns by running the exercises above and
keeping the records. The product generates and retains that evidence; it cannot
generate the practice.
