# Source Code Escrow Agreement

**Status:** final text, ready for legal review and execution by three parties.
**Not yet executed — escrow requires signatures from Depositor, Beneficiary and
the Escrow Agent, and the agent must be appointed first.**

Annotated as in the MSA: **[COMMERCIAL DECISION: …]** marks the points a human
must decide. Everything else is drafted.

---

## Parties

**Depositor:** Provider (the licensor of Vault).
**Beneficiary:** Customer.
**Escrow Agent:** **[COMMERCIAL DECISION: appoint one — see §10 for candidates.]**

---

## 1. Purpose

This Agreement exists so that Beneficiary's continued use of the Service does
not depend on Depositor's continued existence, willingness or solvency. It gives
Beneficiary a route to the source code and the operational knowledge required
to run the Service itself, on defined triggers, verified in advance.

An escrow that has never been verified is a filing cabinet. §6 is therefore not
optional.

---

## 2. Deposit contents

Depositor will deposit, and keep current, all of the following:

| # | Item | Why it is required |
|---|---|---|
| 1 | Complete source code for the Service, including build scripts | Without the build, source is not a running system |
| 2 | Full version control history | To understand why the code is as it is, and to apply a security patch safely |
| 3 | Database schemas and the on-disk format specification | The Service stores JSONL segments with an append-only operation log; the format spec is in `docs/FORMATS.md` |
| 4 | Build and deployment documentation sufficient for a competent engineer to produce a running instance | §6 verification tests exactly this |
| 5 | The complete automated test suite | So Beneficiary can tell whether a change it makes has broken something |
| 6 | Third-party dependency manifest and licences | Currently empty of runtime dependencies by design; the manifest records that, and would record any future addition |
| 7 | Configuration templates and environment variable documentation | |
| 8 | The standalone ledger verifier and its specification | So Beneficiary can continue to prove the integrity of historical records |
| 9 | Architecture documentation and data-flow diagrams | |
| 10 | Names and roles of key technical personnel, and a written statement of key-person dependency | Practical continuity, not just code |
| 11 | Any cryptographic material required to read Depositor-managed data, **excluding** Beneficiary's own keys | Where Beneficiary uses BYOK, CMK or HYOK, no such material exists and this row is satisfied by a statement to that effect |

**Deposit format:** encrypted archive with the decryption key held separately by
the Escrow Agent, released only on a Release Event.

**Deposit frequency:** on execution, then **[COMMERCIAL DECISION: recommend
quarterly, and within 10 business days of any release that changes the on-disk
format or the ledger format]**.

---

## 3. Release Events

The Escrow Agent will release the deposit to Beneficiary on any of the
following, verified as set out in §4:

**3.1 Insolvency.** Depositor enters administration, liquidation, receivership,
bankruptcy, or an equivalent proceeding in any jurisdiction; or makes a general
assignment for the benefit of creditors; or ceases to carry on business.

**3.2 Acquisition without assumption.** A change of control of Depositor occurs
and the acquirer does not affirm the Agreement in writing within 30 days, as
provided in Clause 11.4 of the MSA.

**3.3 Sustained service failure.** Depositor fails to provide the Service in
accordance with the agreed Service Levels for a continuous period of **30 days**,
or fails to remedy a material breach within 30 days of notice.

**3.4 Breach of continuity terms.** Depositor breaches Clause 11.1 of the MSA
(maintaining a self-hostable build), Clause 11.2 (maintaining this escrow), or
Clause 11.3 (independent ledger verification), and fails to remedy within 30
days of notice.

**3.5 Abandonment.** Depositor announces end-of-life for the Service, or ceases
to provide maintenance and security updates for **90 days** without an announced
schedule.

**3.6 Failure to verify.** Depositor fails a verification under §6 and does not
remedy the deficiency within **30 days**.

> *Note on 3.6: this trigger is uncommon and is included deliberately. Escrow
> agreements usually treat verification as informational. If the deposit is
> found not to build, the beneficiary's protection is already gone, and
> discovering that at the moment of insolvency is the worst possible time.*

---

## 4. Release procedure

4.1 Beneficiary gives the Escrow Agent written notice specifying the Release
Event and the evidence for it, copied to Depositor.

4.2 Depositor has **10 business days** to file a counter-notice disputing the
event.

4.3 If no counter-notice is filed, the Escrow Agent releases the deposit.

4.4 If a counter-notice is filed, the dispute is referred to a single expert
appointed by **[COMMERCIAL DECISION: recommend the Escrow Agent's standard
expert-determination process, or a named body]**, whose determination is final
and binding on the release question only. The expert will decide within 15
business days. Costs follow the outcome.

4.5 **Insolvency exception.** For a Release Event under §3.1, the Escrow Agent
releases immediately on satisfactory evidence, without the counter-notice period.
An insolvency practitioner's incentive is to preserve the estate, and a 10-day
window is long enough for the Service to go dark.

---

## 5. Licence on release

5.1 On release, Depositor grants Beneficiary a **perpetual, irrevocable,
non-exclusive, worldwide, royalty-free licence** to use, modify, compile and
operate the deposited materials **solely** for the purpose of continuing to
receive, for itself, the functionality of the Service.

5.2 The licence includes the right to engage a third party to perform that work
on Beneficiary's behalf, subject to that third party accepting equivalent
confidentiality obligations.

5.3 The licence does **not** permit Beneficiary to distribute, sublicense, resell
or offer the Service to third parties as a product or service.

5.4 The licence survives termination of the MSA and any insolvency of Depositor.

5.5 Beneficiary will treat the source code as Depositor's Confidential
Information, and that obligation survives indefinitely.

---

## 6. Verification

6.1 **[COMMERCIAL DECISION: verification level — recommend Level 2 or above.]**

| Level | What is tested | Recommended |
|---|---|---|
| 1 — File listing | The deposit exists and its inventory matches the declared contents | Insufficient on its own |
| 2 — Build test | An independent engineer compiles the deposit into a running system from the documentation alone | **Recommended minimum** |
| 3 — Functional test | The built system passes the deposited test suite and serves a scripted scenario | Recommended for production use |
| 4 — Full recreation | The system is rebuilt on clean infrastructure, restored from a backup, and verified end to end | Recommended annually if the Service is business-critical |

6.2 **Frequency: annually**, and on any material architectural change.

6.3 Verification is performed by the Escrow Agent or an independent third party.
Depositor will provide reasonable assistance but will not perform the
verification itself.

6.4 The verification report goes to all three parties. A failure engages §3.6.

6.5 **A specific test that must be included at Level 3 or above:** the deposited
standalone ledger verifier must verify a ledger export produced by the built
system, using a public key supplied by Beneficiary, and must exit non-zero on a
tampered export. That property is the one Beneficiary most needs to survive
Depositor's disappearance, and it is testable in isolation.

---

## 7. Fees

**[COMMERCIAL DECISION: who pays.]** Market practice is that Depositor pays the
annual escrow fee and Beneficiary pays for verification it requests beyond the
agreed level. Where Beneficiary requires a level above the standard, Beneficiary
pays the increment.

---

## 8. Term

8.1 This Agreement runs for the Term of the MSA and for **[COMMERCIAL DECISION:
recommend 12 months]** after it ends, so that a Release Event occurring during a
migration is still covered.

8.2 On expiry with no Release Event, the Escrow Agent will destroy or return the
deposit on Depositor's instruction.

---

## 9. General

9.1 The Escrow Agent acts as a stakeholder, not as agent for either party, and
its duties are limited to those expressly stated.

9.2 **[COMMERCIAL DECISION: governing law and jurisdiction — should match the
MSA unless the Escrow Agent requires otherwise.]**

9.3 Nothing in this Agreement transfers ownership of any intellectual property.

---

## 10. Candidate Escrow Agents

Selection is a human decision. Considerations: jurisdictional coverage, the
verification levels offered, whether they hold deposits in a form that survives
their own insolvency, and cost.

| Agent | Notes |
|---|---|
| **NCC Group Software Resilience** | The largest; full range of verification levels; strong UK/EU/US coverage |
| **Iron Mountain (Escrow Services)** | Long-established; broad jurisdictional reach |
| **EscrowTech** | Smaller, often lower cost; verification available |
| **Codekeeper** | Modern, developer-oriented; continuous deposit from a repository, which suits the quarterly cadence in §2 |
| **PRAXIS Technology Escrow** | US-focused; well regarded for verification depth |

**Recommendation:** an agent offering *continuous* deposit from a version
control system, because a quarterly manual deposit drifts and the gap is only
discovered at the moment it matters.

---

## Signature

Executed as an agreement by all three parties.

| | Depositor | Beneficiary | Escrow Agent |
|---|---|---|---|
| Signature | | | |
| Name | | | |
| Title | | | |
| Date | | | |

---

*Execution requires three signatures and the prior appointment of an Escrow
Agent. This document is complete as drafting; it is not in force until signed.*
