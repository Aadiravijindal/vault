# Contractual positions this product can stand behind

Not a contract. This is a working document for whoever drafts one: for each term
a customer will ask for, it states what the software actually does, so that the
commitment made in a signed agreement is one the engineering can support.

**A term the product cannot evidence should not be signed.** Every row below is
marked accordingly.

---

## 1. Data protection

| Term customers ask for | Can the product evidence it? | Where |
|---|---|---|
| Processor obligations under GDPR Art 28 | **Yes** | Purpose lock, instruction record, sub-processor register, deletion on termination — all in the ledger |
| Assist with data-subject requests | **Yes** | `vault.privacy` DSAR workflow, per-subject retrieval by pseudonym, deadline tracking |
| Assist with DPIAs | **Yes** | Generated from live configuration, not a template — `privacy.compliancePack()` |
| Breach notification within 24–72h | **Partly** | The product detects, clocks and packages. *Meeting* the deadline is an operational commitment; the plan is in docs/INCIDENT-RESPONSE.md |
| Delete all customer data on termination | **Yes, with a caveat that must be in the contract** | Erasure workflow + crypto-shredding. The WORM archive has no delete path; backups are shredded by key destruction. The receipt says which, honestly |
| No training on customer data | **Yes, structurally** | There is no training pipeline. This is the absence of a capability, not a setting |
| Data residency | **Yes** | Per-region keys, residency verification against the bucket's actual reported region, cross-border read blocking |
| International transfers | **Yes** | SCC/IDTA generation per flow; transfer assessments in the jurisdiction packs |

**Do not sign:** a blanket "all data deleted from all systems including backups
within N days" without the crypto-shredding explanation. Deleting a record from
immutable media is not possible; destroying the key is, and it is a stronger
guarantee — but it is a different sentence and the contract should say the true
one.

---

## 2. Security

| Term | Evidence? | Note |
|---|---|---|
| Encryption at rest and in transit | **Yes** | AES-256-GCM envelope encryption; TLS |
| Customer-managed keys | **Yes** | BYOK/CMK/HYOK/HSM/split-key, against real AWS KMS, Azure Key Vault or GCP Cloud KMS |
| Least privilege | **Yes** | Role matrix enforced at the route; connectors request only catalogued scopes and never widen |
| Audit logging | **Yes** | Hash-chained, signed, externally anchored, independently verifiable |
| Immutable audit trail | **Yes** | WORM collections with no update/delete code path |
| Notify of security incidents | **Yes, operationally** | Clock tracking and packaging are automated; notification is a human commitment |
| Annual penetration test | **NO — do not sign without arranging one** | Not performed. `bin/vault-supplychain.js` runs static and secret analysis; that is not a pen test |
| SOC 2 Type II / ISO 27001 / ISO 42001 | **NO — do not sign** | Certification requires an accredited auditor over an observation window. The product generates control evidence; it cannot generate an opinion |
| Vulnerability disclosure programme | **Operational** | Needs a published policy and a triage commitment |
| Sub-processor list and change notice | **Commercial** | With zero runtime dependencies the technical list is short, but hosting, email and support tooling are still sub-processors |

The pattern: everything that is a **property of the software** can be evidenced
today. Everything that is an **assertion about the organisation** requires the
organisation to earn it. Signing the second kind on the strength of the first is
how vendors end up in breach of their own MSA.

---

## 3. Availability and support

| Term | Position |
|---|---|
| Uptime SLA | **Only for hosted deployments, and only once measured.** `statusPage.uptime()` computes availability from declared incidents and explicitly refuses to report a quiet window as 100%. Self-hosted availability is the customer's |
| Support response times | Commercial |
| RTO / RPO commitments | **Measure first.** `vault.drill.run()` reports both at the customer's scale on their hardware. Do not quote a number from our machine |
| Maintenance windows | Scheduled through `statusPage.scheduleMaintenance()`, which flags short notice rather than averaging it away |
| Status page | Built. Public view is allow-listed so internal names cannot leak |

---

## 4. Liability and indemnity

Commercial, and counsel's call. Two engineering observations relevant to drafting:

- **The record is the defence.** For claims about what a system knew or did, the
  ledger is contemporaneous, tamper-evident, signed with the customer's key and
  verifiable by a third party. That is unusually strong evidence, and it cuts
  both ways — it will also show what the customer configured.
- **The product makes no employment or credit decisions and contains no capability
  to.** Affect analysis, productivity scoring and individual performance views are
  structurally absent. That supports a narrow carve-out on employment-decision
  liability, and it is defensible because it is architectural rather than a
  setting.

---

## 5. Exit

| Term | Position |
|---|---|
| Data export on request | **Yes** — complete, documented, self-describing |
| Export in a non-proprietary format | **Yes** — newline-delimited JSON with a schema document |
| Continued access during wind-down | **Yes** — the software runs without us; there is no licence server |
| Escrow | See docs/legal/ESCROW.md — the architecture largely removes the need, but the deposit is trivial to do |
| Assistance with migration | Commercial |

---

## 6. The terms to refuse

Refusing these is the professional answer, not the awkward one:

1. **Any certification not held.** Say "not certified; here is the control
   evidence and the gap analysis."
2. **An uptime SLA on software the customer hosts.** You do not control their
   infrastructure.
3. **"Deletion from all backups"** without the crypto-shredding wording.
4. **An RTO/RPO not measured on the customer's own data.** Offer the drill instead.
5. **Unlimited liability for data loss** where the customer holds the signing key
   and controls their own mirror. Losing a key you hold is not our failure.
6. **A warranty that the gate catches every attack.** It catches the classes it
   is built for, adversarially tested; "every" is unprovable and the first
   novel technique makes it a false statement.
