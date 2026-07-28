# SOC 2 Readiness Package

**Standard:** AICPA TSP Section 100 (2017, revised 2022)  
**Generated:** 2026-07-28T19:48:42.758Z  
**Scope:** The Vault platform: ingestion, the gate, the fact store, the sealed archive, the ledger, and the control surface.

This package is generated from the live system. Every row marked *satisfied* cites
the sequence number of a real entry in the hash-chained ledger, which an auditor can
verify independently with `bin/vault-verify.js` and the customer-held public key.

## Summary

| | |
|---|---|
| Total Controls | 51 |
| Satisfied | 41 |
| No Evidence | 4 |
| Organisational | 6 |
| Excluded | 0 |
| With Known Gaps | 9 |
| Technical Coverage | 41/51 (80%) evidenced from the ledger |
| Ledger Entries Cited | 108 |

## Observation window

47 of 51 controls can only be evidenced over an observation period. Until that period has elapsed and been audited, this is a Type I position — a point-in-time design assessment — however complete the control matrix looks.

**Minimum period:** 3 months for an initial Type II; 6 or 12 months is what most enterprise buyers accept

## Control matrix

| Control | Name | Applicability | Status | Ledger entries | Evidence |
|---|---|---|---|---|---|
| CC1.1 | Demonstrates commitment to integrity and ethical values | included | organisational | 0 | _organisational — no software artefact evidences this_ |
| CC1.2 | Board exercises oversight responsibility | included | satisfied | 2 | VLT-5: 2 × `agent.registered`, `agent.scope_changed`, `agent.retired`, `agent.suspended` (latest seq 51) |
| CC1.3 | Management establishes structure, authority and responsibility | included | satisfied | 2 | VLT-5: 2 × `agent.registered`, `agent.scope_changed`, `agent.retired`, `agent.suspended` (latest seq 51) |
| CC1.4 | Demonstrates commitment to competence | included | organisational | 0 | _organisational — no software artefact evidences this_ |
| CC1.5 | Enforces accountability | included | satisfied | 2 | VLT-3: 1 × `review.decision`, `review.escalated`, `review.sla_breach` (latest seq 34)<br>VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49) |
| CC2.1 | Obtains or generates relevant quality information | included | satisfied | 2 | VLT-3: 1 × `review.decision`, `review.escalated`, `review.sla_breach` (latest seq 34)<br>VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49) |
| CC2.2 | Internally communicates information | included | satisfied | 1 | VLT-3: 1 × `review.decision`, `review.escalated`, `review.sla_breach` (latest seq 34) |
| CC2.3 | Communicates with external parties | included | satisfied | 2 | VLT-8: 2 × `privacy.erasure`, `fact.erased`, `key.destroyed` (latest seq 43) |
| CC3.1 | Specifies objectives with sufficient clarity | included | organisational | 0 | _organisational — no software artefact evidences this_ |
| CC3.2 | Identifies and analyses risk | included | satisfied | 5 | VLT-12: 5 × `security.alert`, `security.detection` (latest seq 47) |
| CC3.3 | Considers the potential for fraud | included | satisfied | 5 | VLT-2: 4 × `fact.held`, `fact.blocked`, `security.detection` (latest seq 45)<br>VLT-7: 1 × `folder.wall_changed`, `admin.breakglass` (latest seq 35) |
| CC3.4 | Identifies and analyses significant change | included | satisfied | 1 | VLT-11: 1 × `agent.registered`, `agent.scope_changed` (latest seq 19) |
| CC4.1 | Selects, develops and performs ongoing evaluations | included | satisfied | 5 | VLT-12: 5 × `security.alert`, `security.detection` (latest seq 47) |
| CC4.2 | Evaluates and communicates deficiencies | included | satisfied | 5 | VLT-12: 5 × `security.alert`, `security.detection` (latest seq 47) |
| CC5.1 | Selects and develops control activities | included | satisfied | 4 | VLT-1: 4 × `fact.written`, `fact.held`, `fact.blocked`, `fact.masked`, `fact.quarantined` (latest seq 33) |
| CC5.2 | Selects and develops general technology controls | included | satisfied | 5 | VLT-1: 4 × `fact.written`, `fact.held`, `fact.blocked`, `fact.masked`, `fact.quarantined` (latest seq 33)<br>VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49) |
| CC5.3 | Deploys through policies and procedures | included | organisational | 0 | _organisational — no software artefact evidences this_ |
| CC6.1 | Implements logical access security | included | satisfied | 5 | VLT-1: 4 × `fact.written`, `fact.held`, `fact.blocked`, `fact.masked`, `fact.quarantined` (latest seq 33)<br>VLT-7: 1 × `folder.wall_changed`, `admin.breakglass` (latest seq 35) |
| CC6.2 | Registers and authorises new users | included | satisfied | 2 | VLT-5: 2 × `agent.registered`, `agent.scope_changed`, `agent.retired`, `agent.suspended` (latest seq 51) |
| CC6.3 | Removes access when no longer required | included | satisfied | 1 | VLT-7: 1 × `folder.wall_changed`, `admin.breakglass` (latest seq 35) |
| CC6.4 | Restricts physical access | included | organisational | 0 | _organisational — no software artefact evidences this_ |
| CC6.5 | Disposes of data securely | included | satisfied | 2 | VLT-8: 2 × `privacy.erasure`, `fact.erased`, `key.destroyed` (latest seq 43) |
| CC6.6 | Restricts access from outside the system boundary | included | satisfied | 4 | VLT-1: 4 × `fact.written`, `fact.held`, `fact.blocked`, `fact.masked`, `fact.quarantined` (latest seq 33) |
| CC6.7 | Restricts transmission and movement of information | included | satisfied | 1 | VLT-7: 1 × `folder.wall_changed`, `admin.breakglass` (latest seq 35) |
| CC6.8 | Prevents or detects unauthorised software | included | satisfied | 2 | VLT-16: 2 × `admin.action`, `connector.connected` (latest seq 44) |
| CC7.1 | Detects and monitors configuration changes | included | satisfied | 2 | VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49)<br>VLT-11: 1 × `agent.registered`, `agent.scope_changed` (latest seq 19) |
| CC7.2 | Monitors for anomalies and security events | included | satisfied | 6 | VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49)<br>VLT-12: 5 × `security.alert`, `security.detection` (latest seq 47) |
| CC7.3 | Evaluates security events for impact | included | satisfied | 1 | VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49) |
| CC7.4 | Responds to identified security incidents | included | satisfied | 2 | VLT-10: 2 × `killswitch.engaged`, `killswitch.released` (latest seq 40) |
| CC7.5 | Recovers from identified security incidents | included | satisfied | 2 | VLT-10: 2 × `killswitch.engaged`, `killswitch.released` (latest seq 40) |
| CC8.1 | Authorises, designs, develops, tests and approves changes | included | satisfied | 1 | VLT-11: 1 × `agent.registered`, `agent.scope_changed` (latest seq 19) |
| CC9.1 | Identifies and mitigates business disruption risk | included | satisfied | 2 | VLT-10: 2 × `killswitch.engaged`, `killswitch.released` (latest seq 40) |
| CC9.2 | Assesses and manages vendor and business partner risk | included | satisfied | 2 | VLT-13: 2 × `admin.action` (latest seq 44) |
| A1.1 | Maintains and monitors capacity | included | organisational | 0 | _organisational — no software artefact evidences this_ |
| A1.2 | Environmental protections, backup and recovery infrastructure | included | satisfied | 2 | VLT-10: 2 × `killswitch.engaged`, `killswitch.released` (latest seq 40) |
| A1.3 | Tests recovery plan procedures | included | satisfied | 2 | VLT-10: 2 × `killswitch.engaged`, `killswitch.released` (latest seq 40) |
| C1.1 | Identifies and maintains confidential information | included | no-evidence | 0 | _none yet_ |
| C1.2 | Disposes of confidential information | included | satisfied | 2 | VLT-8: 2 × `privacy.erasure`, `fact.erased`, `key.destroyed` (latest seq 43) |
| PI1.1 | Obtains or generates relevant quality information about objectives | included | satisfied | 1 | VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49) |
| PI1.2 | Inputs are complete and accurate | included | satisfied | 8 | VLT-1: 4 × `fact.written`, `fact.held`, `fact.blocked`, `fact.masked`, `fact.quarantined` (latest seq 33)<br>VLT-2: 4 × `fact.held`, `fact.blocked`, `security.detection` (latest seq 45) |
| PI1.3 | Processing is complete, accurate and timely | included | satisfied | 4 | VLT-1: 4 × `fact.written`, `fact.held`, `fact.blocked`, `fact.masked`, `fact.quarantined` (latest seq 33) |
| PI1.4 | Outputs are complete, accurate and distributed appropriately | included | satisfied | 1 | VLT-7: 1 × `folder.wall_changed`, `admin.breakglass` (latest seq 35) |
| PI1.5 | Stores inputs and outputs completely and accurately | included | satisfied | 2 | VLT-4: 1 × `anchor.published`, `export.created` (latest seq 49)<br>VLT-15: 1 × `fact.expired`, `storage.lifecycle`, `legal.hold_placed` (latest seq 48) |
| P1.1 | Notice about privacy practices | included | no-evidence | 0 | _none yet_ |
| P2.1 | Choice and consent | included | satisfied | 1 | VLT-9: 1 × `privacy.consent_recorded`, `privacy.consent_withdrawn` (latest seq 38) |
| P3.1 | Collection limited to identified purposes | included | no-evidence | 0 | _none yet_ |
| P4.1 | Use, retention and disposal | included | satisfied | 3 | VLT-15: 1 × `fact.expired`, `storage.lifecycle`, `legal.hold_placed` (latest seq 48)<br>VLT-8: 2 × `privacy.erasure`, `fact.erased`, `key.destroyed` (latest seq 43) |
| P5.1 | Access by data subjects | included | satisfied | 2 | VLT-8: 2 × `privacy.erasure`, `fact.erased`, `key.destroyed` (latest seq 43) |
| P6.1 | Disclosure to third parties | included | satisfied | 2 | VLT-13: 2 × `admin.action` (latest seq 44) |
| P7.1 | Quality of personal information | included | satisfied | 2 | VLT-8: 2 × `privacy.erasure`, `fact.erased`, `key.destroyed` (latest seq 43) |
| P8.1 | Monitoring and enforcement | included | no-evidence | 0 | _none yet_ |

## Statement of Applicability

Every control carries a justification for inclusion or exclusion, as required.

| Control | Decision | Justification |
|---|---|---|
| CC1.1 | included | Applies to every service organisation. |
| CC1.2 | included | Applies to every service organisation. |
| CC1.3 | included | Applies to every service organisation. |
| CC1.4 | included | Applies to every service organisation. |
| CC1.5 | included | Applies to every service organisation. |
| CC2.1 | included | Core to the service. |
| CC2.2 | included | Core to the service. |
| CC2.3 | included | Core to the service. |
| CC3.1 | included | Applies to every service organisation. |
| CC3.2 | included | Applies to every service organisation. |
| CC3.3 | included | Directly applicable: the product exists to resist deliberate manipulation. |
| CC3.4 | included | Applies to every service organisation. |
| CC4.1 | included | Applies to every service organisation. |
| CC4.2 | included | Applies to every service organisation. |
| CC5.1 | included | Core to the service. |
| CC5.2 | included | Core to the service. |
| CC5.3 | included | Applies to every service organisation. |
| CC6.1 | included | Core to the service. |
| CC6.2 | included | Core to the service. |
| CC6.3 | included | Core to the service. |
| CC6.4 | included | Included for Vault Cloud, inherited from the IaaS provider under a carve-out or inclusive method. |
| CC6.5 | included | Core to the service. |
| CC6.6 | included | Core to the service. |
| CC6.7 | included | Core to the service. |
| CC6.8 | included | Core to the service. |
| CC7.1 | included | Core to the service. |
| CC7.2 | included | Core to the service. |
| CC7.3 | included | Core to the service. |
| CC7.4 | included | Core to the service. |
| CC7.5 | included | Core to the service. |
| CC8.1 | included | Core to the service. |
| CC9.1 | included | Core to the service. |
| CC9.2 | included | Core to the service. |
| A1.1 | included | Selected. Customers contract to an availability SLA, so capacity monitoring is in scope. |
| A1.2 | included | Selected. Backup and recovery infrastructure is the mechanism behind the availability commitment; without it the SLA is unbacked. |
| A1.3 | included | Selected. A recovery plan that has never been executed is a document; the drill is what makes the commitment real. |
| C1.1 | included | Selected. The service holds customer confidential information by design, so confidentiality is a criterion the buyer relies on. |
| C1.2 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| PI1.1 | included | Selected. The service asserts that stored memory is traceable to its source, which is a processing-integrity claim. |
| PI1.2 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| PI1.3 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| PI1.4 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| PI1.5 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P1.1 | included | Selected. The service processes personal data on behalf of customers as a processor under GDPR Article 28. |
| P2.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P3.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P4.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P5.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P6.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P7.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |
| P8.1 | included | Selected. In scope because the service commits to this criterion contractually and the buyer relies on it. |

## Gap report

9 controls have a stated gap. A package reporting no gaps has not been read carefully.

| Control | Status | Gap | What closes it |
|---|---|---|---|
| CC1.1 | organisational | Requires a signed code of conduct and evidence of annual acknowledgement. No software artefact satisfies this. | A human process and its records. No code change closes this. |
| CC1.2 | satisfied | Needs minuted board meetings across the observation window. | See the gap text. |
| CC1.4 | organisational | Requires training records over the observation window. | A human process and its records. No code change closes this. |
| CC6.4 | organisational | Requires the sub-service organisation report (AWS/Azure/GCP SOC 2) and a decision on carve-out vs inclusive. | A human process and its records. No code change closes this. |
| CC8.1 | satisfied | Requires evidence of code review and CI gating across the observation window; no CI configuration is currently committed. | Configure the scanner in CI and retain results across the observation window. |
| C1.1 | no-evidence | Mapped to a Vault control, but no ledger entry has been produced yet. Exercise the control, or confirm it is not reachable in this deployment. | Exercise the control once in this tenant so the ledger carries an entry, or record why it is unreachable here. |
| P1.1 | no-evidence | Mapped to a Vault control, but no ledger entry has been produced yet. Exercise the control, or confirm it is not reachable in this deployment. | Exercise the control once in this tenant so the ledger carries an entry, or record why it is unreachable here. |
| P3.1 | no-evidence | Mapped to a Vault control, but no ledger entry has been produced yet. Exercise the control, or confirm it is not reachable in this deployment. | Exercise the control once in this tenant so the ledger carries an entry, or record why it is unreachable here. |
| P8.1 | no-evidence | Mapped to a Vault control, but no ledger entry has been produced yet. Exercise the control, or confirm it is not reachable in this deployment. | Exercise the control once in this tenant so the ledger carries an entry, or record why it is unreachable here. |
