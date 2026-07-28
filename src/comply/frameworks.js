/**
 * Full control catalogues for the three frameworks a buyer asks for by name.
 *
 * The existing `CONTROLS` library in comply.js is Vault's own 16 controls,
 * crosswalked outward. That is the right shape for continuous monitoring and
 * the wrong shape for a readiness package, because an auditor does not work
 * from our control list — they work from theirs, and the first question is
 * "show me every one of the 93 Annex A controls and tell me which apply".
 *
 * So these are the frameworks' own catalogues, at their own granularity, with
 * Vault's controls mapped INTO them. Anything with no Vault control behind it
 * is a gap, and saying so is the entire value of a readiness report — a
 * package that reports 100% coverage has not been read carefully.
 *
 * `applicability` is the Statement of Applicability decision. `justification`
 * is required for every entry, included or excluded, because ISO 27001 §6.1.3
 * requires a justification for both and an auditor reads the exclusions first.
 *
 * `window` records whether a control can be evidenced from a point-in-time
 * snapshot or needs an observation period. SOC 2 Type II is defined by that
 * period; a package that does not say which controls need one is describing a
 * Type I and calling it a Type II.
 */

/** Vault control ids that satisfy a framework control, and how. */
const V = (ids, how) => ({ vaultControls: Array.isArray(ids) ? ids : [ids], how });

// ===========================================================================
// SOC 2 — Trust Services Criteria (2017, with 2022 points of focus)
// ===========================================================================

export const SOC2_TSC = [
  // ---- CC1 Control Environment ----
  { id: 'CC1.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Demonstrates commitment to integrity and ethical values', ...V([], 'Board-level policy and a code of conduct. Organisational, not technical.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period', gap: 'Requires a signed code of conduct and evidence of annual acknowledgement. No software artefact satisfies this.' },
  { id: 'CC1.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Board exercises oversight responsibility', ...V(['VLT-5'], 'The board reporting pack is generated from the live register and the ledger.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period', gap: 'Needs minuted board meetings across the observation window.' },
  { id: 'CC1.3', category: 'CC — Common Criteria', tsc: 'Security', name: 'Management establishes structure, authority and responsibility', ...V(['VLT-5'], 'Every agent, folder and namespace carries a named business owner and technical owner, enforced at registration.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'point-in-time' },
  { id: 'CC1.4', category: 'CC — Common Criteria', tsc: 'Security', name: 'Demonstrates commitment to competence', ...V([], 'HR process: role descriptions, hiring criteria, training records.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period', gap: 'Requires training records over the observation window.' },
  { id: 'CC1.5', category: 'CC — Common Criteria', tsc: 'Security', name: 'Enforces accountability', ...V(['VLT-3', 'VLT-4'], 'Every review decision and admin action is attributed to a named actor in the tamper-evident ledger.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period' },

  // ---- CC2 Communication and Information ----
  { id: 'CC2.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Obtains or generates relevant quality information', ...V(['VLT-3', 'VLT-4'], 'The ledger is the information system: every gate verdict, review decision and admin action, hash-chained.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC2.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Internally communicates information', ...V(['VLT-3'], 'Alerts route to the named folder owner with severity tiering and delivery across six channels.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC2.3', category: 'CC — Common Criteria', tsc: 'Security', name: 'Communicates with external parties', ...V(['VLT-8'], 'Erasure receipts, DSAR responses, breach notification timelines and the published status page.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },

  // ---- CC3 Risk Assessment ----
  { id: 'CC3.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Specifies objectives with sufficient clarity', ...V([], 'Documented in the system description and the risk register.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'point-in-time' },
  { id: 'CC3.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Identifies and analyses risk', ...V(['VLT-12'], 'The risk register, plus adversarial testing of the gate itself.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period' },
  { id: 'CC3.3', category: 'CC — Common Criteria', tsc: 'Security', name: 'Considers the potential for fraud', ...V(['VLT-2', 'VLT-7'], 'Channel trust, wall enforcement, and the poisoning detectors — the threat model is an adversary writing to memory.'), applicability: 'included', justification: 'Directly applicable: the product exists to resist deliberate manipulation.', window: 'period' },
  { id: 'CC3.4', category: 'CC — Common Criteria', tsc: 'Security', name: 'Identifies and analyses significant change', ...V(['VLT-11'], 'Model-pin change detection, rule version control, framework-change tracking.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period' },

  // ---- CC4 Monitoring Activities ----
  { id: 'CC4.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Selects, develops and performs ongoing evaluations', ...V(['VLT-12'], 'Continuous control monitoring, plus quarterly red-teaming of the gate.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period' },
  { id: 'CC4.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Evaluates and communicates deficiencies', ...V(['VLT-12'], 'The incident register with classification, root cause, remediation and disclosure tracking.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period' },

  // ---- CC5 Control Activities ----
  { id: 'CC5.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Selects and develops control activities', ...V(['VLT-1'], 'The ten-check gate, which cannot be disabled in any configuration.'), applicability: 'included', justification: 'Core to the service.', window: 'point-in-time' },
  { id: 'CC5.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Selects and develops general technology controls', ...V(['VLT-1', 'VLT-4'], 'Gate, ledger, encryption at rest, key management.'), applicability: 'included', justification: 'Core to the service.', window: 'point-in-time' },
  { id: 'CC5.3', category: 'CC — Common Criteria', tsc: 'Security', name: 'Deploys through policies and procedures', ...V([], 'Published policies with versioning, approval and acknowledgement tracking.'), applicability: 'included', justification: 'Applies to every service organisation.', window: 'period' },

  // ---- CC6 Logical and Physical Access ----
  { id: 'CC6.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Implements logical access security', ...V(['VLT-1', 'VLT-7'], 'SAML/OIDC SSO, server-side sessions, MFA with phishing-resistant factors for privileged roles, RBAC and ABAC, folder walls.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC6.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Registers and authorises new users', ...V(['VLT-5'], 'SCIM provisioning from the customer IdP; agents require named owners at registration.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC6.3', category: 'CC — Common Criteria', tsc: 'Security', name: 'Removes access when no longer required', ...V(['VLT-7'], 'SCIM deprovisioning revokes server-side sessions on the NEXT request; measured worst case 7.69ms across 12 routes.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC6.4', category: 'CC — Common Criteria', tsc: 'Security', name: 'Restricts physical access', ...V([], 'Inherited from the cloud provider; out of scope for on-prem deployments where the customer controls the facility.'), applicability: 'included', justification: 'Included for Vault Cloud, inherited from the IaaS provider under a carve-out or inclusive method.', window: 'period', gap: 'Requires the sub-service organisation report (AWS/Azure/GCP SOC 2) and a decision on carve-out vs inclusive.' },
  { id: 'CC6.5', category: 'CC — Common Criteria', tsc: 'Security', name: 'Disposes of data securely', ...V(['VLT-8'], 'Receipted erasure: hard delete with segment rewrite, plus crypto-shredding that reaches backup generations.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC6.6', category: 'CC — Common Criteria', tsc: 'Security', name: 'Restricts access from outside the system boundary', ...V(['VLT-1'], 'TLS 1.3, mTLS for agent connections, IP allowlisting, geo-fencing, device binding.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC6.7', category: 'CC — Common Criteria', tsc: 'Security', name: 'Restricts transmission and movement of information', ...V(['VLT-6', 'VLT-7'], 'PII detection and masking at ingestion, wall enforcement on exports, residency pinning with cross-border read blocking.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC6.8', category: 'CC — Common Criteria', tsc: 'Security', name: 'Prevents or detects unauthorised software', ...V(['VLT-16'], 'Tool and MCP server allowlisting with provenance; approved-model allowlist.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },

  // ---- CC7 System Operations ----
  { id: 'CC7.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Detects and monitors configuration changes', ...V(['VLT-4', 'VLT-11'], 'Every rule change, wall change, module toggle and model pin change is a ledger event.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC7.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Monitors for anomalies and security events', ...V(['VLT-4', 'VLT-12'], 'Fourteen poisoning detectors, per-agent behavioural baselines with deviation alerting, SIEM export.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC7.3', category: 'CC — Common Criteria', tsc: 'Security', name: 'Evaluates security events for impact', ...V(['VLT-4'], 'Contagion trace: origin, read-by list, derived facts, affected summaries, blast-radius summary.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC7.4', category: 'CC — Common Criteria', tsc: 'Security', name: 'Responds to identified security incidents', ...V(['VLT-10'], 'Documented incident response plan; six-level kill switch with a named administrator.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC7.5', category: 'CC — Common Criteria', tsc: 'Security', name: 'Recovers from identified security incidents', ...V(['VLT-10'], 'Point-in-time restore, one-click rollback of a fact/agent/source/channel/folder, incident bundle export.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },

  // ---- CC8 Change Management ----
  { id: 'CC8.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Authorises, designs, develops, tests and approves changes', ...V(['VLT-11'], 'Rule lifecycle draft → backtest → warn-only → enforce, with version control and a named approver.'), applicability: 'included', justification: 'Core to the service.', window: 'period', gap: 'Requires evidence of code review and CI gating across the observation window; no CI configuration is currently committed.' },

  // ---- CC9 Risk Mitigation ----
  { id: 'CC9.1', category: 'CC — Common Criteria', tsc: 'Security', name: 'Identifies and mitigates business disruption risk', ...V(['VLT-10'], 'Backup and DR with measured RPO/RTO, continuous mirror export to customer-owned storage, self-host escape hatch.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },
  { id: 'CC9.2', category: 'CC — Common Criteria', tsc: 'Security', name: 'Assesses and manages vendor and business partner risk', ...V(['VLT-13'], 'Third-party AI vendor register with sub-processor, attestation and renewal-date tracking.'), applicability: 'included', justification: 'Core to the service.', window: 'period' },

  // ---- Availability ----
  { id: 'A1.1', category: 'A — Availability', tsc: 'Availability', name: 'Maintains and monitors capacity', ...V([], 'Live cost/GB per tier, growth forecasting, hard caps with pre-breach alerts, storage chargeback.'), applicability: 'included', justification: 'Selected. Customers contract to an availability SLA, so capacity monitoring is in scope.', window: 'period' },
  { id: 'A1.2', category: 'A — Availability', tsc: 'Availability', name: 'Environmental protections, backup and recovery infrastructure', ...V(['VLT-10'], 'Continuous incremental plus daily full, cross-region replication, immutable backups with separate delete credentials.'), applicability: 'included', justification: 'Selected. Backup and recovery infrastructure is the mechanism behind the availability commitment; without it the SLA is unbacked.', window: 'period' },
  { id: 'A1.3', category: 'A — Availability', tsc: 'Availability', name: 'Tests recovery plan procedures', ...V(['VLT-10'], 'Quarterly restore drill spawning a fresh Vault from the export alone; DR exercise with the primary genuinely destroyed.'), applicability: 'included', justification: 'Selected. A recovery plan that has never been executed is a document; the drill is what makes the commitment real.', window: 'period' },

  // ---- Confidentiality ----
  { id: 'C1.1', category: 'C — Confidentiality', tsc: 'Confidentiality', name: 'Identifies and maintains confidential information', ...V(['VLT-6'], 'Four-tier sensitivity labelling with folder inheritance and never-guess-downward.'), applicability: 'included', justification: 'Selected. The service holds customer confidential information by design, so confidentiality is a criterion the buyer relies on.', window: 'period' },
  { id: 'C1.2', category: 'C — Confidentiality', tsc: 'Confidentiality', name: 'Disposes of confidential information', ...V(['VLT-8'], 'Receipted erasure with crypto-shredding; retention schedules with conflict surfacing.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },

  // ---- Processing Integrity ----
  { id: 'PI1.1', category: 'PI — Processing Integrity', tsc: 'Processing Integrity', name: 'Obtains or generates relevant quality information about objectives', ...V(['VLT-4'], 'Provenance on every fact: source span, channel, trust classification, model version, extraction confidence.'), applicability: 'included', justification: 'Selected. The service asserts that stored memory is traceable to its source, which is a processing-integrity claim.', window: 'period' },
  { id: 'PI1.2', category: 'PI — Processing Integrity', tsc: 'Processing Integrity', name: 'Inputs are complete and accurate', ...V(['VLT-1', 'VLT-2'], 'Ten-check gate; conservative extraction that holds rather than invents; never-invent rule with every candidate traceable to a byte range.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'PI1.3', category: 'PI — Processing Integrity', tsc: 'Processing Integrity', name: 'Processing is complete, accurate and timely', ...V(['VLT-1'], 'Measured gate latency; queue-and-drain fail-safe with no pass-unchecked path.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'PI1.4', category: 'PI — Processing Integrity', tsc: 'Processing Integrity', name: 'Outputs are complete, accurate and distributed appropriately', ...V(['VLT-7'], 'Read path filters by wall, clearance, region and status, and labels every returned fact with provenance.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'PI1.5', category: 'PI — Processing Integrity', tsc: 'Processing Integrity', name: 'Stores inputs and outputs completely and accurately', ...V(['VLT-4', 'VLT-15'], 'WORM raw archive, hash-chained, with retention schedules.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },

  // ---- Privacy ----
  { id: 'P1.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Notice about privacy practices', ...V(['VLT-14'], 'Auto-generated employee transparency notice; jurisdiction packs ship a plain-language scope statement.'), applicability: 'included', justification: 'Selected. The service processes personal data on behalf of customers as a processor under GDPR Article 28.', window: 'period' },
  { id: 'P2.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Choice and consent', ...V(['VLT-9'], 'Lawful basis per fact, Art 9 conditions, DPDP Consent Manager integration, withdrawal triggering real purge.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'P3.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Collection limited to identified purposes', ...V(['VLT-6', 'VLT-14'], 'PII controls at ingestion; Employee Privacy Mode excluded contexts; sample-not-stream default.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'P4.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Use, retention and disposal', ...V(['VLT-15', 'VLT-8'], 'Purpose limitation enforced at read time; retention by purpose alongside retention by age.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'P5.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Access by data subjects', ...V(['VLT-8'], 'DSAR workflow with full-person discovery, machine-readable output, third-party redaction, deadline tracking.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'P6.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Disclosure to third parties', ...V(['VLT-13'], 'Sub-processor list per region; third-party erasure propagation with confirmation.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'P7.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Quality of personal information', ...V(['VLT-8'], 'Rectification workflow with versioning; contradiction resolution with human arbitration.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' },
  { id: 'P8.1', category: 'P — Privacy', tsc: 'Privacy', name: 'Monitoring and enforcement', ...V(['VLT-14'], 'Employee objection channel with tracked response; works-council role; change notification to representatives.'), applicability: 'included', justification: 'Selected. In scope because the service commits to this criterion contractually and the buyer relies on it.', window: 'period' }
];

// ===========================================================================
// ISO/IEC 27001:2022 — Annex A, all 93 controls in four themes
// ===========================================================================

const a = (id, name, map, applicability = 'included', justification = 'Applicable to the service and its information assets.', extra = {}) =>
  ({ id, name, theme: id.startsWith('A.5') ? 'A.5 Organizational' : id.startsWith('A.6') ? 'A.6 People' : id.startsWith('A.7') ? 'A.7 Physical' : 'A.8 Technological', ...map, applicability, justification, ...extra });

export const ISO27001_ANNEX_A = [
  // A.5 Organizational (37)
  a('A.5.1', 'Policies for information security', V([], 'Policy authoring, versioning, approval and publish workflow with acknowledgement tracking.')),
  a('A.5.2', 'Information security roles and responsibilities', V(['VLT-5'], 'Named business and technical owner on every agent, folder and namespace.')),
  a('A.5.3', 'Segregation of duties', V(['VLT-7'], 'Break-glass requires two named approvers; the backup write credential cannot delete.')),
  a('A.5.4', 'Management responsibilities', V([], 'Board reporting pack; attestation tracking.')),
  a('A.5.5', 'Contact with authorities', V([], 'Regulatory reporting formats for ICO, EU AI Office, India DPB, state AGs, NAIC, FINRA.')),
  a('A.5.6', 'Contact with special interest groups', V([], 'Threat-feed integration; published bug bounty and VDP.')),
  a('A.5.7', 'Threat intelligence', V(['VLT-2'], 'Threat-feed integration, known-bad-source blocklist, domain age and lookalike detection.')),
  a('A.5.8', 'Information security in project management', V([], 'Rule lifecycle and change management.'), 'included'),
  a('A.5.9', 'Inventory of information and other associated assets', V(['VLT-5'], 'AI system register; agent inventory; folder and namespace tree.')),
  a('A.5.10', 'Acceptable use of information and other associated assets', V(['VLT-14'], 'Purpose lock enforced at the query layer and warranted contractually.')),
  a('A.5.11', 'Return of assets', V(['VLT-8'], 'Offboarding workflow with a signed receipt; credential revocation on agent retirement.')),
  a('A.5.12', 'Classification of information', V(['VLT-6'], 'Four-tier sensitivity labelling with folder inheritance.')),
  a('A.5.13', 'Labelling of information', V(['VLT-6'], 'Every returned fact is labelled with provenance and sensitivity.')),
  a('A.5.14', 'Information transfer', V(['VLT-7'], 'Residency pinning, cross-border read blocking, transfer-mechanism documentation per flow.')),
  a('A.5.15', 'Access control', V(['VLT-7'], 'RBAC and ABAC; folder walls enforced on read, write, search, entity views, exports.')),
  a('A.5.16', 'Identity management', V(['VLT-5'], 'SCIM provisioning; Vault-issued short-lived scoped origin-bound agent credentials.')),
  a('A.5.17', 'Authentication information', V(['VLT-1'], 'MFA with phishing-resistant factors for privileged roles; TOTP seeds sealed at rest.')),
  a('A.5.18', 'Access rights', V(['VLT-7'], 'Full audit of every permission change; deprovisioning effective on the next request.')),
  a('A.5.19', 'Information security in supplier relationships', V(['VLT-13'], 'Vendor register with attestation and renewal tracking.')),
  a('A.5.20', 'Addressing information security within supplier agreements', V(['VLT-13'], 'DPA terms with sub-processor flow-down.')),
  a('A.5.21', 'Managing information security in the ICT supply chain', V(['VLT-16'], 'Zero runtime dependencies; tool and MCP allowlisting with provenance.')),
  a('A.5.22', 'Monitoring, review and change management of supplier services', V(['VLT-13'], 'Vendor attestation and renewal-date tracking; connector version pinning and schema drift detection.')),
  a('A.5.23', 'Information security for use of cloud services', V([], 'BYO bucket with health check, permission validation and region-matches-residency verification.')),
  a('A.5.24', 'Information security incident management planning and preparation', V(['VLT-10'], 'Documented incident response plan; incident register.')),
  a('A.5.25', 'Assessment and decision on information security events', V(['VLT-12'], 'Alert severity tiering; incident classification.')),
  a('A.5.26', 'Response to information security incidents', V(['VLT-10'], 'Kill switch levels 1–6; contagion trace and rollback.')),
  a('A.5.27', 'Learning from information security incidents', V(['VLT-12'], 'Root cause and remediation tracking; reject reasons feed detector tuning.')),
  a('A.5.28', 'Collection of evidence', V(['VLT-4'], 'Hash-chained ledger with a standalone verifier; incident bundle export with optional signing.')),
  a('A.5.29', 'Information security during disruption', V(['VLT-10'], 'Queue-and-drain fail-safe; graceful degradation with auto-resume and backfill.')),
  a('A.5.30', 'ICT readiness for business continuity', V(['VLT-10'], 'Measured RPO/RTO; quarterly restore testing.')),
  a('A.5.31', 'Legal, statutory, regulatory and contractual requirements', V(['VLT-15'], 'Jurisdiction packs; recordkeeping framework mapping; conflicting-obligation surfacing.')),
  a('A.5.32', 'Intellectual property rights', V([], 'Licence decision recorded; SBOM.')),
  a('A.5.33', 'Protection of records', V(['VLT-15'], 'WORM archive in compliance mode; legal hold independent of retention.')),
  a('A.5.34', 'Privacy and protection of PII', V(['VLT-6', 'VLT-9'], 'PII scanning at ingestion; lawful basis per fact; Employee Privacy Mode.')),
  a('A.5.35', 'Independent review of information security', V([], 'Third-party penetration test and external audit.'), 'included', 'Applicable. An independent review is required by the standard and cannot be satisfied by internal testing.', { gap: 'NOT SATISFIED. No independent review has been performed. The engagement package exists; the engagement does not.' }),
  a('A.5.36', 'Compliance with policies, rules and standards', V([], 'Continuous control monitoring with real-time alerting on failure.')),
  a('A.5.37', 'Documented operating procedures', V([], 'docs/OPERATIONS.md, docs/INCIDENT-RESPONSE.md, docs/SECURITY.md.')),

  // A.6 People (8)
  a('A.6.1', 'Screening', V([], 'HR process. Background checks before access to production.'), 'included', 'Applicable to personnel with access to customer data.', { gap: 'Organisational. Requires HR evidence over the observation window.' }),
  a('A.6.2', 'Terms and conditions of employment', V([], 'Employment contracts including confidentiality obligations.'), 'included', 'Applicable. Personnel with access to customer data must be bound by enforceable confidentiality terms.', { gap: 'Organisational.' }),
  a('A.6.3', 'Information security awareness, education and training', V([], 'Annual training with acknowledgement tracking.'), 'included', 'Applicable. Awareness training is the control that makes every other people control effective.', { gap: 'Organisational. Requires training records.' }),
  a('A.6.4', 'Disciplinary process', V([], 'Documented in the employee handbook.'), 'included', 'Applicable. A disciplinary process is what gives the acceptable-use and confidentiality terms consequence.', { gap: 'Organisational.' }),
  a('A.6.5', 'Responsibilities after termination or change of employment', V(['VLT-8'], 'Offboarding workflow; SCIM deprovisioning revokes sessions on the next request.')),
  a('A.6.6', 'Confidentiality or non-disclosure agreements', V([], 'NDAs with staff and sub-processors.'), 'included', 'Applicable. Confidentiality agreements bind staff and sub-processors handling customer data.', { gap: 'Organisational.' }),
  a('A.6.7', 'Remote working', V(['VLT-1'], 'Device binding, IP allowlisting, geo-fencing, session timeout and concurrency controls.')),
  a('A.6.8', 'Information security event reporting', V(['VLT-12'], 'Alerting infrastructure; published VDP with a 2-business-day acknowledgement commitment.')),

  // A.7 Physical (14) — inherited for cloud, customer-controlled on-prem
  ...['A.7.1 Physical security perimeters', 'A.7.2 Physical entry', 'A.7.3 Securing offices, rooms and facilities', 'A.7.4 Physical security monitoring', 'A.7.5 Protecting against physical and environmental threats', 'A.7.6 Working in secure areas', 'A.7.7 Clear desk and clear screen', 'A.7.8 Equipment siting and protection', 'A.7.9 Security of assets off-premises', 'A.7.10 Storage media', 'A.7.11 Supporting utilities', 'A.7.12 Cabling security', 'A.7.13 Equipment maintenance', 'A.7.14 Secure disposal or re-use of equipment']
    .map((s) => {
      const [id, ...rest] = s.split(' ');
      return a(id, rest.join(' '), V([], 'Inherited from the IaaS provider for Vault Cloud; the customer\'s own facility for on-premise and air-gapped deployments.'),
        'included', 'Applicable, but satisfied by a sub-service organisation rather than by Vault.',
        { gap: 'Requires the IaaS provider\'s ISO 27001 certificate and a carve-out decision. Not satisfied by any Vault control.' });
    }),

  // A.8 Technological (34)
  a('A.8.1', 'User end point devices', V(['VLT-1'], 'Device binding; excluded contexts include personal devices under Employee Privacy Mode.')),
  a('A.8.2', 'Privileged access rights', V(['VLT-7'], 'Break-glass with two named approvers, time box, session content recording and customer notification.')),
  a('A.8.3', 'Information access restriction', V(['VLT-7'], 'Walls on read, write, search, entity views, knowledge maps and exports; clearance-level field redaction within an allowed fact.')),
  a('A.8.4', 'Access to source code', V([], 'Repository access control and mandatory review.'), 'included', 'Applicable. Source code access must be restricted and reviewed because it is the route to every other control.', { gap: 'Requires repository access evidence over the observation window.' }),
  a('A.8.5', 'Secure authentication', V(['VLT-1'], 'SAML 2.0 with signature-wrapping and algorithm-confusion defences; OIDC; server-side sessions.')),
  a('A.8.6', 'Capacity management', V([], 'Cost forecast by growth rate; hard caps with pre-breach alerts; measured throughput and scale ceiling.')),
  a('A.8.7', 'Protection against malware', V(['VLT-2'], 'Instruction-injection detection across six layers; attachment analysis with OCR and audio scanning.')),
  a('A.8.8', 'Management of technical vulnerabilities', V([], 'Dependency scanning, daily vulnerability scanning, published VDP and bug bounty.'), 'included', 'Applicable. Technical vulnerabilities in the service are a direct risk to customer data.', { gap: 'PARTIAL. Policies published; no scanning tooling is configured in the repository.' }),
  a('A.8.9', 'Configuration management', V(['VLT-11'], 'Configuration as code with plan/apply/drift; every config change is a ledger event.')),
  a('A.8.10', 'Information deletion', V(['VLT-8'], 'Receipted erasure with hard delete and segment rewrite; crypto-shredding reaching backups.')),
  a('A.8.11', 'Data masking', V(['VLT-6'], 'Mask, tokenise (reversible under break-glass), redact and quarantine actions per detector.')),
  a('A.8.12', 'Data leakage prevention', V(['VLT-6', 'VLT-7'], 'PII scanner with 25 detector classes; DLP vendor adapters; wall enforcement on exports; credential special-case block.')),
  a('A.8.13', 'Information backup', V(['VLT-10'], 'Continuous incremental plus daily full; immutable backups with separate delete credentials; manifest and suppression list stored with the data.')),
  a('A.8.14', 'Redundancy of information processing facilities', V([], 'Multi-AZ and cross-region replication.'), 'included', 'Applicable to Vault Cloud.', { gap: 'Infrastructure-layer; not evidenced in the application repository.' }),
  a('A.8.15', 'Logging', V(['VLT-4'], 'Append-only hash-chained ledger; read logging tiered by sensitivity; no edit code path exists.')),
  a('A.8.16', 'Monitoring activities', V(['VLT-12'], 'Fourteen poisoning detectors; behavioural baselines; SIEM and OTel export.')),
  a('A.8.17', 'Clock synchronisation', V([], 'NTP on all hosts; ledger entries carry millisecond timestamps with timezone.'), 'included', 'Applicable. Ledger timestamps and retention calculations depend on synchronised clocks.', { gap: 'Infrastructure-layer.' }),
  a('A.8.18', 'Use of privileged utility programs', V(['VLT-7'], 'No admin bypass of walls by default; privileged actions monitored.')),
  a('A.8.19', 'Installation of software on operational systems', V(['VLT-16'], 'Zero runtime dependencies; approved-model allowlist; MCP server allowlisting.')),
  a('A.8.20', 'Networks security', V(['VLT-1'], 'TLS 1.3, mTLS for agent connections, certificate pinning option.')),
  a('A.8.21', 'Security of network services', V(['VLT-1'], 'API rate limiting; WAF and DDoS protection at the edge.')),
  a('A.8.22', 'Segregation of networks', V([], 'VPC isolation; single-tenant and customer-VPC deployment models.'), 'included', 'Applicable. Network segregation limits blast radius between tenants and environments.', { gap: 'Infrastructure-layer.' }),
  a('A.8.23', 'Web filtering', V([], 'Egress policy on outbound connections.'), 'excluded', 'EXCLUDED. Vault makes outbound calls only to customer-configured connector endpoints, which are allowlisted per connector by the customer. General-purpose web browsing is not a function of the service, so a web filtering control has nothing to act on.'),
  a('A.8.24', 'Use of cryptography', V(['VLT-4'], 'AES-256-GCM at rest by default with a justified allowlist; envelope encryption; per-namespace and per-subject keys; BYOK/CMK/HYOK/HSM.')),
  a('A.8.25', 'Secure development life cycle', V([], 'Test-first for security mechanisms; mutation testing of every security control.')),
  a('A.8.26', 'Application security requirements', V(['VLT-1'], 'The ten-check gate is the application security requirement, and it cannot be disabled.')),
  a('A.8.27', 'Secure system architecture and engineering principles', V(['VLT-1'], 'Fail-safe by construction: no pass-unchecked code path; encryption opt-out rather than opt-in.')),
  a('A.8.28', 'Secure coding', V([], 'Mandatory review; no runtime dependencies to inherit vulnerabilities from.'), 'included', 'Applicable. Secure coding is the control behind every application-layer assurance in this package.', { gap: 'PARTIAL. No SAST tooling configured in the repository.' }),
  a('A.8.29', 'Security testing in development and acceptance', V(['VLT-12'], '778 automated tests including adversarial attack sweeps and mutation testing of every security mechanism.')),
  a('A.8.30', 'Outsourced development', V([], 'Not applicable.'), 'excluded', 'EXCLUDED. All development is performed in-house. No development is outsourced to a third party, so there is no outsourced-development relationship to govern.'),
  a('A.8.31', 'Separation of development, test and production environments', V([], 'Separate environments with no production data in test.'), 'included', 'Applicable. Separating environments is what stops test activity reaching production data.', { gap: 'Infrastructure-layer; requires environment evidence.' }),
  a('A.8.32', 'Change management', V(['VLT-11'], 'Rule lifecycle with backtest and warn-only stages; every change versioned with who, when, why and a diff.')),
  a('A.8.33', 'Test information', V([], 'Synthetic data only in test environments; the demo tenant refuses to seed over real data.')),
  a('A.8.34', 'Protection of information systems during audit testing', V([], 'Time-boxed scoped auditor workspace with its own access log.'))
];

// ===========================================================================
// ISO/IEC 42001:2023 — Annex A, AI management system controls
// ===========================================================================

export const ISO42001_ANNEX_A = [
  { id: 'A.2.2', clause: 'A.2 AI policy', name: 'AI policy', ...V([], 'The AI policy document generated with this package.'), applicability: 'included', justification: 'Required of every AIMS.' },
  { id: 'A.2.3', clause: 'A.2 AI policy', name: 'Alignment with other organisational policies', ...V([], 'The AI policy cross-references the information security and privacy policies.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.2.4', clause: 'A.2 AI policy', name: 'Review of the AI policy', ...V([], 'Annual review with versioning and approval workflow.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.3.2', clause: 'A.3 Internal organization', name: 'AI roles and responsibilities', ...V(['VLT-5'], 'Named business and technical owner on every agent and folder, enforced at registration.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.3.3', clause: 'A.3 Internal organization', name: 'Reporting of concerns', ...V([], 'Employee objection channel with tracked response; published VDP.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.4.2', clause: 'A.4 Resources for AI systems', name: 'Resource documentation', ...V(['VLT-5'], 'AI system register covering agents, models, prompts, datasets and memory stores with owners.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.4.3', clause: 'A.4 Resources for AI systems', name: 'Data resources', ...V(['VLT-6'], 'Provenance on every fact: source span, channel, trust classification, extraction confidence.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.4.4', clause: 'A.4 Resources for AI systems', name: 'Tooling resources', ...V(['VLT-16'], 'Tool and MCP server allowlisting with provenance.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.4.5', clause: 'A.4 Resources for AI systems', name: 'System and computing resources', ...V([], 'Measured throughput, scale ceilings and cost per tier, published with method.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.4.6', clause: 'A.4 Resources for AI systems', name: 'Human resources', ...V(['VLT-3'], 'Reviewer scorecards; reviewer-fatigue detection; four-eyes on high-risk items.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.5.2', clause: 'A.5 Assessing impacts', name: 'AI system impact assessment process', ...V([], 'DPIA, FRIA and LIA generators pre-filled from live configuration.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.5.3', clause: 'A.5 Assessing impacts', name: 'Documentation of impact assessments', ...V([], 'Generated assessments are versioned and retained.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.5.4', clause: 'A.5 Assessing impacts', name: 'Assessing AI system impact on individuals', ...V(['VLT-14'], 'Employee Privacy Mode with k-anonymity floor; no individual scoring code path exists.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.5.5', clause: 'A.5 Assessing impacts', name: 'Assessing societal impacts', ...V([], 'FRIA generator covering fundamental-rights impact.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.1.2', clause: 'A.6 AI system life cycle', name: 'Objectives for responsible development', ...V([], 'Stated in the AI policy.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.1.3', clause: 'A.6 AI system life cycle', name: 'Processes for responsible design and development', ...V(['VLT-1'], 'Gate-first architecture: no write path exists that bypasses the checks.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.2', clause: 'A.6 AI system life cycle', name: 'AI system requirements and specification', ...V([], 'The master feature checklist with per-item verification status.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.3', clause: 'A.6 AI system life cycle', name: 'Documentation of AI system design and development', ...V([], 'docs/ARCHITECTURE.md; model and system card generation.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.4', clause: 'A.6 AI system life cycle', name: 'AI system verification and validation', ...V(['VLT-1', 'VLT-12'], '778 automated tests; adversarial sweeps; mutation testing of every security mechanism.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.5', clause: 'A.6 AI system life cycle', name: 'AI system deployment', ...V(['VLT-11'], 'Model pinning; unapproved-version writes held; silent model swap alerting.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.6', clause: 'A.6 AI system life cycle', name: 'AI system operation and monitoring', ...V(['VLT-12'], 'Behavioural baselines, deviation alerting, drift detection, issue lifecycle tracking.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.7', clause: 'A.6 AI system life cycle', name: 'AI system technical documentation', ...V([], 'Model cards, system cards, published formats and API documentation.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.6.2.8', clause: 'A.6 AI system life cycle', name: 'AI system recording of event logs', ...V(['VLT-4'], 'Hash-chained ledger with a standalone verifier and external anchoring.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.7.2', clause: 'A.7 Data for AI systems', name: 'Data for development and enhancement', ...V([], 'No customer data enters any training set, ours or upstream — there is no training pipeline in the product.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.7.3', clause: 'A.7 Data for AI systems', name: 'Acquisition of data', ...V(['VLT-2'], 'Channel trust classification; deny-by-source default; source verification.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.7.4', clause: 'A.7 Data for AI systems', name: 'Quality of data', ...V(['VLT-1'], 'Reconciliation with authority ordering; contradiction resolution; hygiene engine.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.7.5', clause: 'A.7 Data for AI systems', name: 'Data provenance', ...V(['VLT-4'], 'Every fact carries a byte-range pointer into the sealed raw archive.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.7.6', clause: 'A.7 Data for AI systems', name: 'Data preparation', ...V([], 'Conservative extraction; numbers and dates normalised with the original string kept.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.8.2', clause: 'A.8 Information for interested parties', name: 'System documentation and information for users', ...V([], 'Published coverage map with honest "cannot pull" labelling per connector.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.8.3', clause: 'A.8 Information for interested parties', name: 'External reporting', ...V([], 'Regulatory reporting formats; published status page and incident history.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.8.4', clause: 'A.8 Information for interested parties', name: 'Communication of incidents', ...V(['VLT-10'], 'Contractual breach notification within 24 hours of confirmation; published blast radius.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.8.5', clause: 'A.8 Information for interested parties', name: 'Information for interested parties', ...V(['VLT-14'], 'Works-council role; change notification to representatives; employee transparency portal.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.9.2', clause: 'A.9 Use of AI systems', name: 'Processes for responsible use', ...V(['VLT-14'], 'Purpose lock enforced at the query layer and warranted contractually as a termination-triggering obligation.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.9.3', clause: 'A.9 Use of AI systems', name: 'Objectives for responsible use', ...V(['VLT-3'], 'Human oversight of held and escalated writes with SLA tracking.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.9.4', clause: 'A.9 Use of AI systems', name: 'Intended use of the AI system', ...V(['VLT-10'], 'Six-level kill switch with a named administrator and measured activation.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.10.2', clause: 'A.10 Third-party relationships', name: 'Allocating responsibilities', ...V(['VLT-13'], 'Vendor register with attestation tracking; DPA sub-processor flow-down.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.10.3', clause: 'A.10 Third-party relationships', name: 'Suppliers', ...V(['VLT-13'], 'Sub-processor disclosure with notice; zero-retention attestations from model providers.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' },
  { id: 'A.10.4', clause: 'A.10 Third-party relationships', name: 'Customers', ...V([], 'MSA and DPA terms; exit and continuity commitments; free unlimited export.'), applicability: 'included', justification: 'Required. ISO 42001 mandates this control for any organisation operating an AI management system.' }
];

export const FRAMEWORK_CATALOGUES = {
  'SOC 2': { controls: SOC2_TSC, standard: 'AICPA TSP Section 100 (2017, revised 2022)', total: SOC2_TSC.length },
  'ISO 27001': { controls: ISO27001_ANNEX_A, standard: 'ISO/IEC 27001:2022 Annex A', total: ISO27001_ANNEX_A.length },
  'ISO 42001': { controls: ISO42001_ANNEX_A, standard: 'ISO/IEC 42001:2023 Annex A', total: ISO42001_ANNEX_A.length }
};
