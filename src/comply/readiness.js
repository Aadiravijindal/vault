/**
 * Readiness packages: SOC 2 Type II, ISO 27001, ISO 42001.
 *
 * The point of difference, and the thing that has to be proven rather than
 * asserted: **evidence is collected from the ledger, and every evidence item
 * carries the sequence number of a real entry.** A readiness package whose
 * evidence column says "see the audit log" is a table of intentions. One where
 * each row says "ledger seq 4,182, hash 9f3a…, verifiable with
 * bin/vault-verify.js" is something an auditor can pull on.
 *
 * So `collectEvidence` here does not describe evidence — it goes and gets it,
 * and a control with no ledger entry behind it is reported as `no-evidence`
 * rather than quietly presented as satisfied. That number appearing in the gap
 * report is the honest output; a package reporting 100% coverage has not been
 * read carefully.
 *
 * Three things this deliberately will NOT do:
 *
 *  - Mark a control satisfied because a Vault control is mapped to it. The
 *    mapping says what WOULD satisfy it; the ledger says whether it ran.
 *  - Mark an organisational control (training records, background checks,
 *    board minutes) satisfied at all. No software artefact evidences those and
 *    claiming otherwise is how a readiness report becomes worthless.
 *  - Describe a point-in-time snapshot as Type II evidence. Every control
 *    carries `window`, and the report states plainly which need an observation
 *    period and how long.
 */
import { FRAMEWORK_CATALOGUES } from './frameworks.js';
import { CONTROLS } from './comply.js';
import { iso, now } from '../util/time.js';

/**
 * Ledger event types that evidence a given Vault control.
 *
 * Deliberately explicit rather than a substring match on the control id: a
 * fuzzy match would find *something* for every control and the gap report
 * would come out empty, which is the failure mode this whole file exists to
 * avoid.
 */
const EVIDENCE_SOURCES = {
  'VLT-1': { events: ['fact.written', 'fact.held', 'fact.blocked', 'fact.masked', 'fact.quarantined'], what: 'Gate verdicts. Every write carries the outcome of all ten checks.' },
  'VLT-2': { events: ['fact.held', 'fact.blocked', 'security.detection'], what: 'Writes refused or held on channel-trust grounds.' },
  'VLT-3': { events: ['review.decision', 'review.escalated', 'review.sla_breach'], what: 'Human review decisions with actor, timing and reasoning.' },
  'VLT-4': { events: ['anchor.published', 'export.created'], what: 'Chain anchoring and export events; the chain itself is the evidence.' },
  'VLT-5': { events: ['agent.registered', 'agent.scope_changed', 'agent.retired', 'agent.suspended'], what: 'The AI system inventory, as a stream of registration events with named owners.' },
  'VLT-6': { events: ['fact.masked', 'fact.blocked'], what: 'PII detections and the action taken.' },
  'VLT-7': { events: ['folder.wall_changed', 'admin.breakglass'], what: 'Wall configuration changes and every privileged access grant.' },
  'VLT-8': { events: ['privacy.erasure', 'fact.erased', 'key.destroyed'], what: 'Erasure executions with their receipts and the keys destroyed.' },
  'VLT-9': { events: ['privacy.consent_recorded', 'privacy.consent_withdrawn'], what: 'Lawful basis records and withdrawals.' },
  'VLT-10': { events: ['killswitch.engaged', 'killswitch.released'], what: 'Kill switch activations, including scheduled tests.' },
  'VLT-11': { events: ['agent.registered', 'agent.scope_changed'], what: 'Model pins recorded at registration and every change to them.' },
  'VLT-12': { events: ['security.alert', 'security.detection'], what: 'Adversarial findings and detector firings.' },
  'VLT-13': { events: ['admin.action'], what: 'Vendor register entries and attestation tracking.' },
  'VLT-14': { events: ['privacy.mode_changed', 'privacy.reidentification'], what: 'Privacy Mode configuration and every re-identification.' },
  'VLT-15': { events: ['fact.expired', 'storage.lifecycle', 'legal.hold_placed'], what: 'Retention executions and legal holds.' },
  'VLT-16': { events: ['admin.action', 'connector.connected'], what: 'Tool and MCP allowlisting decisions.' }
};

/**
 * Pull real ledger entries for one Vault control.
 * @returns {{controlId:string, entries:Array, count:number, what:string}}
 */
export function evidenceForVaultControl(ledger, controlId, { limit = 25 } = {}) {
  const src = EVIDENCE_SOURCES[controlId];
  if (!src) return { controlId, entries: [], count: 0, what: 'no evidence source is declared for this control' };
  const found = ledger.entries({ type: src.events, limit: Infinity });
  return {
    controlId,
    what: src.what,
    eventTypes: src.events,
    count: found.length,
    // The reference an auditor follows. Sequence and hash, not a description.
    entries: found.slice(-limit).map((e) => ({
      seq: e.seq, type: e.type, at: iso(e.at), actor: e.actor, hash: e.hash,
      verify: `bin/vault-verify.js <export> --entry ${e.seq}`
    }))
  };
}

/**
 * Generate one framework's readiness package.
 *
 * @param {object} o
 * @param {import('../ledger/ledger.js').Ledger} o.ledger
 * @param {'SOC 2'|'ISO 27001'|'ISO 42001'} o.framework
 * @param {object} [o.org] customer/organisation details for the system description
 */
export function readinessPackage({ ledger, framework, org = {}, at = now() }) {
  const cat = FRAMEWORK_CATALOGUES[framework];
  if (!cat) throw new Error(`no catalogue for ${framework}`);

  // Cache: many framework controls map to the same Vault control.
  const cache = new Map();
  const evidence = (id) => {
    if (!cache.has(id)) cache.set(id, evidenceForVaultControl(ledger, id));
    return cache.get(id);
  };

  const rows = cat.controls.map((c) => {
    const vaultControls = c.vaultControls ?? [];
    const collected = vaultControls.map(evidence).filter((e) => e.count > 0);
    const totalEntries = collected.reduce((a, e) => a + e.count, 0);

    /**
     * Four states, and the difference between them is the whole report:
     *  - satisfied     : a Vault control is mapped AND the ledger proves it ran
     *  - no-evidence   : mapped, but nothing in the ledger yet (a new tenant, or
     *                    a control that has genuinely never fired)
     *  - organisational: no software artefact can evidence this
     *  - excluded      : out of scope, with a justification
     */
    let status;
    if (c.applicability === 'excluded') status = 'excluded';
    else if (vaultControls.length === 0) status = 'organisational';
    else if (totalEntries > 0) status = 'satisfied';
    else status = 'no-evidence';

    return {
      id: c.id,
      name: c.name,
      category: c.category ?? c.theme ?? c.clause ?? null,
      applicability: c.applicability,
      justification: c.justification,
      window: c.window ?? (framework === 'SOC 2' ? 'period' : 'point-in-time'),
      vaultControls,
      how: c.how ?? null,
      status,
      ledgerEntries: totalEntries,
      evidence: collected.map((e) => ({
        vaultControl: e.controlId, what: e.what, eventTypes: e.eventTypes,
        count: e.count, samples: e.entries.slice(-3)
      })),
      gap: c.gap ?? (status === 'no-evidence'
        ? 'Mapped to a Vault control, but no ledger entry has been produced yet. Exercise the control, or confirm it is not reachable in this deployment.'
        : null)
    };
  });

  const by = (s) => rows.filter((r) => r.status === s);
  const needsWindow = rows.filter((r) => r.window === 'period');

  return {
    framework,
    standard: cat.standard,
    generatedAt: iso(at),
    organisation: {
      name: org.name ?? 'Vault (the service organisation)',
      service: org.service ?? 'Vault — governed shared AI memory',
      scope: org.scope ?? 'The Vault platform: ingestion, the gate, the fact store, the sealed archive, the ledger, and the control surface.'
    },
    summary: {
      totalControls: rows.length,
      satisfied: by('satisfied').length,
      noEvidence: by('no-evidence').length,
      organisational: by('organisational').length,
      excluded: by('excluded').length,
      withKnownGaps: rows.filter((r) => r.gap).length,
      // Deliberately not a percentage of "controls with a mapping" — that
      // number flatters. This is a percentage of every control in the standard.
      technicalCoverage: `${by('satisfied').length}/${rows.length} (${Math.round((by('satisfied').length / rows.length) * 100)}%) evidenced from the ledger`,
      ledgerEntriesCited: rows.reduce((a, r) => a + r.ledgerEntries, 0)
    },
    observationWindow: {
      required: framework === 'SOC 2',
      controlsRequiringAPeriod: needsWindow.length,
      minimumPeriod: framework === 'SOC 2' ? '3 months for an initial Type II; 6 or 12 months is what most enterprise buyers accept' : 'not applicable — ISO certification audits a management system, not a period of operating effectiveness',
      statement: framework === 'SOC 2'
        ? `${needsWindow.length} of ${rows.length} controls can only be evidenced over an observation period. Until that period has elapsed and been audited, this is a Type I position — a point-in-time design assessment — however complete the control matrix looks.`
        : 'ISO 27001 and 42001 certification assess whether the management system is designed and operating, in a Stage 1 (documentation) and Stage 2 (implementation) audit. No fixed observation window applies, but Stage 2 expects records showing the system has been operating, typically for at least three months.'
    },
    controls: rows,
    gaps: rows.filter((r) => r.gap).map((r) => ({ id: r.id, name: r.name, status: r.status, gap: r.gap, closes: closureFor(r) }))
  };
}

function closureFor(row) {
  if (row.status === 'organisational') return 'A human process and its records. No code change closes this.';
  if (row.status === 'no-evidence') return 'Exercise the control once in this tenant so the ledger carries an entry, or record why it is unreachable here.';
  if (/independent review|penetration/i.test(row.gap ?? '')) return 'Commission the engagement in docs/PENTEST-PACKAGE.md. Requires a signed contract and a budget.';
  if (/sub-service|IaaS|Infrastructure-layer/i.test(row.gap ?? '')) return 'Obtain the IaaS provider\'s report and decide carve-out versus inclusive method.';
  if (/scanning tooling|SAST|CI/i.test(row.gap ?? '')) return 'Configure the scanner in CI and retain results across the observation window.';
  return 'See the gap text.';
}

/** The System Description a SOC 2 report requires (AICPA DC section 200). */
export function systemDescription({ vault, org = {}, at = now() }) {
  const stats = (() => { try { return vault.status(); } catch { return {}; } })();
  return {
    generatedAt: iso(at),
    organisation: org.name ?? 'Vault',
    typesOfServices: 'Vault provides a governed shared memory layer for AI agents. Interactions are captured verbatim into a sealed, hash-chained archive; candidate facts are extracted with a pointer back to their source bytes; every candidate passes a ten-check gate before it can become durable memory; and every event is recorded in an append-only, externally-anchored ledger that a customer can verify independently of Vault.',
    principalServiceCommitments: [
      'Every write to the fact store passes the gate. There is no configuration, credential or module state in which the gate does not run, and no "pass unchecked" code path exists.',
      'The audit ledger is append-only and hash-chained. There is no edit path in the code, and a customer can verify the chain with a standalone open-source verifier, holding their own signing key, without any Vault software.',
      'Customer content is encrypted at rest by default. Encryption is opt-out with a justified allowlist, not opt-in.',
      'A right-to-erasure request is executed and receipted, and the receipt states per record which stores were reached — including where a record sealed under a shared key could NOT be crypto-shredded in backups.',
      'Deprovisioning through SCIM revokes access on the next request, not at the next token refresh.',
      'Customer data is never used for training, by Vault or by any upstream model provider.'
    ],
    systemRequirements: [
      'Availability: 99.9% standard, 99.95% enterprise, 99.99% multi-region.',
      'Recovery: RPO 5 minutes, RTO 1 hour.',
      'Erasure: 24 hours for hot and warm tiers, 7 days including backups and archive.',
      'Full-tenant export: under 24 hours at any size, free and unthrottled.'
    ],
    componentsOfTheSystem: {
      infrastructure: 'Node.js ≥22 with zero runtime dependencies, deployable to Vault Cloud (multi- or single-tenant), the customer\'s VPC, on-premise, or fully air-gapped.',
      software: 'Twelve layers: connection, raw archive, extraction, the gate, fact store, hygiene, read path, ledger, observability, governance, storage, control surface.',
      people: 'Named administrators for the kill switch; two named approvers for break-glass; folder owners for review routing.',
      procedures: 'Documented in docs/OPERATIONS.md, docs/INCIDENT-RESPONSE.md and docs/SECURITY.md.',
      data: 'Customer conversations, extracted facts, governance metadata and the audit ledger. Sensitivity labelled in four tiers with folder inheritance.'
    },
    boundariesAndSubservice: {
      inScope: 'The Vault application and its data stores.',
      subserviceOrganisations: 'For Vault Cloud, the IaaS provider (physical security, environmental controls, hardware). Model providers where a connected module invokes one.',
      method: 'DECISION REQUIRED: carve-out or inclusive. Carve-out is the usual choice and requires the sub-service organisation\'s own SOC 2 report; this is a commercial and audit-strategy decision, not an engineering one.'
    },
    complementaryUserEntityControls: [
      'The customer configures folder walls, retention schedules and residency pinning to match their own obligations. Vault enforces what is configured; it cannot know the customer\'s legal position.',
      'The customer names the kill-switch administrators and the two break-glass approvers.',
      'The customer manages their own IdP, and the accuracy of SCIM deprovisioning depends on the customer deprovisioning in that IdP.',
      'Where the customer holds their own signing key or KMS key, key custody is the customer\'s responsibility, and loss of that key is unrecoverable by design.'
    ],
    measuredPerformance: {
      note: 'Measured in this environment, on the date above. Reproduce with `npm test` and bin/vault-scale.js.',
      ...stats
    }
  };
}

/** Markdown rendering, because an auditor reads a document, not a JSON blob. */
export function renderPackage(pkg) {
  const L = [];
  L.push(`# ${pkg.framework} Readiness Package`);
  L.push('');
  L.push(`**Standard:** ${pkg.standard}  `);
  L.push(`**Generated:** ${pkg.generatedAt}  `);
  L.push(`**Scope:** ${pkg.organisation.scope}`);
  L.push('');
  L.push('This package is generated from the live system. Every row marked *satisfied* cites');
  L.push('the sequence number of a real entry in the hash-chained ledger, which an auditor can');
  L.push('verify independently with `bin/vault-verify.js` and the customer-held public key.');
  L.push('');
  L.push('## Summary');
  L.push('');
  L.push('| | |');
  L.push('|---|---|');
  for (const [k, v] of Object.entries(pkg.summary)) {
    L.push(`| ${k.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase())} | ${v} |`);
  }
  L.push('');
  L.push('## Observation window');
  L.push('');
  L.push(pkg.observationWindow.statement);
  L.push('');
  L.push(`**Minimum period:** ${pkg.observationWindow.minimumPeriod}`);
  L.push('');
  L.push('## Control matrix');
  L.push('');
  L.push('| Control | Name | Applicability | Status | Ledger entries | Evidence |');
  L.push('|---|---|---|---|---|---|');
  for (const c of pkg.controls) {
    const ev = c.evidence.length
      ? c.evidence.map((e) => `${e.vaultControl}: ${e.count} × \`${e.eventTypes.join('`, `')}\` (latest seq ${e.samples[e.samples.length - 1]?.seq ?? '—'})`).join('<br>')
      : (c.status === 'organisational' ? '_organisational — no software artefact evidences this_' : c.status === 'excluded' ? '_excluded_' : '_none yet_');
    L.push(`| ${c.id} | ${c.name} | ${c.applicability} | ${c.status} | ${c.ledgerEntries} | ${ev} |`);
  }
  L.push('');
  L.push('## Statement of Applicability');
  L.push('');
  L.push('Every control carries a justification for inclusion or exclusion, as required.');
  L.push('');
  L.push('| Control | Decision | Justification |');
  L.push('|---|---|---|');
  for (const c of pkg.controls) L.push(`| ${c.id} | ${c.applicability} | ${c.justification} |`);
  L.push('');
  L.push('## Gap report');
  L.push('');
  L.push(`${pkg.gaps.length} controls have a stated gap. A package reporting no gaps has not been read carefully.`);
  L.push('');
  L.push('| Control | Status | Gap | What closes it |');
  L.push('|---|---|---|---|');
  for (const g of pkg.gaps) L.push(`| ${g.id} | ${g.status} | ${g.gap} | ${g.closes} |`);
  L.push('');
  return L.join('\n');
}
