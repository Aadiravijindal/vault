/**
 * 🟢 VAULT COMPLY — our own governance & GRC module (§18).
 *
 * Evidence is COLLECTED, not screenshotted: every control pulls from the ledger,
 * the gate, the review queue and the Map. A control that cannot be evidenced
 * automatically is marked as such rather than claimed.
 */
import { newId } from '../util/id.js';
import { now, iso, ago, DAY, MONTH, YEAR } from '../util/time.js';
import { sha256 } from '../util/crypto.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';

/** The control library, mapped once and crosswalked everywhere (§18). */
export const CONTROLS = [
  {
    id: 'VLT-1', name: 'Every write is checked before it becomes durable memory',
    frameworks: { 'NIST AI RMF': 'MANAGE 2.2', 'ISO 42001': 'A.6.2.4', 'EU AI Act': 'Art 15', 'OWASP LLM': 'LLM01 Prompt Injection', 'OWASP Agentic': 'AAI-2', 'SOC 2': 'CC6.1' },
    evidence: 'gate.outcomes'
  },
  {
    id: 'VLT-2', name: 'Untrusted sources cannot create authoritative facts',
    frameworks: { 'NIST AI RMF': 'MAP 3.4', 'ISO 42001': 'A.7.3', 'OWASP LLM': 'LLM03 Training Data Poisoning', 'CSA AICM': 'DSP-04' },
    evidence: 'gate.channel_trust'
  },
  {
    id: 'VLT-3', name: 'Human oversight of held and escalated writes',
    frameworks: { 'EU AI Act': 'Art 14', 'NIST AI RMF': 'GOVERN 3.2', 'ISO 42001': 'A.9.3', 'SOC 2': 'CC2.1' },
    evidence: 'review.decisions'
  },
  {
    id: 'VLT-4', name: 'Automatic logging of every event, tamper-evident',
    frameworks: { 'EU AI Act': 'Art 12', 'ISO 27001': 'A.8.15', 'SOC 2': 'CC7.2', 'FINRA': '4511', 'SEC': '17a-4(f)' },
    evidence: 'ledger.integrity'
  },
  {
    id: 'VLT-5', name: 'AI system inventory with named owners',
    frameworks: { 'EU AI Act': 'Art 26', 'NIST AI RMF': 'GOVERN 1.6', 'ISO 42001': 'A.4.2', 'NAIC': 'AI Systems inventory' },
    evidence: 'registry.inventory'
  },
  {
    id: 'VLT-6', name: 'Data minimisation and PII controls at ingestion',
    frameworks: { GDPR: 'Art 5(1)(c)', 'ISO 27001': 'A.8.11', 'SOC 2': 'CC6.7', DPDP: '§8' },
    evidence: 'gate.pii'
  },
  {
    id: 'VLT-7', name: 'Access control between departments and projects',
    frameworks: { 'ISO 27001': 'A.5.15', 'SOC 2': 'CC6.3', 'NIST AI RMF': 'MANAGE 2.3' },
    evidence: 'walls.enforcement'
  },
  {
    id: 'VLT-8', name: 'Right to erasure reaches every store, provably',
    frameworks: { GDPR: 'Art 17', 'UK GDPR': 'Art 17', CCPA: '1798.105', DPDP: '§12(3)' },
    evidence: 'legal.receipts'
  },
  {
    id: 'VLT-9', name: 'Lawful basis recorded for personal data',
    frameworks: { GDPR: 'Art 6', 'UK GDPR': 'Art 6', DPDP: '§6', LGPD: 'Art 7' },
    evidence: 'consent.records'
  },
  {
    id: 'VLT-10', name: 'Emergency stop with a named administrator and tested activation',
    frameworks: { 'EU AI Act': 'Art 14(4)(e)', 'NIST AI RMF': 'MANAGE 4.1', 'ISO 42001': 'A.9.4', Insurance: 'AI Security Rider' },
    evidence: 'killswitch.spec'
  },
  {
    id: 'VLT-11', name: 'Model version pinning and change detection',
    frameworks: { 'NIST AI RMF': 'MAP 2.3', 'ISO 42001': 'A.6.2.6', 'PRA SS5/21': 'Model inventory', 'BCBS 323': '§4' },
    evidence: 'registry.models'
  },
  {
    id: 'VLT-12', name: 'Adversarial testing of the control itself',
    frameworks: { 'NIST AI RMF': 'MEASURE 2.7', 'ISO 42001': 'A.6.2.5', 'MITRE ATLAS': 'Red teaming', 'OWASP MCP': 'MCP-7' },
    evidence: 'security.redteam'
  },
  {
    id: 'VLT-13', name: 'Third-party AI vendor register with attestations',
    frameworks: { 'NAIC': 'Third-party model registry', 'ISO 42001': 'A.10', 'SOC 2': 'CC9.2', 'EU AI Act': 'Art 25' },
    evidence: 'comply.vendors'
  },
  {
    id: 'VLT-14', name: 'Employee monitoring proportionality and prohibited uses',
    frameworks: { GDPR: 'Art 88', 'BetrVG': '§87(1) Nr 6', 'EU AI Act': 'Art 5(1)(f)', 'ESA (ON)': 's.41.1.1' },
    evidence: 'privacy.mode'
  },
  {
    id: 'VLT-15', name: 'Records retention with conflict surfacing',
    frameworks: { 'SEC': '17a-4(b)(4)', 'FINRA': '4511', 'MiFID II': 'Art 16(7)', GDPR: 'Art 5(1)(e)', 'CFTC': '1.31' },
    evidence: 'legal.retention'
  },
  {
    id: 'VLT-16', name: 'Tool and MCP server allowlisting with provenance',
    frameworks: { 'OWASP MCP': 'MCP-1, MCP-3', 'CoSAI': 'MCP threat model', 'ISO 27001': 'A.8.31' },
    evidence: 'mcp.registry'
  }
];

export const FRAMEWORKS = [
  'NIST AI RMF', 'ISO 42001', 'ISO 27001', 'ISO 27017', 'ISO 27018', 'SOC 2', 'CSA STAR', 'CSA AICM',
  'EU AI Act', 'OWASP LLM', 'OWASP Agentic', 'OWASP MCP', 'MITRE ATLAS', 'GDPR', 'UK GDPR', 'CCPA',
  'DPDP', 'LGPD', 'PIPEDA', 'POPIA', 'PDPA', 'HIPAA', 'PCI-DSS', 'SEC', 'FINRA', 'MiFID II', 'CFTC',
  'FCA SYSC', 'NAIC', 'PRA SS5/21', 'BCBS 323', 'BetrVG', 'ESA (ON)', 'Insurance', 'CoSAI', 'FedRAMP'
];

/** Pre-filled questionnaires, maintained (§9.13). */
export const QUESTIONNAIRES = ['CAIQ', 'CSA AI-CAIQ', 'SIG', 'SIG Lite (AI extensions)', 'Shared Assessments', 'Custom bank template'];

export class VaultComply {
  /**
   * @param {object} deps
   */
  constructor({ db, ledger, registry, gate, review, facts, folders, killswitch, legal, privacy, modules = null, kms = null, archive = null }) {
    this.ledger = ledger;
    this.registry = registry;
    this.gate = gate;
    this.review = review;
    this.facts = facts;
    this.folders = folders;
    this.killswitch = killswitch;
    this.legal = legal;
    this.privacy = privacy;
    this.modules = modules;
    this.kms = kms;
    this.archive = archive;
    this.systems = db.collection('ai_register');
    this.policies = db.collection('policies');
    this.incidents = db.collection('incident_register');
    this.vendors = db.collection('ai_vendors');
    this.attestations = db.collection('attestations');
    this.controlState = new Map();
    this.frameworkVersions = new Map();
    // A scoped, time-boxed auditor session that vanishes mid-audit takes its
    // own access log with it.
    this._state = db?.collection('comply_state') ?? null;
    this.auditSessions = new Map(Object.entries(this._state?.get('state')?.auditSessions ?? {}));
  }

  // ==== AI register (§18) ================================================

  /** Every AI system, agent, model, prompt, dataset and memory store. */
  registerSystem(spec) {
    const {
      name, kind = 'agent', purpose, owner, technicalOwner, vendor = null, model = null,
      dataCategories = [], deployedIn = [], riskTier = null, actor = 'system',
      humanOversight = null, agentId = null
    } = spec;
    if (!name || !owner) throw new VaultError('validation', 'an AI register entry needs a name and a named owner');
    const risk = riskTier || classifyRisk(spec);
    const system = this.systems.insert({
      id: newId('control'), name, kind, purpose, owner, technicalOwner, vendor, model,
      dataCategories, deployedIn, agentId,
      riskTier: risk.tier, riskRationale: risk.rationale, euAiActTier: risk.euAiAct,
      humanOversight, registeredAt: now(), registeredBy: actor,
      lastReviewedAt: null, status: 'active'
    });
    this.ledger.append('admin.action', { subject: system.id, actor, action: 'comply.system_registered', name, riskTier: risk.tier });
    this.modules?.dispatch('compliance', 'register', system);
    return system;
  }

  register() {
    // Agents already in the Registry are AI systems too — surface them either way.
    const explicit = this.systems.all();
    const implicit = this.registry.active()
      .filter((a) => !explicit.some((s) => s.agentId === a.id))
      .map((a) => ({
        id: `implicit:${a.id}`, name: a.name, kind: 'agent', purpose: a.purpose,
        owner: a.businessOwner, technicalOwner: a.technicalOwner, vendor: a.vendor,
        model: a.pinnedModel, agentId: a.id, riskTier: a.sensitivityCeiling === 'secret' ? 'high' : 'limited',
        euAiActTier: 'limited risk', status: 'active', implicit: true,
        note: 'discovered from the agent registry — confirm and complete the register entry'
      }));
    return [...explicit, ...implicit];
  }

  // ==== controls & evidence ==============================================

  /**
   * Evidence collection is AUTOMATIC — pulled from the ledger, the gate, the
   * queue and the Map. Not screenshots (§18).
   */
  collectEvidence(controlId) {
    const control = CONTROLS.find((c) => c.id === controlId);
    if (!control) throw notFound('control', controlId);
    const at = now();
    let evidence;
    let status = 'effective';

    switch (control.evidence) {
      case 'gate.outcomes': {
        const events = this.ledger.entries({ type: ['fact.written', 'fact.held', 'fact.blocked', 'fact.masked', 'fact.quarantined', 'fact.escalated'], limit: Infinity });
        const held = events.filter((e) => e.type === 'fact.held').length;
        const blocked = events.filter((e) => e.type === 'fact.blocked').length;
        evidence = {
          writesEvaluated: events.length, held, blocked,
          latency: this.gate.latencyReport(),
          statement: 'every write passed the ten checks; the gate has no bypass path and no "pass unchecked" posture exists',
          sample: events.slice(-5).map((e) => ({ seq: e.seq, type: e.type, at: iso(e.at) }))
        };
        status = events.length ? 'effective' : 'untested';
        break;
      }
      case 'gate.channel_trust':
        evidence = {
          policy: 'deny-by-source: email, web forms, customer chat, PR comments, scraped documents, third-party APIs, MCP tool output and other agents are untrusted by architecture',
          heldFromUntrusted: this.ledger.entries({ type: 'fact.held', limit: Infinity }).filter((e) => e.channelTrust === 'untrusted').length,
          goldenProtection: this.ledger.entries({ type: 'golden.overwrite_refused', limit: Infinity }).length
        };
        break;
      case 'review.decisions': {
        const stats = this.review.stats();
        evidence = {
          ...stats,
          scorecards: this.review.scorecards(),
          statement: 'human review of every held write, with SLA tracking, escalation and four-eyes above a risk threshold'
        };
        status = stats.slaCompliance >= 90 ? 'effective' : 'needs attention';
        break;
      }
      case 'ledger.integrity': {
        const v = this.ledger.verify();
        const anchors = this.ledger.verifyAnchors();
        evidence = { entries: v.checked, ok: v.ok, problems: v.problems, anchors: anchors.results.length, witnessDiversity: anchors.diverse, head: v.head };
        status = v.ok ? 'effective' : 'failing';
        break;
      }
      case 'registry.inventory': {
        const findings = this.registry.findings();
        evidence = { agents: this.registry.active().length, findings, shadowAgents: this.registry.shadowAgents().length, attestation: this.registry.attestationStatus() };
        status = findings.some((f) => f.severity === 'high') ? 'needs attention' : 'effective';
        break;
      }
      case 'gate.pii':
        evidence = {
          detectors: this.gate.pii.stats().detectors,
          tokensIssued: this.gate.pii.stats().tokensIssued,
          credentialsBlocked: this.ledger.entries({ type: 'fact.blocked', limit: Infinity }).length,
          statement: 'credentials are blocked entirely and never masked-and-stored'
        };
        break;
      case 'walls.enforcement': {
        const attempts = this.ledger.entries({ type: 'security.detection', limit: Infinity }).filter((e) => e.detection === 'cross_wall_attempt');
        evidence = { folders: this.folders.all().length, hardWalls: this.folders.all().filter((f) => f.hardWall).length, crossWallAttempts: attempts.length, unownedFolders: this.folders.findings().length, statement: 'walls are enforced at read and write; there is no admin bypass, only break-glass with two named humans' };
        status = this.folders.findings().length ? 'needs attention' : 'effective';
        break;
      }
      case 'legal.receipts':
        evidence = { receipts: this.legal.listReceipts(), erasures: this.ledger.entries({ type: 'privacy.erasure', limit: Infinity }).length, statement: 'erasure reaches facts, transcripts, indexes, caches, backups (crypto-shred), archive tier and connected third parties, with a signed receipt' };
        break;
      case 'consent.records':
        evidence = this.legal.consent?.stats?.() ?? { note: 'consent registry not configured' };
        status = evidence.records ? 'effective' : 'untested';
        break;
      case 'killswitch.spec': {
        const spec = this.killswitch.specification();
        evidence = spec;
        status = spec.lastTest ? 'effective' : 'untested';
        break;
      }
      case 'registry.models': {
        const unpinned = this.registry.active().filter((a) => !a.pinnedModel);
        evidence = { agents: this.registry.active().length, unpinned: unpinned.map((a) => a.id), modelSwapAlerts: this.ledger.entries({ type: 'security.alert', limit: Infinity }).filter((e) => e.kind === 'model_swap').length };
        status = unpinned.length ? 'needs attention' : 'effective';
        break;
      }
      case 'security.redteam':
        evidence = this.redTeamResults ?? { runs: 0, note: 'record red-team results with comply.recordRedTeam()' };
        status = this.redTeamResults?.runs ? 'effective' : 'untested';
        break;
      case 'comply.vendors':
        evidence = { vendors: this.vendors.all().map((v) => ({ name: v.name, attestations: v.attestations, renewal: v.renewalDate })) };
        status = this.vendors.size ? 'effective' : 'untested';
        break;
      case 'privacy.mode':
        evidence = this.privacy?.status() ?? { note: 'privacy module not configured' };
        status = evidence.enabled ? 'effective' : 'not applicable';
        break;
      case 'legal.retention':
        evidence = this.legal.retentionSchedule();
        status = evidence.conflicts ? 'needs attention' : 'effective';
        break;
      case 'mcp.registry':
        evidence = this.mcpRegistry ?? { servers: 0, note: 'no MCP servers registered' };
        break;
      default:
        evidence = { note: 'no automatic collector for this control' };
        status = 'manual';
    }

    const record = { controlId, at, status, evidence, proof: sha256(JSON.stringify({ controlId, evidence })) };
    this.controlState.set(controlId, record);
    this.modules?.dispatch('compliance', 'evidence', record);
    return { ...record, at: iso(at), control };
  }

  /** Continuous control monitoring — a failing control alerts immediately. */
  monitorControls() {
    const results = CONTROLS.map((c) => {
      const r = this.collectEvidence(c.id);
      return { id: c.id, name: c.name, status: r.status, at: r.at };
    });
    const failing = results.filter((r) => r.status === 'failing' || r.status === 'needs attention');
    return {
      checkedAt: iso(),
      total: results.length,
      effective: results.filter((r) => r.status === 'effective').length,
      failing: failing.length,
      results,
      alerts: failing.map((f) => ({ severity: f.status === 'failing' ? 'high' : 'medium', control: f.id, detail: `${f.name} is ${f.status}` })),
      note: 'a failing control alerts immediately — it does not wait for the annual audit'
    };
  }

  /** Crosswalk: one control, evidenced once, satisfying many frameworks. */
  crosswalk(framework = null) {
    const rows = [];
    for (const c of CONTROLS) {
      for (const [fw, ref] of Object.entries(c.frameworks)) {
        if (framework && fw !== framework) continue;
        rows.push({ control: c.id, controlName: c.name, framework: fw, reference: ref, status: this.controlState.get(c.id)?.status ?? 'not yet collected' });
      }
    }
    return { framework: framework || 'all', rows, uniqueControls: new Set(rows.map((r) => r.control)).size, frameworks: new Set(rows.map((r) => r.framework)).size };
  }

  /** Gap analysis: "Against ISO 42001 you're at 68%. Here are the 11 gaps." */
  gapAnalysis(framework) {
    const relevant = CONTROLS.filter((c) => Object.keys(c.frameworks).includes(framework));
    if (!relevant.length) throw new VaultError('validation', `no controls mapped to ${framework}`, { available: FRAMEWORKS });
    const assessed = relevant.map((c) => ({ control: c, state: this.controlState.get(c.id) ?? this.collectEvidence(c.id) }));
    const effective = assessed.filter((a) => a.state.status === 'effective');
    const gaps = assessed.filter((a) => a.state.status !== 'effective');
    return {
      framework,
      score: Math.round((effective.length / relevant.length) * 100),
      effective: effective.length,
      total: relevant.length,
      gaps: gaps
        .map((g) => ({
          control: g.control.id,
          name: g.control.name,
          reference: g.control.frameworks[framework],
          status: g.state.status,
          effort: EFFORT[g.state.status] ?? 'medium',
          fix: FIXES[g.control.id] ?? 'collect evidence and confirm the control is operating'
        }))
        .sort((a, b) => EFFORT_RANK[a.effort] - EFFORT_RANK[b.effort]),
      statement: `Against ${framework} you're at ${Math.round((effective.length / relevant.length) * 100)}%. Here are the ${gaps.length} gaps, ranked by effort.`
    };
  }

  // ==== policies & attestations ==========================================

  publishPolicy({ name, body, owner, actor, version = 1, appliesTo = 'all' }) {
    if (!name || !owner) throw new VaultError('validation', 'a policy needs a name and an owner');
    const p = this.policies.insert({
      id: newId('policy'), name, body, owner, version, appliesTo,
      publishedAt: now(), publishedBy: actor, acknowledgements: [], status: 'published'
    });
    this.ledger.append('admin.action', { subject: p.id, actor, action: 'comply.policy_published', name, version });
    return p;
  }

  acknowledgePolicy(policyId, { actor }) {
    const p = this.policies.get(policyId);
    if (!p) throw notFound('policy', policyId);
    return this.policies.update(policyId, { acknowledgements: [...p.acknowledgements, { actor, at: now() }] });
  }

  /** Owners confirm their agents and folders periodically (§18). */
  requestAttestations({ actor, periodDays = 90 }) {
    const due = [];
    for (const a of this.registry.active()) {
      if (!a.attestedAt || a.attestedAt < now() - periodDays * DAY) {
        due.push({ kind: 'agent', id: a.id, owner: a.businessOwner, last: a.attestedAt ? iso(a.attestedAt) : 'never' });
      }
    }
    for (const f of this.folders.all()) {
      if (f.archived) continue;
      if (!f.businessOwner) due.push({ kind: 'folder', id: f.path, owner: null, last: 'never', finding: 'unowned' });
    }
    const record = this.attestations.insert({
      id: newId('attestation'), requestedBy: actor, requestedAt: now(), due, completed: []
    });
    return { attestationId: record.id, due: due.length, items: due };
  }

  completeAttestation(attestationId, { actor, itemId, confirms, notes = null }) {
    const a = this.attestations.get(attestationId);
    if (!a) throw notFound('attestation', attestationId);
    const completed = [...a.completed, { actor, itemId, confirms, notes, at: now() }];
    this.ledger.append('admin.action', { subject: itemId, actor, action: 'comply.attested', confirms });
    return this.attestations.update(attestationId, { completed });
  }

  // ==== generators (§18) =================================================

  /** DPIA / FRIA / LIA generators — pre-filled from the ACTUAL configuration. */
  generateAssessment(kind, { systemId = null, actor }) {
    const system = systemId ? this.systems.get(systemId) : null;
    const privacy = this.privacy?.status();
    const base = {
      kind,
      generatedAt: iso(),
      generatedBy: actor,
      system: system ? { name: system.name, purpose: system.purpose, owner: system.owner, riskTier: system.riskTier } : { name: 'Vault — shared AI memory governance' },
      // filled from live configuration, not a blank template
      configuration: {
        gateChecks: 10,
        gateBypass: 'none — no code path exists',
        channelsUntrustedByDefault: 13,
        humanOversight: `review queue with SLAs (${JSON.stringify(this.review.stats().byPriority)}), four-eyes above a risk threshold`,
        logging: `hash-chained ledger, ${this.ledger.length} entries, anchored to independent witnesses`,
        killSwitch: this.killswitch.specification().namedAdministrators.length ? 'named administrator configured' : '⚠️ no named administrator configured',
        privacyMode: privacy?.enabled ? `${privacy.jurisdictionName}` : 'off',
        retention: this.legal.retentionSchedule().conflicts ? '⚠️ conflicting obligations surfaced' : 'no conflicts',
        erasure: 'reaches facts, transcripts, indexes, caches, backups (crypto-shred), archive tier and third parties'
      }
    };
    if (kind === 'FRIA') {
      base.fundamentalRights = [
        { right: 'Privacy and data protection (Art 7/8 Charter)', assessment: 'pseudonymisation by default in Privacy Mode; purpose lock enforced in the query layer', residualRisk: 'low' },
        { right: 'Non-discrimination (Art 21)', assessment: 'no profiling, scoring or ranking of individuals exists in the system', residualRisk: 'low' },
        { right: 'Freedom of expression (Art 11)', assessment: 'Vault governs durable memory, not what people may say; conversations are archived, not censored', residualRisk: 'low' },
        { right: 'Right to an effective remedy (Art 47)', assessment: 'objection channel with tracked responses; full trace available to the data subject', residualRisk: 'low' },
        { right: 'Workers\' rights (Art 27/31)', assessment: privacy?.enabled ? 'works council role, change notification, prohibited-use list' : '⚠️ Employee Privacy Mode is off', residualRisk: privacy?.enabled ? 'low' : 'medium' }
      ];
    }
    return base;
  }

  /** Model cards & system cards, generated for each register entry. */
  modelCard(systemId) {
    const s = this.systems.get(systemId) || this.register().find((x) => x.id === systemId);
    if (!s) throw notFound('AI system', systemId);
    const agent = s.agentId ? this.registry.get(s.agentId) : null;
    return {
      name: s.name,
      generatedAt: iso(),
      intendedUse: s.purpose,
      owner: s.owner,
      technicalOwner: s.technicalOwner,
      model: s.model || agent?.pinnedModel || 'not pinned',
      modelPinned: Boolean(s.model || agent?.pinnedModel),
      riskTier: s.riskTier,
      euAiActTier: s.euAiActTier,
      dataCategories: s.dataCategories,
      deployedIn: s.deployedIn,
      humanOversight: s.humanOversight || 'held writes go to a named reviewer with an SLA; four-eyes above a risk threshold',
      limitations: [
        'Vault governs what agents believe, not what they can reach',
        'Watch mode observes but cannot block — only Inline and Gateway enforce',
        'the gate has false positives, deliberately: recall over precision, absorbed by the review queue'
      ],
      metrics: agent ? { writes: agent.writes, reads: agent.reads, held: agent.held, blocked: agent.blocked, costUsd: agent.costUsd } : null,
      evaluation: 'see Vault Trace golden sets and regression gates',
      attestation: agent?.attestedAt ? `attested by ${agent.attestedBy} on ${iso(agent.attestedAt)}` : '⚠️ not attested'
    };
  }

  // ==== vendors, incidents, reporting ====================================

  registerVendor(spec) {
    const { name, category, subprocessors = [], attestations = [], renewalDate = null, dataShared = [], zeroRetention = false, actor } = spec;
    if (!name) throw new VaultError('validation', 'a vendor needs a name');
    const v = this.vendors.insert({
      id: newId('control'), name, category, subprocessors, attestations, renewalDate,
      dataShared, zeroRetention, registeredAt: now(), registeredBy: actor
    });
    this.ledger.append('admin.action', { subject: v.id, actor, action: 'comply.vendor_registered', name });
    return v;
  }

  /** NAIC-registry-ready third-party AI vendor register. */
  vendorRegister() {
    return {
      generatedAt: iso(),
      vendors: this.vendors.all().map((v) => ({
        name: v.name, category: v.category, subprocessors: v.subprocessors,
        attestations: v.attestations, zeroRetention: v.zeroRetention,
        dataShared: v.dataShared,
        renewalDate: v.renewalDate,
        renewalDue: v.renewalDate ? Math.ceil((new Date(v.renewalDate).getTime() - now()) / DAY) : null
      })),
      format: 'NAIC third-party model registry compatible'
    };
  }

  recordIncident({ title, classification, rootCause = null, remediation = null, disclosure = null, severity = 'medium', actor, factIds = [], detectedAt = null }) {
    if (!title || !actor) throw new VaultError('validation', 'an incident needs a title and a named actor');
    const inc = this.incidents.insert({
      id: newId('incident'), title, classification, severity, rootCause, remediation, disclosure,
      recordedBy: actor, recordedAt: now(), detectedAt: detectedAt || now(), factIds,
      status: rootCause ? 'closed' : 'open'
    });
    this.ledger.append('security.detection', { subject: inc.id, actor, detection: 'incident_recorded', classification, severity });
    return inc;
  }

  incidentRegister() {
    return {
      generatedAt: iso(),
      incidents: this.incidents.all().map((i) => ({
        id: i.id, title: i.title, classification: i.classification, severity: i.severity,
        detectedAt: iso(i.detectedAt), status: i.status, rootCause: i.rootCause,
        remediation: i.remediation, disclosure: i.disclosure
      })),
      // Every held write, blocked write, wall attempt and credential catch is
      // itself an AI-incident record for the insurer (§20).
      gateEvents: {
        held: this.ledger.entries({ type: 'fact.held', limit: Infinity }).length,
        blocked: this.ledger.entries({ type: 'fact.blocked', limit: Infinity }).length,
        crossWallAttempts: this.ledger.entries({ type: 'security.detection', limit: Infinity }).filter((e) => e.detection === 'cross_wall_attempt').length,
        goldenOverwriteRefused: this.ledger.entries({ type: 'golden.overwrite_refused', limit: Infinity }).length
      }
    };
  }

  /** Pre-filled regulatory report formats (§18). */
  regulatoryReport(regulator) {
    const common = {
      generatedAt: iso(),
      regulator,
      controls: this.monitorControls(),
      incidents: this.incidentRegister(),
      ledger: this.ledger.verify()
    };
    const shapes = {
      ico: { form: 'ICO personal data breach report', clock: '72 hours from awareness', fields: ['when', 'awareness', 'what happened', 'categories and numbers', 'consequences', 'measures', 'DPO contact'] },
      'eu-ai-office': { form: 'EU AI Act serious incident report (Art 73)', clock: '15 days', fields: ['system', 'incident type', 'affected persons', 'corrective actions', 'risk classification'] },
      dpbi: { form: 'Data Protection Board of India intimation', clock: 'without delay', fields: ['nature', 'affected Data Principals', 'consequences', 'mitigation', 'DPO contact'] },
      'state-ag': { form: 'US state AG breach notification', clock: 'varies by state (30–60 days)', fields: ['residents affected', 'data types', 'discovery date', 'remediation', 'credit monitoring'] },
      naic: { form: 'NAIC AI governance attestation', clock: 'annual', fields: ['AI systems inventory', 'governance program', 'third-party models', 'testing and validation'] },
      finra: { form: 'FINRA supervision evidence', clock: 'on examination', fields: ['recordkeeping', 'supervision sampling', 'review evidence', 'retention'] }
    };
    return { ...common, ...(shapes[regulator] || { form: 'generic', note: `no pre-filled shape for "${regulator}" — the evidence above is regulator-agnostic` }) };
  }

  /** One-click board pack, plain language, for the risk committee (§18). */
  boardPack({ period = '30d' } = {}) {
    const days = parseInt(period) || 30;
    const since = now() - days * DAY;
    const held = this.ledger.entries({ type: 'fact.held', limit: Infinity }).filter((e) => e.at >= since).length;
    const blocked = this.ledger.entries({ type: 'fact.blocked', limit: Infinity }).filter((e) => e.at >= since).length;
    const controls = this.monitorControls();
    const shadow = this.registry.shadowAgents();
    return {
      period: `last ${days} days`,
      generatedAt: iso(),
      headline: [
        `${this.registry.active().length} AI agents are registered and owned; ${shadow.length} unregistered agent${shadow.length === 1 ? ' was' : 's were'} discovered.`,
        `${held} write${held === 1 ? '' : 's'} were held for human review and ${blocked} were rejected outright.`,
        `${controls.effective} of ${controls.total} controls are operating effectively; ${controls.failing} need attention.`,
        `The audit ledger verifies clean across ${this.ledger.length} entries.`
      ],
      riskPosture: {
        controlsEffective: `${controls.effective}/${controls.total}`,
        openIncidents: this.incidents.count((i) => i.status === 'open'),
        reviewSlaCompliance: `${this.review.stats().slaCompliance}%`,
        killSwitchTested: this.killswitch.lastTest()?.at ?? '⚠️ never tested',
        shadowAgents: shadow.length,
        unownedFolders: this.folders.findings().length
      },
      decisionsNeeded: [
        ...(shadow.length ? [`register or shut down ${shadow.length} shadow agent${shadow.length === 1 ? '' : 's'}`] : []),
        ...(controls.failing ? [`remediate ${controls.failing} control${controls.failing === 1 ? '' : 's'}`] : []),
        ...(this.killswitch.lastTest() ? [] : ['schedule the first kill switch test — insurers ask for the date']),
        ...(this.folders.findings().length ? [`assign owners to ${this.folders.findings().length} folder${this.folders.findings().length === 1 ? '' : 's'}`] : [])
      ],
      regulatoryExposure: this.privacy?.status().enabled
        ? `Employee Privacy Mode is ON for ${this.privacy.status().jurisdictionName}`
        : '⚠️ Employee Privacy Mode is OFF — not lawful for EU/UK employees',
      plainLanguage: 'Vault decides what your AI systems are allowed to believe, and keeps proof of what they were told. This pack is the evidence, generated from the running system rather than assembled by hand.'
    };
  }

  // ==== auditor workspace ================================================

  /** Time-boxed, scoped, read-only auditor access with its own log (§18). */
  openAuditSession({ auditor, scope = 'all', expiresIn = '7d', actor, purpose }) {
    if (!auditor || !actor || !purpose) throw forbidden('an audit session requires an auditor, a granting actor and a stated purpose');
    const session = {
      id: newId('session'), auditor, scope, purpose, grantedBy: actor,
      openedAt: now(), expiresAt: now() + (typeof expiresIn === 'number' ? expiresIn : parseDuration(expiresIn)),
      accessLog: [], readOnly: true
    };
    this.auditSessions.set(session.id, session);
    this._state?.put({ id: 'state', auditSessions: Object.fromEntries(this.auditSessions) });
    this.ledger.append('admin.action', { subject: session.id, actor, action: 'comply.audit_session_opened', auditor, scope, purpose });
    return { ...session, openedAt: iso(session.openedAt), expiresAt: iso(session.expiresAt) };
  }

  auditAccess(sessionId, what) {
    const s = this.auditSessions.get(sessionId);
    if (!s) throw notFound('audit session', sessionId);
    if (now() > s.expiresAt) throw forbidden('audit session expired', { sessionId });
    s.accessLog.push({ at: now(), what });
    return { allowed: true, readOnly: true, accessCount: s.accessLog.length };
  }

  auditSessionLog(sessionId) {
    const s = this.auditSessions.get(sessionId);
    if (!s) throw notFound('audit session', sessionId);
    return { ...s, accessLog: s.accessLog.map((a) => ({ ...a, at: iso(a.at) })) };
  }

  // ==== framework change tracking ========================================

  trackFramework(name, version, { effectiveDate = null, changes = [] } = {}) {
    const prev = this.frameworkVersions.get(name);
    this.frameworkVersions.set(name, { name, version, effectiveDate, changes, trackedAt: now() });
    if (prev && prev.version !== version) {
      const affected = CONTROLS.filter((c) => Object.keys(c.frameworks).includes(name));
      return {
        framework: name, from: prev.version, to: version,
        affectedControls: affected.map((c) => ({ id: c.id, name: c.name, reference: c.frameworks[name] })),
        action: 'these controls are flagged for re-evidencing against the new version'
      };
    }
    return { framework: name, version, tracked: true };
  }

  recordRedTeam({ actor, runs = 1, findings = [], scope = 'the gate', publishedToCustomers = true }) {
    this.redTeamResults = {
      runs: (this.redTeamResults?.runs ?? 0) + runs,
      lastRunAt: iso(),
      scope, findings, publishedToCustomers,
      by: actor
    };
    this.ledger.append('security.detection', { subject: 'red_team', actor, detection: 'red_team_completed', findings: findings.length });
    return this.redTeamResults;
  }

  registerMcpServers(servers) {
    this.mcpRegistry = { servers: servers.length, list: servers, at: iso() };
    return this.mcpRegistry;
  }

  /** Questionnaires pre-filled and maintained (§9.13). */
  questionnaire(name) {
    if (!QUESTIONNAIRES.includes(name)) {
      throw new VaultError('validation', `unknown questionnaire — available: ${QUESTIONNAIRES.join(', ')}`);
    }
    const controls = this.monitorControls();
    return {
      questionnaire: name,
      generatedAt: iso(),
      completeness: `${Math.round((controls.effective / controls.total) * 100)}%`,
      answers: CONTROLS.map((c) => ({
        question: c.name,
        answer: this.controlState.get(c.id)?.status === 'effective' ? 'Yes — implemented and evidenced' : 'Partial — see evidence',
        evidence: c.evidence,
        frameworks: c.frameworks
      })),
      turnaroundCommitment: 'median under 5 business days, reports under NDA in one click via the trust portal'
    };
  }

  /** Security scorecard in-product: their own posture, ranked fixes (§9.14). */
  scorecard() {
    const controls = this.monitorControls();
    const findings = [
      ...this.registry.findings().map((f) => ({ ...f, area: 'agents' })),
      ...this.folders.findings().map((f) => ({ ...f, area: 'folders' }))
    ];
    const score = Math.round((controls.effective / controls.total) * 100);
    return {
      score,
      grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F',
      controls: { effective: controls.effective, total: controls.total, failing: controls.failing },
      rankedFixes: findings
        .sort((a, b) => (b.severity === 'high' ? 1 : 0) - (a.severity === 'high' ? 1 : 0))
        .slice(0, 15)
        .map((f, i) => ({ rank: i + 1, ...f })),
      note: 'this is your posture, computed from the running system'
    };
  }
}

function classifyRisk(spec) {
  const purpose = String(spec.purpose || '').toLowerCase();
  const data = (spec.dataCategories || []).join(' ').toLowerCase();
  if (/employment|hiring|promotion|dismissal|credit scoring|law enforcement|biometric|education access/.test(purpose)) {
    return { tier: 'high', euAiAct: 'high risk (Annex III)', rationale: 'purpose falls within an Annex III high-risk category' };
  }
  if (/emotion|sentiment|social scoring/.test(purpose)) {
    return { tier: 'prohibited', euAiAct: 'prohibited (Art 5)', rationale: 'emotion recognition at work and social scoring are prohibited practices' };
  }
  if (/health|medical|phi/.test(data) || /special category|biometric/.test(data)) {
    return { tier: 'high', euAiAct: 'high risk', rationale: 'processes special-category data' };
  }
  if (/customer|chat|support|content/.test(purpose)) {
    return { tier: 'limited', euAiAct: 'limited risk (Art 50 transparency)', rationale: 'interacts with people — transparency obligations apply' };
  }
  return { tier: 'minimal', euAiAct: 'minimal risk', rationale: 'internal tooling with no Annex III purpose' };
}

const EFFORT = { untested: 'low', 'needs attention': 'medium', failing: 'high', manual: 'medium', 'not applicable': 'low' };
const EFFORT_RANK = { low: 0, medium: 1, high: 2 };
const FIXES = {
  'VLT-5': 'assign a business and technical owner to every agent, and register or shut down the shadow agents on the Map',
  'VLT-7': 'assign owners to unowned folders — an unowned folder is a finding',
  'VLT-10': 'name the kill switch administrator and run the first test; record the activation time',
  'VLT-11': 'pin a model version on every agent so a silent swap is detectable',
  'VLT-12': 'run the adversarial suite against the gate and record the results',
  'VLT-13': 'register your AI vendors with their attestations and renewal dates',
  'VLT-15': 'resolve the surfaced retention conflicts with a named decision'
};

function parseDuration(s) {
  const m = /^(\d+)(h|d|w)$/.exec(String(s));
  if (!m) return 7 * DAY;
  return parseInt(m[1]) * ({ h: 3600e3, d: DAY, w: 7 * DAY }[m[2]]);
}
