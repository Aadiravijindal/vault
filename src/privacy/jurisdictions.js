/**
 * Jurisdiction packs (§15.3–15.5).
 *
 * Each pack ships: a settings preset · policy templates · document templates ·
 * a framework crosswalk · an evidence export · and a plain-language "what this
 * pack does and doesn't cover".
 *
 * Bringing a first draft of the works agreement to the table is what turns an
 * 18-month German blocker into a six-week approval. That draft is in here.
 */

const EU_EXCLUSIONS = [
  'personal_account', 'personal_email', 'union_communications', 'works_council_communications',
  'health_portal', 'banking_portal', 'legal_advice', 'break_periods',
  'outside_working_hours', 'personal_devices'
];

const BASE_ON = {
  noIndividualDashboards: true,
  aggregateOnly: true,
  kAnonymityFloor: 5,
  pseudonymiseByDefault: true,
  purposeLock: true,
  affectAnalysis: 'never — the code does not exist',
  productivityScoring: false,
  excludedContexts: EU_EXCLUSIONS,
  sampleDontStream: true,
  sampleRate: 0.05,
  workingHoursOnly: false,
  covertMonitoring: 'does not exist',
  employeeRetention: '6mo',
  transparencyPortal: true,
  objectionChannel: true,
  worksCouncilRole: false,
  changeNotification: true
};

export const JURISDICTIONS = {
  off: {
    id: 'off',
    name: 'OFF — full visibility (US at-will default)',
    flag: '',
    settings: {
      ...BASE_ON,
      noIndividualDashboards: false, aggregateOnly: false, kAnonymityFloor: null,
      pseudonymiseByDefault: false, purposeLock: false, excludedContexts: [],
      sampleDontStream: false, employeeRetention: null, changeNotification: false
    },
    controls: [],
    documents: [],
    crosswalk: {},
    coverage: 'No employee-privacy restrictions applied. Individual views are available. Affect analysis and productivity scoring still do not exist — those are design commitments, not settings.',
    requiresConsultation: false,
    plainLanguage: 'This mode is lawful in US at-will jurisdictions with no state-specific monitoring statute. It is NOT lawful in the EU, UK, or most of Canada.'
  },

  uk: {
    id: 'uk',
    name: 'United Kingdom',
    flag: '🇬🇧',
    settings: { ...BASE_ON, workingHoursOnly: true, employeeRetention: '6mo' },
    controls: [
      { id: 'uk-basis', control: 'UK GDPR + DPA 2018 basis', applies: 'Legitimate interest documented with a full LIA, pre-generated' },
      { id: 'uk-ico', control: 'ICO Employment Practices guidance alignment', applies: 'Proportionality, necessity, transparency and least-intrusive-means documented' },
      { id: 'uk-dpia', control: 'DPIA auto-generated', applies: 'ICO-format DPIA, pre-filled, ready for the DPO to sign' },
      { id: 'uk-notice', control: 'Transparency notice', applies: 'Employee-facing privacy notice, UK-specific wording, ready to publish' },
      { id: 'uk-works', control: 'No works council requirement', applies: 'The UK has no statutory co-determination — but the consultation pack still ships, because unions and staff forums exist and the ICO expects consultation evidence' },
      { id: 'uk-union', control: 'Union consultation pack', applies: 'Optional but recommended; template included' },
      { id: 'uk-dsar', control: 'DSAR workflow', applies: 'UK one-month deadline, extension tracking, ICO-format response' },
      { id: 'uk-residency', control: 'Data residency', applies: 'UK-only storage option, UK keys, no EU or US transfer' },
      { id: 'uk-idta', control: 'International transfer', applies: 'UK IDTA / Addendum to EU SCCs, generated per flow' },
      { id: 'uk-breach', control: 'ICO breach reporting', applies: '72-hour clock tracking, ICO report format pre-filled' },
      { id: 'uk-covert', control: 'Covert monitoring', applies: 'Disabled entirely. UK guidance permits it only in narrow criminal-suspicion cases, which Vault does not support.' },
      { id: 'uk-adm', control: 'Automated decision-making', applies: 'Art 22 safeguards; Vault never makes an employment decision, and says so in writing' }
    ],
    documents: [
      { name: 'UK Legitimate Interests Assessment (LIA)', format: 'markdown', body: ukLia },
      { name: 'UK DPIA (ICO format)', format: 'markdown', body: ukDpia },
      { name: 'Employee transparency notice (UK)', format: 'markdown', body: ukNotice },
      { name: 'Union / staff forum consultation pack', format: 'markdown', body: consultationPack },
      { name: 'ICO breach report template', format: 'markdown', body: icoBreach }
    ],
    crosswalk: {
      'UK GDPR Art 5': 'purpose limitation, minimisation, storage limitation — §14.5, §14.6',
      'UK GDPR Art 6(1)(f)': 'legitimate interest with LIA — this pack',
      'UK GDPR Art 13/14': 'transparency notice — this pack',
      'UK GDPR Art 15': 'DSAR workflow — §14.4',
      'UK GDPR Art 22': 'no automated employment decisions — §15.3',
      'UK GDPR Art 35': 'DPIA — this pack',
      'DPA 2018 Sch 1': 'employment processing conditions',
      'ICO Employment Practices': 'proportionality and least-intrusive-means evidence'
    },
    coverage: 'Covers UK employee monitoring lawfulness, transparency, DSARs, breach reporting and international transfers.',
    doesNotCover: 'Does not cover employment-law questions outside data protection (contracts, dismissal, TUPE), nor sector regulators (FCA SYSC 10A is in the US-FinServ/UK-FinServ pack).',
    requiresConsultation: false,
    plainLanguage: 'One click and UK-lawful employee monitoring settings are on, with an LIA, a DPIA and a transparency notice generated for your DPO to sign.'
  },

  de: {
    id: 'de',
    name: 'Germany',
    flag: '🇩🇪',
    settings: {
      ...BASE_ON,
      workingHoursOnly: true,
      employeeRetention: '3mo',
      worksCouncilRole: true,
      kAnonymityFloor: 10,
      noIndividualPerformanceVisibility: 'not even to HR, not even with break-glass'
    },
    controls: [
      { id: 'de-betrvg', control: '§87(1) no. 6 BetrVG readiness', applies: 'Pre-drafted Betriebsvereinbarung (works agreement) template — purpose, scope, retention, access matrix, prohibited uses, deletion, dispute process, term' },
      { id: 'de-bdsg', control: '§26 BDSG basis documentation', applies: 'Written necessity and proportionality assessment' },
      { id: 'de-portal', control: 'Works council portal', applies: 'The Betriebsrat gets its own read-only role and a formal veto-tracked change process' },
      { id: 'de-einigungsstelle', control: 'Einigungsstelle-ready documentation', applies: 'If it goes to arbitration, the documentation pack is already assembled' },
      { id: 'de-bdg', control: 'Beschäftigtendatengesetz forward-compatibility', applies: 'Designed against the anticipated Employee Data Act' },
      { id: 'de-verboten', control: 'Prohibited-by-design list, in German', applies: 'For the works council to read' },
      { id: 'de-noperf', control: 'No individual performance visibility, at all', applies: 'Not even to HR. Not even with break-glass.' }
    ],
    documents: [
      { name: 'Betriebsvereinbarung (works agreement) — Entwurf', format: 'markdown', body: betriebsvereinbarung },
      { name: '§26 BDSG Erforderlichkeits- und Verhältnismäßigkeitsprüfung', format: 'markdown', body: bdsgAssessment },
      { name: 'Verbotene Verwendungen (prohibited uses, in German)', format: 'markdown', body: verboteneVerwendungen },
      { name: 'Einigungsstelle documentation pack', format: 'markdown', body: einigungsstelle },
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia }
    ],
    crosswalk: {
      '§87(1) Nr. 6 BetrVG': 'co-determination on technical monitoring systems — works agreement template',
      '§26 BDSG': 'employee data processing necessity — assessment document',
      'GDPR Art 88': 'employment-context national rules',
      'GDPR Art 35': 'DPIA — included',
      'EU AI Act Art 5(1)(f)': 'emotion recognition at work prohibited — structurally absent in Vault'
    },
    coverage: 'Covers co-determination readiness, §26 BDSG necessity, works council oversight and arbitration documentation.',
    doesNotCover: 'Does not replace negotiation with your Betriebsrat, and does not cover collective bargaining agreements specific to your sector.',
    requiresConsultation: true,
    plainLanguage: 'The strictest preset. It ships a first draft of the works agreement, which is what turns an 18-month blocker into a six-week approval.'
  },

  at: {
    id: 'at', name: 'Austria', flag: '🇦🇹',
    settings: { ...BASE_ON, workingHoursOnly: true, worksCouncilRole: true, employeeRetention: '3mo' },
    controls: [
      { id: 'at-arbvg', control: '§96(1) Z3 ArbVG', applies: 'Betriebsvereinbarung required for systems affecting human dignity — template included' },
      { id: 'at-dsg', control: 'Austrian DSG', applies: 'National employment-context rules documented' }
    ],
    documents: [
      { name: 'Betriebsvereinbarung (AT) — Entwurf', format: 'markdown', body: betriebsvereinbarung },
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia }
    ],
    crosswalk: { '§96(1) Z3 ArbVG': 'works agreement requirement', 'GDPR Art 88': 'employment-context rules' },
    coverage: 'Austrian co-determination and GDPR employment context.',
    requiresConsultation: true,
    plainLanguage: 'Austria requires a works agreement for monitoring systems that touch human dignity. The draft is included.'
  },

  nl: {
    id: 'nl', name: 'Netherlands', flag: '🇳🇱',
    settings: { ...BASE_ON, worksCouncilRole: true, employeeRetention: '6mo' },
    controls: [
      { id: 'nl-wor', control: 'Article 27 WOR', applies: 'Ondernemingsraad consent required for personnel monitoring systems' },
      { id: 'nl-ap', control: 'Autoriteit Persoonsgegevens guidance', applies: 'Proportionality and subsidiarity documented' }
    ],
    documents: [
      { name: 'Ondernemingsraad instemmingsverzoek (consent request)', format: 'markdown', body: consultationPack },
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia }
    ],
    crosswalk: { 'WOR Art 27': 'works council consent', 'GDPR Art 88': 'employment-context rules' },
    coverage: 'Dutch works council consent and GDPR employment context.',
    requiresConsultation: true,
    plainLanguage: 'The OR must consent before a monitoring system goes live. The consent request is drafted for you.'
  },

  se: {
    id: 'se', name: 'Sweden', flag: '🇸🇪',
    settings: { ...BASE_ON, worksCouncilRole: true, employeeRetention: '6mo' },
    controls: [
      { id: 'se-mbl', control: 'MBL §11 primary negotiation', applies: 'Union negotiation before implementation — pack included' },
      { id: 'se-imy', control: 'IMY guidance', applies: 'Swedish DPA employment monitoring expectations' }
    ],
    documents: [
      { name: 'MBL §11 förhandlingsunderlag (negotiation pack)', format: 'markdown', body: consultationPack },
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia }
    ],
    crosswalk: { 'MBL §11': 'primary negotiation duty', 'GDPR Art 88': 'employment-context rules' },
    coverage: 'Swedish co-determination negotiation and GDPR employment context.',
    requiresConsultation: true,
    plainLanguage: 'Sweden requires primary negotiation with the union before implementation. The negotiation pack is drafted.'
  },

  fr: {
    id: 'fr', name: 'France', flag: '🇫🇷',
    settings: { ...BASE_ON, worksCouncilRole: true, workingHoursOnly: true, employeeRetention: '3mo' },
    controls: [
      { id: 'fr-cse', control: 'CSE consultation (Art L2312-38)', applies: 'Comité social et économique must be consulted before any monitoring tool' },
      { id: 'fr-cnil', control: 'CNIL guidance', applies: 'Proportionality, information of employees, and no permanent surveillance' },
      { id: 'fr-deconnexion', control: 'Droit à la déconnexion', applies: 'No capture outside working hours' }
    ],
    documents: [
      { name: 'Consultation du CSE — dossier', format: 'markdown', body: consultationPack },
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia }
    ],
    crosswalk: { 'C. trav. L2312-38': 'CSE consultation', 'GDPR Art 88': 'employment-context rules' },
    coverage: 'French CSE consultation, CNIL proportionality, right to disconnect.',
    requiresConsultation: true,
    plainLanguage: 'The CSE must be consulted before the tool goes live, and nothing is captured outside working hours.'
  },

  eu: {
    id: 'eu', name: 'EU baseline', flag: '🇪🇺',
    settings: { ...BASE_ON },
    controls: [
      { id: 'eu-art6', control: 'GDPR Art 6 lawful basis', applies: 'Recorded per data subject and purpose' },
      { id: 'eu-art9', control: 'GDPR Art 9 special category', applies: 'Condition required and recorded' },
      { id: 'eu-art15', control: 'GDPR Art 15/16/17', applies: 'Access, rectification and erasure workflows' },
      { id: 'eu-art22', control: 'GDPR Art 22', applies: 'No automated employment decisions' },
      { id: 'eu-art35', control: 'GDPR Art 35', applies: 'DPIA generated from the actual configuration' },
      { id: 'eu-monitoring', control: 'Employee-monitoring proportionality', applies: 'Necessity and least-intrusive-means documented' },
      { id: 'eu-residency', control: 'Residency', applies: 'EU data stays in EU, per-region keys, cross-border read blocking' },
      { id: 'eu-aiact', control: 'EU AI Act Art 5(1)(f)', applies: 'Emotion recognition at work is prohibited — structurally absent' }
    ],
    documents: [
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia },
      { name: 'Employee transparency notice (EU)', format: 'markdown', body: ukNotice },
      { name: 'Delete-vs-retain decision record', format: 'markdown', body: deleteVsRetain }
    ],
    crosswalk: {
      'GDPR Art 5/6/9/15/16/17/22/35': 'core obligations — §14',
      'EU AI Act Art 12': 'automatic logging — the ledger',
      'EU AI Act Art 14': 'human oversight — the review queue',
      'EU AI Act Art 26': 'deployer obligations — Vault Comply',
      'EU AI Act Art 50': 'transparency'
    },
    coverage: 'GDPR employee-monitoring baseline plus AI Act logging, oversight and transparency hooks.',
    requiresConsultation: false,
    plainLanguage: 'The EU floor. Individual member states (DE, AT, NL, SE, FR) add co-determination on top — use those packs where they apply.'
  },

  in: {
    id: 'in', name: 'India (DPDP)', flag: '🇮🇳',
    settings: { ...BASE_ON, employeeRetention: '12mo', kAnonymityFloor: 5 },
    controls: [
      { id: 'in-fiduciary', control: 'Data Fiduciary obligations', applies: 'Notice, purpose limitation, security safeguards, breach notification' },
      { id: 'in-consent-manager', control: 'Consent Manager integration', applies: 'API-level, registered-manager compatible' },
      { id: 'in-logs', control: 'Security log retention', applies: '1-year minimum for security logs' },
      { id: 'in-sdf', control: 'Significant Data Fiduciary', applies: 'Annual DPIA + independent audit + named DPO in India' },
      { id: 'in-erasure', control: 'Erasure across all stores', applies: 'Including backups, via crypto-shredding' },
      { id: 'in-children', control: 'DPDP §9 children\'s data', applies: 'Verifiable parental consent; no tracking or behavioural monitoring of children' },
      { id: 'in-milestones', control: 'Milestone tracking', applies: 'November 2026 and May 2027 compliance milestones tracked' },
      { id: 'in-penalty', control: 'Penalty exposure framing', applies: 'Up to ₹250 crore per contravention — surfaced on the board pack' }
    ],
    documents: [
      { name: 'DPDP notice (English + regional language placeholder)', format: 'markdown', body: dpdpNotice },
      { name: 'DPDP DPIA (SDF annual)', format: 'markdown', body: euDpia },
      { name: 'Consent Manager integration record', format: 'markdown', body: consentManagerRecord }
    ],
    crosswalk: {
      'DPDP §4-§8': 'grounds, notice, obligations of the Data Fiduciary',
      'DPDP §9': 'children\'s data — verifiable parental consent',
      'DPDP §10': 'Significant Data Fiduciary — DPIA, audit, DPO',
      'DPDP §12': 'rights of the Data Principal',
      'DPDP Rules': '1-year security log retention, 7-year consent records'
    },
    coverage: 'DPDP Data Fiduciary obligations, consent management, erasure, children\'s data and SDF duties.',
    requiresConsultation: false,
    plainLanguage: 'India-specific. Includes the Consent Manager interface and the SDF annual DPIA/audit hooks, plus the 2026/2027 milestone tracker.'
  },

  us_strict: {
    id: 'us_strict', name: 'US — CA/CO/CT strict states', flag: '🇺🇸',
    settings: { ...BASE_ON, kAnonymityFloor: 5, employeeRetention: '12mo', workingHoursOnly: false },
    controls: [
      { id: 'us-ccpa', control: 'CCPA/CPRA incl. employee data', applies: 'Notice at collection, access, deletion, correction, opt-out of sharing' },
      { id: 'us-admt', control: 'CPRA ADMT regulations', applies: 'Pre-use notice, opt-out and access rights for automated decision-making — Vault makes no employment decisions' },
      { id: 'us-co', control: 'Colorado Privacy Act', applies: 'Universal opt-out, DPA assessments' },
      { id: 'us-ct', control: 'Connecticut CTDPA', applies: 'Assessment and consumer rights' },
      { id: 'us-bipa', control: 'BIPA-style biometric care', applies: 'No biometric processing; biometric references are detected and masked' },
      { id: 'us-ecpa', control: 'ECPA / state two-party consent', applies: 'Voice capture requires disclosure; covert monitoring does not exist' }
    ],
    documents: [
      { name: 'Notice at collection (CA)', format: 'markdown', body: ukNotice },
      { name: 'ADMT pre-use notice', format: 'markdown', body: admtNotice },
      { name: 'State-patchwork applicability matrix', format: 'markdown', body: usMatrix }
    ],
    crosswalk: { 'CCPA/CPRA': 'employee data rights', 'CPRA ADMT': 'automated decision-making', 'CPA/CTDPA': 'assessments and opt-outs', 'BIPA': 'biometrics' },
    coverage: 'Strict-state US employee privacy, ADMT notices, biometric care.',
    requiresConsultation: false,
    plainLanguage: 'For US employers in CA/CO/CT and similar. Litigation hold and eDiscovery live in the US general pack.'
  },

  ca: {
    id: 'ca', name: 'Canada', flag: '🇨🇦',
    settings: { ...BASE_ON, employeeRetention: '12mo' },
    controls: [
      { id: 'ca-pipeda', control: 'PIPEDA', applies: 'Meaningful consent, accountability, access' },
      { id: 'ca-q25', control: 'Quebec Law 25', applies: 'Privacy by default, transfer assessments, automated decision transparency' },
      { id: 'ca-provincial', control: 'AB/BC PIPA', applies: 'Provincial employee-data variants' },
      { id: 'ca-monitoring', control: 'Ontario ESA electronic monitoring policy', applies: 'Written policy required for employers of 25+' }
    ],
    documents: [
      { name: 'Ontario electronic monitoring policy', format: 'markdown', body: ontarioMonitoring },
      { name: 'Quebec Law 25 transfer assessment', format: 'markdown', body: euDpia }
    ],
    crosswalk: { PIPEDA: 'consent and access', 'Law 25': 'privacy by default and ADM transparency', 'ESA s.41.1.1': 'electronic monitoring policy' },
    coverage: 'Canadian federal and provincial employee privacy, including Ontario\'s written monitoring policy duty.',
    requiresConsultation: false,
    plainLanguage: 'Canada-wide baseline with Quebec and Ontario specifics.'
  },

  global_strictest: {
    id: 'global_strictest', name: 'GLOBAL STRICTEST (union of all)', flag: '🌍',
    settings: {
      ...BASE_ON,
      kAnonymityFloor: 10,
      workingHoursOnly: true,
      worksCouncilRole: true,
      employeeRetention: '3mo',
      sampleRate: 0.02,
      noIndividualPerformanceVisibility: 'not even to HR, not even with break-glass'
    },
    controls: [{ id: 'global', control: 'Union of every pack', applies: 'The strictest setting from every jurisdiction, applied everywhere' }],
    documents: [
      { name: 'Betriebsvereinbarung (works agreement) — Entwurf', format: 'markdown', body: betriebsvereinbarung },
      { name: 'EU DPIA (Art 35)', format: 'markdown', body: euDpia },
      { name: 'UK Legitimate Interests Assessment (LIA)', format: 'markdown', body: ukLia },
      { name: 'Employee transparency notice', format: 'markdown', body: ukNotice },
      { name: 'Consultation pack', format: 'markdown', body: consultationPack }
    ],
    crosswalk: { 'all packs': 'strictest control from each' },
    coverage: 'Everything. Use when you operate in many jurisdictions and would rather not maintain per-country configuration.',
    requiresConsultation: true,
    plainLanguage: 'One setting that is lawful nearly everywhere, at the cost of the least visibility.'
  }
};

/** Sector packs (§15.5). These layer on top of a jurisdiction rather than replacing it. */
export const SECTOR_PACKS = {
  us_finserv: {
    id: 'us_finserv', name: 'US financial services',
    frameworks: ['FINRA 4511', 'FINRA 3110', 'SEC 17a-4(b)(4)', 'FINRA Notice 24-09', 'FINRA Notice 25-07', 'MiFID II 16(7)', 'FCA SYSC 10A', 'CFTC 1.31'],
    requires: ['WORM archive', 'supervision workflow', 'lexicon review', 'employee-to-account linking', 'journaling completeness'],
    settings: { regulatoryRecord: 'finra-4511', wormRequired: true, supervisionSampling: 5 },
    coverage: 'Recordkeeping, supervision and AI-content-as-business-record.',
    doesNotCover: 'Trade surveillance, market-abuse detection and best-execution monitoring.'
  },
  insurance: {
    id: 'insurance', name: 'Insurance',
    frameworks: ['NAIC AI governance', 'NAIC third-party model registry'],
    requires: ['AI Security Rider evidence pack', 'carrier-format AI inventory', 'AI-incident register'],
    settings: {},
    coverage: 'Carrier-facing evidence, AI inventory and incident register.',
    doesNotCover: 'Rate filing, underwriting model validation and actuarial review.'
  },
  banking: {
    id: 'banking', name: 'Banking (forward-looking)',
    frameworks: ['PRA SS5/21', 'BCBS 323', 'April 2026 interagency guidance gap'],
    requires: ['agent inventory', 'lineage', 'validation evidence'],
    settings: {},
    coverage: 'Model risk management extended to agents: inventory, lineage and validation evidence, staged for the coming RFI.',
    doesNotCover: 'Capital modelling and credit risk model validation.'
  },
  healthcare: {
    id: 'healthcare', name: 'Healthcare',
    frameworks: ['HIPAA', 'HITECH'],
    requires: ['BAA', 'minimum necessary', 'PHI handling', 'breach notification'],
    settings: { phiDetection: true, minimumNecessary: true, breachClockHours: 60 * 24 },
    coverage: 'PHI detection, minimum-necessary enforcement, BAA and breach notification timing.',
    doesNotCover: 'Clinical decision support validation and FDA SaMD obligations.'
  },
  us_general: {
    id: 'us_general', name: 'US general',
    frameworks: ['CCPA/CPRA', 'state patchwork', 'FRCP litigation hold', 'BIPA'],
    requires: ['litigation hold', 'eDiscovery export', 'biometric care'],
    settings: {},
    coverage: 'US privacy patchwork plus litigation hold and eDiscovery.',
    doesNotCover: 'Sector regulators — see the finserv, insurance and healthcare packs.'
  }
};

/** @param {string} id */
export function jurisdictionPack(id) {
  const pack = JURISDICTIONS[id] || JURISDICTIONS[String(id).toLowerCase()];
  if (!pack) {
    throw new Error(`unknown jurisdiction "${id}" — available: ${Object.keys(JURISDICTIONS).join(', ')}`);
  }
  return pack;
}

export function listJurisdictions() {
  return Object.values(JURISDICTIONS).map((j) => ({
    id: j.id, name: j.name, flag: j.flag,
    requiresConsultation: j.requiresConsultation,
    documents: j.documents.length,
    summary: j.plainLanguage
  }));
}

// ---------------------------------------------------------------------------
// Document templates. These are first drafts a DPO or works council can work
// from, not legal advice — and each says so.
// ---------------------------------------------------------------------------

const DISCLAIMER = '\n\n---\n*Generated by Vault from your live configuration. This is a first draft for your DPO, works council or counsel to review and adapt — it is not legal advice.*\n';

function ukLia({ settings, generatedAt }) {
  return `# Legitimate Interests Assessment (LIA)
**System:** Vault — shared AI memory governance
**Generated:** ${generatedAt}
**Basis considered:** UK GDPR Art 6(1)(f)

## 1. Purpose test — is there a legitimate interest?
The organisation operates AI agents that read from and write to a shared memory. Without governance, any content an
agent reads can become a durable, trusted fact, and no record exists of what was believed or who acted on it. The
legitimate interests are: preventing memory poisoning and prompt injection; maintaining an accurate record for
regulatory, contractual and litigation purposes; and demonstrating accountability under Art 5(2).

## 2. Necessity test — is the processing necessary?
The processing is limited to what governance requires:
- capture is ${settings.sampleDontStream ? 'event-triggered and sampled, not continuous' : 'continuous'};
- identity is ${settings.pseudonymiseByDefault ? 'pseudonymised by default, with re-identification requiring two named approvers and a stated legal reason' : 'retained'};
- ${settings.excludedContexts.length} contexts are excluded from capture entirely: ${settings.excludedContexts.join(', ')};
- employee-linked data is retained for ${settings.employeeRetention ?? 'the standard period'};
- ${settings.workingHoursOnly ? 'capture is limited to contracted working hours' : 'capture is not time-limited'}.
No less intrusive means would achieve the purpose: aggregate-only telemetry cannot trace a poisoned fact to its source,
which is the core purpose.

## 3. Balancing test — do the individual's interests override?
| Factor | Assessment |
|---|---|
| Reasonable expectations | Employees are informed via the transparency notice and can see their own data in the My Data portal. |
| Intrusiveness | ${settings.noIndividualDashboards ? 'No individual dashboards exist. No screen shows one named employee\'s activity.' : 'Individual views exist.'} |
| Profiling | None. No productivity, performance, sentiment or emotion scoring exists in the system. |
| Automated decisions | None. Vault never makes an employment decision (Art 22). |
| Special category data | Detected and ${settings.pseudonymiseByDefault ? 'masked' : 'labelled'}; an Art 9 condition is required before any is stored. |
| Children's data | Detected and quarantined pending a lawful-basis decision. |
| Safeguards | Purpose lock enforced in the query layer; k-anonymity floor of ${settings.kAnonymityFloor}; objection channel; full audit of every access. |

## 4. Outcome
Legitimate interest is available, subject to the safeguards above remaining in force. A change to any of them requires
this assessment to be revisited, and Vault notifies ${settings.changeNotification ? 'employee representatives automatically' : 'the DPO'} when
monitoring-relevant settings change.

## 5. Review
Reviewed at least annually, and on any change to the settings recorded above.${DISCLAIMER}`;
}

function ukDpia({ settings, generatedAt }) {
  return `# Data Protection Impact Assessment (ICO format)
**Generated:** ${generatedAt}

## Step 1 — Identify the need for a DPIA
Vault processes employee-linked data in the course of governing an AI memory system. Systematic monitoring of employees
is listed by the ICO as requiring a DPIA.

## Step 2 — Describe the processing
- **Nature:** capture of AI agent interactions; extraction of candidate facts; ten governance checks before storage; sealed audit ledger.
- **Scope:** ${settings.sampleDontStream ? 'event-triggered sampling' : 'continuous capture'}; ${settings.excludedContexts.length} excluded contexts; retention ${settings.employeeRetention ?? 'standard'}.
- **Context:** employees are aware, informed by notice, and can access their own data.
- **Purpose:** memory governance only, enforced by a purpose lock in the query layer.

## Step 3 — Consultation
${settings.worksCouncilRole ? 'Employee representatives hold a formal read-only role with an objection channel and automatic change notification.' : 'Staff and, where present, recognised unions are consulted using the included consultation pack. The ICO expects consultation evidence even where there is no statutory works council.'}

## Step 4 — Necessity and proportionality
See the Legitimate Interests Assessment. Least-intrusive-means is evidenced by: absence of individual dashboards,
absence of any affect or productivity scoring, pseudonymisation by default, and a k-anonymity floor of ${settings.kAnonymityFloor}.

## Step 5 — Risks
| Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|
| Function creep into performance management | Low | High | Purpose lock in the query layer plus a contractual warranty; breach is a termination event |
| Re-identification of pseudonymised employees | Low | Medium | Two named approvers, stated legal reason, time box, receipt, reported to employee reps |
| Excessive retention | Low | Medium | ${settings.employeeRetention ?? 'Standard'} retention for employee-linked data, enforced automatically |
| Capture of excluded contexts | Low | High | ${settings.excludedContexts.length} contexts structurally excluded at ingestion |
| Covert monitoring | None | High | Covert mode does not exist in the product |

## Step 6 — Measures and sign-off
Residual risk: **low**. Sign-off required from the DPO.${DISCLAIMER}`;
}

function euDpia(ctx) {
  return ukDpia(ctx).replace('(ICO format)', '(GDPR Art 35)').replace('the ICO', 'the supervisory authority');
}

function ukNotice({ settings, generatedAt }) {
  return `# How we use AI memory data about you
**Last updated:** ${generatedAt}

We run AI assistants that share a governed memory. This notice explains what that means for you.

**What we record.** Interactions with company AI tools, and the facts those interactions produce. ${settings.sampleDontStream ? 'We sample rather than stream: capture is triggered by events, not continuous.' : ''}

**What we never record.** ${settings.excludedContexts.length ? `Nothing from: ${settings.excludedContexts.join(', ')}.` : ''} We never record or infer your mood, sentiment, stress, engagement, motivation or honesty — that capability does not exist in the system. We do not score your productivity.

**Who can see it.** ${settings.noIndividualDashboards ? 'No screen anywhere shows one named employee\'s AI activity. Managers see department-level aggregates only, and only where at least ' + settings.kAnonymityFloor + ' people are in the group.' : 'Managers can see individual activity.'} ${settings.pseudonymiseByDefault ? 'Your identity is replaced with a rotating token by default; re-identifying it requires two named approvers, a stated legal reason and a time limit, and is logged and reported to employee representatives.' : ''}

**What it can be used for.** Memory governance only — keeping AI answers accurate and traceable. It cannot be queried for performance, productivity, discipline, promotion or any HR decision. This is enforced in the software and warranted in our contract.

**How long we keep it.** Employee-linked data: ${settings.employeeRetention ?? 'the standard retention period'}.

**Your rights.** See everything we hold about you in the **My Data** portal, export it, ask for a correction, or object formally to any fact about you — objections are tracked and answered.

**Automated decisions.** Vault never makes an employment decision about you.${DISCLAIMER}`;
}

function betriebsvereinbarung({ settings, generatedAt }) {
  return `# Betriebsvereinbarung über den Einsatz von Vault (KI-Gedächtnis-Governance)
**Entwurf — Stand ${generatedAt}**

Zwischen der Geschäftsleitung und dem Betriebsrat wird gemäß **§ 87 Abs. 1 Nr. 6 BetrVG** Folgendes vereinbart:

## § 1 Gegenstand und Zweck
Vault dient ausschließlich der Governance des gemeinsamen KI-Gedächtnisses: der Verhinderung manipulierter oder
falscher Inhalte, der Nachvollziehbarkeit von KI-Aussagen und der Erfüllung gesetzlicher Aufbewahrungspflichten.
**Eine Verhaltens- oder Leistungskontrolle ist ausgeschlossen.**

## § 2 Erfassungsumfang
(1) Erfasst werden Interaktionen mit betrieblichen KI-Systemen ${settings.sampleDontStream ? 'ereignisbasiert und stichprobenartig' : 'laufend'}.
(2) **Nicht erfasst werden:** ${(settings.excludedContexts || []).join(', ')}.
(3) Die Erfassung erfolgt ${settings.workingHoursOnly ? 'ausschließlich innerhalb der vertraglichen Arbeitszeit' : 'ohne Zeitbeschränkung'}.

## § 3 Pseudonymisierung
(1) Beschäftigtenbezogene Daten werden standardmäßig pseudonymisiert (rotierendes Token).
(2) Eine Re-Identifizierung ist nur zulässig bei Vorliegen eines dokumentierten rechtlichen Grundes, mit **Zustimmung
    von zwei namentlich benannten Personen**, zeitlich befristet, protokolliert und dem Betriebsrat berichtet.

## § 4 Auswertung
(1) Auswertungen erfolgen ausschließlich aggregiert, mindestens auf Abteilungsebene, mit einer Mindestgruppengröße von
    **k = ${settings.kAnonymityFloor}**. Unterhalb dieser Schwelle wird **kein Wert angezeigt**.
(2) **Individuelle Leistungsauswertungen sind technisch nicht vorhanden** — auch nicht für die Personalabteilung und
    auch nicht über Notfallzugriffe.

## § 5 Verbotene Verwendungen
Ausgeschlossen sind: Leistungs- und Verhaltenskontrolle, Produktivitätsmessung, Emotions-, Stimmungs-, Stress-,
Engagement-, Motivations- oder Ehrlichkeitsanalyse, verdeckte Überwachung, sowie jede Verwendung für
personalrechtliche Maßnahmen.

## § 6 Aufbewahrung und Löschung
Beschäftigtenbezogene Daten werden nach **${settings.employeeRetention ?? '3 Monaten'}** gelöscht, soweit keine
gesetzliche Aufbewahrungspflicht entgegensteht. Kollisionen zwischen Löschpflicht und Aufbewahrungspflicht werden
dokumentiert und dem Betriebsrat offengelegt.

## § 7 Rechte der Beschäftigten
Jede beschäftigte Person kann über das Portal „Meine Daten" einsehen, welche Daten zu ihr vorliegen, diese exportieren,
Berichtigung verlangen und **förmlich Widerspruch** gegen einzelne Einträge einlegen; Widersprüche werden nachverfolgt
und beantwortet.

## § 8 Beteiligung des Betriebsrats
(1) Der Betriebsrat erhält eine eigene **Nur-Lese-Rolle** mit Einsicht in Konfiguration, Aufbewahrungsfristen,
    Zugriffsmatrix und alle Re-Identifizierungen.
(2) Jede Änderung überwachungsrelevanter Einstellungen wird dem Betriebsrat **automatisch angezeigt**.
(3) Änderungen bedürfen der Zustimmung des Betriebsrats.

## § 9 Streitigkeiten
Kommt keine Einigung zustande, entscheidet die **Einigungsstelle**. Die erforderliche Dokumentation wird von Vault
vollständig bereitgestellt.

## § 10 Inkrafttreten und Laufzeit
Diese Vereinbarung tritt mit Unterzeichnung in Kraft und kann mit einer Frist von drei Monaten gekündigt werden.
Bei Kündigung wird die Verarbeitung beschäftigtenbezogener Daten eingestellt.

_____________________          _____________________
Geschäftsleitung               Betriebsrat${DISCLAIMER}`;
}

function bdsgAssessment({ settings, generatedAt }) {
  return `# Erforderlichkeits- und Verhältnismäßigkeitsprüfung nach § 26 BDSG
**Stand:** ${generatedAt}

## 1. Zweck
Governance des gemeinsamen KI-Gedächtnisses; Verhinderung manipulierter Inhalte; Nachweisbarkeit gegenüber Aufsicht,
Gerichten und Versicherern.

## 2. Erforderlichkeit
Ohne Herkunftsnachweis je Aussage lässt sich eine manipulierte Information weder erkennen noch zurückverfolgen. Eine
rein aggregierte Erfassung erreicht den Zweck nicht.

## 3. Verhältnismäßigkeit
- Pseudonymisierung standardmäßig: **${settings.pseudonymiseByDefault ? 'ja' : 'nein'}**
- Ausgeschlossene Kontexte: **${(settings.excludedContexts || []).length}**
- Aufbewahrung beschäftigtenbezogener Daten: **${settings.employeeRetention ?? 'Standard'}**
- Individuelle Leistungsauswertung: **technisch nicht vorhanden**
- Emotions-/Stimmungsanalyse: **im Produkt nicht vorhanden** (EU AI Act Art. 5 Abs. 1 lit. f, Verbot seit Februar 2025)
- Verdeckte Überwachung: **im Produkt nicht vorhanden**

## 4. Ergebnis
Die Verarbeitung ist im beschriebenen Umfang erforderlich und verhältnismäßig. Jede Ausweitung erfordert eine erneute
Prüfung und die Zustimmung des Betriebsrats.${DISCLAIMER}`;
}

function verboteneVerwendungen({ generatedAt }) {
  return `# Verbotene Verwendungen (Prohibited uses)
**Stand:** ${generatedAt}

Die folgenden Verwendungen sind **technisch ausgeschlossen** — nicht lediglich untersagt:

1. **Individuelle Leistungs- oder Verhaltenskontrolle.** Es existiert keine Abfrage, die die KI-Aktivität einer
   namentlich benannten beschäftigten Person zurückgibt.
2. **Emotions-, Stimmungs-, Stress-, Engagement-, Motivations- oder Ehrlichkeitsanalyse.** Diese Funktion existiert im
   Quellcode nicht. Emotionserkennung am Arbeitsplatz ist in der EU seit Februar 2025 verboten.
3. **Produktivitätsmessung.** Keine Ausgabezählung pro Person, keine Geschwindigkeitsranglisten, keine Aktivitätsscores.
4. **Verdeckte Überwachung.** Ein verdeckter Modus existiert nicht.
5. **Verwendung für personalrechtliche Maßnahmen.** Der Zweckbindungs-Riegel wird in der Abfrageschicht durchgesetzt und
   ist vertraglich zugesichert; ein Verstoß ist ein Kündigungsgrund des Vertrages mit Haftungsfolge.${DISCLAIMER}`;
}

function einigungsstelle({ generatedAt }) {
  return `# Einigungsstelle — Dokumentationspaket
**Stand:** ${generatedAt}

Für ein Verfahren vor der Einigungsstelle stellt Vault vollständig bereit:

1. Entwurf der Betriebsvereinbarung (§ 87 Abs. 1 Nr. 6 BetrVG)
2. Erforderlichkeits- und Verhältnismäßigkeitsprüfung nach § 26 BDSG
3. Datenschutz-Folgenabschätzung nach Art. 35 DSGVO
4. Liste der verbotenen Verwendungen, in deutscher Sprache
5. Vollständige Zugriffsmatrix: welche Rolle sieht welche Datenkategorie
6. Aufbewahrungs- und Löschkonzept, einschließlich Kollisionsdokumentation
7. Protokoll aller Re-Identifizierungen mit Begründung und Genehmigenden
8. Änderungshistorie aller überwachungsrelevanten Einstellungen
9. Technischer Nachweis der Abwesenheit individueller Leistungsauswertung${DISCLAIMER}`;
}

function consultationPack({ settings, generatedAt }) {
  return `# Employee representative consultation pack
**Generated:** ${generatedAt}

## What is being introduced
Vault governs the shared memory used by the company's AI assistants. It decides what an AI is allowed to treat as true,
and keeps a record of what was believed and why.

## What it does with employee data
- Capture: ${settings.sampleDontStream ? 'event-triggered sampling, not continuous streaming' : 'continuous'}
- Identity: ${settings.pseudonymiseByDefault ? 'pseudonymised by default' : 'retained'}
- Excluded entirely: ${(settings.excludedContexts || []).join(', ') || 'none'}
- Retention: ${settings.employeeRetention ?? 'standard'}
- Analytics: aggregate only, minimum group size k=${settings.kAnonymityFloor}

## What it will never do
No individual activity dashboards. No productivity scoring. No sentiment, mood, stress, engagement, motivation or
honesty analysis — that code does not exist. No covert monitoring — that mode does not exist.

## What we are asking for
Review, comment, and (where required) agreement. We propose: a named representative role with read-only oversight,
automatic notification of any monitoring-relevant change, and a formal objection channel with tracked responses.

## Questions we expect, answered in advance
| Question | Answer |
|---|---|
| Can my manager see what I asked the AI? | No. No screen shows one named employee's activity. |
| Could that change with a setting? | No — the query does not exist. Enabling it would require a code change, which would be visible to you through the change notification. |
| Is my tone or mood analysed? | No. That capability is not in the product at all. |
| What if I disagree with something recorded about me? | Raise a formal objection in the My Data portal. It is tracked and must be answered. |
| How long is it kept? | ${settings.employeeRetention ?? 'The standard period'}, then deleted automatically. |${DISCLAIMER}`;
}

function icoBreach({ generatedAt }) {
  return `# ICO personal data breach report (pre-filled)
**Prepared:** ${generatedAt}

1. **When did the breach happen?** _[from the incident register]_
2. **When did you become aware?** _[first alert timestamp from the ledger]_ — the 72-hour clock runs from here.
3. **What happened?** _[incident bundle narrative]_
4. **Categories and approximate number of data subjects** _[from the erasure/discovery counts — categories only, never content]_
5. **Categories and approximate number of records** _[from the ledger]_
6. **Likely consequences** _[risk assessment]_
7. **Measures taken** _[containment: kill switch level engaged, scope, activation time; rollback performed; contagion trace]_
8. **DPO contact** _[configured]_

Attachments Vault generates automatically: the incident bundle, the sealed chain proof, the contagion trace, the
timeline, and the human-oversight evidence.${DISCLAIMER}`;
}

function deleteVsRetain({ generatedAt }) {
  return `# Delete-vs-retain decision record
**Generated:** ${generatedAt}

When an erasure request meets a preservation obligation, Vault does not silently pick one. It records:

| Field | Value |
|---|---|
| Request | _[request id]_ |
| Items affected | _[count]_ |
| Privacy obligation | GDPR Art 17 — erasure without undue delay |
| Competing obligation | _[matter / records rule]_ |
| Decision | Items locked and **minimised** to the least the obligation requires; all other fields crypto-shredded |
| Decided by | _[named person]_ |
| Decided at | _[timestamp]_ |
| Auto-delete | On lift of the obligation, automatically |
| Subject notified | Yes — written explanation of the deferral |${DISCLAIMER}`;
}

function dpdpNotice({ settings, generatedAt }) {
  return `# Notice under the Digital Personal Data Protection Act, 2023
**Issued:** ${generatedAt}

**Data Fiduciary:** _[your entity]_ · **Contact / DPO:** _[configured]_

**Personal data processed:** interactions with company AI systems and the facts derived from them.
**Purpose:** governance of the shared AI memory — accuracy, traceability and security. Nothing else.
**Grounds:** consent, and where applicable legitimate uses under §7.
**Retention:** ${settings.employeeRetention ?? 'as required for the stated purpose'}; security logs retained one year as required by the Rules.

**Your rights as a Data Principal:** access a summary of your data and processing; correction and completion; erasure;
grievance redressal; nomination.

**How to exercise them:** through the My Data portal, or via the registered Consent Manager, or by writing to the DPO.
We respond within 90 days.

**Children's data:** processed only with verifiable parental consent; no tracking or behavioural monitoring of children.

**This notice is available in English and in the languages specified in the Eighth Schedule on request.**${DISCLAIMER}`;
}

function consentManagerRecord({ generatedAt }) {
  return `# Consent Manager integration record
**Generated:** ${generatedAt}

- Integration: API-level, compatible with a registered Consent Manager under DPDP §6(7).
- Every consent recorded in Vault is registered with the Consent Manager and carries its reference.
- Withdrawal received from the Consent Manager triggers an **actual purge**, not a flag, and produces a signed deletion receipt.
- Consent records are retained **seven years**, as required, even after withdrawal.
- Consent receipts are exportable in machine-readable and human-readable form.${DISCLAIMER}`;
}

function admtNotice({ generatedAt }) {
  return `# Pre-use notice — automated decision-making technology (CPRA ADMT)
**Issued:** ${generatedAt}

**Vault does not make automated decisions about you.** It governs what AI systems are permitted to treat as true, and
records what was believed and why.

Specifically: Vault does not produce employment decisions, scores, rankings, or recommendations about individuals. It
has no productivity scoring and no affect analysis. Where an AI system elsewhere in the business makes a decision, Vault
records the facts that were available to it, which supports your right to an explanation.

**Your rights:** pre-use notice (this document), the right to opt out of ADMT where it applies, and the right to access
information about the logic involved. Because Vault makes no decisions about individuals, an opt-out has no effect on
your treatment — you may still request the access information.${DISCLAIMER}`;
}

function usMatrix({ generatedAt }) {
  return `# US state applicability matrix
**Generated:** ${generatedAt}

| State | Statute | Applies to employee data? | Vault control |
|---|---|---|---|
| California | CCPA/CPRA + ADMT regs | Yes | Notice at collection, access/deletion/correction, ADMT pre-use notice |
| Colorado | CPA | Consumers; employee coverage limited | Universal opt-out plumbing, assessments |
| Connecticut | CTDPA | Consumers | Assessments, rights workflows |
| Illinois | BIPA | Biometrics | No biometric processing; biometric references detected and masked |
| New York | NY LL s.203-f | Electronic monitoring notice | Transparency notice on hire |
| Texas | TDPSA | Consumers | Rights workflows |
| Washington | My Health My Data | Health data | Health detection and Art 9-equivalent handling |

Two-party consent states (CA, FL, IL, MD, MA, MI, MT, NV, NH, PA, WA) require disclosure before voice capture. Vault has
no covert mode, so capture is always disclosed.${DISCLAIMER}`;
}

function ontarioMonitoring({ settings, generatedAt }) {
  return `# Electronic monitoring policy (Ontario ESA s. 41.1.1)
**Effective:** ${generatedAt}

**Does the employer electronically monitor employees?** Yes, in a limited and specific way described below.

**How.** Vault records interactions with company AI systems, ${settings.sampleDontStream ? 'sampled and event-triggered' : 'continuously'},
in order to govern what those systems are permitted to treat as true.

**In what circumstances.** ${settings.workingHoursOnly ? 'During contracted working hours only.' : 'During use of company AI systems.'}
Excluded entirely: ${(settings.excludedContexts || []).join(', ') || 'none'}.

**Purpose.** Accuracy, traceability and security of the shared AI memory. The information is not used to assess
performance, productivity or conduct, and the system contains no capability to do so.

**Retention.** ${settings.employeeRetention ?? 'Standard retention period'}.

This policy is provided to every employee within 30 days of it taking effect, and to new employees within 30 days of hire.${DISCLAIMER}`;
}
