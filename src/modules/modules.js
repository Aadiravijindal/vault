/**
 * THE CORE PRINCIPLE — built-in by default, bring-your-own by toggle (§1).
 *
 *   🟢 BUILT-IN   Vault's own engine. Default ON. No dependency.
 *   🔵 CONNECTED  Use their tool. Vault's engine goes dormant, data still
 *                 flows through Vault's gate, Vault reads from / writes to theirs.
 *   🟣 BOTH       Vault's engine runs AND pushes to theirs.
 *
 * Non-negotiable rules, enforced here rather than documented elsewhere:
 *   - the gate always runs and is not a module (attempting to toggle it throws)
 *   - switching is reversible with full history
 *   - no data hostage: Vault keeps its own copy unless explicitly disabled
 *   - connected mode degrades gracefully: if their tool is down, the built-in
 *     engine auto-resumes and backfills when theirs returns
 */
import { now, iso, ago } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

export const STATES = /** @type {const} */ (['builtin', 'connected', 'both']);

/** Every toggleable module, with the vendors we ship adapters for. */
export const MODULES = {
  archive: {
    name: 'Archive', builtinName: 'Vault WORM Archive',
    vendors: ['Smarsh', 'Global Relay', 'Theta Lake', 'Proofpoint Archive', 'Microsoft Purview', 'Veritas Enterprise Vault', 'Jatheon', 'Mimecast', 'Shield', 'Generic SFTP/S3/webhook'],
    ops: ['push', 'fetch', 'search']
  },
  search: {
    name: 'Search', builtinName: 'Vault Search',
    vendors: ['Glean', 'GoSearch', 'Guru', 'Microsoft Search/Copilot', 'Elastic', 'Coveo', 'Algolia', 'Dust', 'Onyx', 'Sinequa', 'Lucidworks'],
    ops: ['index', 'query']
  },
  tracing: {
    name: 'Tracing / Evals', builtinName: 'Vault Trace',
    vendors: ['Langfuse', 'Braintrust', 'Arize AX/Phoenix', 'LangSmith', 'Datadog LLM Observability', 'Honeycomb', 'W&B Weave', 'Opik/Comet', 'Helicone', 'Galileo', 'Fiddler', 'AgentOps', 'Laminar', 'Latitude', 'Confident AI', 'Traceloop/OpenLLMetry', 'New Relic', 'Dynatrace', 'Grafana'],
    ops: ['span', 'eval']
  },
  compliance: {
    name: 'Compliance / GRC', builtinName: 'Vault Comply',
    vendors: ['IBM watsonx.governance', 'Credo AI', 'OneTrust', 'ServiceNow AI Control Tower', 'Holistic AI', 'Monitaur', 'ModelOp', 'Trustible', 'Saidot', 'Airia', 'Cranium', 'Relyance', 'Truyo', 'AuditBoard', 'Archer', 'MetricStream', 'LogicGate', 'Vanta', 'Drata', 'Scrut', 'Sprinto'],
    ops: ['evidence', 'control', 'register']
  },
  registry: {
    name: 'Agent Registry', builtinName: 'Vault Registry',
    vendors: ['Microsoft Agent 365 / Entra Agent ID', 'ServiceNow AI Control Tower', 'Okta', 'Ping', 'CyberArk', 'Palo Alto', 'Astrix', 'Cisco', 'Oasis', 'Entro', 'Linx', 'JumpCloud', 'Keycloak'],
    ops: ['push', 'fetch']
  },
  identity: {
    name: 'Identity / SSO', builtinName: 'Vault Identity',
    vendors: ['Okta', 'Entra ID', 'Ping', 'JumpCloud', 'Keycloak', 'Google Workspace', 'OneLogin'],
    ops: ['authenticate', 'provision']
  },
  siem: {
    name: 'SIEM', builtinName: 'Vault Event Stream',
    vendors: ['Splunk', 'Microsoft Sentinel', 'Elastic Security', 'Chronicle', 'QRadar', 'Sumo Logic', 'Datadog', 'Panther'],
    ops: ['emit']
  },
  kms: {
    name: 'Key Management', builtinName: 'Vault KMS',
    vendors: ['AWS KMS', 'Azure Key Vault', 'GCP KMS', 'HashiCorp Vault', 'Thales', 'Entrust', 'CloudHSM'],
    ops: ['wrap', 'unwrap']
  },
  storage: {
    name: 'Storage', builtinName: 'Vault Storage',
    vendors: ['AWS S3', 'Azure Blob', 'Google Cloud Storage', 'Cloudflare R2', 'Backblaze B2', 'Wasabi', 'MinIO', 'Ceph/Swift', 'NetApp', 'Dell EMC', 'Pure', 'IBM COS', 'OCI', 'Any S3-compatible'],
    ops: ['put', 'get']
  },
  dlp: {
    name: 'DLP', builtinName: 'Vault PII Scanner',
    vendors: ['Microsoft Purview DLP', 'Symantec/Broadcom DLP', 'Forcepoint', 'Netskope', 'Nightfall', 'BigID', 'Varonis'],
    ops: ['scan']
  },
  memory: {
    name: 'Memory backing store', builtinName: 'Vault Fact Store',
    vendors: ['Mem0', 'Zep/Graphiti', 'Letta', 'Cognee', 'Supermemory', 'LangMem', 'Pinecone', 'Weaviate', 'Qdrant', 'Chroma'],
    ops: ['put', 'get', 'search']
  },
  insurance: {
    name: 'Insurance Pack', builtinName: 'Vault Insure',
    vendors: [],
    ops: ['pack'],
    noAlternative: true
  }
};

/** Published feature-parity matrix — honest, per module, per vendor (§1). */
export const PARITY = {
  archive: {
    vaultOnly: [
      'memory-aware archive: which facts each conversation produced, and the gate verdict for each',
      'sealed hash chain with customer-held keys and an independent verifier',
      'delete-vs-keep conflict resolution on screen',
      'gate-attempt records for writes that were blocked before they became facts'
    ],
    theirsOnly: [
      'decades of regulator-accepted attestations for the incumbent archive of record',
      'existing supervision lexicons and reviewer workflows your compliance team already trains on',
      'channel capture Vault does not connect to yet (e.g. legacy voice recorders)'
    ]
  },
  search: {
    vaultOnly: [
      'permission checks at query time against walls and labels, not index time',
      'provenance and claim-type labels on every result',
      'point-in-time search ("what did we believe about Acme in March?")',
      'golden-first ranking'
    ],
    theirsOnly: [
      'broader out-of-the-box document connector coverage',
      'established relevance tuning over your existing corpus'
    ]
  },
  tracing: {
    vaultOnly: [
      'memory-aware traces: which facts were read, withheld, written, held or blocked, inline with the reasoning',
      'memory-specific scorers (did the agent use the golden fact? did it repeat a guess as truth?)'
    ],
    theirsOnly: [
      'deeper integration with your existing APM and on-call tooling',
      'larger prompt-management and dataset-curation feature surface'
    ]
  },
  compliance: {
    vaultOnly: [
      'evidence pulled from the ledger and the gate automatically, not screenshots',
      'AI-specific controls mapped to what the gate actually enforced'
    ],
    theirsOnly: [
      'enterprise-wide GRC beyond AI (vendor risk, SOX, operational risk)',
      'existing auditor relationships and report formats'
    ]
  },
  registry: {
    vaultOnly: ['memory-scoped permissions (which folders, which labels, which regions)', 'behavioural baselines per agent'],
    theirsOnly: ['enterprise identity lifecycle, joiners/movers/leavers, conditional access']
  },
  dlp: {
    vaultOnly: ['detection before storage rather than after', 'credential blocking that never stores the secret at all'],
    theirsOnly: ['endpoint and network coverage outside the AI path', 'your existing classification taxonomy']
  }
};

export class ModuleRegistry {
  /**
   * @param {object} opts
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {Record<string, {state?:string, vendor?:string, adapter?:object, keepOwnCopy?:boolean}>} [opts.config]
   */
  constructor({ ledger, config = {} }) {
    this.ledger = ledger;
    /** @type {Map<string, object>} */
    this.state = new Map();
    for (const key of Object.keys(MODULES)) {
      const c = config[key] || {};
      this.state.set(key, {
        module: key,
        state: c.state || 'builtin',
        vendor: c.vendor || null,
        adapter: c.adapter || null,
        keepOwnCopy: c.keepOwnCopy !== false,   // no data hostage: default true
        healthy: true,
        lastError: null,
        lastSuccessAt: null,
        backlog: [],
        history: [{ at: now(), state: c.state || 'builtin', vendor: c.vendor || null, actor: 'config' }]
      });
    }
  }

  /** The gate is not a module. Attempting to toggle it is a hard error. */
  assertNotGate(name) {
    if (['gate', 'checks', 'policy_gate'].includes(String(name).toLowerCase())) {
      throw forbidden('the gate cannot be toggled, disabled, bypassed or replaced — it runs in every module configuration', { code: 'gate_is_not_toggleable' });
    }
  }

  get(name) {
    this.assertNotGate(name);
    const s = this.state.get(name);
    if (!s) throw new VaultError('not_found', 'unknown module', { module: name });
    return s;
  }

  /**
   * @param {string} name
   * @param {'builtin'|'connected'|'both'} state
   * @param {{vendor?:string, adapter?:object, actor:string, reason?:string, keepOwnCopy?:boolean}} opts
   */
  set(name, state, { vendor = null, adapter = null, actor, reason = 'module toggled', keepOwnCopy } = {}) {
    this.assertNotGate(name);
    if (!STATES.includes(state)) throw new VaultError('validation', `state must be one of ${STATES.join(', ')}`);
    if (!actor) throw forbidden('toggling a module requires a named actor');
    const spec = MODULES[name];
    if (!spec) throw new VaultError('not_found', 'unknown module', { module: name });
    if (spec.noAlternative && state !== 'builtin') {
      throw new VaultError('validation', `${spec.name} has no third-party alternative — it stays built-in`);
    }
    if (state !== 'builtin' && !adapter) {
      throw new VaultError('validation', `connecting ${spec.name} requires an adapter implementing ${spec.ops.join(', ')}`);
    }

    const prev = this.get(name);
    const next = {
      ...prev,
      state,
      vendor: state === 'builtin' ? null : (vendor || prev.vendor),
      adapter: state === 'builtin' ? null : adapter,
      keepOwnCopy: keepOwnCopy ?? prev.keepOwnCopy,
      healthy: true,
      history: [...prev.history, { at: now(), state, vendor, actor, reason, from: prev.state }]
    };
    this.state.set(name, next);
    this.ledger.append('admin.module_toggled', {
      subject: name, actor, reason, from: prev.state, to: state, vendor: next.vendor,
      keepOwnCopy: next.keepOwnCopy
    });
    return this.describe(name);
  }

  /**
   * Route an operation. Built-in callers pass their own implementation result;
   * this only handles the third-party side and the degradation policy.
   *
   * @param {string} name
   * @param {string} op
   * @param {any} payload
   * @returns {any|null} the connected tool's result, or null when built-in only
   */
  dispatch(name, op, payload) {
    const s = this.state.get(name);
    if (!s || s.state === 'builtin' || !s.adapter) return null;
    const fn = s.adapter[op];
    if (typeof fn !== 'function') return null;
    try {
      const result = fn(payload);
      s.healthy = true;
      s.lastError = null;
      s.lastSuccessAt = now();
      // Drain anything that queued while they were down.
      if (s.backlog.length) this._backfill(name);
      return result;
    } catch (e) {
      // Connected mode degrades gracefully: the built-in engine auto-resumes and
      // backfills when theirs returns (§1).
      s.healthy = false;
      s.lastError = { message: e.message, at: now() };
      s.backlog.push({ op, payload, at: now() });
      this.ledger.append('connector.health', {
        subject: name, healthy: false, op,
        detail: 'connected module unavailable — built-in engine resumed, work queued for backfill'
      });
      return null;
    }
  }

  _backfill(name) {
    const s = this.state.get(name);
    if (!s?.adapter) return { backfilled: 0 };
    const items = s.backlog.splice(0, s.backlog.length);
    let ok = 0;
    for (const item of items) {
      try { s.adapter[item.op]?.(item.payload); ok++; } catch { s.backlog.push(item); }
    }
    if (ok) {
      this.ledger.append('connector.health', { subject: name, healthy: true, backfilled: ok, detail: 'connected module recovered — backlog drained' });
    }
    return { backfilled: ok, remaining: s.backlog.length };
  }

  /**
   * When a module is CONNECTED, Vault's engine is dormant — unless their tool is
   * down, in which case it auto-resumes. This tells callers which to use.
   */
  useBuiltin(name) {
    const s = this.state.get(name);
    if (!s) return true;
    if (s.state === 'builtin' || s.state === 'both') return true;
    // connected: use built-in only while theirs is unhealthy, or if we keep a copy
    return !s.healthy || s.keepOwnCopy;
  }

  describe(name) {
    const s = this.get(name);
    const spec = MODULES[name];
    return {
      module: name,
      name: spec.name,
      state: s.state,
      icon: { builtin: '🟢', connected: '🔵', both: '🟣' }[s.state],
      using: s.state === 'builtin' ? spec.builtinName
        : s.state === 'both' ? `Vault + ${s.vendor}` : s.vendor,
      action: spec.noAlternative ? '—' : (s.state === 'builtin' ? 'Connect mine' : "Use Vault's"),
      vendorOptions: spec.vendors,
      keepOwnCopy: s.keepOwnCopy,
      healthy: s.healthy,
      lastError: s.lastError ? { at: iso(s.lastError.at), message: s.lastError.message } : null,
      backlog: s.backlog.length,
      lastSuccess: s.lastSuccessAt ? ago(s.lastSuccessAt) : null,
      parity: PARITY[name] ?? null,
      history: s.history.map((h) => ({ ...h, at: iso(h.at) }))
    };
  }

  /** The ⚙️ ADMIN → MODULES screen (§1). */
  table() {
    return Object.keys(MODULES).map((k) => {
      const d = this.describe(k);
      return {
        module: d.name, state: `${d.icon} ${d.state === 'builtin' ? 'Built-in' : d.state === 'both' ? 'Both' : 'Connected'}`,
        using: d.using, action: d.action, healthy: d.healthy, keepOwnCopy: d.keepOwnCopy
      };
    });
  }

  /**
   * One-click migration, both ways, documented format, no charge (§1).
   * @param {string} name
   * @param {'import'|'export'} direction
   */
  migrate(name, direction, { actor, data = null, reason = 'migration' }) {
    this.assertNotGate(name);
    if (!actor) throw forbidden('migration requires a named actor');
    const s = this.get(name);
    if (direction === 'export') {
      const payload = s.adapter?.export ? s.adapter.export() : null;
      this.ledger.append('export.created', { subject: name, actor, reason, direction, format: 'vault.module.v1' });
      return { module: name, direction, format: 'vault.module.v1', exportedAt: iso(), payload };
    }
    const result = s.adapter?.import ? s.adapter.import(data) : { imported: 0, note: 'no import adapter configured' };
    this.ledger.append('admin.action', { subject: name, actor, action: 'module.import', reason, ...result });
    return { module: name, direction, ...result };
  }

  /** Switching a module never loses data (§1). */
  guarantees() {
    return {
      gateAlwaysRuns: 'whatever module state you pick, every write still passes Vault\'s 10 checks — not optional, not toggleable',
      switchingIsReversible: 'turn a module back to Built-in and it resumes with full history',
      noDataHostage: Object.fromEntries([...this.state].map(([k, v]) => [k, v.keepOwnCopy ? 'Vault keeps a complete copy' : 'copy explicitly disabled by the customer'])),
      gracefulDegradation: 'if their tool goes down, the built-in engine auto-resumes and backfills when theirs returns',
      publishedParity: 'an honest matrix per module, per vendor — see PARITY',
      migrationBothWays: 'documented format, no charge, either direction'
    };
  }

  health() {
    return [...this.state.values()].map((s) => ({
      module: s.module, state: s.state, vendor: s.vendor, healthy: s.healthy,
      backlog: s.backlog.length, lastError: s.lastError?.message ?? null,
      lastSuccess: s.lastSuccessAt ? iso(s.lastSuccessAt) : null
    }));
  }
}

/**
 * Build a simple adapter around a set of functions. Real adapters live in
 * src/connectors/, but this keeps the interface honest and testable.
 */
export function makeAdapter(vendor, impl) {
  return { vendor, ...impl };
}
