/**
 * VAULT — the company's shared AI memory, with a guard at the door, a recorder
 * that never stops, and a complete built-in stack you can swap for your own.
 *
 * This file wires the twelve layers together and exposes the write path
 * (`ingest`) and the read path (`read`). Everything else hangs off `vault.*`.
 *
 *   L1  connection layer      L7  read path
 *   L2  raw archive           L8  ledger
 *   L3  extraction            L9  observability
 *   L4  THE GATE              L10 governance
 *   L5  fact store            L11 storage
 *   L6  hygiene               L12 control surface
 */
import { Db } from './storage/db.js';
import { Kms, KEY_MODES } from './storage/kms.js';
import { createKeyClient, RemoteKeyBridge } from './storage/kmsclient.js';
import { TieringEngine } from './storage/tiers.js';
import { createBucket, DRIVERS, HashOnlyBucket as HashOnlyBucketType } from './storage/buckets.js';
import { Ledger, Witness } from './ledger/ledger.js';
import { Archive } from './archive/archive.js';
import { Extractor } from './extract/extract.js';
import { Gate } from './gate/gate.js';
import { PiiScanner } from './gate/pii.js';
import { InstructionDetector } from './gate/instructions.js';
import { RulesEngine, RULE_TEMPLATES } from './gate/rules.js';
import { Reconciler } from './gate/reconcile.js';
import { FactStore } from './facts/factstore.js';
import { FolderTree } from './facts/folders.js';
import { EntityResolver } from './facts/entities.js';
import { Registry } from './registry/registry.js';
import { ConsentRegistry } from './legal/consent.js';
import { LegalOps } from './legal/legal.js';
import { PrivacyMode } from './privacy/privacy.js';
import { AlertManager } from './security/alerts.js';
import { KillSwitch } from './security/killswitch.js';
import { TemporalDetector } from './security/temporal.js';
import { ModuleRegistry } from './modules/modules.js';
import { ReviewQueue } from './review/review.js';
import { SearchEngine } from './search/search.js';
import { ReadPath } from './read/read.js';
import { HygieneEngine } from './hygiene/hygiene.js';
import { TraceEngine } from './trace/trace.js';
import { VaultTrace } from './observability/vaulttrace.js';
import { VaultComply } from './comply/comply.js';
import { VaultInsure } from './insure/insure.js';
import { ValueEngine } from './value/value.js';
import { Continuity } from './continuity/continuity.js';
import { ConnectorManager, Gateway } from './connectors/connectors.js';
import { Notifier } from './notify/notify.js';
import { Metering } from './billing/metering.js';
import { BulkImport, Offboarding } from './lifecycle/lifecycle.js';
import { OnboardingWizard, DemoData, timingReport } from './onboarding/onboarding.js';
import { StatusPage } from './status/status.js';
import { RestoreDrill } from './continuity/drill.js';
import { ConfigEngine } from './iac/iac.js';
import { SlackApp, TeamsApp } from './integrations/chatops.js';
import { RateLimiter, ApiKeyStore } from './api/ratelimit.js';
import { coverageMap } from './connectors/catalog.js';
import { now, iso } from './util/time.js';
import { VaultError } from './util/errors.js';

export class Vault {
  /**
   * @param {object} [options]
   * @param {string|null} [options.dir] data directory; null = in-memory
   * @param {object} [options.kms] key management config (mode, rootKey, external callbacks)
   * @param {object} [options.modules] per-module toggle config
   * @param {object} [options.privacy] { enabled, jurisdiction }
   * @param {string[]} [options.administrators] named kill-switch administrators
   * @param {{privateKeyPem:string, publicKeyPem:string}} [options.signingKey] customer-held
   * @param {string|null} [options.mirrorDir] continuous mirror export destination
   * @param {'queue'|'reject'} [options.failSafe]
   * @param {boolean} [options.seedRules] install the rule template library
   */
  constructor(options = {}) {
    const {
      dir = null, kms: kmsOpts = {}, modules: moduleConfig = {},
      privacy: privacyOpts = {}, administrators = [], signingKey = null,
      mirrorDir = null, failSafe = 'queue', seedRules = true,
      witnesses = ['transparency-log', 'notary'], anchorEvery = 250,
      corporateDomains = []
    } = options;

    this.options = options;
    this.corporateDomains = corporateDomains;

    // ---- L11 storage ----------------------------------------------------
    // A cloud KMS, if one is configured, wraps the key hierarchy rather than
    // replacing it: scopes, versions and crypto-shredding still work the same
    // way, but the root material lives in the customer's AWS/Azure/GCP key and
    // Vault holds only ciphertext. Scopes must be primed before first write —
    // `await vault.primeKeyScope(scope)` — because an unprimed scope throws
    // rather than quietly degrading to a Vault-managed key.
    this.keyClient = null;
    this.keyBridge = null;
    if (kmsOpts.provider) {
      this.keyClient = createKeyClient(kmsOpts.provider, kmsOpts.providerConfig || kmsOpts);
      this.keyBridge = new RemoteKeyBridge(this.keyClient, {
        ttlMs: kmsOpts.keyCacheTtlMs, onEvent: (e) => this._keyEvent(e)
      });
    }
    this.kms = new Kms({
      ...kmsOpts,
      ...(this.keyBridge ? this.keyBridge.adapters() : {}),
      ...(this.keyBridge && !KEY_MODES.includes(kmsOpts.mode) ? { mode: 'cmk' } : {}),
      onEvent: (e) => this._keyEvent(e)
    });
    this.db = new Db({ dir, kms: this.kms });
    this.signingKey = signingKey;

    // ---- L8 ledger (constructed early: everything else logs to it) -------
    this.witnesses = witnesses.map((w) => (typeof w === 'string' ? new Witness(w) : w));
    this.ledger = new Ledger({
      collection: this.db.collection('ledger', { worm: true }),
      signingKey,
      witnesses: this.witnesses,
      anchorEvery
    });

    // ---- modules (built-in / connected / both) --------------------------
    this.modules = new ModuleRegistry({
      ledger: this.ledger,
      collection: this.db.collection('modules'),
      config: moduleConfig
    });

    // ---- alerts, kill switch --------------------------------------------
    this.alerts = new AlertManager({
      collection: this.db.collection('alerts'),
      cases: this.db.collection('cases'),
      ledger: this.ledger
    });
    this.killswitch = new KillSwitch({
      ledger: this.ledger,
      collection: this.db.collection('killswitch'),
      administrators
    });

    // ---- bring your own bucket (§5.2) ------------------------------------
    // Configured, not compiled in: a customer supplies driver + credentials and
    // Vault writes there, verifying the write-through on every put.
    this.bucket = options.bucket ? createBucket(options.bucket.driver, options.bucket) : null;

    // ---- storage tiering ------------------------------------------------
    this.tiering = new TieringEngine({
      isHeld: (id) => this.legal?.isHeld(id) ?? false,
      onEvent: (e) => this.ledger.append(e.type, e)
    });

    // ---- L2 archive ------------------------------------------------------
    this.archive = new Archive({
      collection: this.db.collection('conversations', { worm: true }),
      reviews: this.db.collection('supervision_reviews'),
      state: this.db.collection('archive_state'),
      ledger: this.ledger,
      tiering: this.tiering,
      modules: this.modules
    });

    // ---- L5 fact store, folders, entities --------------------------------
    this.folders = new FolderTree({
      collection: this.db.collection('folders'),
      ledger: this.ledger,
      onAlert: (a) => this.alerts.raise(a)
    });
    this.entities = new EntityResolver({
      collection: this.db.collection('entities'),
      ledger: this.ledger
    });
    this.facts = new FactStore({
      collection: this.db.collection('facts'),
      golden: this.db.collection('golden_facts'),
      versions: this.db.collection('fact_versions'),
      ledger: this.ledger,
      entities: this.entities,
      signingKey
    });

    // ---- L1 registry ------------------------------------------------------
    this.registry = new Registry({
      collection: this.db.collection('agents'),
      baselines: this.db.collection('agent_baselines'),
      discovery: this.db.collection('agent_discovery'),
      ledger: this.ledger,
      modules: this.modules
    });

    // ---- consent & legal --------------------------------------------------
    this.consent = new ConsentRegistry({
      collection: this.db.collection('consent'),
      ledger: this.ledger
    });
    this.legal = new LegalOps({
      facts: this.facts, archive: this.archive, ledger: this.ledger, kms: this.kms,
      db: this.db, consent: this.consent, entities: this.entities, tiering: this.tiering,
      signingKey
    });
    // Withdrawal triggers an actual purge, not a flag.
    this.consent.onWithdrawal = ({ subject, actor, reason }) => {
      try {
        return this.legal.erase({ subject, actor, reason: `consent withdrawn: ${reason}`, confirm: true });
      } catch (e) {
        return { error: e.message };
      }
    };

    // ---- privacy ----------------------------------------------------------
    this.privacy = new PrivacyMode({
      ledger: this.ledger,
      collection: this.db.collection('privacy'),
      ...privacyOpts
    });

    // ---- notification delivery (§9.8) -------------------------------------
    this.notifier = new Notifier({
      ledger: this.ledger,
      collection: this.db.collection('notifications'),
      transport: options.notifyTransport ?? null
    });
    // Every alert raised anywhere now has a way out to a human.
    this.alerts.subscribe((alert) => { this.notifier.notify(alert).catch(() => {}); });

    // ---- L3 extraction ----------------------------------------------------
    this.extractor = new Extractor();

    // ---- L4 the gate ------------------------------------------------------
    this.pii = new PiiScanner({
      onCredential: (e) => this.alerts.raise({
        severity: 'critical', kind: 'credential_detected',
        detail: `${e.count} credential(s) detected and blocked before storage (${e.detectors.join(', ')})`,
        subject: e.subject
      })
    });
    this.instructions = new InstructionDetector({
      goldenFacts: () => this.facts.goldenFacts().map((g) => ({ id: g.id, claim: g.claim }))
    });
    this.rules = new RulesEngine({ collection: this.db.collection('rules'), ledger: this.ledger });
    this.reconciler = new Reconciler({ findRelated: (c) => this.facts.findRelated(c) });
    this.temporal = new TemporalDetector({
      registry: this.registry,
      recentFacts: () => this.facts.live()
    });
    this.gate = new Gate({
      registry: this.registry, folders: this.folders, pii: this.pii,
      instructions: this.instructions, rules: this.rules, reconciler: this.reconciler,
      consent: this.consent, ledger: this.ledger, killswitch: this.killswitch,
      temporal: this.temporal, alerts: this.alerts, modules: this.modules,
      privacy: this.privacy, failSafe
    });

    // ---- L7 read path, search --------------------------------------------
    this.search = new SearchEngine({
      facts: this.facts, entities: this.entities, archive: this.archive,
      modules: this.modules, ledger: this.ledger,
      state: this.db.collection('search_state')
    });
    this.readPath = new ReadPath({
      facts: this.facts, folders: this.folders, search: this.search, registry: this.registry,
      ledger: this.ledger, killswitch: this.killswitch, temporal: this.temporal,
      alerts: this.alerts, instructions: this.instructions, consent: this.consent,
      privacy: this.privacy
    });

    // ---- review queue -----------------------------------------------------
    this.review = new ReviewQueue({
      collection: this.db.collection('reviews'),
      ledger: this.ledger, folders: this.folders, facts: this.facts,
      alerts: this.alerts, temporal: this.temporal, archive: this.archive, gate: this.gate
    });

    // ---- L6 hygiene -------------------------------------------------------
    this.hygiene = new HygieneEngine({
      facts: this.facts, folders: this.folders, entities: this.entities, search: this.search,
      ledger: this.ledger, archive: this.archive, registry: this.registry,
      alerts: this.alerts, tiering: this.tiering
    });

    // ---- trace, observability --------------------------------------------
    this.trace = new TraceEngine({
      facts: this.facts, archive: this.archive, ledger: this.ledger, registry: this.registry,
      folders: this.folders, search: this.search, alerts: this.alerts, tiering: this.tiering,
      signingKey
    });
    this.vaultTrace = new VaultTrace({
      spans: this.db.collection('spans'),
      evals: this.db.collection('eval_runs'),
      ledger: this.ledger,
      modules: this.modules,
      state: this.db.collection('observability_state')
    });

    // ---- L10 governance ---------------------------------------------------
    this.comply = new VaultComply({
      db: this.db, ledger: this.ledger, registry: this.registry, gate: this.gate,
      review: this.review, facts: this.facts, folders: this.folders,
      killswitch: this.killswitch, legal: this.legal, privacy: this.privacy,
      modules: this.modules, kms: this.kms, archive: this.archive
    });
    this.insure = new VaultInsure({
      registry: this.registry, ledger: this.ledger, gate: this.gate, review: this.review,
      folders: this.folders, killswitch: this.killswitch, comply: this.comply,
      privacy: this.privacy, facts: this.facts, modules: this.modules, archive: this.archive,
      state: this.db.collection('insure_state')
    });
    this.value = new ValueEngine({
      facts: this.facts, folders: this.folders, entities: this.entities, registry: this.registry,
      review: this.review, ledger: this.ledger, gate: this.gate, search: this.search,
      archive: this.archive, tiering: this.tiering, killswitch: this.killswitch,
      privacy: this.privacy, hygiene: this.hygiene
    });

    // ---- continuity -------------------------------------------------------
    this.continuity = new Continuity({
      facts: this.facts, archive: this.archive, ledger: this.ledger, rules: this.rules,
      folders: this.folders, entities: this.entities, registry: this.registry,
      legal: this.legal, db: this.db, signingKey, mirrorDir
    });

    // ---- L1 connectors ----------------------------------------------------
    this.connectors = new ConnectorManager({
      db: this.db, ledger: this.ledger, registry: this.registry, archive: this.archive,
      alerts: this.alerts, ingest: (raw) => this.ingest(raw)
    });
    this.gateway = new Gateway({
      registry: this.registry, ingest: (raw) => this.ingest(raw),
      ledger: this.ledger, alerts: this.alerts, posture: options.gatewayPosture || 'observe'
    });

    if (seedRules) this._seedRules();
    // ---- metering, lifecycle, API protection -------------------------------
    this.metering = new Metering({
      registry: this.registry, facts: this.facts, tiering: this.tiering,
      ledger: this.ledger, collection: this.db.collection('billing'),
      rates: options.rates ?? {}, caps: options.caps ?? {}
    });
    this.bulkImport = new BulkImport({
      ingest: (raw, ctx) => this.ingest(raw, ctx),
      ledger: this.ledger,
      collection: this.db.collection('import_jobs')
    });
    this.offboarding = new Offboarding({
      vault: this, ledger: this.ledger,
      collection: this.db.collection('offboarding'), signingKey
    });
    this.apiKeys = new ApiKeyStore({ collection: this.db.collection('api_keys'), ledger: this.ledger });
    this.rateLimiter = new RateLimiter({
      perMinute: options.apiRateLimitPerMinute ?? 600,
      onLimit: ({ key, path }) => this.alerts.raise({
        severity: 'low', kind: 'api_rate_limited', subject: key,
        detail: `rate limit hit on ${path}`
      })
    });

    // Day 0: the guided setup checks live system state rather than a form, and
    // the sample tenant refuses to seed over real data.
    this.onboarding = new OnboardingWizard({ vault: this, ledger: this.ledger });
    this.demo = new DemoData({ vault: this, ledger: this.ledger });
    // Deliberately NOT `this.status` — that name is already the system-health
    // summary method, and shadowing it silently broke `vault status` on the CLI.
    this.statusPage = new StatusPage({ vault: this, ledger: this.ledger, notifier: this.notifier });

    // The restore drill spawns a *fresh* Vault from the export alone, so it
    // proves the export is sufficient rather than proving this process still
    // has the data in memory.
    // Configuration as code: plan/apply/drift against the same API a Terraform
    // provider would call.
    this.config = new ConfigEngine({ vault: this, ledger: this.ledger });

    // Chat apps are constructed only when a signing secret is present. An
    // endpoint that accepts unverified payloads is a remote kill switch for
    // whoever finds the URL, so there is no "no secret configured" mode.
    this.slack = options.slack?.signingSecret
      ? new SlackApp({ vault: this, ledger: this.ledger, ...options.slack })
      : null;
    this.teams = options.teams?.securityToken
      ? new TeamsApp({ vault: this, ledger: this.ledger, ...options.teams })
      : null;

    this.drill = new RestoreDrill({
      vault: this, ledger: this.ledger,
      collection: this.db.collection('restore_drills'),
      spawn: ({ dir: freshDir }) => new Vault({ dir: freshDir, signingKey, seedRules: false })
    });

    this.startedAt = now();
  }

  _keyEvent(e) {
    // Key events are ledger events too, but the ledger may not exist during the
    // KMS's own construction.
    if (!this.ledger) return;
    const type = { 'key.created': 'key.created', 'key.rotated': 'key.rotated', 'key.destroyed': 'key.destroyed', 'key.share_presented': 'key.share_presented' }[e.type];
    if (type) {
      try { this.ledger.append(type, { subject: e.scope ?? e.holder, keyId: e.keyId, actor: e.actor ?? 'system' }); } catch { /* non-fatal */ }
    }
  }

  _seedRules() {
    for (const t of RULE_TEMPLATES) {
      try {
        this.rules.create({
          ...t, state: 'draft', actor: 'vault:templates',
          reason: 'installed from the rule template library — enable after a backtest'
        });
      } catch { /* a template that fails to compile is skipped, not fatal */ }
    }
  }

  // =========================================================================
  // THE WRITE PATH
  // =========================================================================

  /**
   * The whole pipeline: archive → extract → gate → store.
   *
   * @param {object} raw an interaction (transcript, turns, or plain content)
   * @param {object} [ctx] overrides ({ actor, purpose, region, breakGlass, ... })
   * @returns {object} what happened to every candidate fact
   */
  ingest(raw, ctx = {}) {
    const started = process.hrtime.bigint();

    // Employee Privacy Mode can exclude a context from capture entirely.
    const capture = this.privacy.shouldCapture({ ...raw, ...ctx });
    if (!capture.capture) {
      return { captured: false, reason: capture.reason, context: capture.context ?? null, facts: [] };
    }

    // Kill switch: writes may be refused or queued, never passed unchecked.
    const writeBlock = this.killswitch.writesBlocked({ ...raw, ...ctx });
    if (writeBlock.blocked) {
      if (this.gate.failSafe === 'queue') {
        const q = this.killswitch.enqueue({ raw, ctx });
        return { captured: false, queued: true, position: q.position, reason: writeBlock.reason, agentMessage: this.killswitch.agentMessage(), facts: [] };
      }
      throw new VaultError('killswitch', writeBlock.reason, { agentMessage: this.killswitch.agentMessage() });
    }

    // ---- L2: SEAL FIRST, before extraction, before any check -------------
    const conversation = this.archive.seal(raw);

    // ---- L3: extract candidates -----------------------------------------
    const agent = this.registry.get(raw.agentId ?? ctx.agentId);
    const { candidates, stats } = this.extractor.extract(conversation, {
      agent,
      channelTrust: this.gate._checkChannel({ channel: raw.channel }).trust,
      knownEntities: this.entities.all(),
      folderHint: ctx.folderHint ?? raw.folderHint,
      project: ctx.project ?? agent?.projects?.[0],
      systemOfRecord: raw.channel === 'system_of_record'
    });

    // ---- L4: the gate, per candidate -------------------------------------
    const results = [];
    const verdicts = [];
    for (const candidate of candidates) {
      // Folders build themselves as facts arrive (§11.1). Creating it BEFORE the
      // gate matters: otherwise the wall check resolves to the nearest existing
      // ancestor and the fact is filed one level too high.
      if (candidate.proposedFolder) {
        try { this.folders.ensure(candidate.proposedFolder); } catch { /* unroutable path */ }
      }
      const gateCtx = {
        agentId: raw.agentId ?? ctx.agentId,
        credential: ctx.credential,
        origin: ctx.origin,
        channel: raw.channel,
        source: raw.source ?? ctx.source ?? {},
        conversation,
        connectorMode: raw.connectorMode,
        folderHint: ctx.folderHint ?? candidate.proposedFolder,
        folderExplicit: Boolean(ctx.folderHint ?? raw.folderHint),
        region: raw.region ?? ctx.region,
        storageRegion: ctx.storageRegion,
        dataSubjectRegion: ctx.dataSubjectRegion,
        modelVersion: raw.modelVersion ?? ctx.modelVersion,
        purpose: ctx.purpose ?? 'memory_governance',
        explicitLabel: ctx.label,
        externalLabel: raw.externalLabel,
        businessRecord: raw.regulatoryRecord != null,
        regulatoryRecord: raw.regulatoryRecord,
        privileged: raw.privileged,
        breakGlass: ctx.breakGlass,
        freezeWindow: ctx.freezeWindow,
        corporateDomains: this.corporateDomains,
        businessOwner: ctx.businessOwner,
        technicalOwner: ctx.technicalOwner
      };

      const verdict = this.gate.evaluate(candidate, gateCtx);

      // A reviewer-confirmed pattern can auto-approve — but never one carrying a
      // hard signal, and the rule is human-enabled and time-boxed.
      if (verdict.outcome === 'hold' && this.review.isAutoApproved(candidate, verdict)) {
        verdict.outcome = 'pass';
        verdict.reasons.push('auto-approved by a human-enabled pattern rule');
      }

      verdicts.push({ candidate, verdict, gateCtx });
    }

    // A message that carries an instruction is a compromised source, so nothing
    // extracted from it is trustworthy — not even the sentences that look
    // innocent. Holding only the payload is exactly the split-message attack:
    // bundle the poison with the fact you actually want planted, let the poison
    // be caught, and the fact lands. Contaminate the whole conversation instead.
    const contaminated = verdicts.find(({ verdict }) => verdict.instruction?.detected);
    if (contaminated) {
      for (const item of verdicts) {
        if (item.verdict.outcome === 'pass' || item.verdict.outcome === 'mask') {
          item.verdict.outcome = 'hold';
          item.verdict.reasons.push(
            'another part of this same message was instruction-shaped — everything extracted from it is held together, '
            + 'because splitting poison across a message is how a benign-looking fact gets planted'
          );
        }
      }
    }

    for (const { candidate, verdict, gateCtx } of verdicts) {
      results.push(this._applyVerdict(candidate, verdict, gateCtx, conversation));
    }

    if (agent) {
      this.registry.recordUsage(agent.id, {
        write: results.filter((r) => r.outcome === 'pass' || r.outcome === 'mask').length,
        held: results.filter((r) => r.outcome === 'hold' || r.outcome === 'escalate').length,
        blocked: results.filter((r) => r.outcome === 'block').length,
        costUsd: raw.costUsd ?? 0
      });
    }

    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    return {
      captured: true,
      conversationId: conversation.id,
      sealHash: conversation.sealHash,
      extraction: stats,
      facts: results,
      summary: summarise(results),
      latencyMs: Math.round(elapsed * 100) / 100
    };
  }

  _applyVerdict(candidate, verdict, ctx, conversation) {
    const reconciliation = verdict.reconciliation;

    // Duplicate / refinement paths fold into an existing fact rather than
    // creating a new one.
    if (verdict.outcome === 'pass' && reconciliation?.action === 'merge') {
      const merged = this.facts.merge(reconciliation.into, candidate, { reason: reconciliation.explanation });
      this.search.index(merged);
      return { outcome: 'merged', factId: merged.id, claim: candidate.claim, explanation: reconciliation.explanation, verdict };
    }
    if (verdict.outcome === 'pass' && reconciliation?.action === 'refine') {
      const refined = this.facts.refine(reconciliation.into, candidate, { reason: reconciliation.explanation });
      this.search.index(refined);
      return { outcome: 'refined', factId: refined.id, claim: candidate.claim, explanation: reconciliation.explanation, verdict };
    }

    const fact = this.facts.write(candidate, verdict, ctx);

    if (verdict.outcome === 'pass' || verdict.outcome === 'mask') {
      this.search.index(fact);
      // Contradiction resolved in favour of the incoming fact.
      if (reconciliation?.action === 'supersede') {
        this.facts.supersede(reconciliation.against, fact, {
          actor: ctx.agentId ?? 'system',
          reason: reconciliation.explanation,
          decidedBy: reconciliation.decidedBy
        });
      }
    }

    if (['hold', 'escalate', 'require-4-eyes'].includes(verdict.outcome)) {
      const item = this.review.enqueue({ factId: fact.id, candidate, verdict, ctx });
      return { outcome: verdict.outcome, factId: fact.id, reviewId: item.id, claim: candidate.claim, reasons: verdict.reasons, explanation: verdict.explanation, verdict };
    }

    if (verdict.outcome === 'block') {
      this.alerts.raise({
        severity: reconciliation?.golden ? 'critical' : 'medium',
        kind: reconciliation?.golden ? 'golden_overwrite_attempt' : 'write_blocked',
        actor: ctx.agentId, subject: fact.id,
        detail: verdict.reasons.join('; ')
      });
      if (reconciliation?.golden) {
        this.ledger.append('golden.overwrite_refused', {
          subject: reconciliation.against, actor: ctx.agentId,
          attemptedBy: candidate.saidBy?.name, channel: ctx.channel
        });
      }
    }

    if (verdict.outcome === 'quarantine') {
      this.folders.ensure('_quarantine/');
      this.facts.quarantine(fact.id, { actor: ctx.agentId ?? 'system', reason: verdict.reasons.join('; ') });
    }

    return {
      outcome: verdict.outcome,
      factId: fact.id,
      claim: candidate.claim,
      reasons: verdict.reasons,
      explanation: verdict.explanation,
      verdict
    };
  }

  // =========================================================================
  // THE READ PATH
  // =========================================================================

  /** @see ReadPath#read */
  read(query, ctx = {}) {
    return this.readPath.read(query, ctx);
  }

  /** The labelled block an agent actually receives. */
  ask(query, ctx = {}) {
    return this.readPath.render(this.read(query, ctx));
  }

  // =========================================================================
  // convenience surface
  // =========================================================================

  registerAgent(spec) { return this.registry.register(spec); }
  issueCredential(agentId, opts) { return this.registry.issueCredential(agentId, opts); }
  createGoldenFact(spec, auth) {
    const g = this.facts.createGolden(spec, auth);
    // Golden facts rank first at read time — which requires them to be in the
    // index at all.
    this.search.index(g);
    return g;
  }
  createRule(spec) { return this.rules.create(spec); }
  backtest(spec, opts) { return this.rules.backtest(spec, this.gate.history(), opts); }
  needsReview(q) { return this.review.list(q); }
  decide(id, d) { return this.review.decide(id, d); }
  traceFact(id) { return this.trace.trace(id); }
  contagion(id) { return this.trace.contagion(id); }
  undo(opts) { return this.trace.undo(opts); }
  incidentBundle(id, opts) { return this.trace.incidentBundle(id, opts); }
  runHygiene(opts) { return this.hygiene.run(opts); }
  verifyLedger(range) { return this.ledger.verify(range); }
  /** The routine check: only what has happened since the last external anchor. */
  verifyLedgerTail() { return this.ledger.verifySinceAnchor(); }
  exportAll(opts) { return this.continuity.export(opts); }
  coverage() { return coverageMap({ connected: this.connectors.all().map((c) => c.catalogId) }); }

  /**
   * Risk-score one memory store for the Map (§23).
   *
   * Ranked by what actually goes wrong: nobody accountable, nothing expiring,
   * personal data with no lawful basis, an unlabelled or unwalled store holding
   * sensitive material. Each factor names its own fix, because a score with no
   * remedy is just an accusation.
   */
  folderRisk(folder) {
    const f = typeof folder === 'string' ? this.folders.get(folder) : folder;
    if (!f) throw new VaultError('not_found', 'folder not found', { path: String(folder) });
    const facts = this.facts.byFolder(f.path);
    const live = facts.filter((x) => x.status === 'live');
    const factors = [];
    const add = (weight, finding, fix) => factors.push({ weight, finding, fix });

    if (!f.businessOwner || !f.technicalOwner) {
      add(25, `no ${!f.businessOwner ? 'business' : 'technical'} owner — an unowned store is a finding`, 'assign an owner on the Walls screen');
    }
    if (!f.retention) add(15, 'no retention schedule — nothing here ever expires', 'set a retention schedule for this folder');
    if (!f.residency) add(5, 'no residency pinned — cross-border rules cannot be enforced', 'pin a region');

    const withPii = live.filter((x) => (x.piiFindings || []).length > 0);
    if (withPii.length) {
      add(Math.min(25, 5 + withPii.length), `${withPii.length} fact(s) carry personal data`, 'confirm a lawful basis and a retention limit');
    }
    const noBasis = live.filter((x) => (x.entities || []).some((e) => e.type === 'person') && !x.consentBasis);
    if (noBasis.length) {
      add(Math.min(30, 10 + noBasis.length * 2), `${noBasis.length} fact(s) about a person with no recorded lawful basis`, 'record a basis, or erase them');
    }
    const sensitive = live.filter((x) => ['confidential', 'secret'].includes(x.sensitivity));
    if (sensitive.length && !f.hardWall) {
      add(20, `${sensitive.length} confidential-or-higher fact(s) in a store with no hard wall`, 'promote this folder to a hard wall');
    }
    const singleSource = live.filter((x) => (x.corroboratingSources ?? 1) < 2 && x.claimType === 'guessed');
    if (singleSource.length) add(10, `${singleSource.length} single-source guessed fact(s)`, 'corroborate or demote them');
    const stale = live.filter((x) => x.decaying);
    if (stale.length) add(5, `${stale.length} decaying fact(s)`, 'reconfirm or let them expire');

    const score = Math.min(100, factors.reduce((n, x) => n + x.weight, 0));
    return {
      path: f.path,
      businessOwner: f.businessOwner, technicalOwner: f.technicalOwner,
      wall: f.hardWall ? '🧱 hard wall' : `${f.read.join(', ')} read`,
      retention: f.retention, residency: f.residency,
      facts: facts.length, liveFacts: live.length,
      risk: score,
      band: score >= 60 ? 'high' : score >= 30 ? 'medium' : score > 0 ? 'low' : 'none',
      factors: factors.sort((x, y) => y.weight - x.weight)
    };
  }

  /** Run the tiering lifecycle for real: hot → warm → cold → archive (§5.3). */
  runStorageLifecycle({ actor, dryRun = false } = {}) {
    if (!actor) throw new VaultError('forbidden', 'running the storage lifecycle requires a named actor');
    const preview = this.tiering.previewLifecycle();
    if (dryRun) return { dryRun: true, ...preview };
    const result = this.tiering.runLifecycle();
    this.ledger.append('admin.action', {
      subject: 'storage', actor, action: 'storage.lifecycle_run',
      moved: result.moved, heldBack: preview.moves.filter((m) => m.heldBack).length
    });
    return { ...result, heldBack: preview.moves.filter((m) => m.heldBack).length };
  }

  /** ⚙️ ADMIN → STORAGE. What Vault holds, where, and under whose keys. */
  storage() {
    return {
      db: this.db.stats(),
      tiers: this.tiering.costReport(),
      lifecycle: this.tiering.previewLifecycle(),
      keys: { mode: this.kms.mode, shredded: this.kms.inventory().filter((k) => k.shredded).length },
      bucket: this.bucket
        ? {
          driver: this.bucket.config.driver || this.bucket.name,
          bucket: this.bucket.config.bucket || this.bucket.config.container || null,
          region: this.bucket.config.region ?? null,
          immutability: this.bucket.config.objectLockMode || this.bucket.config.immutable || null,
          contentLeavesTheEstate: !(this.bucket instanceof HashOnlyBucketType),
          stats: this.bucket.stats
        }
        : { driver: 'vault-managed', note: 'no customer bucket configured — data is in Vault storage' },
      driversAvailable: Object.keys(DRIVERS),
      keyService: this.keyBridge ? this.keyBridge.status() : { provider: 'vault-managed' }
    };
  }

  /**
   * Load the wrapping key for a namespace from the customer's cloud KMS.
   *
   * Must be called before the first write to a scope when a provider is
   * configured. It is deliberately explicit rather than lazy: a lazy fetch on
   * the write path means a KMS outage turns into a stalled ingest queue with no
   * obvious cause, whereas a startup call fails at startup, where someone is
   * looking.
   */
  async primeKeyScope(scope, { actor = 'system' } = {}) {
    if (!this.keyBridge) {
      throw new VaultError('config', 'no cloud KMS is configured — pass kms: { provider: "aws"|"azure"|"gcp", ... }');
    }
    const out = await this.keyBridge.primeScope(scope);
    this.ledger.append('admin.action', { subject: scope, actor, action: 'key.scope_primed', provider: this.keyClient.provider });
    return out;
  }

  /** Prove the customer's KMS credentials, key policy and network path work. */
  async keyServiceHealth() {
    if (!this.keyClient) {
      return {
        ok: true, provider: 'vault-managed', mode: this.kms.mode,
        note: 'keys are derived inside Vault. For "the key never leaves our HSM", configure kms.provider.'
      };
    }
    const health = await this.keyClient.healthCheck();
    if (!health.ok) {
      this.alerts.raise({
        kind: 'kms_unreachable', severity: 'critical', subject: this.keyClient.provider,
        detail: health.message || 'the customer key service did not answer'
      });
    }
    return health;
  }

  /** ⚙️ ADMIN → MODULES. */
  moduleTable() { return this.modules.table(); }
  setModule(name, state, opts) { return this.modules.set(name, state, opts); }

  /** 🔒 Employee Privacy Mode. */
  privacyPreview(jurisdiction) { return this.privacy.preview(jurisdiction); }
  applyPrivacyMode(jurisdiction, opts) { return this.privacy.apply(jurisdiction, opts); }

  /** 🗺️ THE MAP — every AI tool, memory store, mode, owner, risk, coverage. */
  map() {
    const agents = this.registry.inventory();
    const shadow = this.registry.shadowAgents();
    const connectors = this.connectors.health();
    return {
      generatedAt: iso(),
      agents: agents.map((a) => ({
        ...a,
        risk: riskScore(a),
        coverage: a.mode === 'inline' ? 'full — can hold, block, mask and escalate'
          : a.mode === 'gateway' ? 'discovery + optional enforcement'
          : 'observation only — Watch mode cannot block',
        health: a.lastSeen ? 'seen' : 'never seen'
      })),
      shadowAgents: shadow,
      connectors,
      memoryStores: [
        { store: 'Vault fact store', facts: this.facts.stats().total, owner: 'Vault', governed: true },
        ...this.connectors.all().filter((c) => c.category === 'memory').map((c) => ({
          store: c.name, owner: c.owner, governed: true, note: 'Vault sits in front as the gate'
        }))
      ],
      folders: this.folders.all().map((f) => this.folderRisk(f)),
      findings: [...this.registry.findings(), ...this.folders.findings()],
      health: this.value.health(),
      insuranceReadiness: {
        gaps: this.insure.gaps().length,
        killSwitchTested: Boolean(this.killswitch.lastTest()),
        ready: this.insure.gaps().filter((g) => g.impact === 'high').length === 0
      },
      coverageMap: this.coverage()
    };
  }

  /** Everything, for the dashboard and the CLI status screen. */
  status() {
    return {
      startedAt: iso(this.startedAt),
      uptimeMs: now() - this.startedAt,
      facts: this.facts.stats(),
      archive: this.archive.stats(),
      ledger: { entries: this.ledger.length, head: this.ledger.head, anchors: this.ledger.anchors.length },
      agents: { total: this.registry.all().length, active: this.registry.active().length, shadow: this.registry.shadowAgents().length },
      review: this.review.stats(),
      alerts: this.alerts.stats(),
      gate: this.gate.latencyReport(),
      killswitch: this.killswitch.state(),
      privacy: this.privacy.status(),
      modules: this.modules.table(),
      storage: { ...this.db.stats(), cost: this.tiering.costReport() },
      search: this.search.stats(),
      trace: this.vaultTrace.stats(),
      health: this.value.health(),
      connectors: this.connectors.health().length
    };
  }

  /** Self-check — the `vault doctor` command. */
  doctor() {
    const problems = [];
    const warn = (severity, area, detail, fix) => problems.push({ severity, area, detail, fix });

    const chain = this.ledger.verify();
    if (!chain.ok) warn('critical', 'ledger', `chain verification failed: ${chain.problems.length} problem(s)`, 'investigate immediately — the ledger is the evidence');

    const integrity = this.facts.verifyIntegrity();
    if (!integrity.ok) warn('critical', 'facts', `${integrity.problems.length} fact(s) failed integrity check`, 'restore from the mirror and investigate');

    const consistency = this.hygiene.consistencyCheck();
    if (!consistency.ok) warn('high', 'consistency', `${consistency.problems.length} three-way reconciliation problem(s)`, 'run hygiene and review the report');

    for (const f of this.registry.findings()) warn(f.severity === 'high' ? 'high' : 'medium', 'agents', f.finding, f.fix ?? 'assign owners or register the agent');
    for (const f of this.folders.findings()) warn('medium', 'folders', `${f.path}: ${f.finding}`, 'assign a business and technical owner');

    if (!this.killswitch.specification().namedAdministrators.length) {
      warn('high', 'killswitch', 'no named kill switch administrator', 'name one — it is an RFP question and an insurance question');
    }
    if (!this.killswitch.lastTest()) {
      warn('medium', 'killswitch', 'the kill switch has never been tested', 'run vault.killswitch.test({ actor }) — insurers ask for the date');
    }
    if (!this.signingKey) {
      warn('high', 'proof', 'no customer-held signing key configured', 'generate one: a chain we sign ourselves proves nothing to an adversary');
    }
    if (!this.continuity.mirrorEnabled) {
      warn('high', 'continuity', 'continuous mirror export is not configured', 'enable it — this is the answer to "what if you disappear?"');
    }
    if (!this.privacy.isOn()) {
      warn('medium', 'privacy', 'Employee Privacy Mode is off', 'required for EU/UK employees — one click in Admin');
    }
    const enforced = this.rules.all().filter((r) => r.state === 'enforce');
    if (!enforced.length) warn('medium', 'rules', 'no rules are enforcing', 'backtest a template from the library, then enable it');

    return {
      at: iso(),
      ok: problems.filter((p) => p.severity === 'critical').length === 0,
      problems: problems.sort((a, b) => RANK[a.severity] - RANK[b.severity]),
      checks: { ledger: chain.ok, factIntegrity: integrity.ok, consistency: consistency.ok }
    };
  }

  close() {
    try { this.continuity._unsubscribe?.(); } catch { /* nothing to release */ }
  }
}

const RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function riskScore(agent) {
  let score = 0;
  if (agent.mode === 'watch') score += 30;
  if (!agent.pinnedModel) score += 15;
  if (!agent.businessOwner || !agent.technicalOwner) score += 25;
  if (agent.sensitivityCeiling === 'secret') score += 15;
  if (!agent.folders?.length) score += 10;
  if (agent.blocked > 0) score += Math.min(15, agent.blocked);
  return { score: Math.min(100, score), band: score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low' };
}

function summarise(results) {
  const counts = {};
  for (const r of results) counts[r.outcome] = (counts[r.outcome] || 0) + 1;
  const parts = Object.entries(counts).map(([k, v]) => `${v} ${k}`);
  return parts.length ? parts.join(' · ') : 'no candidate facts extracted';
}

export { Witness } from './ledger/ledger.js';
export { Ledger } from './ledger/ledger.js';
export { ConfigEngine, RESOURCES, renderPlan } from './iac/iac.js';
export { SlackApp, TeamsApp } from './integrations/chatops.js';
export { I18n, LOCALES, coverage as localeCoverage, negotiate } from './ui/i18n.js';
export { Benchmark, Samples, growth, BUDGETS } from './observability/bench.js';
export { RestoreDrill } from './continuity/drill.js';
export { StatusPage, COMPONENTS } from './status/status.js';
export { OnboardingWizard, DemoData, STEPS as SETUP_STEPS } from './onboarding/onboarding.js';
export { ExternalKeyService } from './storage/kms.js';
export { AwsKmsClient, AzureKeyVaultClient, GcpKmsClient, createKeyClient, RemoteKeyBridge, KEY_PROVIDERS } from './storage/kmsclient.js';
export { RULE_TEMPLATES } from './gate/rules.js';
export { CHANNEL_TRUST, OUTCOMES } from './gate/gate.js';
export { CLAIM_TYPES } from './extract/extract.js';
export { JURISDICTIONS, SECTOR_PACKS, listJurisdictions } from './privacy/jurisdictions.js';
export { CONNECTORS, coverageMap, MODES } from './connectors/catalog.js';
export { MODULES, PARITY } from './modules/modules.js';
export { CONTROLS, FRAMEWORKS } from './comply/comply.js';
export { DEPLOYMENT_MODELS, BUCKET_TARGETS, TIERS } from './storage/tiers.js';
export default Vault;
