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
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Db } from './storage/db.js';
import { Kms, KEY_MODES } from './storage/kms.js';
import { FieldCrypto, FIELD_POLICIES } from './storage/fields.js';
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
import { ModelProvider } from './ai/provider.js';
import { MemoryFile } from './ai/memory.js';
import { Journal } from './audit/journal.js';
import { Librarian } from './ai/orchestrate.js';
import { ask } from './ai/ask.js';
import { refilePass } from './ai/refile.js';
import { RedTeamWatchdog } from './security/watchdog.js';
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
import { BackupEngine, BackupStore } from './continuity/backup.js';
import { ConfigEngine } from './iac/iac.js';
import { SlackApp, TeamsApp } from './integrations/chatops.js';
import { SamlProvider, OidcProvider, SessionStore, AccessPolicy, MfaRegistry } from './identity/identity.js';
import { ScimService } from './identity/scim.js';
import { PrivilegedAccess } from './identity/privileged.js';
import { RateLimiter, ApiKeyStore } from './api/ratelimit.js';
import { analyseAttachment } from './media/media.js';
import { coverageMap } from './connectors/catalog.js';
import { now, iso } from './util/time.js';
import { VaultError } from './util/errors.js';

/**
 * How many individually-attributed read entries one query may write.
 *
 * A bulk read of ten thousand facts should not write ten thousand journal
 * entries — but it must not silently write none either, and it must say which
 * of the two happened. Above this the query entry still names every id it
 * returned, and a marker records that per-fact attribution was truncated.
 */
const JOURNAL_READ_CAP = 100;

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
    this.administrators = [...administrators];

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
    // A Vault-managed root key is random per process, which is fine when
    // nothing is encrypted and fatal once something is: the next restart could
    // not read its own store. So when Vault manages the key AND there is a data
    // directory, the root is persisted beside it — see _rootKeyFile for exactly
    // what that does and does not protect against.
    this.rootKeySource = kmsOpts.rootKey ? 'customer-supplied'
      : kmsOpts.provider ? `${kmsOpts.provider} key service`
        : dir ? 'vault-managed, persisted in the data directory'
          : 'vault-managed, in memory only';
    const managedRoot = (!kmsOpts.rootKey && !kmsOpts.provider && dir)
      ? Vault._rootKeyFile(dir)
      : null;
    this.kms = new Kms({
      ...kmsOpts,
      ...(managedRoot ? { rootKey: managedRoot } : {}),
      ...(this.keyBridge ? this.keyBridge.adapters() : {}),
      ...(this.keyBridge && !KEY_MODES.includes(kmsOpts.mode) ? { mode: 'cmk' } : {}),
      // Destroyed keys are recorded on disk, so a crypto-shred survives the
      // restart it would otherwise be undone by.
      ...(dir ? { tombstonePath: join(dir, 'shredded.jsonl') } : {}),
      onEvent: (e) => this._keyEvent(e)
    });
    this.db = new Db({ dir, kms: this.kms });
    this.signingKey = signingKey;

    /**
     * Encryption at rest, actually switched on.
     *
     * The envelope machinery has always worked — per-object DEK, per-scope KEK,
     * crypto-shredding — but no collection was ever constructed with
     * `encrypted: true`, so transcripts and facts sat on disk as readable JSON.
     * A capability nothing enables is not a control, and "AES-256-GCM at rest"
     * was not true of the default build.
     *
     * The key scope is the namespace, so destroying `ns:hr` makes every HR
     * record on disk, in every backup and in the archive tier undecryptable in
     * one step — which is what makes the erasure receipt's crypto-shred claim
     * real rather than aspirational.
     *
     * Records are plaintext in memory, so the gate, search, verification and
     * export are unaffected; only the bytes on disk change.
     *
     * How much this is worth depends entirely on where the key is, and the
     * product reports which case it is in rather than letting a reader assume
     * the strongest one. See `storage().encryptionAtRest.protectsAgainst`.
     */
    this.encryptAtRest = options.encryptAtRest !== false;
    /**
     * The key scope decides what a crypto-shred can actually destroy, so it has
     * to match what the erasure path destroys — otherwise erasure destroys a key
     * that was not the one encrypting the record, and the receipt is false.
     *
     * Facts carry a folder, so they key by namespace: shredding `ns:hr` removes
     * every HR fact from disk and from every backup at once.
     *
     * Conversations do not — a transcript can produce facts in several folders,
     * so no single namespace owns it. They key per conversation, which is
     * exactly the scope `LegalOps.erase` destroys (`conversation:<id>`) when it
     * removes a transcript from the WORM archive.
     */
    const nsOf = (doc) => `ns:${String(doc?.folder ?? doc?.namespace ?? 'unfiled').split('/')[0] || 'unfiled'}`;
    const perConversation = (doc) => `conversation:${doc?.id ?? 'unknown'}`;
    this._contentCollection = (name, extra = {}) => this.db.collection(name, {
      encrypted: this.encryptAtRest, keyScope: nsOf, ...extra
    });

    /**
     * Field-level encryption for collections that are NOT whole-record sealed.
     *
     * The operational collections — sessions, SCIM users — have to stay
     * partly legible: an operator debugging a login needs to see that a session
     * exists, when it was created and whether it was revoked. Sealing the whole
     * record would take that away; leaving it alone put employee email
     * addresses, names and departments on disk in the clear, which is what a
     * raw scan of a live data directory showed.
     *
     * So the identifying columns are sealed under their own key scopes and the
     * operational ones are not. `principal` and `userName` additionally carry a
     * blind index, so "revoke every session for this person" and SCIM's
     * `userName eq` filter still work without a key.
     */
    this.fieldCrypto = new FieldCrypto({ kms: this.kms });
    this._fields = (policy) => ({ fields: { policy, crypto: this.fieldCrypto } });

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
      collection: this._contentCollection('conversations', { worm: true, keyScope: perConversation }),
      reviews: this._contentCollection('supervision_reviews'),
      state: this.db.collection('archive_state'),
      ledger: this.ledger,
      tiering: this.tiering,
      modules: this.modules
    });

    // ---- L5 fact store, folders, entities --------------------------------
    this.folders = new FolderTree({
      collection: this.db.collection('folders'),
      ledger: this.ledger,
      onAlert: (a) => this.alerts.raise(a),
      administrators
    });
    this.entities = new EntityResolver({
      collection: this._contentCollection('entities'),
      ledger: this.ledger
    });
    this.facts = new FactStore({
      collection: this._contentCollection('facts'),
      golden: this._contentCollection('golden_facts'),
      versions: this._contentCollection('fact_versions'),
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
      collection: this._contentCollection('consent'),
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

    // ---- the model layer, optional by construction -------------------------
    // Absent by default. Filing and answers both run without it and say which
    // path produced their result, so an air-gapped deployment loses wording,
    // never correctness. Configure `ollama` and it runs on the customer's own
    // hardware, which is the only configuration where a payroll claim can be
    // classified by a model without that being a disclosure.
    this.model = new ModelProvider(options.model ?? {});

    // ---- what the filing has learned about THIS company ---------------------
    // One small signed file. Consulted before any model call, which is why most
    // facts get filed without one — see src/ai/memory.js. Deleting it costs
    // speed and nothing else.
    this.memory = new MemoryFile({
      path: options.memoryPath ?? (dir ? join(dir, 'ai-memory.vmem') : null),
      signingKey,
      tenant: options.tenant ?? 'default'
    });

    // ---- the exhaustive record, beside the sealed one ----------------------
    // The ledger is small, content-free and provable. This is complete, and
    // holds what the ledger deliberately refuses so that "show me everything
    // that ever happened to this record" has a single answer rather than a
    // five-way join. See src/audit/journal.js.
    this.journal = new Journal({
      collection: this._contentCollection('journal'),
      ledger: this.ledger,
      signingKey
    });

    /**
     * Who may ask questions of the memory in natural language.
     *
     * Deliberately a separate, narrower list than "who can read facts". The
     * ordinary read path returns what you are cleared for and nothing else, and
     * an agent hitting it retrieves the four facts it needs. Ask is a different
     * shape of access: it ranges over everything at once, summarises, and hands
     * back prose that is easy to paste somewhere it should not go. So it starts
     * closed — administrators, plus anyone explicitly named — and every use is
     * journalled whether it succeeded or not.
     */
    this.askAllowlist = new Set([...(options.askAllowlist ?? []), ...administrators]);

    // ---- review queue -----------------------------------------------------
    this.review = new ReviewQueue({
      collection: this._contentCollection('reviews'),
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
      // Spans and eval runs carry model inputs and outputs — which is customer
      // content whatever the observability screen calls it.
      spans: this._contentCollection('spans'),
      evals: this._contentCollection('eval_runs'),
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

    // ---- identity ---------------------------------------------------------
    // Sessions are server-side state so that SCIM deprovisioning revokes access
    // on the NEXT REQUEST, not at the next token refresh. That requirement is
    // what makes this a session store rather than a JWT issuer.
    this.sessions = new SessionStore({
      collection: this.db.collection('sessions', this._fields({ principal: 'sealed+indexed', ip: 'sealed', userAgent: 'sealed' })),
      ledger: this.ledger,
      ...(options.sessions ?? {})
    });
    this.mfa = new MfaRegistry({ ledger: this.ledger });
    this.accessPolicy = new AccessPolicy({ ledger: this.ledger, ...(options.accessPolicy ?? {}) });
    this.saml = options.saml ? new SamlProvider({ ...options.saml, ledger: this.ledger }) : null;
    this.oidc = options.oidc ? new OidcProvider({ ...options.oidc, ledger: this.ledger }) : null;
    this.scim = new ScimService({
      sessions: this.sessions, ledger: this.ledger,
      collection: this.db.collection('scim_users', this._fields({
        // displayName defaults to userName, so leaving it out would have put
        // the address back on disk beside the sealed copy of itself.
        userName: 'sealed+indexed', externalId: 'sealed+indexed',
        emails: 'sealed', name: 'sealed', displayName: 'sealed', department: 'sealed'
      })),
      ...(options.scim ?? {})
    });
    // The half of break-glass that never existed: enforcement lived in
    // folders.check() but nothing could grant a session, so the emergency path
    // in practice was "give someone the admin role".
    this.privileged = new PrivilegedAccess({
      ledger: this.ledger, sessions: this.sessions,
      collection: this.db.collection('breakglass'),
      alerts: this.alerts,
      notify: (e) => this.notifier?.notify(e),
      ...(options.privileged ?? {})
    });

    this.drill = new RestoreDrill({
      vault: this, ledger: this.ledger,
      collection: this.db.collection('restore_drills'),
      spawn: ({ dir: freshDir }) => new Vault({ dir: freshDir, signingKey, seedRules: false })
    });

    // Backups need somewhere immutable to go and a credential the primary does
    // not also hold for deletion, so they are configured rather than defaulted:
    // silently backing up to a directory this process can also erase would be
    // worse than having no backup, because it would look like having one.
    this.backup = options.backup
      ? new BackupEngine({
        source: dir, db: this.db, kms: this.kms, ledger: this.ledger, folders: this.folders,
        alerts: this.alerts, ...options.backup
      })
      : null;

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

    // The message itself, before anything was made of it. Recorded here rather
    // than after extraction so that a message which produced no facts at all
    // still leaves a trace — "nothing was captured from that call" is an answer
    // an investigator needs, and silence cannot provide it.
    this.journal.record('message.sealed', {
      subject: conversation.id,
      subjectKind: 'conversation',
      actor: { id: raw.agentId ?? ctx.agentId ?? 'unknown', kind: raw.agentId || ctx.agentId ? 'agent' : 'human', onBehalfOf: ctx.onBehalfOf ?? null, sessionId: ctx.sessionId ?? null, ip: ctx.ip ?? null },
      how: { channel: raw.channel, connector: raw.source?.connector ?? null, connectorMode: raw.connectorMode ?? null },
      where: { region: raw.region ?? ctx.region ?? null },
      purpose: ctx.purpose ?? 'memory_governance',
      excerpt: conversation.transcriptText,
      detail: {
        sealHash: conversation.sealHash,
        participants: conversation.participants,
        attachments: (raw.attachments ?? []).length,
        turns: conversation.turns?.length ?? null
      }
    });

    // ---- attachments: pixels and audio are text too (§5 Check 7) ---------
    //
    // Until this existed, an attachment was sealed into the archive and never
    // looked at, so a PNG carrying "ignore previous instructions" as pale grey
    // text reached extraction with the gate never having seen the words. The
    // recovered text goes through the same detector as anything typed into the
    // conversation — not a parallel, weaker check.
    const attachmentFindings = [];
    for (const a of raw.attachments ?? []) {
      let finding = null;
      try {
        finding = analyseAttachment(a, { detector: this.gate.instructions });
      } catch (e) {
        // A crash in a decoder must not become a bypass.
        finding = { kind: 'unknown', name: a?.name ?? 'attachment', hold: true, reasons: [`the attachment could not be inspected (${e.message})`] };
      }
      if (!finding) continue;
      attachmentFindings.push(finding);
      if (!finding.hold) continue;
      this.ledger.append('security.detection', {
        subject: conversation.id, actor: raw.agentId ?? ctx.agentId ?? 'unknown',
        action: 'attachment.held', attachment: finding.name, kind: finding.kind,
        sha256: finding.sha256 ?? null, reason: (finding.reasons ?? []).join('; ')
      });
      this.alerts.raise({
        severity: 'high', kind: 'attachment_injection', subject: finding.name,
        actor: raw.agentId ?? ctx.agentId ?? 'unknown',
        detail: (finding.reasons ?? []).join('; ')
      });
    }

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
      // What the images and audio said. Reported even when nothing was held,
      // so a caller can see that the check ran rather than inferring it from
      // silence.
      attachmentFindings,
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
    this._journalWrite(fact, candidate, verdict, ctx, conversation);

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

  /**
   * Record a write in full, and teach the memory from it.
   *
   * Everything the gate decided is captured here while it is still in scope —
   * every check that ran and its result, every rule that fired, the channel and
   * its trust at the time, the PII findings, the reconciliation outcome. After
   * this returns, reassembling that costs a join across four collections and
   * loses the parts nobody persisted.
   */
  _journalWrite(fact, candidate, verdict, ctx, conversation) {
    const action = {
      pass: 'fact.written', mask: 'fact.masked', hold: 'fact.held', block: 'fact.blocked',
      escalate: 'fact.held', quarantine: 'fact.quarantined', 'require-4-eyes': 'fact.held'
    }[verdict.outcome] ?? 'fact.held';

    this.journal.record(action, {
      subject: fact.id,
      actor: {
        id: ctx.agentId ?? 'system',
        kind: ctx.agentId ? 'agent' : 'system',
        credentialId: ctx.credential?.id ?? null,
        onBehalfOf: candidate.saidBy?.name ?? null
      },
      where: { folder: fact.folder, namespace: fact.namespace, region: fact.region },
      why: (verdict.reasons ?? []).join('; ') || null,
      purpose: ctx.purpose ?? 'memory_governance',
      how: {
        channel: fact.channel, channelTrust: fact.channelTrust,
        connectorMode: fact.connectorMode, model: fact.model, modelVersion: fact.modelVersion
      },
      allowed: verdict.outcome !== 'block',
      outcome: verdict.outcome,
      excerpt: fact.claim,
      after: { folder: fact.folder, sensitivity: fact.sensitivity, status: fact.status, version: 1 },
      detail: {
        conversationId: conversation?.id ?? null,
        sealHash: conversation?.sealHash ?? null,
        claimType: fact.claimType,
        saidBy: fact.saidBy,
        extractionConfidence: fact.extractionConfidence,
        checks: (verdict.checks ?? []).map((c) => ({ check: c.check, name: c.name, result: c.result, reason: c.reason ?? null })),
        rulesEvaluated: fact.rulesEvaluated,
        instructionScore: fact.instructionScore,
        piiFindings: (fact.piiFindings ?? []).map((p) => ({ kind: p.kind ?? p.type, action: p.action ?? null })),
        anomalies: fact.anomalyFlags,
        reconciliation: verdict.reconciliation ? { action: verdict.reconciliation.action, against: verdict.reconciliation.into ?? verdict.reconciliation.against ?? null } : null,
        latencyMs: verdict.latencyMs,
        fastPath: Boolean(verdict.fastPath),
        contentHash: fact.contentHash,
        ledgerPosition: fact.ledgerPosition
      },
      ledgerSeq: fact.ledgerPosition
    });

    // The rules just made a filing decision. That is a training signal, and it
    // is free — no model call, no network. See src/ai/memory.js for why the
    // deterministic path is weighted below a human's correction.
    if (verdict.outcome === 'pass' || verdict.outcome === 'mask') {
      try {
        this.memory.learn({
          factId: fact.id, folder: fact.folder, claim: fact.claim,
          sensitivity: fact.sensitivity, by: 'rules', entities: fact.entities ?? []
        });
      } catch { /* learning must never break a write */ }
    }
  }

  // =========================================================================
  // THE READ PATH
  // =========================================================================

  /** @see ReadPath#read */
  read(query, ctx = {}) {
    const result = this.readPath.read(query, ctx);
    // Derived the same way the read path derives it, so the journal records the
    // actor the wall actually saw rather than a plausible-looking reconstruction
    // of it. The two drifting apart is how an audit record starts describing a
    // system that isn't the one running.
    const actor = ctx.agentId
      ? {
        id: ctx.agentId, kind: 'agent',
        department: this.registry.get(ctx.agentId)?.department ?? null,
        credentialId: ctx.credential?.id ?? null
      }
      : {
        id: typeof ctx.actor === 'string' ? ctx.actor : (ctx.actor?.id ?? 'unknown'),
        kind: 'human',
        department: ctx.department ?? ctx.actor?.department ?? null,
        clearance: ctx.clearance ?? null,
        sessionId: ctx.sessionId ?? null,
        ip: ctx.ip ?? null
      };
    const facts = result.facts ?? [];
    const how = { route: ctx.route ?? null, channel: ctx.channel ?? null };

    // The query as an event. Both halves are recorded — what came back and what
    // was held back — because a read that returned three of eleven facts is a
    // different event from one that returned three of three, and only one of
    // them is worth investigating.
    this.journal.record('search.performed', {
      subject: typeof query === 'string' ? 'search' : 'read',
      subjectKind: 'query',
      actor,
      purpose: ctx.purpose ?? null,
      why: ctx.reason ?? null,
      how,
      excerpt: typeof query === 'string' ? query : (query?.text ?? null),
      detail: {
        returned: facts.length,
        withheld: result.withheld ?? 0,
        withheldReasons: result.withheldReasons ?? [],
        heldInReview: result.heldInReview ?? 0,
        factIds: facts.map((f) => f.id).slice(0, JOURNAL_READ_CAP),
        folders: [...new Set(facts.map((f) => f.folder))]
      }
    });

    // And one entry per record actually disclosed, so that "who has read this
    // fact" is answerable FROM THE FACT rather than by scanning every query
    // anyone ever ran and checking whether this id was in the result set. That
    // is the question a subject access request asks, and a query-level record
    // alone cannot answer it.
    for (const f of facts.slice(0, JOURNAL_READ_CAP)) {
      this.journal.record('fact.read', {
        subject: f.id,
        actor,
        purpose: ctx.purpose ?? null,
        why: ctx.reason ?? null,
        where: { folder: f.folder },
        how,
        detail: {
          viaQuery: typeof query === 'string' ? query.slice(0, 120) : null,
          redactedFields: f.redactedFields ?? [],
          sensitivity: f.sensitivity ?? null
        }
      });
    }
    if (facts.length > JOURNAL_READ_CAP) {
      this.journal.record('search.performed', {
        subject: 'search', subjectKind: 'query', actor,
        why: `${facts.length - JOURNAL_READ_CAP} further fact(s) were disclosed by this query and are named in the query entry above rather than individually`,
        detail: { truncated: true, returned: facts.length, recorded: JOURNAL_READ_CAP }
      });
    }
    return result;
  }

  /** The labelled block an agent actually receives. */
  ask(query, ctx = {}) {
    return this.readPath.render(this.read(query, ctx));
  }

  /**
   * A question in, an answer grounded in facts this asker is cleared to see.
   *
   * Retrieval goes through the ordinary gated search — permissions checked at
   * query time, withheld facts counted, provenance attached. A model, if one is
   * configured, only turns those retrieved facts into a sentence, and any
   * answer citing a fact that was not retrieved is discarded whole. With no
   * model the deterministic answer is returned and labelled as such.
   */
  async answer(question, ctx = {}) {
    const actor = ctx.actor ?? { id: ctx.agentId ?? 'unknown', kind: 'human' };
    const gate = this.mayAsk(actor);
    if (!gate.allowed) {
      this.journal.record('ask.refused', {
        subject: 'memory', subjectKind: 'memory', actor, allowed: false,
        why: gate.reason, purpose: ctx.purpose ?? 'ask', excerpt: question,
        detail: { allowlist: [...this.askAllowlist] }
      });
      throw new VaultError('forbidden', gate.reason, { code: 'ask_not_permitted', asker: actor.id });
    }

    const searchResult = this.search.search(question, {
      actor,
      clearance: ctx.clearance ?? 'internal',
      canRead: ctx.canRead ?? (() => true),
      folder: ctx.folder ?? null,
      entity: ctx.entity ?? null,
      limit: ctx.limit ?? 12,
      purpose: ctx.purpose ?? 'ask',
      naturalLanguage: true
    });
    const result = await ask({ question, searchResult, provider: this.model });

    // The question, who asked it, what came back and what was held back. An ask
    // that returns a summary of forty facts is a bigger disclosure than any
    // single read, so it is recorded in more detail than one, not less.
    this.journal.record('ask.performed', {
      subject: 'memory', subjectKind: 'memory', actor,
      purpose: ctx.purpose ?? 'ask',
      excerpt: question,
      how: { model: result.source === 'model' ? this.model.model : null, provider: result.source === 'model' ? this.model.provider : null, local: this.model.local },
      detail: {
        retrieved: result.retrieved,
        withheld: result.withheld,
        withheldReasons: result.withheldReasons,
        answeredBy: result.source,
        citedFactIds: result.citations?.map((c) => c.id) ?? [],
        sufficient: result.sufficient
      }
    });
    return { ...result, asker: actor.id, permittedBecause: gate.reason };
  }

  /**
   * May this actor ask questions of the memory?
   *
   * Separate from "may they read facts" on purpose — see askAllowlist above.
   * The refusal names the list rather than saying "forbidden", because the
   * person hitting it needs to know who to go to, and hiding that only means
   * they ask around until somebody runs it for them.
   */
  mayAsk(actor) {
    const id = typeof actor === 'string' ? actor : actor?.id;
    if (!id) return { allowed: false, reason: 'an ask must be attributed to a named person — anonymous questions of the whole memory are not permitted' };
    // Set by the identity layer from the provider's own role mapping, not
    // claimed by the caller. Kept separate from `administrator` because a
    // lawyer needs to ask and must not thereby gain administrator-only folders.
    if (actor?.canAsk === true) return { allowed: true, reason: `granted by the identity provider for this session` };
    if (actor?.administrator === true) return { allowed: true, reason: 'named administrator' };
    if (this.askAllowlist.has(id)) {
      return { allowed: true, reason: this.administrators.includes(id) ? 'named administrator' : 'explicitly permitted to ask' };
    }
    return {
      allowed: false,
      reason: `${id} is not permitted to ask questions of the memory. Ask ranges over everything at once and returns prose, `
        + `so it is limited to administrators and people named explicitly — currently ${this.askAllowlist.size} `
        + `person(s). The ordinary read path is unaffected: ${id} can still retrieve the facts they are cleared for.`
    };
  }

  /** Let a named administrator grant or revoke the right to ask. */
  permitAsk(who, { actor, reason, revoke = false }) {
    if (!this.administrators.includes(actor) && this.administrators.length) {
      throw new VaultError('forbidden', `only a named administrator may change who can ask — ${actor} is not one`);
    }
    if (!reason) throw new VaultError('validation', 'granting or revoking the right to ask requires a reason');
    if (revoke) this.askAllowlist.delete(who); else this.askAllowlist.add(who);
    this.ledger.append('admin.action', { subject: who, actor, action: revoke ? 'ask.revoked' : 'ask.granted', reason });
    this.journal.record('admin.action', {
      subject: who, subjectKind: 'person', actor: { id: actor, kind: 'human' }, why: reason,
      before: { canAsk: revoke }, after: { canAsk: !revoke }
    });
    return { who, canAsk: !revoke, allowlist: [...this.askAllowlist] };
  }

  /**
   * The librarian: the model organising the file room.
   *
   * Lazy for the same reason `redteam` is — it is a whole subsystem and most
   * callers never touch it. See src/ai/orchestrate.js for what it may and may
   * never do; the short version is that it invents tags freely and cannot
   * invent a folder, because a tag is an index and a folder is a wall.
   */
  get librarian() {
    if (!this._librarian) this._librarian = new Librarian({ vault: this, administrators: this.administrators });
    return this._librarian;
  }

  /** One organising pass. @see Librarian#organize */
  organize(opts = {}) {
    return this.librarian.organize(opts);
  }

  /**
   * Let a model refine where already-filed facts live.
   *
   * Runs off the write path on purpose: the gate has a latency budget and a
   * model call would blow it, and a model outage must never become a write
   * outage. Every fact this touches is already filed and already behind
   * whatever wall its folder has. See src/ai/refile.js for what a re-file may
   * and may never do.
   */
  refileWithModel(opts = {}) {
    return refilePass({ vault: this, ...opts });
  }

  /**
   * The adversarial suite as a scheduled control rather than a command.
   *
   * Created on first use, not in the constructor: starting it eagerly would
   * fire the whole corpus on every instantiation, including every test. Each
   * run happens in a throwaway vault built from the same code, so the real
   * archive never accumulates attack payloads — see src/security/watchdog.js.
   */
  get redteam() {
    if (!this._redteam) this._redteam = new RedTeamWatchdog({ vault: this });
    return this._redteam;
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
      keyService: this.keyBridge ? this.keyBridge.status() : { provider: 'vault-managed' },
      encryptionAtRest: this.encryptionPosture()
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

  /**
   * What encryption at rest actually protects against here.
   *
   * Stated rather than implied, because "AES-256-GCM at rest" means something
   * very different depending on where the key is, and a security questionnaire
   * answered with the strong reading when the weak one is true is a false
   * statement somebody signs.
   */
  encryptionPosture() {
    if (!this.encryptAtRest) {
      return {
        enabled: false, keyLocation: 'n/a',
        protectsAgainst: 'nothing — encryption at rest is switched off',
        recommendation: 'remove encryptAtRest:false unless you have a specific reason'
      };
    }
    const external = Boolean(this.keyClient) || this.kms.mode === 'byok' || Boolean(this.options.kms?.rootKey);
    return {
      enabled: true,
      algorithm: 'AES-256-GCM, per-object data key wrapped by a per-namespace key',
      keySource: this.rootKeySource,
      keyOnSameHostAsData: !external && Boolean(this.options.dir),
      protectsAgainst: external
        ? 'a stolen bucket, a copied backup, a decommissioned disk, AND a compromised Vault host — the root key is never on this machine'
        : 'a stolen bucket, a copied backup, a decommissioned disk, an exposed object store, a snapshot shared with a vendor',
      doesNotProtectAgainst: external
        ? 'an attacker who can call your key service as this process can'
        : 'anyone who can read the whole data directory — the root key is in it, at root.key. This is NOT what a security questionnaire means by encryption at rest.',
      recommendation: external ? null : 'configure kms.rootKey (BYOK) or kms.provider (AWS/Azure/GCP) so the key is never on this host'
    };
  }

  /**
   * Load or create the Vault-managed root key for a data directory.
   *
   * Written 0600 alongside the data. Be precise about what that buys:
   *
   *   Protects against — a stolen bucket, a copied backup, a decommissioned
   *   disk, an exposed object store, a snapshot shared with a vendor. These are
   *   the common breaches, and in all of them the attacker has the data files
   *   and not the host filesystem.
   *
   *   Does NOT protect against — anyone who can read the whole directory,
   *   because the key is in it. That is not encryption at rest in the sense a
   *   security questionnaire means, and doctor() says so.
   *
   * The fix is BYOK or a cloud KMS, where the key is never on this host at all.
   */
  static _rootKeyFile(dir) {
    const path = join(dir, 'root.key');
    if (existsSync(path)) return Buffer.from(readFileSync(path, 'utf8').trim(), 'hex');
    mkdirSync(dir, { recursive: true });
    const key = randomBytes(32);
    writeFileSync(path, key.toString('hex'), { mode: 0o600 });
    return key;
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

    const enc = this.encryptionPosture();
    if (!enc.enabled) {
      warn('high', 'encryption', 'encryption at rest is switched off — transcripts and facts are readable JSON on disk',
        'remove encryptAtRest:false');
    } else if (enc.keyOnSameHostAsData) {
      // Deliberately a finding rather than a footnote: a customer who answers
      // "yes, AES-256 at rest" on a questionnaire while the key sits in the same
      // directory has said something they cannot defend in an audit.
      warn('medium', 'encryption',
        'the root key is stored beside the data, so encryption at rest protects a stolen bucket or backup but not a compromised host',
        'configure kms.rootKey (BYOK) or kms.provider (AWS/Azure/GCP) — then the key is never on this machine');
    }

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
export { BackupEngine, BackupStore } from './continuity/backup.js';
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
