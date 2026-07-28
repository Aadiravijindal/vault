/**
 * L12 — THE CONTROL SURFACE (§23).
 *
 * A full HTTP API for everything in the UI, plus the UI itself, webhooks, SIEM
 * and OTel export. Zero dependencies: node:http, because this has to run
 * on-premise and air-gapped where "just add a web framework" is a procurement.
 *
 * Auth is token → role. Roles are the ones in §24, and each sees only what that
 * section says it sees — including "not content" for admins.
 */
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, extname, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomToken, constantTimeEqual, sha256 } from '../util/crypto.js';
import { now, iso } from '../util/time.js';
import { VaultError } from '../util/errors.js';
import { timingReport, recommendedFirstConnectors } from '../onboarding/onboarding.js';
import { renderPlan } from '../iac/iac.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const UI_DIR = join(HERE, '..', 'ui');

/** §24 — who sees what. Enforced, not documented. */
export const ROLES = {
  end_user: { sees: ['my-data'], content: 'own only' },
  folder_owner: { sees: ['memory', 'review', 'value', 'my-data'], content: 'own folders' },
  department_head: { sees: ['memory', 'review', 'value', 'map', 'my-data'], content: 'own department', noIndividualViews: true },
  platform: { sees: ['map', 'admin', 'observability', 'value'], content: 'none' },
  security: { sees: ['map', 'rules', 'security', 'trace', 'review', 'admin'], content: 'break-glass only' },
  legal: { sees: ['cases', 'archive', 'trace', 'memory', 'comply'], content: 'full', privilegeCleared: true },
  compliance: { sees: ['comply', 'archive', 'review', 'trace'], content: 'supervision samples' },
  finance: { sees: ['value'], content: 'none' },
  risk: { sees: ['insure', 'security', 'map'], content: 'none' },
  works_council: { sees: ['privacy'], content: 'none', noIndividualViews: true },
  admin: { sees: ['admin', 'map', 'modules'], content: 'break-glass only' },
  auditor: { sees: ['comply', 'trace', 'archive'], content: 'read-only scoped', readOnly: true },
  agent: { sees: [], content: 'read path only' }
};

export class ApiServer {
  /**
   * @param {object} opts
   * @param {import('../index.js').Vault} opts.vault
   * @param {Record<string,{role:string, name:string, department?:string, clearance?:string}>} [opts.tokens]
   */
  constructor({ vault, tokens = null, port = 8080, host = '0.0.0.0', requireAuth = true }) {
    this.vault = vault;
    this.port = port;
    this.host = host;
    this.requireAuth = requireAuth;
    /** @type {Map<string, object>} token → principal */
    this.tokens = new Map();
    if (tokens) for (const [t, p] of Object.entries(tokens)) this.tokens.set(t, p);
    this.webhooks = [];
    this.siemSinks = [];
    this.requestLog = [];
    this.routes = [];
    this._install();
  }

  /** Mint a token for a principal. Returned once. */
  issueToken(principal) {
    const token = `vlt_${randomToken(24)}`;
    this.tokens.set(token, { ...principal, issuedAt: now() });
    return token;
  }

  addWebhook(url, events = ['*']) {
    this.webhooks.push({ url, events, secret: randomToken(16) });
    return this.webhooks[this.webhooks.length - 1];
  }

  addSiemSink(fn) { this.siemSinks.push(fn); return this; }

  // -- routing -------------------------------------------------------------

  /**
   * Routes are matched most-specific-first, not registration-first: a literal
   * segment always beats a parameter at the same position. Otherwise
   * `/api/review/:id` — registered earlier because it reads naturally there —
   * silently swallows `/api/review/suggestions`, and the screen that calls it
   * gets "review item not found" instead of its data.
   */
  route(method, pattern, roles, handler) {
    const keys = [];
    const rx = new RegExp('^' + pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
    const segments = pattern.split('/').filter(Boolean);
    this.routes.push({ method, pattern, rx, keys, roles, handler, segments });
    this.routes.sort((a, b) => {
      const n = Math.max(a.segments.length, b.segments.length);
      for (let i = 0; i < n; i++) {
        const av = a.segments[i], bv = b.segments[i];
        if (av === bv) continue;
        if (av === undefined) return -1;
        if (bv === undefined) return 1;
        const ap = av.startsWith(':'), bp = bv.startsWith(':');
        if (ap !== bp) return ap ? 1 : -1;   // literal before parameter
        return 0;
      }
      return 0;
    });
  }

  _install() {
    const v = this.vault;
    const ALL = null;              // null = any authenticated principal
    const R = (...roles) => roles;

    // ---- health & status -------------------------------------------------
    this.route('GET', '/api/health', ALL, () => ({ ok: true, at: iso(), uptimeMs: now() - v.startedAt }));
    this.route('GET', '/api/whoami', ALL, ({ principal }) => ({
      name: principal.name, role: principal.role, department: principal.department ?? null,
      clearance: principal.clearance ?? 'internal',
      sees: ROLES[principal.role]?.sees ?? [],
      contentAccess: ROLES[principal.role]?.content ?? 'none',
      note: ROLES[principal.role]?.noIndividualViews
        ? 'this role never sees an individual employee view'
        : undefined
    }));
    this.route('GET', '/api/status', R('platform', 'admin', 'security', 'department_head'), () => v.status());
    this.route('GET', '/api/doctor', R('platform', 'admin', 'security'), () => v.doctor());

    // ---- 🗺️ MAP ----------------------------------------------------------
    this.route('GET', '/api/map', R('platform', 'security', 'admin', 'department_head', 'risk'), () => v.map());
    this.route('GET', '/api/coverage', ALL, () => v.coverage());
    this.route('GET', '/api/connectors', R('platform', 'admin', 'security'), () => ({
      catalog: v.connectors.all(), health: v.connectors.health(), cost: v.connectors.costReport()
    }));
    this.route('GET', '/api/connectors/:id/describe', ALL, ({ params }) => v.connectors.describe(params.id));
    this.route('POST', '/api/connectors', R('platform', 'admin'), ({ body, principal }) =>
      v.connectors.connect({ ...body, actor: principal.name }));
    this.route('POST', '/api/connectors/:id/events', ALL, ({ params, body }) => v.connectors.receive(params.id, body));
    this.route('POST', '/api/connectors/:id/kill', R('platform', 'admin', 'security'), ({ params, body, principal }) =>
      v.connectors.kill(params.id, { actor: principal.name, reason: body.reason }));
    this.route('GET', '/api/connectors/gaps', R('platform', 'admin', 'security'), () => v.connectors.detectGaps());

    // ---- 🧠 MEMORY --------------------------------------------------------
    this.route('GET', '/api/facts', ALL, ({ query, principal }) => {
      const canRead = (f) => v.folders.check('read', principalActor(principal), f.folder || 'company/');
      return v.facts.all()
        .filter((f) => (query.folder ? String(f.folder || '').startsWith(query.folder) : true))
        .filter((f) => (query.status ? f.status === query.status : true))
        .filter((f) => canRead(f).allowed)
        .slice(0, Number(query.limit) || 100)
        .map((f) => summariseFact(f, principal));
    });
    this.route('GET', '/api/facts/:id', ALL, ({ params, principal }) => {
      const f = v.facts.require(params.id);
      const wall = v.folders.check('read', principalActor(principal), f.folder || 'company/');
      if (!wall.allowed) throw new VaultError('wall_violation', wall.reason);
      return f;
    });
    this.route('GET', '/api/facts/:id/trace', R('security', 'legal', 'compliance', 'auditor', 'platform', 'admin'), ({ params }) => v.traceFact(params.id));
    this.route('GET', '/api/facts/:id/contagion', R('security', 'legal', 'compliance', 'auditor'), ({ params }) => v.contagion(params.id));
    this.route('GET', '/api/facts/:id/history', ALL, ({ params }) => v.facts.history(params.id));
    this.route('POST', '/api/facts/:id/incident-bundle', R('security', 'legal', 'compliance'), ({ params, body, principal }) =>
      v.incidentBundle(params.id, { actor: principal.name, matter: body.matter }));
    this.route('GET', '/api/folders', ALL, () => v.folders.all());
    this.route('POST', '/api/folders/:path/owners', R('admin', 'platform', 'department_head'), ({ params, body, principal }) =>
      v.folders.setOwners(decodeURIComponent(params.path), { ...body, actor: principal.name }));
    this.route('GET', '/api/entities', ALL, () => v.entities.all());
    this.route('GET', '/api/entities/graph', ALL, ({ query }) => v.entities.graph({ rootId: query.root, depth: Number(query.depth) || 2 }));

    // ---- golden facts -----------------------------------------------------
    this.route('GET', '/api/golden', ALL, () => v.facts.goldenFacts());
    this.route('GET', '/api/golden/due', ALL, () => v.facts.goldenDue());
    this.route('POST', '/api/golden', R('legal', 'admin', 'department_head', 'compliance'), ({ body, principal }) =>
      v.createGoldenFact(body.fact, { actor: principal.name, actorKind: 'human', authorityRole: body.authorityRole, secondApprover: body.secondApprover }));
    this.route('POST', '/api/golden/:id/reattest', R('legal', 'admin', 'department_head', 'compliance'), ({ params, body, principal }) =>
      v.facts.reattest(params.id, { actor: principal.name, ...body }));
    this.route('GET', '/api/golden/:id/blast-radius', ALL, ({ params }) => v.facts.goldenBlastRadius(params.id));

    // ---- write / read paths -----------------------------------------------
    this.route('POST', '/api/ingest', ALL, ({ body, principal }) =>
      v.ingest(body.raw ?? body, { ...body.ctx, actor: principal.name, credential: body.credential }));
    this.route('POST', '/api/read', ALL, ({ body, principal }) =>
      v.read(body.query, { ...body, actor: principal.name, clearance: body.clearance ?? principal.clearance ?? 'internal' }));
    this.route('POST', '/api/search', ALL, ({ body, principal }) =>
      v.search.search(body.query, {
        actor: { id: principal.name, kind: 'human', groups: principal.groups || [] },
        clearance: principal.clearance ?? 'internal',
        canRead: (f) => v.folders.check('read', principalActor(principal), f.folder || 'company/'),
        ...body
      }));

    // ---- ⏳ NEEDS REVIEW ---------------------------------------------------
    this.route('GET', '/api/review', ALL, ({ query, principal }) =>
      v.needsReview({ assignee: query.mine === '1' ? principal.name : query.assignee, folder: query.folder, priority: query.priority, status: query.status }));
    this.route('GET', '/api/review/stats', ALL, () => ({ ...v.review.stats(), volumeAlarm: v.review.volumeAlarm() }));
    this.route('GET', '/api/review/:id', ALL, ({ params }) => v.review.view(params.id));
    this.route('POST', '/api/review/:id/decide', ALL, ({ params, body, principal }) =>
      v.decide(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/review/bulk', ALL, ({ body, principal }) =>
      v.review.bulkDecide(body.ids, { ...body, actor: principal.name }));
    this.route('GET', '/api/review/:id/similar', ALL, ({ params }) => v.review.similar(params.id));
    this.route('GET', '/api/review/suggestions', ALL, () => v.review.autoApproveSuggestions());
    this.route('GET', '/api/review/scorecards', R('department_head', 'admin', 'security', 'compliance'), () => v.review.scorecards());
    this.route('POST', '/api/review/escalate', R('admin', 'platform'), ({ body }) => v.review.escalateOverdue(body));
    this.route('POST', '/api/review/ooo', ALL, ({ body, principal }) =>
      v.review.setOutOfOffice(body.person ?? principal.name, { ...body, actor: principal.name }));

    // ---- 📜 RULES ----------------------------------------------------------
    this.route('GET', '/api/rules', ALL, () => v.rules.all());
    this.route('GET', '/api/rules/templates', ALL, async () => (await import('../gate/rules.js')).RULE_TEMPLATES);
    this.route('POST', '/api/rules', R('security', 'admin', 'compliance', 'legal'), ({ body, principal }) =>
      v.createRule({ ...body, actor: principal.name }));
    this.route('PATCH', '/api/rules/:id', R('security', 'admin', 'compliance', 'legal'), ({ params, body, principal }) =>
      v.rules.update(params.id, body.patch, { actor: principal.name, reason: body.reason }));
    this.route('POST', '/api/rules/backtest', ALL, ({ body }) => v.backtest(body, body.options));
    this.route('GET', '/api/rules/conflicts', ALL, () => v.rules.detectConflicts());
    this.route('GET', '/api/rules/:id/tests', ALL, ({ params }) => v.rules.runTests(params.id));
    this.route('GET', '/api/rules/export', ALL, ({ query }) => ({ format: query.format || 'yaml', body: v.rules.exportAsCode(query.format || 'yaml') }));

    // ---- 📚 ARCHIVE --------------------------------------------------------
    this.route('GET', '/api/archive/search', R('legal', 'compliance', 'security', 'auditor'), ({ query, principal }) =>
      v.archive.search(query.q || '', { ...query, limit: Number(query.limit) || 50, privileged: ROLES[principal.role]?.privilegeCleared }));
    this.route('GET', '/api/archive/:id', R('legal', 'compliance', 'security', 'auditor'), ({ params }) => v.archive.require(params.id));
    this.route('GET', '/api/archive/stats', ALL, () => v.archive.stats());
    this.route('GET', '/api/archive/supervision', R('compliance', 'legal'), ({ query }) => v.archive.supervisionQueue(query));
    this.route('POST', '/api/archive/supervision/:id', R('compliance', 'legal'), ({ params, body, principal }) =>
      v.archive.decideSupervision(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/archive/production', R('legal', 'compliance'), ({ body, principal }) =>
      v.archive.createProduction({ ...body, actor: principal.name }));
    this.route('GET', '/api/archive/production/:id/export', R('legal', 'compliance'), ({ params, query }) =>
      v.archive.exportProduction(params.id, query.format || 'edrm', { includePrivileged: query.privileged === '1' }));

    // ---- 🔭 OBSERVABILITY ---------------------------------------------------
    this.route('GET', '/api/traces/:id', ALL, ({ params }) => v.vaultTrace.getTrace(params.id));
    this.route('GET', '/api/traces/:id/render', ALL, ({ params }) => ({ text: v.vaultTrace.render(params.id) }));
    this.route('GET', '/api/evals', ALL, () => v.vaultTrace.evalsCol.all());
    this.route('GET', '/api/observability/stats', ALL, () => v.vaultTrace.stats());
    this.route('GET', '/api/observability/clusters', ALL, () => v.vaultTrace.clusterFailures());

    // ---- ⚖️ CASES (legal & privacy) ----------------------------------------
    this.route('GET', '/api/legal/holds', R('legal', 'compliance', 'admin'), () => v.legal.activeHolds());
    this.route('POST', '/api/legal/holds', R('legal'), ({ body, principal }) =>
      v.legal.placeHold({ ...body, actor: principal.name }));
    this.route('POST', '/api/legal/holds/:id/lift', R('legal'), ({ params, body, principal }) =>
      v.legal.liftHold(params.id, { ...body, actor: principal.name }));
    this.route('GET', '/api/legal/erasure/plan', R('legal', 'compliance'), ({ query }) => v.legal.erasurePlan(query.subject));
    this.route('POST', '/api/legal/erasure', R('legal'), ({ body, principal }) =>
      v.legal.erase({ ...body, actor: principal.name }));
    this.route('GET', '/api/legal/receipts', R('legal', 'compliance', 'auditor'), ({ query }) => v.legal.listReceipts(query));
    this.route('GET', '/api/legal/receipts/:proof/verify', ALL, ({ params }) => v.legal.verifyReceipt(params.proof));
    this.route('POST', '/api/legal/dsar', R('legal', 'compliance'), ({ body, principal }) =>
      v.legal.openDsar({ ...body, actor: principal.name }));
    this.route('POST', '/api/legal/dsar/:id/fulfil', R('legal', 'compliance'), ({ params, principal }) =>
      v.legal.fulfilDsar(params.id, { actor: principal.name }));
    this.route('GET', '/api/legal/dsar', R('legal', 'compliance'), () => v.legal.dsarStatus());
    this.route('GET', '/api/legal/retention', R('legal', 'compliance', 'admin'), () => v.legal.retentionSchedule());
    this.route('GET', '/api/legal/retention/preview', R('legal', 'compliance', 'admin'), ({ query }) =>
      v.legal.retentionPreview({ withinDays: Number(query.days) || 30 }));
    this.route('GET', '/api/legal/privilege', R('legal'), () => v.legal.privilegeLogReport());
    this.route('GET', '/api/consent/:subject', R('legal', 'compliance'), ({ params }) => v.consent.status(params.subject));
    this.route('POST', '/api/consent', R('legal', 'compliance', 'platform'), ({ body, principal }) =>
      v.consent.record({ ...body, actor: principal.name }));

    // ---- 🛡️ SECURITY --------------------------------------------------------
    this.route('GET', '/api/security/alerts', R('security', 'admin', 'platform', 'risk'), ({ query }) => v.alerts.open(query));
    this.route('POST', '/api/security/alerts/:id/ack', R('security', 'admin'), ({ params, body, principal }) =>
      v.alerts.acknowledge(params.id, { actor: principal.name, note: body.note }));
    this.route('POST', '/api/security/alerts/:id/resolve', R('security', 'admin'), ({ params, body, principal }) =>
      v.alerts.resolve(params.id, { actor: principal.name, resolution: body.resolution }));
    this.route('GET', '/api/security/cases', R('security', 'admin', 'legal'), () => v.alerts.cases.all());
    this.route('GET', '/api/security/scorecard', R('security', 'admin', 'risk'), () => v.comply.scorecard());
    this.route('GET', '/api/security/detectors', ALL, () => ({
      temporal: v.temporal.stats(),
      reviewers: v.temporal.reviewerScorecards(),
      contradictionRadar: v.facts.contradictionRadar()
    }));
    this.route('POST', '/api/security/undo', R('security', 'admin', 'legal'), ({ body, principal }) =>
      v.undo({ ...body, actor: principal.name }));
    this.route('POST', '/api/killswitch', R('security', 'admin'), ({ body, principal }) =>
      v.killswitch.engage(body.level, { ...body, actor: principal.name }));
    this.route('DELETE', '/api/killswitch', R('security', 'admin'), ({ body, principal }) =>
      v.killswitch.release({ actor: principal.name, reason: body.reason }));
    this.route('GET', '/api/killswitch', ALL, () => {
      const s = v.killswitch.state();
      return { ...s, scopeMatches: undefined, spec: v.killswitch.specification() };
    });
    this.route('POST', '/api/killswitch/test', R('security', 'admin'), ({ body, principal }) =>
      v.killswitch.test({ ...body, actor: principal.name }));

    // ---- 📋 COMPLY -----------------------------------------------------------
    this.route('GET', '/api/comply/controls', R('compliance', 'security', 'auditor', 'admin', 'legal'), () => v.comply.monitorControls());
    this.route('GET', '/api/comply/crosswalk', ALL, ({ query }) => v.comply.crosswalk(query.framework || null));
    this.route('GET', '/api/comply/gaps', R('compliance', 'security', 'admin'), ({ query }) => v.comply.gapAnalysis(query.framework || 'ISO 42001'));
    this.route('GET', '/api/comply/register', R('compliance', 'security', 'admin', 'auditor', 'risk'), () => v.comply.register());
    this.route('GET', '/api/comply/board-pack', R('compliance', 'admin', 'risk', 'legal'), ({ query }) => v.comply.boardPack(query));
    this.route('GET', '/api/comply/questionnaire', ALL, ({ query }) => v.comply.questionnaire(query.name || 'CAIQ'));
    this.route('GET', '/api/comply/vendors', ALL, () => v.comply.vendorRegister());
    this.route('GET', '/api/comply/incidents', R('compliance', 'security', 'risk', 'legal'), () => v.comply.incidentRegister());
    this.route('POST', '/api/comply/audit-session', R('compliance', 'admin'), ({ body, principal }) =>
      v.comply.openAuditSession({ ...body, actor: principal.name }));

    // ---- 🏛️ INSURE -----------------------------------------------------------
    this.route('GET', '/api/insure/pack', R('risk', 'compliance', 'admin', 'security'), ({ query, principal }) =>
      v.insure.pack({ actor: principal.name, carrier: query.carrier }));
    this.route('GET', '/api/insure/gaps', ALL, () => v.insure.gaps());
    this.route('GET', '/api/insure/questionnaire', R('risk', 'compliance', 'admin'), () => v.insure.carrierQuestionnaire());
    this.route('GET', '/api/insure/renewals', ALL, () => v.insure.renewalCalendar());

    // ---- 📈 VALUE ------------------------------------------------------------
    this.route('GET', '/api/value', ALL, ({ query }) => v.value.report(query));
    this.route('GET', '/api/value/health', ALL, ({ query }) => v.value.health(query));
    this.route('GET', '/api/value/departments', ALL, () => v.value.byDepartment());
    this.route('GET', '/api/value/patterns', ALL, ({ query }) => v.value.patterns(query));
    this.route('GET', '/api/value/chargeback', R('finance', 'admin', 'platform', 'department_head'), ({ query }) => v.value.chargeback(query));
    this.route('GET', '/api/value/kill-candidates', R('finance', 'admin', 'platform'), () => v.value.killCandidates());
    this.route('GET', '/api/value/map', ALL, ({ principal }) => v.value.knowledgeMap({
      canRead: (f) => v.folders.check('read', principalActor(principal), f.folder || 'company/')
    }));

    // ---- 👤 MY DATA -----------------------------------------------------------
    this.route('GET', '/api/my-data', ALL, ({ principal }) => {
      const facts = v.facts.all().filter((f) => (f.entities || []).some((e) => e.name === principal.name));
      const conversations = v.archive.conversationsForPerson(principal.name);
      const reads = facts.reduce((a, f) => a + (f.readCount || 0), 0);
      return v.privacy.transparencyPortal(principal.name, { facts: facts.map((f) => summariseFact(f, principal)), conversations: conversations.map((c) => ({ id: c.id, at: iso(c.startedAt), channel: c.channel })), reads });
    });
    this.route('POST', '/api/my-data/object', ALL, ({ body, principal }) =>
      v.privacy.objection({ employee: principal.name, factId: body.factId, objection: body.objection }));

    // ---- ⚙️ ADMIN -------------------------------------------------------------
    this.route('GET', '/api/admin/modules', R('admin', 'platform', 'security'), () => v.moduleTable());
    // `endpoint` is how a module gets connected over JSON — an adapter object
    // has functions and cannot survive the wire. See ModuleRegistry#set.
    this.route('POST', '/api/admin/modules/:name', R('admin', 'platform'), ({ params, body, principal }) =>
      v.setModule(params.name, body.state, {
        vendor: body.vendor ?? null,
        endpoint: body.endpoint ?? null,
        keepOwnCopy: body.keepOwnCopy,
        reason: body.reason,
        actor: principal.name
      }));
    this.route('GET', '/api/admin/agents', R('admin', 'platform', 'security', 'department_head', 'risk'), () => v.registry.inventory());
    this.route('POST', '/api/admin/agents', R('admin', 'platform'), ({ body, principal }) =>
      v.registerAgent({ ...body, actor: principal.name }));
    this.route('POST', '/api/admin/agents/:id/credential', R('admin', 'platform'), ({ params, body, principal }) =>
      v.issueCredential(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/admin/agents/:id/retire', R('admin', 'platform'), ({ params, body, principal }) =>
      v.registry.retire(params.id, { ...body, actor: principal.name }));
    this.route('GET', '/api/admin/privacy', ALL, () => v.privacy.status());
    this.route('GET', '/api/admin/privacy/preview', R('admin', 'legal', 'compliance', 'works_council'), ({ query }) =>
      v.privacyPreview(query.jurisdiction));
    this.route('POST', '/api/admin/privacy', R('admin', 'legal'), ({ body, principal }) =>
      v.applyPrivacyMode(body.jurisdiction, { actor: principal.name, reason: body.reason }));
    this.route('GET', '/api/admin/privacy/pack', R('admin', 'legal', 'compliance', 'works_council'), () => v.privacy.compliancePack());
    this.route('GET', '/api/admin/works-council', R('works_council', 'admin', 'legal'), () => v.privacy.worksCouncilView());
    this.route('GET', '/api/admin/keys', R('admin', 'security'), () => ({ inventory: v.kms.inventory(), accessLog: v.kms.accessLog({ limit: 100 }) }));
    this.route('POST', '/api/admin/keys/:scope/rotate', R('admin', 'security'), ({ params, body, principal }) =>
      v.kms.rotate(decodeURIComponent(params.scope), { actor: principal.name, reason: body.reason }));
    this.route('GET', '/api/admin/storage', R('admin', 'platform', 'finance'), () => v.storage());
    this.route('POST', '/api/admin/storage/lifecycle', R('admin', 'platform'), ({ body, principal }) =>
      v.runStorageLifecycle({ ...body, actor: principal.name }));
    this.route('POST', '/api/admin/hygiene', R('admin', 'platform'), ({ body, principal }) =>
      v.runHygiene({ ...body, actor: principal.name }));
    this.route('GET', '/api/admin/continuity', ALL, () => v.continuity.commitments());

    // ---- notifications, keys, metering, lifecycle -------------------------
    this.route('GET', '/api/admin/notifications', R('admin', 'platform', 'security'), () => v.notifier.status());
    this.route('POST', '/api/admin/notifications', R('admin', 'platform', 'security'), ({ body, principal }) =>
      v.notifier.configure(body.channel, body.config ?? {}, { actor: principal.name, severityFloor: body.severityFloor }));
    this.route('POST', '/api/admin/notifications/test', R('admin', 'platform', 'security'), ({ body, principal }) =>
      v.notifier.notify({ kind: 'notification_test', severity: body.severity ?? 'medium', subject: 'test', detail: 'a test notification', actor: principal.name }, { force: true }));
    this.route('POST', '/api/admin/notifications/preferences', ALL, ({ body, principal }) =>
      v.notifier.setPreference(body.recipient ?? principal.name, { ...body, actor: principal.name }));

    this.route('GET', '/api/admin/api-keys', R('admin', 'platform'), () => v.apiKeys.list());
    this.route('POST', '/api/admin/api-keys', R('admin', 'platform'), ({ body, principal }) =>
      v.apiKeys.issue({ ...body, actor: principal.name }));
    this.route('POST', '/api/admin/api-keys/:id/revoke', R('admin', 'platform'), ({ params, body, principal }) =>
      v.apiKeys.revoke(params.id, { actor: principal.name, reason: body.reason }));
    this.route('GET', '/api/admin/rate-limits', R('admin', 'platform', 'security'), () => v.rateLimiter.stats());

    this.route('GET', '/api/billing', R('admin', 'finance', 'platform'), ({ query }) => v.metering.dashboard(query));
    this.route('GET', '/api/billing/usage', R('admin', 'finance', 'platform'), ({ query }) => v.metering.usage(query));
    this.route('POST', '/api/billing/caps', R('admin', 'finance'), ({ body, principal }) =>
      v.metering.setCaps(body, { actor: principal.name }));

    this.route('GET', '/api/admin/imports', R('admin', 'platform'), () => v.bulkImport.all());
    this.route('POST', '/api/admin/imports', R('admin', 'platform'), ({ body, principal }) =>
      v.bulkImport.start({ ...body, actor: principal.name }));
    this.route('POST', '/api/admin/imports/:id/feed', R('admin', 'platform'), ({ params, body }) =>
      v.bulkImport.feed(params.id, body.records ?? [], { credential: body.credential }));
    this.route('GET', '/api/admin/imports/:id', R('admin', 'platform'), ({ params }) => v.bulkImport.progress(params.id));
    this.route('POST', '/api/admin/imports/:id/finish', R('admin', 'platform'), ({ params, principal }) =>
      v.bulkImport.finish(params.id, { actor: principal.name }));

    this.route('POST', '/api/admin/offboarding/plan', R('admin'), ({ body, principal }) =>
      v.offboarding.plan({ actor: principal.name, reason: body.reason }));
    this.route('POST', '/api/admin/offboarding/confirm', R('admin'), ({ body, principal }) =>
      v.offboarding.confirm(body.plan, { actor: principal.name, secondApprover: body.secondApprover, confirm: body.confirm }));
    this.route('GET', '/api/admin/offboarding', R('admin', 'legal'), () => v.offboarding.receipts());

    this.route('POST', '/api/admin/storage/health', R('admin', 'platform'), async () => {
      if (!v.bucket) return { configured: false, note: 'no customer bucket configured — data is in Vault storage' };
      const health = await v.bucket.healthCheck();
      const residency = await v.bucket.verifyResidency(v.bucket.config.region);
      return { configured: true, health, residency };
    });
    // ---- day 0: guided setup and the sample tenant ---------------------------
    this.route('GET', '/api/setup', R('admin', 'platform'), () => v.onboarding.status());
    this.route('GET', '/api/setup/next', R('admin', 'platform'), () => v.onboarding.next());
    this.route('POST', '/api/setup/start', R('admin', 'platform'), ({ principal }) => v.onboarding.start({ actor: principal.name }));
    this.route('POST', '/api/setup/skip', R('admin', 'platform'), ({ body, principal }) =>
      v.onboarding.skip(body.step, { actor: principal.name, reason: body.reason }));
    this.route('GET', '/api/setup/timing', R('admin', 'platform'), () => timingReport(v.onboarding));
    this.route('GET', '/api/setup/connectors', R('admin', 'platform'), () => recommendedFirstConnectors());
    this.route('GET', '/api/demo', R('admin', 'platform'), () => v.demo.report());
    this.route('POST', '/api/demo/load', R('admin', 'platform'), ({ body, principal }) =>
      v.demo.load({ actor: principal.name, force: body?.force === true }));
    this.route('POST', '/api/demo/purge', R('admin', 'platform'), ({ body, principal }) =>
      v.demo.purge({ actor: principal.name, reason: body?.reason }));

    // ---- status page ---------------------------------------------------------
    // Deliberately readable by every role: an outage that only administrators
    // can see is an outage everyone else experiences as the product being
    // broken and nobody saying so.
    this.route('GET', '/api/status/page', null, () => v.statusPage.publicView());
    this.route('GET', '/api/status/incidents', null, () => v.statusPage.publicView().history);
    this.route('GET', '/api/status/internal', R('admin', 'platform', 'security'), () => v.statusPage.internalView());
    this.route('GET', '/api/status/uptime', null, ({ query }) => v.statusPage.uptime(query.days ? { windowMs: Number(query.days) * 86400_000 } : {}));
    this.route('POST', '/api/status/incidents', R('admin', 'platform', 'security'), ({ body, principal }) =>
      v.statusPage.declare({ ...body, actor: principal.name }));
    this.route('POST', '/api/status/incidents/:id/update', R('admin', 'platform', 'security'), ({ params, body, principal }) =>
      v.statusPage.update(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/status/incidents/:id/resolve', R('admin', 'platform', 'security'), ({ params, body, principal }) =>
      v.statusPage.resolve(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/status/incidents/:id/post-mortem', R('admin', 'platform', 'security'), ({ params, body, principal }) =>
      v.statusPage.postMortem(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/status/maintenance', R('admin', 'platform'), ({ body, principal }) =>
      v.statusPage.scheduleMaintenance({ ...body, actor: principal.name }));

    this.route('GET', '/api/ledger/verify/tail', R('security', 'compliance', 'legal', 'auditor', 'admin', 'platform'), () => v.verifyLedgerTail());

    this._installIdentity(v, R);

    // ---- configuration as code -----------------------------------------------
    this.route('POST', '/api/config/plan', R('admin', 'platform'), ({ body }) =>
      ({ ...v.config.plan(body.config ?? body, { prune: body.prune === true }), rendered: renderPlan(v.config.plan(body.config ?? body, { prune: body.prune === true })) }));
    this.route('POST', '/api/config/apply', R('admin', 'platform'), ({ body, principal }) =>
      v.config.apply(body.config ?? body, {
        actor: principal.name, reason: body.reason, approvedBy: body.approvedBy,
        prune: body.prune === true, allowDestructive: body.allowDestructive === true,
        credentials: body.credentials, dryRun: body.dryRun === true
      }));
    this.route('POST', '/api/config/drift', R('admin', 'platform', 'security', 'auditor'), ({ body }) => v.config.drift(body.config ?? body));
    this.route('GET', '/api/config/export', R('admin', 'platform'), () => v.config.export());
    this.route('GET', '/api/config/history', R('admin', 'platform', 'auditor'), () => v.config.history());

    // ---- chat apps -----------------------------------------------------------
    // These verify their own signature, so they are registered without a role:
    // the caller is Slack or Teams, not a Vault principal, and the signature IS
    // the authentication. `rawBody` matters — a re-serialised body produces a
    // different HMAC and every request would fail.
    this.route('POST', '/api/integrations/slack/command', 'signed', ({ rawBody, headers }) => {
      if (!v.slack) throw new VaultError('config', 'the Slack app is not configured');
      return v.slack.command({ body: rawBody, headers });
    });
    this.route('POST', '/api/integrations/slack/interact', 'signed', ({ rawBody, headers }) => {
      if (!v.slack) throw new VaultError('config', 'the Slack app is not configured');
      return v.slack.interact({ body: rawBody, headers });
    });
    this.route('POST', '/api/integrations/teams/command', 'signed', ({ rawBody, headers }) => {
      if (!v.teams) throw new VaultError('config', 'the Teams app is not configured');
      return v.teams.command({ body: rawBody, headers });
    });

    // ---- restore drills ------------------------------------------------------
    this.route('GET', '/api/continuity/drills', R('admin', 'platform', 'security', 'compliance', 'auditor', 'risk'), () => ({
      status: v.drill.status(), evidence: v.drill.evidence()
    }));
    this.route('POST', '/api/continuity/drills', R('admin', 'platform'), ({ body, principal }) =>
      v.drill.run({ actor: principal.name, reason: body?.reason, keepArtifacts: body?.keepArtifacts === true }));

    this.route('POST', '/api/admin/keys/health', R('admin', 'platform', 'security'), () => v.keyServiceHealth());
    this.route('POST', '/api/admin/keys/prime', R('admin', 'platform', 'security'), ({ body, principal }) =>
      v.primeKeyScope(body.scope, { actor: principal.name }));
    this.route('GET', '/api/admin/keys', R('admin', 'platform', 'security'), () => ({
      mode: v.kms.mode,
      provider: v.keyClient ? v.keyClient.provider : 'vault-managed',
      bridge: v.keyBridge ? v.keyBridge.status() : null,
      inventory: v.kms.inventory()
    }));
    this.route('GET', '/api/admin/keys/describe', R('admin', 'platform', 'security'), () =>
      (v.keyClient ? v.keyClient.describe() : { provider: 'vault-managed', note: 'no external key service configured' }));

    this.route('POST', '/api/admin/export', R('admin', 'platform', 'legal'), ({ body, principal }) => {
      const r = v.exportAll({ actor: principal.name, dir: body.dir, reason: body.reason });
      return { ...r, files: r.files ? Object.keys(r.files) : r.files };
    });

    // ---- ledger & verification ------------------------------------------------
    this.route('GET', '/api/ledger', R('security', 'compliance', 'legal', 'auditor', 'admin'), ({ query }) =>
      v.ledger.entries({ from: Number(query.from) || 1, to: Number(query.to) || Infinity, type: query.type, limit: Number(query.limit) || 200 }));
    this.route('GET', '/api/ledger/verify', ALL, () => v.verifyLedger());
    this.route('GET', '/api/ledger/anchors', ALL, () => v.ledger.verifyAnchors());
    this.route('GET', '/api/ledger/export', R('admin', 'legal', 'compliance', 'auditor'), () => v.ledger.export());

    // ---- OTel / SIEM export ----------------------------------------------------
    this.route('POST', '/api/otel/v1/traces', ALL, ({ body }) => {
      // Accept OTLP-shaped spans from any agent framework.
      const spans = body.resourceSpans?.flatMap((r) => r.scopeSpans?.flatMap((s) => s.spans) ?? []) ?? [];
      for (const s of spans) {
        v.registry.observeTraffic({
          identifier: s.attributes?.['vault.agent.id'] ?? s.attributes?.['service.name'] ?? 'unknown-otel-source',
          endpoint: s.name, model: s.attributes?.['gen_ai.request.model']
        });
      }
      return { accepted: spans.length };
    });
    this.route('GET', '/api/siem/events', R('security', 'admin', 'platform'), ({ query }) =>
      v.ledger.entries({ from: Number(query.from) || 1, limit: Number(query.limit) || 500 })
        .map((e) => ({ ...e, vendor: 'vault', product: 'ai-memory-governance', severity: siemSeverity(e.type) })));
  }

  /**
   * §22 — the identity control surface.
   *
   * Three different callers reach this server, and conflating them is how
   * enterprise SSO becomes an authentication bypass:
   *
   *  - a *browser*, at the SAML ACS and the OIDC callback, carrying no
   *    credential at all. Those routes are PUBLIC and must be, because the IdP
   *    redirects an unauthenticated user into them. Their entire security is
   *    the signature check, which is why the assertion verifier is attacked
   *    directly in the test suite rather than trusted here.
   *  - the *IdP itself*, at /scim/v2, holding a provisioning secret that is
   *    deliberately not a Vault API token.
   *  - a *Vault principal*, at everything else, holding a bearer token.
   */
  _installIdentity(v, R) {
    const PUBLIC = 'public';

    // ---- SAML ---------------------------------------------------------------
    const saml = () => {
      if (!v.saml) throw new VaultError('config', 'SAML is not configured on this deployment');
      return v.saml;
    };

    this.route('GET', '/api/auth/saml/metadata', PUBLIC, () =>
      new HttpResponse({ body: saml().metadata(), contentType: 'application/samlmetadata+xml; charset=utf-8' }));

    this.route('GET', '/api/auth/saml/login', PUBLIC, ({ query }) => {
      const req = saml().authnRequest({ relayState: safeRelayState(query.next) });
      return HttpResponse.redirect(req.url);
    });

    this.route('POST', '/api/auth/saml/acs', PUBLIC, ({ body, req }) => {
      const identity = saml().consume(body.SAMLResponse);
      const role = v.scim.byUserName(identity.email)?.role ?? roleFromGroups(v.scim, identity.groups);
      const { token } = v.sessions.create({
        principal: { name: identity.email, role, department: identity.department ?? undefined },
        amr: ['mfa'], idp: identity.issuer, ip: clientIp(req), userAgent: req.headers['user-agent'] ?? null
      });
      // RelayState is attacker-influenced: the IdP echoes back whatever it was
      // handed. Following it to another origin would turn the login endpoint
      // into an open redirect, which is the standard phishing primitive.
      return HttpResponse.redirect(safeRelayState(body.RelayState) ?? '/', { cookie: sessionCookie(token) });
    });

    // ---- OIDC ---------------------------------------------------------------
    const oidc = () => {
      if (!v.oidc) throw new VaultError('config', 'OIDC is not configured on this deployment');
      return v.oidc;
    };

    this.route('GET', '/api/auth/oidc/login', PUBLIC, () => HttpResponse.redirect(oidc().authorizationUrl().url));

    this.route('GET', '/api/auth/oidc/callback', PUBLIC, async ({ query, req }) => {
      if (query.error) throw new VaultError('forbidden', `the identity provider refused this login: ${String(query.error).slice(0, 64)}`);
      const { identity } = await oidc().exchangeCode(query.code, { state: query.state });
      const name = identity.email ?? identity.subject;
      const role = v.scim.byUserName(name)?.role ?? roleFromGroups(v.scim, identity.groups);
      const { token } = v.sessions.create({
        principal: { name, role }, amr: identity.amr?.length ? identity.amr : ['mfa'],
        idp: oidc().issuer, ip: clientIp(req), userAgent: req.headers['user-agent'] ?? null
      });
      return HttpResponse.redirect(safeRelayState(query.next) ?? '/', { cookie: sessionCookie(token) });
    });

    // ---- SCIM 2.0 -----------------------------------------------------------
    // Paths are the ones the RFC fixes; an IdP will not be told to use others.
    const SCIM = 'scim';
    const scimJson = (payload, status = 200) =>
      new HttpResponse({ status, json: payload, contentType: 'application/scim+json; charset=utf-8' });

    this.route('GET', '/scim/v2/ServiceProviderConfig', SCIM, () => scimJson(v.scim.serviceProviderConfig()));
    this.route('GET', '/scim/v2/ResourceTypes', SCIM, () => scimJson(v.scim.resourceTypes()));
    this.route('GET', '/scim/v2/Schemas', SCIM, () => scimJson(v.scim.resourceTypes()));

    this.route('GET', '/scim/v2/Users', SCIM, ({ query }) => scimJson(v.scim.listUsers({
      filter: query.filter ?? null,
      startIndex: Number(query.startIndex) || 1,
      count: query.count === undefined ? 100 : Number(query.count)
    })));
    this.route('POST', '/scim/v2/Users', SCIM, ({ body }) => {
      const user = v.scim.createUser(body);
      // 201 with a Location header. Okta treats a 200 here as a protocol error
      // and stops the sync.
      return scimJson(user, 201).header('Location', `/scim/v2/Users/${user.id}`);
    });
    this.route('GET', '/scim/v2/Users/:id', SCIM, ({ params }) => scimJson(v.scim.getUser(params.id)));
    this.route('PUT', '/scim/v2/Users/:id', SCIM, ({ params, body }) => scimJson(v.scim.replaceUser(params.id, body)));
    this.route('PATCH', '/scim/v2/Users/:id', SCIM, ({ params, body }) => scimJson(v.scim.patchUser(params.id, body)));
    this.route('DELETE', '/scim/v2/Users/:id', SCIM, ({ params }) => {
      v.scim.deleteUser(params.id);
      return new HttpResponse({ status: 204, body: '' });
    });

    this.route('GET', '/scim/v2/Groups', SCIM, ({ query }) => scimJson(v.scim.listGroups({
      filter: query.filter ?? null, startIndex: Number(query.startIndex) || 1,
      count: query.count === undefined ? 100 : Number(query.count)
    })));
    this.route('POST', '/scim/v2/Groups', SCIM, ({ body }) => {
      const group = v.scim.createGroup(body);
      return scimJson(group, 201).header('Location', `/scim/v2/Groups/${group.id}`);
    });
    this.route('GET', '/scim/v2/Groups/:id', SCIM, ({ params }) => scimJson(v.scim.getGroup(params.id)));
    this.route('PATCH', '/scim/v2/Groups/:id', SCIM, ({ params, body }) => scimJson(v.scim.patchGroup(params.id, body)));
    this.route('DELETE', '/scim/v2/Groups/:id', SCIM, ({ params }) => {
      v.scim.deleteGroup(params.id);
      return new HttpResponse({ status: 204, body: '' });
    });

    // ---- sessions -----------------------------------------------------------
    this.route('GET', '/api/auth/session', null, ({ principal }) => ({
      name: principal.name, role: principal.role, session: principal.session ?? null
    }));
    this.route('POST', '/api/auth/logout', null, ({ principal }) => {
      if (!principal.session) return { ok: true, note: 'this credential is an API token, not a session; revoke it under /api/keys' };
      v.sessions.revoke(principal.session.id, { actor: principal.name, reason: 'logged out' });
      return new HttpResponse({ json: { ok: true, revoked: 1 }, cookie: 'vault_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax' });
    });
    this.route('GET', '/api/auth/sessions', R('admin', 'security', 'platform'), () => ({ sessions: v.sessions.active() }));
    this.route('DELETE', '/api/auth/sessions/:name', R('admin', 'security'), ({ params, principal, body }) =>
      v.sessions.revokeAllFor(params.name, { actor: principal.name, reason: body?.reason ?? 'revoked by an administrator' }));

    // ---- MFA ----------------------------------------------------------------
    this.route('GET', '/api/auth/mfa', null, ({ principal }) => ({
      factors: v.mfa.factorsFor(principal.name), phishingResistant: v.mfa.hasPhishingResistant(principal.name)
    }));
    this.route('POST', '/api/auth/mfa/totp', null, ({ principal }) => {
      const out = v.mfa.enrolTotp(principal.name, { actor: principal.name });
      return { secret: out.secret, otpauthUrl: out.uri, warning: out.warning };
    });
    this.route('POST', '/api/auth/mfa/totp/verify', null, ({ principal, body }) => {
      const out = v.mfa.verifyTotp(principal.name, body.code);
      // A failed factor is a 403, not a 200 with `ok:false`. A caller that
      // checks only the status code must not read a rejection as a pass.
      if (!out?.ok) throw new VaultError('forbidden', out?.reason ?? 'that code is not valid');
      return out;
    });
    this.route('POST', '/api/auth/mfa/webauthn', null, ({ principal, body }) =>
      v.mfa.enrolWebauthn(principal.name, { ...body, actor: principal.name }));
    this.route('POST', '/api/auth/mfa/webauthn/verify', null, ({ principal, body }) => {
      const out = v.mfa.verifyWebauthn(principal.name, body);
      if (!out?.ok) throw new VaultError('forbidden', out?.reason ?? 'that assertion is not valid');
      return out;
    });

    this.route('GET', '/api/auth/policy', R('admin', 'security', 'platform'), () => ({
      requireMfa: v.accessPolicy.requireMfa,
      phishingResistantRoles: v.accessPolicy.phishingResistantRoles,
      allowedCidrs: v.accessPolicy.allowedCidrs,
      allowedCountries: v.accessPolicy.allowedCountries,
      blockedCountries: v.accessPolicy.blockedCountries
    }));

    // ---- break-glass (§27) --------------------------------------------------
    // The grant path for the privilege the folder walls already enforce. Roles
    // here are the ones that could plausibly need emergency content access;
    // approval is always someone else.
    const BG = R('security', 'admin', 'legal', 'compliance', 'platform');
    this.route('POST', '/api/breakglass', BG, ({ body, principal }) =>
      v.privileged.request({ ...body, requester: principal.name }));
    this.route('GET', '/api/breakglass', BG, () => ({ pending: v.privileged.pending(), summary: v.privileged.monthlySummary() }));
    this.route('GET', '/api/breakglass/summary', BG, ({ query }) => v.privileged.monthlySummary(
      query.from ? { from: Date.parse(query.from), to: query.to ? Date.parse(query.to) : undefined } : {}));
    this.route('GET', '/api/breakglass/:id', BG, ({ params }) => v.privileged.sessionReport(params.id));
    this.route('POST', '/api/breakglass/:id/approve', BG, ({ params, body, principal }) =>
      v.privileged.approve(params.id, { approver: principal.name, chain: body?.chain ?? null, note: body?.note ?? null }));
    this.route('POST', '/api/breakglass/:id/deny', BG, ({ params, body, principal }) =>
      v.privileged.deny(params.id, { approver: principal.name, reason: body?.reason }));
    this.route('POST', '/api/breakglass/:id/record', BG, ({ params, body, principal }) =>
      v.privileged.record(params.id, { ...body, actor: principal.name }));
    this.route('POST', '/api/breakglass/:id/close', BG, ({ params, body, principal }) =>
      v.privileged.close(params.id, { actor: principal.name, summary: body?.summary ?? null }));
  }

  // -- HTTP ----------------------------------------------------------------

  _principal(req) {
    const token = bearerOf(req);
    if (!token) return this.requireAuth ? null : { name: 'anonymous', role: 'platform' };
    for (const [t, p] of this.tokens) {
      if (constantTimeEqual(t, token)) return p;
    }
    // An SSO session. Checked against server-side state on every request, which
    // is the entire reason sessions are not self-describing tokens: SCIM
    // deprovisioning has to bite here, on the next call, not at the next
    // refresh.
    if (token.startsWith('vsx_') && this.vault.sessions) {
      const seen = this.vault.sessions.verify(token, { ip: clientIp(req), deviceId: req.headers['x-vault-device'] || null });
      if (seen.valid) return { ...seen.principal, session: seen.session };
      return null;
    }
    // Customer-side API keys are a first-class principal, not a second auth
    // system: they resolve to the same roles §24 already enforces.
    const viaKey = this.vault.apiKeys?.verify(token);
    if (viaKey?.valid) return { ...viaKey.principal, rateLimitPerMinute: viaKey.rateLimitPerMinute };
    return null;
  }

  async handle(req, res) {
    const started = Date.now();
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;

    // CORS for the UI when served from elsewhere.
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Vault-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

    const isScim = path.startsWith('/scim/');
    if (!path.startsWith('/api/') && !isScim) return this._serveUi(path, res);

    // Signature-verified integration endpoints authenticate by HMAC over the
    // raw body, not by bearer token: the caller is Slack or Teams, not a Vault
    // principal. They are identified here so the token check does not reject
    // them, and they verify their own signature before reading a single field.
    const signedRoute = this.routes.find((r) => r.roles === 'signed' && r.method === req.method && r.rx.test(path));
    // A public route is one the IdP redirects an unauthenticated browser into:
    // the SAML ACS, the OIDC callback, SP metadata. They cannot require a token
    // because the whole point is that the caller does not have one yet.
    const publicRoute = this.routes.find((r) => r.roles === 'public' && r.method === req.method && r.rx.test(path));
    // SCIM's caller is the identity provider, holding a provisioning secret
    // that is deliberately NOT a Vault API token — so a leaked SCIM credential
    // creates accounts but never reads memory.
    const scimRoute = isScim && this.routes.find((r) => r.roles === 'scim' && r.method === req.method && r.rx.test(path));
    if (scimRoute) {
      if (!this.vault.scim?.verifyBearer(bearerOf(req))) {
        return this._scimError(res, 401, 'this endpoint requires the SCIM provisioning credential');
      }
    }

    const principal = signedRoute
      ? { name: 'integration', role: 'agent', signed: true }
      : scimRoute ? { name: 'scim', role: 'scim' }
        : publicRoute ? { name: 'anonymous', role: 'anonymous' }
          : this._principal(req);
    if (!principal) return this._json(res, 401, { error: 'unauthenticated', message: 'present a bearer token' });

    // Rate limit AFTER identifying the caller, so one noisy integration cannot
    // starve everyone else, and BEFORE doing any work. The kill switch and
    // health are exempt: being unable to stop the system because you were
    // throttled is worse than any flood.
    const limit = this.vault.rateLimiter?.check(
      principal.apiKeyId || principal.name || 'anonymous',
      { path, limit: principal.rateLimitPerMinute ?? null }
    );
    if (limit && !limit.allowed) {
      for (const [h, val] of Object.entries(limit.headers || {})) res.setHeader(h, val);
      this._log(req, principal, 429, Date.now() - started);
      return this._json(res, 429, { error: 'rate_limited', message: limit.reason, retryAfterMs: limit.retryAfterMs });
    }
    if (limit?.headers) for (const [h, val] of Object.entries(limit.headers)) res.setHeader(h, val);

    const match = this.routes.find((r) => r.method === req.method && r.rx.test(path));
    if (!match) return this._json(res, 404, { error: 'not_found', message: `no route for ${req.method} ${path}` });

    if (match.roles && typeof match.roles !== 'string' && !match.roles.includes(principal.role)) {
      return this._json(res, 403, {
        error: 'forbidden',
        message: `role "${principal.role}" may not access this endpoint`,
        allowed: match.roles
      });
    }

    let body = {};
    let rawBody = '';
    if (req.method !== 'GET') {
      try {
        const read = await readBody(req);
        body = read.parsed;
        rawBody = read.raw;
      } catch (e) { return this._json(res, 400, { error: 'bad_request', message: e.message }); }
    }

    const m = match.rx.exec(path);
    const params = Object.fromEntries(match.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
    const query = Object.fromEntries(url.searchParams);

    try {
      const result = await match.handler({ params, query, body, rawBody, headers: req.headers, principal, req });
      if (result instanceof HttpResponse) {
        this._log(req, principal, result.status, Date.now() - started);
        this._emitSiem({ at: iso(), actor: principal.name, method: req.method, path, status: result.status });
        return result.send(res);
      }
      this._log(req, principal, 200, Date.now() - started);
      this._emitSiem({ at: iso(), actor: principal.name, method: req.method, path, status: 200 });
      return this._json(res, 200, result === undefined ? { ok: true } : result);
    } catch (e) {
      const status = e instanceof VaultError ? e.status : 500;
      this._log(req, principal, status, Date.now() - started);
      // No content in error messages, ever (§9.11).
      if (scimRoute) return this._scimError(res, status, e instanceof VaultError ? e.message : 'unexpected error', e?.meta?.scimType);
      return this._json(res, status, e instanceof VaultError ? e.toJSON() : { error: 'internal', message: 'unexpected error' });
    }
  }

  /** RFC 7644 §3.12 — an IdP parses this shape, not Vault's. */
  _scimError(res, status, detail, scimType = null) {
    const body = JSON.stringify({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      // The RFC really does make this a string, and Okta's parser really does
      // care.
      status: String(status), detail, ...(scimType ? { scimType } : {})
    });
    res.writeHead(status, {
      'Content-Type': 'application/scim+json; charset=utf-8', 'Content-Length': Buffer.byteLength(body)
    });
    res.end(body);
  }

  _log(req, principal, status, ms) {
    this.requestLog.push({ at: now(), actor: principal.name, method: req.method, path: req.url.split('?')[0], status, ms });
    if (this.requestLog.length > 5000) this.requestLog.splice(0, 2500);
  }

  _emitSiem(event) {
    for (const sink of this.siemSinks) { try { sink(event); } catch { /* a sink must never break the API */ } }
  }

  _json(res, status, payload) {
    const body = JSON.stringify(payload, replacer, status >= 400 ? 0 : 0);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  }

  _serveUi(path, res) {
    // The browser cannot `import` from src/ui/i18n.js without a module server,
    // and duplicating the string table into app.js would guarantee the two
    // drift. So the module is shipped verbatim with its exports bound to a
    // global — one source of truth, no build step.
    if (path === '/i18n-bundle.js') {
      const src = readFileSync(join(UI_DIR, 'i18n.js'), 'utf8')
        .replace(/^export (const|class|function) /gm, '$1 ');
      const body = `window.VaultI18n=(function(){\n${src}\nreturn {LOCALES,STRINGS,I18n,coverage,negotiate};\n})();\n`;
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' });
      return res.end(body);
    }
    const rel = path === '/' ? '/index.html' : path;
    const file = join(UI_DIR, normalize(rel).replace(/^(\.\.[/\\])+/, ''));
    if (!file.startsWith(UI_DIR) || !existsSync(file)) {
      // SPA fallback
      const index = join(UI_DIR, 'index.html');
      if (existsSync(index)) {
        const html = readFileSync(index);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(html);
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('not found');
    }
    const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml' };
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' });
    res.end(readFileSync(file));
  }

  listen() {
    this.server = createServer((req, res) => {
      this.handle(req, res).catch(() => {
        try { res.writeHead(500); res.end('{"error":"internal"}'); } catch { /* socket gone */ }
      });
    });
    return new Promise((resolve) => {
      this.server.listen(this.port, this.host, () => resolve(this));
    });
  }

  close() {
    return new Promise((resolve) => (this.server ? this.server.close(resolve) : resolve()));
  }
}

/**
 * A handler's escape hatch from "200 with a JSON body".
 *
 * Needed because three of the identity endpoints are not API calls at all: the
 * SAML ACS answers a browser form POST with a 302 and a cookie, SP metadata is
 * XML, and SCIM insists on 201/204 with its own content type. Encoding those in
 * the handler's return value keeps the dispatcher one path rather than a
 * growing list of special cases.
 */
export class HttpResponse {
  constructor({ status = 200, body = null, json = undefined, contentType = 'application/json; charset=utf-8', headers = {}, cookie = null } = {}) {
    this.status = status;
    this.headers = { ...headers };
    if (cookie) this.headers['Set-Cookie'] = cookie;
    if (json !== undefined) {
      this.body = JSON.stringify(json, replacer);
      this.headers['Content-Type'] = contentType;
    } else {
      this.body = body ?? '';
      if (this.body !== '') this.headers['Content-Type'] = contentType;
    }
  }

  static redirect(location, { cookie = null, status = 302 } = {}) {
    return new HttpResponse({ status, headers: { Location: location }, cookie, body: '' });
  }

  header(name, value) { this.headers[name] = value; return this; }

  send(res) {
    const headers = { ...this.headers };
    if (this.body !== '') headers['Content-Length'] = Buffer.byteLength(this.body);
    res.writeHead(this.status, headers);
    res.end(this.body);
  }
}

function bearerOf(req) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();
  if (req.headers['x-vault-token']) return String(req.headers['x-vault-token']);
  // The SSO cookie, so a browser that just completed a SAML login is
  // authenticated without JavaScript having to read the token — which is
  // exactly what HttpOnly prevents.
  const cookie = /(?:^|;\s*)vault_session=([^;]+)/.exec(req.headers.cookie || '');
  return cookie ? decodeURIComponent(cookie[1]) : '';
}

/**
 * HttpOnly so XSS cannot read it, Secure so it never crosses plaintext, and
 * SameSite=Lax rather than Strict because the SAML ACS arrives as a
 * cross-site POST redirect and Strict would drop the cookie on the very
 * request that sets it.
 */
function sessionCookie(token) {
  return `vault_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/**
 * RelayState and `next` are attacker-influenced — the IdP echoes back whatever
 * it was handed. Anything that is not a same-site absolute path is dropped
 * rather than sanitised, because a login endpoint that redirects off-origin is
 * a ready-made phishing primitive.
 */
function safeRelayState(value) {
  if (!value) return null;
  const s = String(value);
  if (!s.startsWith('/') || s.startsWith('//')) return null;
  if (/[\r\n]/.test(s)) return null;
  return s;
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket?.remoteAddress ?? null;
}

/** Group names from the assertion, mapped through the same table SCIM uses. */
function roleFromGroups(scim, groups = []) {
  return scim._roleFor(groups.map((g) => (typeof g === 'string' ? g : g?.display ?? g?.value)).filter(Boolean));
}

function principalActor(principal) {
  return {
    id: principal.name,
    kind: 'human',
    department: principal.department,
    approved: true,
    projects: principal.projects,
    privilegeCleared: ROLES[principal.role]?.privilegeCleared,
    breakGlass: principal.breakGlass
  };
}

function summariseFact(f, principal) {
  return {
    id: f.id, claim: f.claim, claimType: f.claimType, golden: Boolean(f.golden),
    folder: f.folder, sensitivity: f.sensitivity, status: f.status,
    confidence: f.confidence, saidBy: f.saidBy?.name, channel: f.channel,
    channelTrust: f.channelTrust, createdAt: iso(f.createdAt), version: f.version,
    readCount: f.readCount, instructionScore: f.instructionScore,
    sourceRef: f.source?.conversationId ?? null, ledgerPosition: f.ledgerPosition
  };
}

function siemSeverity(type) {
  if (type.startsWith('security.') || type === 'fact.blocked' || type === 'golden.overwrite_refused') return 'high';
  if (type.startsWith('killswitch.') || type.startsWith('admin.breakglass')) return 'high';
  if (type.startsWith('privacy.') || type.startsWith('legal.')) return 'medium';
  return 'low';
}

/**
 * Read the body, keeping the raw bytes.
 *
 * Signature-verified integrations (Slack, Teams) HMAC the RAW body. Handing
 * them a re-serialised object produces a different digest and every request
 * fails verification, so the raw string travels alongside the parsed form.
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 8e6) reject(new Error('payload too large'));
    });
    req.on('end', () => {
      if (!data) return resolve({ parsed: {}, raw: '' });
      const type = String(req.headers['content-type'] || '');
      if (type.includes('application/x-www-form-urlencoded')) {
        return resolve({ parsed: Object.fromEntries(new URLSearchParams(data)), raw: data });
      }
      try { resolve({ parsed: JSON.parse(data), raw: data }); } catch { reject(new Error('invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

/** Functions and Maps never survive JSON; drop them rather than throwing. */
function replacer(key, value) {
  if (typeof value === 'function') return undefined;
  if (value instanceof Map) return Object.fromEntries(value);
  if (value instanceof Set) return [...value];
  if (value instanceof RegExp) return value.source;
  if (typeof value === 'bigint') return String(value);
  return value;
}
