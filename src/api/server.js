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
    this.route('POST', '/api/admin/modules/:name', R('admin', 'platform'), ({ params, body, principal }) =>
      v.setModule(params.name, body.state, { ...body, actor: principal.name }));
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
    this.route('GET', '/api/admin/storage', R('admin', 'platform', 'finance'), () => ({
      db: v.db.stats(), tiers: v.tiering.costReport(), lifecycle: v.tiering.previewLifecycle()
    }));
    this.route('POST', '/api/admin/hygiene', R('admin', 'platform'), ({ body, principal }) =>
      v.runHygiene({ ...body, actor: principal.name }));
    this.route('GET', '/api/admin/continuity', ALL, () => v.continuity.commitments());
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

  // -- HTTP ----------------------------------------------------------------

  _principal(req) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : (req.headers['x-vault-token'] || '');
    if (!token) return this.requireAuth ? null : { name: 'anonymous', role: 'platform' };
    for (const [t, p] of this.tokens) {
      if (constantTimeEqual(t, token)) return p;
    }
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

    if (!path.startsWith('/api/')) return this._serveUi(path, res);

    const principal = this._principal(req);
    if (!principal) return this._json(res, 401, { error: 'unauthenticated', message: 'present a bearer token' });

    const match = this.routes.find((r) => r.method === req.method && r.rx.test(path));
    if (!match) return this._json(res, 404, { error: 'not_found', message: `no route for ${req.method} ${path}` });

    if (match.roles && !match.roles.includes(principal.role)) {
      return this._json(res, 403, {
        error: 'forbidden',
        message: `role "${principal.role}" may not access this endpoint`,
        allowed: match.roles
      });
    }

    let body = {};
    if (req.method !== 'GET') {
      try { body = await readBody(req); } catch (e) { return this._json(res, 400, { error: 'bad_request', message: e.message }); }
    }

    const m = match.rx.exec(path);
    const params = Object.fromEntries(match.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
    const query = Object.fromEntries(url.searchParams);

    try {
      const result = await match.handler({ params, query, body, principal, req });
      this._log(req, principal, 200, Date.now() - started);
      this._emitSiem({ at: iso(), actor: principal.name, method: req.method, path, status: 200 });
      return this._json(res, 200, result === undefined ? { ok: true } : result);
    } catch (e) {
      const status = e instanceof VaultError ? e.status : 500;
      this._log(req, principal, status, Date.now() - started);
      // No content in error messages, ever (§9.11).
      return this._json(res, status, e instanceof VaultError ? e.toJSON() : { error: 'internal', message: 'unexpected error' });
    }
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

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 8e6) reject(new Error('payload too large'));
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch { reject(new Error('invalid JSON body')); }
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
