/**
 * L4 — THE GATE (§8).
 *
 * ★ This layer cannot be toggled, disabled, bypassed or replaced. It runs in
 *   every module configuration. There is no "pass unchecked" code path. ★
 *
 * Ten checks on every write, from every agent, forever:
 *   1  identity & authorisation      6  walls
 *   2  channel trust                 7  instruction detection
 *   3  source verification           8  policy rules
 *   4  private information scan      9  reconciliation
 *   5  sensitivity labelling        10  consent & lawful basis
 */
import { now, iso, HOUR, MINUTE } from '../util/time.js';
import { VaultError } from '../util/errors.js';
import { editDistance, truncate } from '../util/text.js';
import { severity as ruleSeverity } from './rules.js';

// ---------------------------------------------------------------------------
// Check 2 — channel trust. Trust comes from ARCHITECTURE, not a filter score.
// A filter can be talked around. A channel classification cannot.
// ---------------------------------------------------------------------------
export const CHANNEL_TRUST = {
  employee_session: { trust: 'trusted', default: 'pass', label: 'Logged-in employee, verified session, MFA' },
  system_of_record: { trust: 'trusted', default: 'pass', label: 'Internal system of record (CRM, ticketing, HRIS)' },
  signed_internal_service: { trust: 'trusted', default: 'pass', label: 'Signed internal service' },
  phone_call_authenticated: { trust: 'semi-trusted', default: 'pass', tag: true, label: 'Voice call with authenticated counterparty' },
  phone_call: { trust: 'untrusted', default: 'hold', label: 'Voice call, unauthenticated' },
  email: { trust: 'untrusted', default: 'hold', label: 'Email — any, including internal' },
  web_form: { trust: 'untrusted', default: 'hold', label: 'Web form / lead form' },
  customer_chat: { trust: 'untrusted', default: 'hold', label: 'Customer chat' },
  pr_comment: { trust: 'untrusted', default: 'hold', label: 'PR / issue / code comment from outside' },
  scraped_document: { trust: 'untrusted', default: 'hold', label: 'Scraped page, doc, PDF, spreadsheet from outside' },
  third_party_api: { trust: 'untrusted', default: 'hold', label: 'Third-party API response' },
  mcp_tool_output: { trust: 'untrusted', default: 'hold', label: 'MCP tool output from an external server' },
  agent_output: { trust: 'untrusted', default: 'hold', label: "Another agent's output" },
  sms: { trust: 'untrusted', default: 'hold', label: 'SMS / messaging' },
  slack_internal: { trust: 'untrusted', default: 'hold', label: 'Internal chat message' },
  unknown: { trust: 'untrusted', default: 'hold', label: 'Unknown / unclassifiable' }
};

export const SENSITIVITY = ['public', 'internal', 'confidential', 'secret'];
export const SENSITIVITY_RANK = { public: 0, internal: 1, confidential: 2, secret: 3 };

export const OUTCOMES = {
  pass: 'Written. Sealed. Indexed. Agent gets confirmation with fact ID.',
  hold: 'Needs Review queue with a plain-language reason. Invisible to all agents.',
  block: 'Rejected. Logged. Alert fired. Agent told, with reason. Source reputation updated.',
  mask: 'Written with sensitive parts removed. Original only in raw archive.',
  escalate: 'Routed to a specific named approver, not the general queue.',
  quarantine: 'Written to an isolated namespace no agent can read. For forensics.',
  'require-4-eyes': 'Two named approvers required before it becomes live.'
};

export class Gate {
  /**
   * @param {object} deps
   */
  constructor({
    registry, folders, pii, instructions, rules, reconciler, consent, ledger,
    killswitch, temporal, alerts, modules, privacy,
    latencyBudget = { p50: 80, p95: 250, p99: 600 },
    failSafe = 'queue',           // 'queue' | 'reject'   ('pass unchecked' does not exist
    fastPathEnabled = true
  }) {
    this.registry = registry;
    this.folders = folders;
    this.pii = pii;
    this.instructions = instructions;
    this.rules = rules;
    this.reconciler = reconciler;
    this.consent = consent;
    this.ledger = ledger;
    this.killswitch = killswitch;
    this.temporal = temporal;
    this.alerts = alerts;
    this.modules = modules;
    this.privacy = privacy;
    this.latencyBudget = latencyBudget;
    if (failSafe !== 'queue' && failSafe !== 'reject') {
      // (c) "pass unchecked" is not an option. No code path. (§8.12)
      throw new VaultError('config', 'failSafe must be "queue" or "reject" — passing writes unchecked is not an available posture');
    }
    this.failSafe = failSafe;
    this.fastPathEnabled = fastPathEnabled;
    /** @type {Map<string,{sent:number[], blocked:number[]}>} */
    this.rateWindows = new Map();
    /** Sender reputation, built from the history of held/blocked/approved writes. */
    this.reputation = new Map();
    this.blocklist = new Set();
    this.knownSenders = new Set();
    this.latencies = [];
    this.evaluationHistory = [];
    this.historyLimit = 5000;
  }

  /**
   * Evaluate one candidate fact.
   * @param {object} candidate from the extractor
   * @param {object} ctx { agentId, actor, channel, source, conversation, folderHint, region, ... }
   * @returns {object} verdict
   */
  evaluate(candidate, ctx = {}) {
    const started = process.hrtime.bigint();
    const checks = [];
    /** @type {string} */
    let outcome = 'pass';
    let escalateTo = null;
    const reasons = [];

    const record = (n, name, result, detail) => {
      checks.push({ check: n, name, result, ...detail });
      return detail;
    };
    const escalateOutcome = (next, why) => {
      if (ruleSeverity(next) > ruleSeverity(outcome)) outcome = next;
      if (why) reasons.push(why);
    };

    // Kill switch first: at level 2+ everything is reviewed or refused. The
    // switch never turns the gate OFF, only ever tightens it (§16.1).
    const ks = this.killswitch?.state() ?? { level: 0 };
    if (ks.level >= 3 && ks.scopeMatches?.(ctx)) {
      escalateOutcome('block', `kill switch level ${ks.level} (${ks.label}) — writes are not being accepted`);
    } else if (ks.level === 2) {
      escalateOutcome('hold', 'kill switch level 2 — every write is going to the review queue');
    } else if (ks.level === 1) {
      reasons.push('kill switch level 1 — everything flagged, nothing changed');
    }

    // ---- CHECK 1 — identity & authorisation (§8.1) ------------------------
    const c1 = this._checkIdentity(ctx);
    record(1, 'identity & authorisation', c1.ok ? 'pass' : 'fail', c1);
    if (!c1.ok) {
      escalateOutcome(c1.action || 'block', c1.reason);
      // An unknown agent writing is how you catch shadow agents. Alert, always.
      if (c1.unknownAgent) {
        this.alerts?.raise({
          severity: 'high', kind: 'unknown_agent_write', actor: ctx.agentId,
          detail: 'an unregistered agent attempted a write', channel: ctx.channel
        });
      }
    }

    // ---- CHECK 2 — channel trust (§8.2) ----------------------------------
    const c2 = this._checkChannel(ctx);
    record(2, 'channel trust', c2.trust === 'trusted' ? 'pass' : c2.default === 'hold' ? 'hold' : 'pass', c2);
    if (c2.default === 'hold') {
      escalateOutcome('hold', `${c2.label} is an untrusted channel by architecture (default deny-by-source)`);
    }

    // ---- CHECK 3 — source verification (§8.3) ----------------------------
    const c3 = this._checkSource(ctx);
    record(3, 'source verification', c3.ok ? 'pass' : 'fail', c3);
    if (!c3.ok) escalateOutcome(c3.action || 'hold', c3.reason);

    // ---- CHECK 4 — private information scan (§8.4) -----------------------
    const c4 = this._checkPii(candidate, ctx);
    record(4, 'private information scan', c4.action === 'allow' ? 'pass' : c4.action, c4);
    if (c4.action !== 'allow') {
      escalateOutcome(c4.action === 'tokenise' || c4.action === 'redact' ? 'mask' : c4.action, c4.reason);
    }

    // ---- CHECK 5 — sensitivity labelling (§8.5) --------------------------
    const c5 = this._checkLabel(candidate, ctx, c4);
    record(5, 'sensitivity labelling', 'pass', c5);
    if (c5.uncertain) escalateOutcome('hold', `classifier was unsure — labelled up to ${c5.label} and sent for review (never guess downward)`);

    // ---- CHECK 6 — walls (§8.6) ------------------------------------------
    const c6 = this._checkWalls(candidate, ctx, c5);
    record(6, 'walls', c6.allowed ? 'pass' : 'fail', c6);
    if (!c6.allowed) {
      escalateOutcome('block', c6.reason);
      this.alerts?.raise({ severity: 'high', kind: 'cross_wall_attempt', actor: ctx.agentId, detail: c6.reason, folder: c6.folder });
    } else if (c6.needsRouting) {
      escalateOutcome('hold', c6.reason);
    }

    // ---- CHECK 7 — instruction detection (§8.7, §9.3) --------------------
    // Runs INDEPENDENTLY of the channel check. Both must pass.
    const c7 = this._checkInstructions(candidate, ctx);
    record(7, 'instruction detection', c7.verdict === 'clean' ? 'pass' : 'hold', c7);
    if (c7.verdict === 'hold') escalateOutcome('hold', c7.explanation);

    // ---- CHECK 8 — policy rules (§8.8) -----------------------------------
    const ruleCtx = this._ruleContext(candidate, ctx, { c2, c4, c5, c7 });
    const c8 = this.rules.evaluate(ruleCtx);
    record(8, 'policy rules', c8.action === 'pass' ? 'pass' : c8.action, {
      evaluated: c8.evaluated, matched: c8.matched.map((m) => ({ id: m.id, name: m.name, action: m.ruleAction, why: m.explanation }))
    });
    if (c8.action !== 'pass') {
      escalateOutcome(c8.action, c8.matched.map((m) => `rule ${m.id} (${m.name})`).join(', '));
      escalateTo = c8.escalateTo || escalateTo;
    }
    // Remember the context so future rules can be backtested against reality.
    this._remember(ruleCtx);

    // ---- CHECK 9 — reconciliation (§8.9) ---------------------------------
    const c9 = this.reconciler.reconcile(candidate, { ...ctx, channelTrust: c2.trust });
    record(9, 'reconciliation', c9.kind, c9);
    if (c9.action === 'block') {
      escalateOutcome('block', c9.explanation);
      this.alerts?.raise({
        severity: 'critical', kind: 'golden_overwrite_attempt', actor: ctx.agentId,
        detail: c9.explanation, goldenId: c9.against
      });
      this._flagSource(ctx, 'attempted to overwrite a golden fact');
    } else if (c9.action === 'arbitrate') {
      escalateOutcome('hold', c9.explanation);
    }

    // ---- CHECK 10 — consent & lawful basis (§8.10) -----------------------
    const c10 = this._checkConsent(candidate, ctx);
    record(10, 'consent & lawful basis', c10.ok ? 'pass' : 'hold', c10);
    if (!c10.ok) {
      escalateOutcome(c10.action || 'hold', c10.reason);
      escalateTo = c10.escalateTo || escalateTo;
    }

    // ---- temporal & behavioural detection (§9.6) -------------------------
    const temporal = this.temporal?.observe(candidate, { ...ctx, outcome, instructionScore: c7.score }) ?? { detections: [] };
    if (temporal.detections.length) {
      checks.push({ check: '+', name: 'temporal & behavioural', result: 'detection', detections: temporal.detections });
      for (const d of temporal.detections) {
        if (d.action === 'hold' || d.action === 'block') escalateOutcome(d.action, d.explanation);
        this.alerts?.raise({ severity: d.severity, kind: d.kind, actor: ctx.agentId, detail: d.explanation });
      }
    }

    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    this.latencies.push(elapsedMs);
    if (this.latencies.length > 10000) this.latencies.splice(0, 5000);

    const fastPath = this.fastPathEnabled && c2.trust === 'trusted' && !c8.matched.length &&
                     c9.kind === 'novel' && c7.verdict === 'clean' && c4.action === 'allow';

    const verdict = {
      outcome,
      escalateTo,
      reasons,
      checks,
      // what the fact store needs
      label: c5.label,
      folder: c6.folder,
      maskedClaim: c4.masked,
      piiFindings: c4.findings,
      instructionScore: c7.score,
      // Explicit, so callers never have to infer "was this instruction-shaped?"
      // from a score threshold — the ensemble already decided.
      instruction: { detected: c7.verdict !== 'clean', score: c7.score, signals: c7.signals ?? [] },
      channelTrust: c2.trust,
      reconciliation: c9,
      consentBasis: c10.basis,
      rulesEvaluated: c8.evaluated.filter((e) => e.result !== 'n/a').map((e) => `${e.id} ${e.result}`),
      temporal: temporal.detections,
      fastPath,
      latencyMs: Math.round(elapsedMs * 100) / 100,
      withinBudget: elapsedMs <= this.latencyBudget.p95,
      description: OUTCOMES[outcome],
      explanation: this.explain({ outcome, reasons, checks })
    };
    return verdict;
  }

  /** Plain-language "why", for the review queue's explain-why panel (§12). */
  explain({ outcome, reasons, checks }) {
    if (outcome === 'pass') {
      return 'All ten checks passed. Written, sealed and indexed.';
    }
    const failed = checks.filter((c) => c.result !== 'pass' && c.result !== 'novel' && c.result !== 'n/a');
    const head = {
      hold: 'Held for review — not visible to any agent until a human decides.',
      block: 'Rejected. This never became a fact.',
      mask: 'Written with the sensitive parts removed; the original stays only in the raw archive.',
      escalate: 'Routed to a named approver rather than the general queue.',
      quarantine: 'Written to an isolated namespace no agent can read, for forensics.',
      'require-4-eyes': 'Two named approvers are required before this becomes live.'
    }[outcome] || outcome;
    return `${head}\n\nWhy: ${reasons.map((r, i) => `${i + 1}. ${r}`).join('\n      ')}\n\n`
      + `Checks that fired: ${failed.map((f) => `${f.check} ${f.name}`).join(' · ')}`;
  }

  // -- CHECK 1 -------------------------------------------------------------

  _checkIdentity(ctx) {
    const agent = this.registry?.get(ctx.agentId);
    if (!agent) {
      return {
        ok: false, unknownAgent: true, action: 'block',
        reason: `unregistered agent "${ctx.agentId ?? 'unknown'}" attempted a write — blocked and alerted (this is how shadow agents surface)`
      };
    }
    const detail = {
      agentId: agent.id, mode: agent.mode,
      businessOwner: agent.businessOwner, technicalOwner: agent.technicalOwner
    };
    if (!agent.businessOwner || !agent.technicalOwner) {
      return { ...detail, ok: false, action: 'hold', reason: `agent ${agent.id} has no ${!agent.businessOwner ? 'business' : 'technical'} owner — an unowned agent is a finding` };
    }
    if (agent.status === 'suspended' || agent.status === 'retired') {
      return { ...detail, ok: false, action: 'block', reason: `agent ${agent.id} is ${agent.status} — writes are rejected` };
    }
    const cred = this.registry.checkCredential(agent.id, ctx.credential, ctx.origin);
    if (!cred.valid) {
      return { ...detail, ok: false, action: 'block', reason: `credential ${cred.reason}` };
    }
    if (ctx.folderHint) {
      const scoped = this.registry.canWriteFolder(agent.id, ctx.folderHint);
      if (!scoped.allowed) {
        // Same distinction as check 6: an explicit out-of-scope write is a
        // block; a classifier-proposed one is a routing question for a human.
        return ctx.folderExplicit
          ? { ...detail, ok: false, action: 'block', reason: scoped.reason }
          : { ...detail, ok: false, action: 'hold', reason: `${scoped.reason} — the folder was proposed by routing, not requested, so this is held for review` };
      }
    }
    if (ctx.label && !this.registry.canWriteSensitivity(agent.id, ctx.label)) {
      return { ...detail, ok: false, action: 'block', reason: `agent ${agent.id} is not cleared to write ${ctx.label} facts` };
    }
    if (ctx.region && agent.regions?.length && !agent.regions.includes(ctx.region)) {
      return { ...detail, ok: false, action: 'block', reason: `agent ${agent.id} is not authorised in region ${ctx.region}` };
    }
    if (agent.pinnedModel && ctx.modelVersion && ctx.modelVersion !== agent.pinnedModel) {
      const approved = (agent.approvedModels || []).includes(ctx.modelVersion);
      if (!approved) {
        return {
          ...detail, ok: false, action: 'hold',
          reason: `model version ${ctx.modelVersion} is not the pinned/approved version (${agent.pinnedModel}) — held pending model review`,
          modelSwap: true
        };
      }
    }
    const rate = this._rate(agent.id);
    if (agent.rateLimitPerHour && rate.hour > agent.rateLimitPerHour) {
      return { ...detail, ok: false, action: 'hold', reason: `agent ${agent.id} is over its rate budget (${rate.hour}/${agent.rateLimitPerHour} per hour)`, rate };
    }
    return { ...detail, ok: true, rate, reason: 'registered, owned, credentialed and in scope' };
  }

  // -- CHECK 2 -------------------------------------------------------------

  _checkChannel(ctx) {
    const key = ctx.channel && CHANNEL_TRUST[ctx.channel] ? ctx.channel : 'unknown';
    const spec = CHANNEL_TRUST[key];
    const override = this.channelOverrides?.[key];
    return {
      channel: key,
      trust: override?.trust ?? spec.trust,
      default: override?.default ?? spec.default,
      label: spec.label,
      tag: spec.tag ?? false,
      note: key === 'email'
        ? 'Internal email is untrusted by design. Employees get phished.'
        : key === 'agent_output'
          ? "Another agent's output is untrusted by default — agent-to-agent trust is not transitive."
          : null
    };
  }

  // -- CHECK 3 -------------------------------------------------------------

  _checkSource(ctx) {
    const src = ctx.source || {};
    const sender = src.sender || src.from || null;
    const domain = sender && sender.includes('@') ? sender.split('@')[1].toLowerCase() : (src.domain || null);
    const problems = [];
    const positives = [];

    if (ctx.channel === 'email') {
      const auth = src.auth || {};
      for (const mech of ['spf', 'dkim', 'dmarc']) {
        if (auth[mech] === 'pass') positives.push(`${mech.toUpperCase()} pass`);
        else if (auth[mech]) problems.push(`${mech.toUpperCase()} ${auth[mech]}`);
        else problems.push(`${mech.toUpperCase()} absent`);
      }
    }
    if (ctx.channel === 'third_party_api' || ctx.channel === 'mcp_tool_output') {
      if (src.signatureValid === true) positives.push('webhook signature valid');
      else if (src.signatureValid === false) problems.push('webhook signature INVALID');
      else problems.push('webhook signature not verified');
    }
    if (ctx.channel === 'signed_internal_service') {
      if (src.mtls === true) positives.push('mTLS verified');
      else problems.push('mTLS not presented for a service claiming internal trust');
    }

    if (this.blocklist.has(sender) || this.blocklist.has(domain)) {
      return { ok: false, action: 'block', reason: `source ${sender || domain} is on the blocklist`, sender, domain };
    }

    const firstTime = sender ? !this.knownSenders.has(sender) : false;
    if (sender) this.knownSenders.add(sender);

    // Lookalike / homoglyph domain detection against the company's own domains.
    let lookalike = null;
    if (domain && ctx.corporateDomains?.length) {
      for (const d of ctx.corporateDomains) {
        const dist = editDistance(domain, d, 3);
        if (dist > 0 && dist <= 2) { lookalike = { domain, resembles: d, distance: dist }; break; }
      }
    }
    if (lookalike) problems.push(`lookalike domain: ${lookalike.domain} resembles ${lookalike.resembles}`);

    const rep = this.reputation.get(sender || domain) || { approved: 0, held: 0, blocked: 0, score: 0.5 };

    if (src.geoAnomaly || src.asnAnomaly) {
      problems.push(`origin anomaly: ${[src.geoAnomaly && `geo ${src.geoAnomaly}`, src.asnAnomaly && `ASN ${src.asnAnomaly}`].filter(Boolean).join(', ')}`);
    }
    if (src.domainAgeDays != null && src.domainAgeDays < 30) {
      problems.push(`domain registered ${src.domainAgeDays} days ago`);
    }

    const ok = problems.length === 0;
    return {
      ok,
      action: lookalike || rep.score < 0.2 ? 'block' : 'hold',
      sender, domain, firstTime, lookalike,
      reputation: rep,
      positives,
      problems,
      reason: ok
        ? `source verified (${positives.join(', ') || 'no verification required for this channel'})`
        : `source verification: ${problems.join('; ')}${firstTime ? ' · first contact from this sender (elevated scrutiny)' : ''}`
    };
  }

  // -- CHECK 4 -------------------------------------------------------------

  _checkPii(candidate, ctx) {
    // 🟢 built-in scanner; 🔵/🟣 a connected DLP's verdict is combined, stricter wins
    const own = this.pii.scan(candidate.claim, { subject: ctx.subject, purpose: ctx.purpose });
    const external = this.modules?.dispatch('dlp', 'scan', { text: candidate.claim, ctx });
    const combined = external?.action
      ? { ...own, action: strictestAction(own.action, external.action), external }
      : own;
    const reason = combined.action === 'block'
      ? `credentials or secrets detected (${combined.credentials.map((c) => c.label).join(', ') || 'high-entropy secret'}) — blocked entirely, never masked-and-stored, source flagged`
      : combined.action === 'quarantine'
        ? "children's data indicators present — quarantined pending a lawful-basis decision"
        : combined.action !== 'allow'
          ? `private information detected (${combined.categories.join(', ')}) — ${combined.action}`
          : 'no private information detected';
    if (combined.action === 'block') this._flagSource(ctx, 'transmitted a credential');
    return { ...combined, reason };
  }

  // -- CHECK 5 -------------------------------------------------------------

  /** explicit rule → folder inheritance → external label → classifier → default */
  _checkLabel(candidate, ctx, pii) {
    const trail = [];
    let label = null;
    let uncertain = false;

    if (ctx.explicitLabel && SENSITIVITY.includes(ctx.explicitLabel)) {
      label = ctx.explicitLabel;
      trail.push(`explicit rule → ${label}`);
    }
    if (!label && ctx.folderHint) {
      const folder = this.folders.resolve(ctx.folderHint);
      if (folder?.defaultSensitivity) {
        label = folder.defaultSensitivity;
        trail.push(`inherited from ${folder.path} → ${label}`);
      }
    }
    if (!label && ctx.externalLabel) {
      label = mapExternalLabel(ctx.externalLabel);
      trail.push(`external label (${ctx.externalLabel}) → ${label}`);
    }
    if (!label) {
      const guess = candidate.sensitivityGuess || 'internal';
      const confident = (candidate.confidence ?? 0) >= 0.7;
      if (!confident) {
        // Never guess downward. Higher label, then review.
        label = SENSITIVITY[Math.min(SENSITIVITY_RANK[guess] + 1, 3)];
        uncertain = true;
        trail.push(`classifier unsure (confidence ${candidate.confidence}) → raised to ${label}, sent for review`);
      } else {
        label = guess;
        trail.push(`classifier → ${label}`);
      }
    }
    // PII forces a floor.
    if (pii.specialCategory || pii.categories?.includes('health') || pii.categories?.includes('national_id')) {
      if (SENSITIVITY_RANK[label] < SENSITIVITY_RANK.confidential) {
        label = 'confidential';
        trail.push('special-category or national-ID data present → raised to confidential');
      }
    }
    return {
      label,
      uncertain,
      trail,
      drives: ['which agents can read it', 'retention', 'export permission', 'cross-region movement', 'UI masking', 'read-log fidelity', 'break-glass requirement']
    };
  }

  // -- CHECK 6 -------------------------------------------------------------

  _checkWalls(candidate, ctx, labelCheck) {
    const path = ctx.folderHint || candidate.proposedFolder;
    if (!path) {
      // Uncertain routing → review, never a guess. A misfiled fact crosses a
      // wall, and that's a breach (§11.1).
      return {
        allowed: true, folder: null, needsRouting: true,
        reason: 'folder could not be determined with confidence — routed to review rather than guessed'
      };
    }
    const agent = this.registry?.get(ctx.agentId);
    const actor = {
      id: ctx.agentId, kind: 'agent',
      department: agent?.department, projects: agent?.projects,
      breakGlass: ctx.breakGlass
    };
    const res = this.folders.check('write', actor, path);

    // A folder the CLASSIFIER proposed is not the same as a folder the agent
    // asked for. If routing put the fact somewhere this agent may not write,
    // that is a routing failure — hold it for a human. Treating it as an attack
    // would fill the security queue with classifier noise and train people to
    // ignore it. An explicit cross-wall write is still blocked and alerted.
    if (!res.allowed && !ctx.folderExplicit) {
      return {
        allowed: true,
        needsRouting: true,
        routingFailure: true,
        folder: null,
        proposedFolder: res.folder?.path ?? path,
        reason: `routing uncertain: the classifier proposed ${res.folder?.path ?? path}, which is outside this agent's scope — held for review rather than guessed`,
        hardWall: res.folder?.hardWall ?? false
      };
    }

    return {
      allowed: res.allowed,
      folder: res.folder?.path ?? path,
      reason: res.reason,
      hardWall: res.folder?.hardWall ?? false,
      requiresBreakGlass: res.requiresBreakGlass ?? false
    };
  }

  // -- CHECK 7 -------------------------------------------------------------

  _checkInstructions(candidate, ctx) {
    // Rules check the raw conversation, not just the tidy extracted summary —
    // this closes the obvious bypass (§8.8).
    const claimResult = this.instructions.analyse(candidate.claim, {
      position: candidate.source?.start,
      documentLength: ctx.conversation?.transcriptText?.length,
      surroundingText: ctx.conversation?.transcriptText,
      channel: ctx.channel,
      isToolDescription: ctx.isToolDescription
    });
    // Extraction already flags instruction-shaped candidates; honour that too.
    if (candidate.instructionShaped && claimResult.verdict === 'clean') {
      claimResult.verdict = 'hold';
      claimResult.score = Math.max(claimResult.score, 0.9);
      claimResult.signals.push('extractor_instruction_shaped');
      claimResult.explanation = 'Held: the extractor classified this as instruction-shaped — it describes desired behaviour, not the world.';
    }
    return claimResult;
  }

  // -- CHECK 10 ------------------------------------------------------------

  _checkConsent(candidate, ctx) {
    const people = (candidate.entities || []).filter((e) => e.type === 'person');
    if (!people.length) return { ok: true, basis: null, reason: 'no identifiable person in this claim' };
    if (!this.consent) return { ok: true, basis: null, reason: 'consent module not configured' };

    for (const person of people) {
      const subjectId = person.id || person.name;
      // The id is what consent is keyed on; the name is what a reviewer reads.
      const subjectName = person.name || subjectId;
      const status = this.consent.status(subjectId, { purpose: ctx.purpose || 'memory_governance' });
      if (status.erasureActive) {
        return { ok: false, action: 'block', reason: `${subjectName} has an active erasure request — no new facts about them may be written`, basis: null };
      }
      if (!status.basis) {
        return {
          ok: false, action: 'hold', escalateTo: 'Privacy',
          reason: `no recorded lawful basis for personal data about ${subjectName} — routed to Privacy, not guessed`,
          basis: null
        };
      }
      if (status.withdrawn) {
        return { ok: false, action: 'block', reason: `consent withdrawn for ${subjectId}`, basis: null };
      }
      if (!status.purposeCompatible) {
        return {
          ok: false, action: 'hold', escalateTo: 'Privacy',
          reason: `purpose limitation: this data was collected for "${status.collectedPurpose}" and this write serves "${ctx.purpose}"`,
          basis: status.basis
        };
      }
      if (status.minor && !status.parentalConsent) {
        return { ok: false, action: 'quarantine', reason: `${subjectId} appears to be a minor and no verifiable parental consent is recorded (DPDP §9 / COPPA)`, basis: status.basis };
      }
      if (status.specialCategory && !status.article9Condition) {
        return { ok: false, action: 'hold', escalateTo: 'Privacy', reason: 'special-category data without a recorded Art 9 condition', basis: status.basis };
      }
    }
    const first = people[0];
    const s = this.consent.status(first.id || first.name, { purpose: ctx.purpose || 'memory_governance' });
    return { ok: true, basis: s.basis, subject: first.name, reason: `lawful basis on record: ${s.basis}` };
  }

  // -- helpers -------------------------------------------------------------

  _ruleContext(candidate, ctx, { c2, c4, c5, c7 }) {
    const agent = this.registry?.get(ctx.agentId);
    const rate = this._rate(ctx.agentId);
    return {
      // claim surface
      claim: candidate.claim,
      rawConversation: ctx.conversation?.transcriptText ?? '',
      claimType: candidate.claimType,
      language: candidate.language,
      amount: typeof candidate.structured?.value === 'number' ? candidate.structured.value : numberIn(candidate.claim),
      attribute: candidate.structured?.attribute,
      entityTypes: (candidate.entities || []).map((e) => e.type),
      entityNames: (candidate.entities || []).map((e) => e.name),
      // context
      agentId: ctx.agentId,
      agent: agent ? { id: agent.id, department: agent.department, mode: agent.mode, purpose: agent.purpose } : null,
      channel: c2.channel,
      channelTrust: c2.trust,
      folder: ctx.folderHint || candidate.proposedFolder || '',
      sensitivity: c5.label,
      sensitivityRank: SENSITIVITY_RANK[c5.label],
      region: ctx.region ?? null,
      storageRegion: ctx.storageRegion ?? ctx.region ?? null,
      dataSubjectRegion: ctx.dataSubjectRegion ?? null,
      hour: new Date(now()).getUTCHours(),
      freezeWindow: ctx.freezeWindow ?? null,
      modelVersion: ctx.modelVersion ?? null,
      modelApproved: agent ? (!agent.pinnedModel || !ctx.modelVersion || ctx.modelVersion === agent.pinnedModel || (agent.approvedModels || []).includes(ctx.modelVersion)) : true,
      businessRecord: Boolean(ctx.businessRecord),
      authoritative: Boolean(ctx.authoritative),
      consentBasis: ctx.consentBasis ?? null,
      contradictsGolden: false,   // filled after check 9 for backtests
      instructionScore: c7.score,
      pii: { categories: c4.categories || [], action: c4.action },
      rate,
      saidByKind: candidate.saidBy?.kind ?? 'unknown',
      at: now()
    };
  }

  _remember(ruleCtx) {
    this.evaluationHistory.push(ruleCtx);
    if (this.evaluationHistory.length > this.historyLimit) {
      this.evaluationHistory.splice(0, this.evaluationHistory.length - this.historyLimit);
    }
  }

  /** History for rule backtesting (§8.8). */
  history({ days = 90 } = {}) {
    const cutoff = now() - days * 24 * HOUR;
    return this.evaluationHistory.filter((c) => c.at >= cutoff);
  }

  _rate(agentId) {
    if (!agentId) return { hour: 0, minute: 0, day: 0, baselineMultiple: 0 };
    let w = this.rateWindows.get(agentId);
    if (!w) this.rateWindows.set(agentId, (w = { sent: [], baseline: null }));
    const t = now();
    w.sent.push(t);
    // keep 24h
    while (w.sent.length && t - w.sent[0] > 24 * HOUR) w.sent.shift();
    const hour = w.sent.filter((x) => t - x <= HOUR).length;
    const minute = w.sent.filter((x) => t - x <= MINUTE).length;
    const day = w.sent.length;
    if (w.baseline == null && day >= 20) w.baseline = hour;
    const baselineMultiple = w.baseline ? hour / Math.max(w.baseline, 1) : 0;
    return { hour, minute, day, baseline: w.baseline, baselineMultiple: Math.round(baselineMultiple * 10) / 10 };
  }

  _flagSource(ctx, why) {
    const key = ctx.source?.sender || ctx.source?.domain || ctx.agentId;
    if (!key) return;
    const rep = this.reputation.get(key) || { approved: 0, held: 0, blocked: 0, score: 0.5, flags: [] };
    rep.blocked++;
    rep.flags = [...(rep.flags || []), { why, at: iso() }].slice(-20);
    rep.score = Math.max(0, rep.score - 0.25);
    this.reputation.set(key, rep);
  }

  /** Feedback from review decisions tunes source reputation and the classifier. */
  recordReviewOutcome(source, decision) {
    if (!source) return;
    const rep = this.reputation.get(source) || { approved: 0, held: 0, blocked: 0, score: 0.5, flags: [] };
    if (decision === 'approve') { rep.approved++; rep.score = Math.min(1, rep.score + 0.05); }
    else if (decision === 'reject') { rep.blocked++; rep.score = Math.max(0, rep.score - 0.1); }
    else rep.held++;
    this.reputation.set(source, rep);
  }

  blockSource(sender, { actor, reason }) {
    if (!actor || !reason) throw new VaultError('forbidden', 'blocking a source requires a named actor and a reason');
    this.blocklist.add(sender);
    this.ledger.append('security.detection', { subject: sender, actor, detection: 'source_blocked', reason });
    return { blocked: sender, at: iso() };
  }

  /** Latency percentiles against the published budget (§8.12). */
  latencyReport() {
    const s = [...this.latencies].sort((a, b) => a - b);
    const pct = (p) => (s.length ? Math.round(s[Math.min(s.length - 1, Math.floor(s.length * p))] * 100) / 100 : 0);
    return {
      samples: s.length,
      p50: pct(0.5), p95: pct(0.95), p99: pct(0.99),
      budget: this.latencyBudget,
      withinBudget: s.length ? pct(0.95) <= this.latencyBudget.p95 : true,
      failSafe: this.failSafe,
      note: 'fail-safe postures are queue-and-drain (default) or reject. "Pass unchecked" does not exist — there is no code path.'
    };
  }
}

function strictestAction(a, b) {
  const order = { allow: 0, mask: 1, tokenise: 2, redact: 3, quarantine: 4, block: 5 };
  return (order[b] ?? 0) > (order[a] ?? 0) ? b : a;
}

function mapExternalLabel(l) {
  const s = String(l).toLowerCase();
  if (/secret|restricted|highly confidential|tlp:red/.test(s)) return 'secret';
  if (/confidential|tlp:amber/.test(s)) return 'confidential';
  if (/internal|tlp:green/.test(s)) return 'internal';
  if (/public|tlp:clear|tlp:white/.test(s)) return 'public';
  return 'internal';
}

function numberIn(claim) {
  const m = String(claim).match(/(?:[$£€]\s?)?(\d[\d,]*(?:\.\d+)?)\s?(k|m|bn)?/i);
  if (!m) return null;
  let n = parseFloat(m[1].replace(/,/g, ''));
  const s = (m[2] || '').toLowerCase();
  if (s === 'k') n *= 1e3;
  if (s === 'm') n *= 1e6;
  if (s === 'bn') n *= 1e9;
  return n;
}
