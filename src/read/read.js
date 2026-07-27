/**
 * L7 — THE READ PATH (§11.4).
 *
 *   1 IDENTIFY   2 AUTHORISE   3 RATE CHECK   4 RETRIEVE   5 FILTER
 *   6 RANK       7 LABEL       8 REDACT       9 RETURN    10 LOG   11 DETECT
 *
 * The agent SEES the labels. That is the difference between an AI that says
 * "Acme is evaluating a competitor" and one that says "there's an unconfirmed
 * signal". One of those loses you a deal or a lawsuit.
 *
 * Read logging is tiered on purpose: excessive logging is itself a liability.
 */
import { now, iso, ago, HOUR, MINUTE } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { truncate } from '../util/text.js';

/** §11.4 — read-log fidelity by label. */
export const LOG_FIDELITY = {
  secret: 'full',          // every read, every field returned
  confidential: 'full',
  internal: 'metadata',    // full metadata, sampled content
  public: 'aggregate'
};

export class ReadPath {
  /**
   * @param {object} deps
   */
  constructor({
    facts, folders, search, registry, ledger, killswitch, temporal, alerts,
    instructions, consent, privacy = null, sampleRate = 0.1
  }) {
    this.facts = facts;
    this.folders = folders;
    this.search = search;
    this.registry = registry;
    this.ledger = ledger;
    this.killswitch = killswitch;
    this.temporal = temporal;
    this.alerts = alerts;
    this.instructions = instructions;
    this.consent = consent;
    this.privacy = privacy;
    this.sampleRate = sampleRate;
    /** @type {Map<string, number[]>} read rate windows */
    this.rates = new Map();
    /** @type {Map<string, string[]>} query history per agent */
    this.queryHistory = new Map();
  }

  /**
   * @param {string} query
   * @param {object} ctx { agentId | actor, purpose, folder, entity, limit, clearance }
   */
  read(query, ctx = {}) {
    const started = process.hrtime.bigint();
    const trace = [];

    // -- 1 IDENTIFY --------------------------------------------------------
    const isAgent = Boolean(ctx.agentId);
    const agent = isAgent ? this.registry.get(ctx.agentId) : null;
    if (isAgent && !agent) {
      throw forbidden('unregistered agent attempted a read', { agentId: ctx.agentId });
    }
    if (agent && agent.status === 'retired') {
      throw forbidden('this agent is retired — reads stop immediately on retirement', { agentId: agent.id });
    }
    if (agent && agent.status === 'suspended' && agent.readsAllowed === false) {
      throw forbidden('this agent is suspended', { agentId: agent.id });
    }
    const cred = isAgent ? this.registry.checkCredential(ctx.agentId, ctx.credential, ctx.origin) : { valid: true };
    if (!cred.valid) throw forbidden(`credential ${cred.reason}`, { agentId: ctx.agentId });
    const actor = {
      id: agent?.id ?? ctx.actor ?? 'unknown',
      kind: agent ? 'agent' : 'human',
      department: agent?.department ?? ctx.department,
      projects: agent?.projects ?? ctx.projects,
      groups: ctx.groups ?? [],
      breakGlass: ctx.breakGlass
    };
    trace.push({ step: 1, name: 'IDENTIFY', actor: actor.id, kind: actor.kind, mode: agent?.mode ?? null });

    // Kill switch: reads are blocked only at levels 5 (scoped) and 6 (global).
    const blocked = this.killswitch?.readsBlocked({ ...ctx, agentId: actor.id }) ?? { blocked: false };
    if (blocked.blocked) {
      throw new VaultError('killswitch', blocked.reason, { agentMessage: this.killswitch.agentMessage() });
    }

    // -- 2 AUTHORISE -------------------------------------------------------
    const clearance = ctx.clearance ?? agent?.sensitivityCeiling ?? 'internal';
    const region = ctx.region ?? agent?.regions?.[0] ?? null;
    trace.push({ step: 2, name: 'AUTHORISE', clearance, region });

    // -- 3 RATE CHECK ------------------------------------------------------
    const rate = this._rate(actor.id);
    const budget = agent?.readLimitPerHour ?? 5000;
    if (rate.hour > budget) {
      throw new VaultError('rate_limited', 'read budget exceeded', { agentId: actor.id, hour: rate.hour, budget });
    }
    trace.push({ step: 3, name: 'RATE CHECK', ...rate, budget });

    // -- 11 DETECT (run early so a manipulative query is logged even if it
    //    returns nothing) --------------------------------------------------
    const history = this.queryHistory.get(actor.id) || [];
    const manipulation = this.instructions.analyseQuery(query, { history });
    history.push(query);
    if (history.length > 200) history.shift();
    this.queryHistory.set(actor.id, history);
    const retrieval = this.temporal?.observeQuery(actor.id, query);
    if (manipulation.suspicious || retrieval) {
      this.alerts?.raise({
        severity: 'medium', kind: 'retrieval_manipulation', actor: actor.id,
        detail: retrieval?.explanation || `query shows retrieval-manipulation indicators: ${manipulation.flags.join(', ')}`,
        subject: 'read_path'
      });
    }

    // -- 4 RETRIEVE + 5 FILTER + 6 RANK (delegated to the search engine, which
    //    applies the wall check we hand it) --------------------------------
    const canRead = (fact) => this._canRead(fact, actor, { clearance, region, purpose: ctx.purpose });
    const found = this.search.search(query, {
      actor,
      clearance,
      canRead,
      folder: ctx.folder ?? null,
      entity: ctx.entity ?? null,
      from: ctx.from ?? null,
      to: ctx.to ?? null,
      asOf: ctx.asOf ?? null,
      claimTypes: ctx.claimTypes ?? null,
      includeArchive: ctx.includeArchive ?? false,
      limit: ctx.limit ?? 20,
      purpose: ctx.purpose ?? 'agent_read',
      naturalLanguage: ctx.naturalLanguage ?? false
    });
    trace.push({ step: 4, name: 'RETRIEVE', candidates: found.results.length + found.withheld });
    trace.push({ step: 5, name: 'FILTER', withheld: found.withheld, reasons: found.withheldReasons });
    trace.push({ step: 6, name: 'RANK', order: 'golden > verified > trusted-channel > corroborated > specific > recent' });

    // -- 7 LABEL + 8 REDACT ------------------------------------------------
    const labelled = found.results
      .filter((r) => r.kind === 'fact')
      .map((r) => {
        const fact = this.facts.get(r.id);
        const redacted = this._redact(r, fact, clearance);
        return redacted;
      });
    const documents = found.results.filter((r) => r.kind === 'document');
    trace.push({ step: 7, name: 'LABEL', labelled: labelled.length });
    trace.push({ step: 8, name: 'REDACT', redacted: labelled.filter((r) => r.redactedFields?.length).length });

    // Held items are counted but never returned.
    const heldCount = this.facts.held().filter((f) =>
      (!ctx.folder || String(f.folder || '').startsWith(ctx.folder))).length;

    // -- 10 LOG ------------------------------------------------------------
    for (const r of labelled) {
      const fact = this.facts.get(r.id);
      if (!fact) continue;
      this.facts.recordRead(r.id, { agentId: actor.id, purpose: ctx.purpose ?? 'agent_read', fields: r.redactedFields });
      this.temporal?.observeRead(r.id);
      this._logRead(fact, actor, ctx, r);
    }
    trace.push({ step: 10, name: 'LOG', logged: labelled.length });
    trace.push({ step: 11, name: 'DETECT', suspicious: manipulation.suspicious, flags: manipulation.flags });

    if (agent) this.registry.recordUsage(agent.id, { read: labelled.length });

    const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
    return {
      query,
      facts: labelled,
      documents,
      answer: found.answer ?? null,
      withheld: found.withheld,
      withheldReasons: found.withheldReasons,
      heldInReview: heldCount,
      archive: found.archive,
      summary: `${labelled.length} fact${labelled.length === 1 ? '' : 's'} returned` +
        (found.withheld ? ` · ${found.withheld} withheld (${found.withheldReasons.map((w) => w.reason).join(', ')})` : '') +
        (heldCount ? ` · ${heldCount} held in review` : ''),
      latencyMs: Math.round(latencyMs * 100) / 100,
      trace,
      killswitchNotice: this.killswitch?.agentMessage() ?? null
    };
  }

  _canRead(fact, actor, { clearance, region, purpose }) {
    // Wall check, at read time.
    const wall = this.folders.check('read', actor, fact.folder || 'company/');
    if (!wall.allowed) {
      if (actor.kind === 'agent') {
        const probing = this.temporal?.observeCrossWall(actor.id, fact.folder);
        if (probing) this.alerts?.raise({ ...probing, actor: actor.id, detail: probing.explanation });
      }
      return { allowed: false, reason: 'walled' };
    }
    // Privileged material is excluded from general retrieval, including by
    // agents (§14.7).
    if (fact.privileged && !actor.privilegeCleared) {
      return { allowed: false, reason: 'privileged (attorney-client / work product)' };
    }
    // Region: cross-border read blocking, refused not just logged (§14.8).
    if (fact.region && region && fact.region !== region) {
      return { allowed: false, reason: `residency: ${fact.region} data cannot be read from ${region}` };
    }
    // Purpose limitation, enforced at READ time (§14.5).
    if (this.consent && purpose) {
      for (const e of fact.entities || []) {
        if (e.type !== 'person') continue;
        const check = this.consent.checkReadPurpose(e.id || e.name, purpose);
        if (!check.allowed) return { allowed: false, reason: check.reason };
      }
    }
    // Erased or quarantined never surface.
    if (fact.status === 'quarantined' || fact.status === 'erased') {
      return { allowed: false, reason: 'quarantined or erased' };
    }
    return { allowed: true };
  }

  /** Mask fields above clearance WITHIN an allowed fact (§11.4 step 8). */
  _redact(result, fact, clearance) {
    const redactedFields = [];
    const out = { ...result };
    if (!fact) return out;
    const rank = { public: 0, internal: 1, confidential: 2, secret: 3 };
    if ((fact.piiFindings || []).length && rank[clearance] < rank.confidential) {
      out.claim = maskPii(out.claim, fact.piiFindings);
      redactedFields.push('pii');
    }
    if (rank[clearance] < rank.confidential && fact.saidBy?.kind === 'employee') {
      // Employee Privacy Mode pseudonymises the speaker for non-cleared readers.
      if (this.privacy?.isOn()) {
        out.provenance = { ...out.provenance, saidBy: this.privacy.pseudonymise(fact.saidBy.name) };
        redactedFields.push('speaker');
      }
    }
    out.redactedFields = redactedFields;
    return out;
  }

  _logRead(fact, actor, ctx, presented) {
    const fidelity = fact.legalHold ? 'full'
      : fact.golden ? 'full'
      : LOG_FIDELITY[fact.sensitivity] ?? 'metadata';
    if (fidelity === 'aggregate') {
      // public: aggregate counts only — no per-read ledger entry
      return;
    }
    if (fidelity === 'metadata' && Math.random() > this.sampleRate) {
      // internal: full metadata, sampled content
      this.ledger.append('fact.read', {
        subject: fact.id, actor: actor.id, purpose: ctx.purpose ?? 'agent_read',
        sensitivity: fact.sensitivity, folder: fact.folder, fidelity: 'metadata'
      });
      return;
    }
    this.ledger.append('fact.read', {
      subject: fact.id, actor: actor.id, purpose: ctx.purpose ?? 'agent_read',
      sensitivity: fact.sensitivity, folder: fact.folder, fidelity,
      fieldsReturned: presented.redactedFields?.length ? 'partial' : 'all',
      legalHold: Boolean(fact.legalHold), golden: Boolean(fact.golden)
    });
  }

  _rate(id) {
    let w = this.rates.get(id);
    if (!w) this.rates.set(id, (w = []));
    const t = now();
    w.push(t);
    while (w.length && t - w[0] > HOUR) w.shift();
    return { hour: w.length, minute: w.filter((x) => t - x <= MINUTE).length };
  }

  /**
   * The block an agent actually receives, rendered. This is what changes agent
   * behaviour, so it ships as a first-class output rather than a UI detail.
   */
  render(result) {
    const lines = [];
    lines.push(result.summary);
    lines.push('');
    for (const f of result.facts) {
      const head = f.golden
        ? `★ GOLDEN · approved by ${f.provenance.approvedBy ?? 'a named authority'} · ${f.provenance.age} ago${f.provenance.sources ? ' · signed' : ''}`
        : `${f.badge} · ${f.provenance.saidBy ?? 'unattributed'}${f.provenance.role ? ` (${f.provenance.role})` : ''} · ${f.provenance.channel} · ${f.provenance.age} ago`;
      lines.push(head);
      lines.push(`    "${f.claim}"`);
      if (f.warning) lines.push(`    → ${f.warning}`);
      if (f.stale) lines.push(`    → stale: ${f.staleReason}`);
      lines.push('');
    }
    if (result.heldInReview) lines.push(`⏳ ${result.heldInReview} item${result.heldInReview === 1 ? '' : 's'} held in review — not returned`);
    if (result.killswitchNotice) lines.push(`\n⚠️  ${result.killswitchNotice}`);
    return lines.join('\n');
  }
}

function maskPii(claim, findings) {
  let out = claim;
  for (const f of findings) {
    if (f.preview) out = out.replace(/\S{6,}/, f.preview);
  }
  return out;
}
