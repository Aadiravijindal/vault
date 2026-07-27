/**
 * 🟢 VAULT REGISTRY — agent registry & identity (§19).
 *
 * Every agent: named business AND technical owner, scopes, mode, pinned model,
 * cost, health, behavioural baseline. An unowned agent is a finding.
 *
 * Agent credentials are short-lived, scoped, origin-bound and revocable in one
 * click. Agent-to-agent trust is not transitive: one agent's output is untrusted
 * input to another, by default.
 */
import { newId } from '../util/id.js';
import { randomToken, sha256, constantTimeEqual } from '../util/crypto.js';
import { now, iso, ago, HOUR, DAY, duration, withinBusinessHours } from '../util/time.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { Db } from '../storage/db.js';

export const AGENT_MODES = ['watch', 'inline', 'gateway'];
export const AGENT_STATUS = ['registered', 'active', 'suspended', 'retired'];

export class Registry {
  /**
   * Credentials, behavioural baselines and shadow-agent observations all live in
   * collections rather than process memory: a credential that evaporated when
   * the process restarted would lock every agent out of its own vault, and a
   * baseline that reset on restart would make deviation detection meaningless
   * on any deployment that is not a single long-lived process.
   *
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {import('../modules/modules.js').ModuleRegistry} [opts.modules]
   * @param {import('../storage/db.js').Collection} [opts.baselines]
   * @param {import('../storage/db.js').Collection} [opts.discovery]
   */
  constructor({ collection, ledger, modules = null, credentialTtl = '12h', baselines = null, discovery = null }) {
    this.col = collection;
    this.ledger = ledger;
    this.modules = modules;
    this.credentialTtl = duration(credentialTtl);
    this.col.index('byOwner', (a) => [a.businessOwner, a.technicalOwner]);
    this.col.index('byDepartment', (a) => a.department);
    this.col.index('byStatus', (a) => a.status);
    const scratch = baselines && discovery ? null : new Db();
    /** @type {import('../storage/db.js').Collection} */
    this.baselines = baselines || scratch.collection('agent_baselines');
    /** @type {import('../storage/db.js').Collection} */
    this.discovered = discovery || scratch.collection('agent_discovery');
  }

  /**
   * REGISTER → identity, owners, purpose, scopes, mode, model pinned, budget, region.
   */
  register(spec) {
    const {
      id = newId('agent'), name, purpose, businessOwner, technicalOwner,
      department = null, mode = 'inline', vendor = null, tool = null,
      folders = [], sensitivityCeiling = 'internal', regions = [],
      pinnedModel = null, approvedModels = [], tools = [],
      rateLimitPerHour = 500, monthlyBudgetUsd = null, projects = [],
      parentAgentId = null, defaultFolder = null, actor = 'system'
    } = spec;

    if (!name) throw new VaultError('validation', 'an agent needs a name');
    if (!AGENT_MODES.includes(mode)) throw new VaultError('validation', `mode must be one of ${AGENT_MODES.join(', ')}`);
    if (!businessOwner || !technicalOwner) {
      throw new VaultError('validation', 'an agent needs both a named business owner and a named technical owner — an unowned agent is a finding');
    }

    const parent = parentAgentId ? this.require(parentAgentId) : null;
    // Sub-agents inherit and NARROW their parent's scopes; they can never widen.
    const effectiveFolders = parent
      ? (folders.length ? folders.filter((f) => parent.folders.some((pf) => f.startsWith(pf))) : parent.folders)
      : folders;

    const agent = this.col.insert({
      id, name, purpose: purpose || '', businessOwner, technicalOwner, department,
      mode, vendor, tool, status: 'registered',
      folders: effectiveFolders,
      sensitivityCeiling: parent ? narrower(sensitivityCeiling, parent.sensitivityCeiling) : sensitivityCeiling,
      regions: parent ? (regions.length ? regions.filter((r) => parent.regions.includes(r) || !parent.regions.length) : parent.regions) : regions,
      pinnedModel, approvedModels, tools,
      rateLimitPerHour, monthlyBudgetUsd, projects,
      parentAgentId, defaultFolder,
      registeredAt: now(), registeredBy: actor,
      lastSeenAt: null, retiredAt: null,
      credential: null,
      costUsd: 0, writes: 0, reads: 0, blocked: 0, held: 0,
      attestedAt: null, attestedBy: null,
      trustsAgents: []   // agent-to-agent trust is opt-in and explicit
    });

    this.ledger.append('agent.registered', {
      subject: id, actor, name, mode, businessOwner, technicalOwner,
      folders: effectiveFolders.length, pinnedModel, parentAgentId
    });
    this.modules?.dispatch('registry', 'push', agent);
    return agent;
  }

  get(id) { return id ? this.col.get(id) : null; }
  require(id) {
    const a = this.col.get(id);
    if (!a) throw notFound('agent', id);
    return a;
  }
  all() { return this.col.all(); }
  active() { return this.col.find((a) => a.status !== 'retired'); }

  // -- credentials ---------------------------------------------------------

  /** Short-lived, scoped, origin-bound. Returned once; only the hash is kept. */
  issueCredential(agentId, { origins = [], scopes = [], ttl = this.credentialTtl, actor = 'system' } = {}) {
    const agent = this.require(agentId);
    const secret = `vlt_${agent.id}_${randomToken(32)}`;
    const expiresAt = now() + duration(ttl);
    this.col.update(agent.id, {
      credential: { hash: sha256(secret), issuedAt: now(), expiresAt, origins, scopes, revoked: false },
      status: agent.status === 'registered' ? 'active' : agent.status
    });
    this.ledger.append('agent.credential_rotated', { subject: agent.id, actor, expiresAt: iso(expiresAt), origins: origins.length });
    return { agentId: agent.id, credential: secret, expiresAt: iso(expiresAt), note: 'store this now — Vault keeps only its hash' };
  }

  checkCredential(agentId, presented, origin) {
    const agent = this.get(agentId);
    const entry = agent?.credential;
    if (!entry) {
      // Watch-mode agents observe logs and never present a credential.
      if (agent?.mode === 'watch') return { valid: true, reason: 'watch mode — no write credential required' };
      return { valid: false, reason: 'no credential has been issued for this agent' };
    }
    if (entry.revoked) return { valid: false, reason: 'revoked' };
    if (now() > entry.expiresAt) return { valid: false, reason: 'expired' };
    // A credential that is only checked when offered is not a credential: it
    // makes knowing an agent id sufficient to write as that agent, which is the
    // agent-impersonation case in the threat model. Once one has been issued,
    // presenting it is mandatory.
    if (!presented) return { valid: false, reason: 'not presented — this agent has a credential and must use it' };
    if (!constantTimeEqual(sha256(presented), entry.hash)) return { valid: false, reason: 'does not match' };
    if (entry.origins.length && origin && !entry.origins.includes(origin)) {
      return { valid: false, reason: `presented from an unexpected origin (${origin})` };
    }
    return { valid: true, reason: 'valid', expiresAt: iso(entry.expiresAt) };
  }

  revokeCredential(agentId, { actor, reason }) {
    const agent = this.get(agentId);
    if (agent?.credential && !agent.credential.revoked) {
      this.col.update(agentId, { credential: { ...agent.credential, revoked: true, revokedAt: now() } });
    }
    this.ledger.append('agent.credential_rotated', { subject: agentId, actor, reason, revoked: true });
    return { agentId, revoked: true, at: iso() };
  }

  /** Non-secret view of an agent's credential, for the Registry screen. */
  credentialState(agentId) {
    const c = this.get(agentId)?.credential;
    if (!c) return { issued: false, state: 'none' };
    const state = c.revoked ? 'revoked' : (now() > c.expiresAt ? 'expired' : 'valid');
    return {
      issued: true, state,
      issuedAt: iso(c.issuedAt), expiresAt: iso(c.expiresAt),
      expiresIn: state === 'valid' ? ago(now(), c.expiresAt) : null,
      origins: c.origins, scopes: c.scopes
    };
  }

  // -- scoping -------------------------------------------------------------

  canWriteFolder(agentId, folder) {
    const agent = this.get(agentId);
    if (!agent) return { allowed: false, reason: 'unknown agent' };
    if (!agent.folders.length) return { allowed: true, reason: 'no folder restriction configured' };
    const ok = agent.folders.some((f) => String(folder).startsWith(f));
    return {
      allowed: ok,
      reason: ok ? `${folder} is within the agent's scope`
        : `agent ${agentId} is scoped to ${agent.folders.join(', ')} and may not write to ${folder}`
    };
  }

  canWriteSensitivity(agentId, label) {
    const agent = this.get(agentId);
    if (!agent) return false;
    const rank = { public: 0, internal: 1, confidential: 2, secret: 3 };
    return (rank[label] ?? 1) <= (rank[agent.sensitivityCeiling] ?? 1);
  }

  /** Agent-to-agent trust: explicit, narrow, and never transitive. */
  trustAgent(agentId, trustedAgentId, { actor, reason }) {
    const agent = this.require(agentId);
    this.require(trustedAgentId);
    if (!actor || !reason) throw forbidden('granting agent-to-agent trust requires a named actor and a reason');
    const updated = this.col.update(agentId, { trustsAgents: [...new Set([...agent.trustsAgents, trustedAgentId])] });
    this.ledger.append('agent.scope_changed', { subject: agentId, actor, reason, change: 'agent_trust_granted', trusted: trustedAgentId });
    return updated;
  }

  trusts(agentId, otherAgentId) {
    return Boolean(this.get(agentId)?.trustsAgents?.includes(otherAgentId));
  }

  // -- lifecycle -----------------------------------------------------------

  changeScope(agentId, patch, { actor, reason, approvedBy }) {
    const agent = this.require(agentId);
    if (!actor || !reason) throw forbidden('scope changes require a named actor and a reason');
    if (!approvedBy || approvedBy === actor) {
      throw forbidden('scope changes require approval from the owner, distinct from the requester', { owner: agent.businessOwner });
    }
    const before = { folders: agent.folders, sensitivityCeiling: agent.sensitivityCeiling, regions: agent.regions, mode: agent.mode };
    const updated = this.col.update(agentId, patch);
    this.ledger.append('agent.scope_changed', {
      subject: agentId, actor, reason, approvedBy,
      before, after: { folders: updated.folders, sensitivityCeiling: updated.sensitivityCeiling, regions: updated.regions, mode: updated.mode }
    });
    return updated;
  }

  suspend(agentId, { actor, reason, readsAllowed = true }) {
    const agent = this.require(agentId);
    if (!actor || !reason) throw forbidden('suspension requires a named actor and a reason');
    this.revokeCredential(agentId, { actor, reason: `suspended: ${reason}` });
    const updated = this.col.update(agentId, { status: 'suspended', suspendedAt: now(), suspendReason: reason, readsAllowed });
    this.ledger.append('agent.suspended', { subject: agentId, actor, reason, readsAllowed });
    return updated;
  }

  /**
   * RETIRE → credentials revoked, reads stop immediately, WRITES REMAIN,
   * ownership reassigns to the folder owner, history intact forever (§26).
   */
  retire(agentId, { actor, reason, reassignTo }) {
    const agent = this.require(agentId);
    if (!actor || !reason) throw forbidden('retiring an agent requires a named actor and a reason');
    this.revokeCredential(agentId, { actor, reason: `retired: ${reason}` });
    const updated = this.col.update(agentId, {
      status: 'retired', retiredAt: now(), retireReason: reason,
      businessOwner: reassignTo || agent.businessOwner,
      ownershipReassignedFrom: reassignTo ? agent.businessOwner : null
    });
    this.ledger.append('agent.retired', { subject: agentId, actor, reason, reassignedTo: reassignTo || null });
    return {
      ...updated,
      note: 'credentials revoked and reads stopped; the facts this agent wrote remain, with their full history'
    };
  }

  /** Owners re-confirm their agents quarterly (§19). */
  attest(agentId, { actor, confirms = true, notes = null }) {
    const agent = this.require(agentId);
    if (actor !== agent.businessOwner && actor !== agent.technicalOwner) {
      throw forbidden('only a named owner may attest to an agent', { agentId });
    }
    const updated = this.col.update(agentId, { attestedAt: now(), attestedBy: actor, attestationNotes: notes });
    this.ledger.append('admin.action', { subject: agentId, actor, action: 'agent.attested', confirms, notes });
    return updated;
  }

  attestationStatus({ periodDays = 90 } = {}) {
    const due = now() - periodDays * DAY;
    return this.active().map((a) => ({
      agentId: a.id, name: a.name, owner: a.businessOwner,
      attestedAt: a.attestedAt ? iso(a.attestedAt) : null,
      overdue: !a.attestedAt || a.attestedAt < due,
      ageDays: a.attestedAt ? Math.round((now() - a.attestedAt) / DAY) : null
    }));
  }

  // -- discovery (§19) -----------------------------------------------------

  /**
   * Find unregistered agents via Gateway and connector telemetry. This is the
   * shadow-agent finder, and it is the wedge in the Discover tier.
   */
  observeTraffic({ identifier, channel, endpoint, model, at = now(), bytes = 0, origin = null }) {
    if (this.get(identifier)) {
      this.col.update(identifier, { lastSeenAt: at });
      return { known: true };
    }
    const prev = this.discovered.get(identifier);
    const seen = prev
      ? { ...prev }
      : { id: identifier, identifier, firstSeen: at, lastSeen: at, count: 0, channels: [], endpoints: [], models: [], bytes: 0, origins: [] };
    seen.lastSeen = at;
    seen.count++;
    seen.bytes += bytes;
    seen.channels = addTo(seen.channels, channel);
    seen.endpoints = addTo(seen.endpoints, endpoint);
    seen.models = addTo(seen.models, model);
    seen.origins = addTo(seen.origins, origin);
    this.discovered.put(seen);
    if (seen.count === 1) {
      this.ledger.append('agent.discovered', { subject: identifier, channel, endpoint, model, origin });
    }
    return { known: false, shadow: true, observations: seen.count };
  }

  shadowAgents() {
    return this.discovered.all()
      .filter((d) => !this.get(d.identifier))
      .map((d) => ({
        identifier: d.identifier,
        firstSeen: iso(d.firstSeen),
        lastSeen: iso(d.lastSeen),
        age: ago(d.firstSeen),
        observations: d.count,
        channels: d.channels,
        endpoints: d.endpoints,
        models: d.models,
        origins: d.origins,
        bytes: d.bytes,
        finding: 'unregistered agent observed writing or calling models — register it or shut it down',
        severity: d.count > 100 ? 'high' : 'medium'
      }))
      .sort((a, b) => b.observations - a.observations);
  }

  // -- behavioural baseline (§9.6, §19) -----------------------------------

  /**
   * Per-agent normal: write rate, folders touched, claim types, hours, channels.
   * Deviation → alert. Insurers and forensics both want this.
   */
  observeBehaviour(agentId, { folder, claimType, channel, at = now(), outcome = 'pass' }) {
    const prev = this.baselines.get(agentId);
    const b = prev
      ? { ...prev, folders: { ...prev.folders }, claimTypes: { ...prev.claimTypes }, channels: { ...prev.channels }, outcomes: { ...prev.outcomes }, hours: [...prev.hours], hourlyCounts: [...prev.hourlyCounts] }
      : {
        id: agentId, agentId, samples: 0, folders: {}, claimTypes: {}, channels: {},
        hours: new Array(24).fill(0), hourlyCounts: [], established: false, outcomes: {}
      };
    b.samples++;
    if (folder) b.folders[folder] = (b.folders[folder] || 0) + 1;
    if (claimType) b.claimTypes[claimType] = (b.claimTypes[claimType] || 0) + 1;
    if (channel) b.channels[channel] = (b.channels[channel] || 0) + 1;
    b.outcomes[outcome] = (b.outcomes[outcome] || 0) + 1;
    b.hours[new Date(at).getUTCHours()]++;
    b.hourlyCounts.push(at);
    while (b.hourlyCounts.length && at - b.hourlyCounts[0] > 7 * DAY) b.hourlyCounts.shift();
    if (b.samples >= 30) b.established = true;
    this.baselines.put(b);
    return b;
  }

  /** @returns {{deviations:object[], baseline:object|null}} */
  checkDeviation(agentId, { folder, claimType, channel, at = now() }) {
    const b = this.baselines.get(agentId);
    if (!b || !b.established) return { deviations: [], baseline: null, note: 'baseline not yet established' };
    const deviations = [];
    if (folder && !(folder in b.folders)) {
      deviations.push({ kind: 'novel_folder', detail: `first write to ${folder} by this agent`, severity: 'medium' });
    }
    if (channel && !(channel in b.channels)) {
      deviations.push({ kind: 'novel_channel', detail: `first write from channel ${channel} by this agent`, severity: 'medium' });
    }
    const hour = new Date(at).getUTCHours();
    const hourShare = b.hours[hour] / Math.max(b.samples, 1);
    if (hourShare < 0.01 && !withinBusinessHours(at)) {
      deviations.push({ kind: 'timing_anomaly', detail: `write at ${hour}:00 UTC from an agent that normally runs elsewhere in the day`, severity: 'medium' });
    }
    const lastHour = b.hourlyCounts.filter((t) => at - t <= HOUR).length;
    const avgHour = b.hourlyCounts.length / Math.max(1, (at - b.hourlyCounts[0]) / HOUR);
    if (avgHour > 0 && lastHour > avgHour * 50) {
      deviations.push({ kind: 'volume_anomaly', detail: `writing ${Math.round(lastHour / avgHour)}× its baseline rate`, severity: 'high' });
    }
    return { deviations, baseline: this.baselineSummary(agentId) };
  }

  baselineSummary(agentId) {
    const b = this.baselines.get(agentId);
    if (!b) return null;
    const top = (m, n = 3) => Object.entries(m).sort((a, c) => c[1] - a[1]).slice(0, n).map(([k, v]) => ({ [k]: v }));
    return {
      agentId, samples: b.samples, established: b.established,
      topFolders: top(b.folders), topClaimTypes: top(b.claimTypes), topChannels: top(b.channels),
      activeHours: b.hours.map((n, h) => ({ h, n })).filter((x) => x.n > 0).map((x) => x.h)
    };
  }

  // -- accounting ----------------------------------------------------------

  recordUsage(agentId, { costUsd = 0, write = 0, read = 0, blocked = 0, held = 0 }) {
    const agent = this.get(agentId);
    if (!agent) return null;
    return this.col.update(agentId, {
      costUsd: Math.round((agent.costUsd + costUsd) * 10000) / 10000,
      writes: agent.writes + write,
      reads: agent.reads + read,
      blocked: agent.blocked + blocked,
      held: agent.held + held,
      lastSeenAt: now()
    });
  }

  overBudget() {
    return this.active()
      .filter((a) => a.monthlyBudgetUsd && a.costUsd > a.monthlyBudgetUsd)
      .map((a) => ({ agentId: a.id, name: a.name, spent: a.costUsd, budget: a.monthlyBudgetUsd, owner: a.businessOwner }));
  }

  /** Health: a connector silent for N hours is an alert to a named owner (§4.4). */
  health({ silentAfterMs = 4 * HOUR } = {}) {
    return this.active().map((a) => {
      const silentFor = a.lastSeenAt ? now() - a.lastSeenAt : null;
      return {
        agentId: a.id, name: a.name, mode: a.mode, status: a.status,
        lastSeen: a.lastSeenAt ? ago(a.lastSeenAt) : 'never',
        healthy: a.lastSeenAt ? silentFor < silentAfterMs : false,
        alert: a.lastSeenAt && silentFor >= silentAfterMs
          ? `silent for ${ago(a.lastSeenAt)} — notify ${a.technicalOwner}`
          : (!a.lastSeenAt ? `never seen — notify ${a.technicalOwner}` : null),
        owner: a.businessOwner, technicalOwner: a.technicalOwner
      };
    });
  }

  /** Ownership enforcement — surfaced on the Map (§19). */
  findings() {
    const out = [];
    for (const a of this.active()) {
      if (!a.businessOwner || !a.technicalOwner) {
        out.push({ agentId: a.id, finding: 'agent has no complete ownership', severity: 'high' });
      }
      if (a.mode === 'watch') {
        out.push({ agentId: a.id, finding: 'watch mode: Vault can see this agent but cannot block it', severity: 'medium', fix: 'move to Inline' });
      }
      if (!a.pinnedModel) {
        out.push({ agentId: a.id, finding: 'no pinned model version — a silent model swap would go unnoticed', severity: 'medium' });
      }
    }
    for (const s of this.shadowAgents()) {
      out.push({ agentId: s.identifier, finding: s.finding, severity: s.severity, shadow: true });
    }
    return out;
  }

  inventory() {
    return this.all().map((a) => ({
      id: a.id, name: a.name, purpose: a.purpose, vendor: a.vendor, tool: a.tool,
      mode: a.mode, status: a.status, department: a.department,
      businessOwner: a.businessOwner, technicalOwner: a.technicalOwner,
      folders: a.folders, sensitivityCeiling: a.sensitivityCeiling, regions: a.regions,
      pinnedModel: a.pinnedModel, tools: a.tools,
      writes: a.writes, reads: a.reads, blocked: a.blocked, held: a.held,
      costUsd: a.costUsd, budget: a.monthlyBudgetUsd,
      registeredAt: iso(a.registeredAt), lastSeen: a.lastSeenAt ? iso(a.lastSeenAt) : null,
      attestedAt: a.attestedAt ? iso(a.attestedAt) : null,
      parentAgentId: a.parentAgentId
    }));
  }
}

function addTo(list, value) {
  if (!value || list.includes(value)) return list;
  return [...list, value];
}

function narrower(a, b) {
  const rank = { public: 0, internal: 1, confidential: 2, secret: 3 };
  return (rank[a] ?? 1) <= (rank[b] ?? 1) ? a : b;
}
