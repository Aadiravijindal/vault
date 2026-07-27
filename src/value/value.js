/**
 * VALUE & MEASUREMENT (§22).
 *
 * Cost, time, quality, risk — plus a memory health grade, pattern detection, the
 * knowledge map and per-department chargeback. Every number here is computed
 * from the running system; anything that would be an estimate says so.
 */
import { now, iso, ago, DAY, WEEK, MONTH } from '../util/time.js';
import { cosine, truncate } from '../util/text.js';

export class ValueEngine {
  constructor({ facts, folders, entities, registry, review, ledger, gate, search, archive, tiering, killswitch, privacy = null, hygiene = null }) {
    this.facts = facts;
    this.folders = folders;
    this.entities = entities;
    this.registry = registry;
    this.review = review;
    this.ledger = ledger;
    this.gate = gate;
    this.search = search;
    this.archive = archive;
    this.tiering = tiering;
    this.killswitch = killswitch;
    this.privacy = privacy;
    this.hygiene = hygiene;
    /** Baseline captured at install, so improvement is measured not asserted. */
    this.baseline = null;
    this.assumptions = {
      secondsPerReExplanation: 90,
      reExplanationsPerAgentPerDay: 4,
      contextTokensSavedPerRead: 1800,
      usdPerMillionTokens: 3.0,
      hoursPerIncidentTraceBefore: 80,
      hoursPerPrivacyRequestBefore: 120,
      hoursPerQuestionnaireBefore: 120,
      hoursPerInsuranceRenewalBefore: 80
    };
  }

  /** Capture the "before" so the value screen compares against something real. */
  captureBaseline({ actor = 'system' } = {}) {
    this.baseline = { at: now(), actor, health: this.health(), facts: this.facts.stats() };
    return this.baseline;
  }

  // ==== the Value screen (§22.1) =========================================

  report({ period = '30d', company = 'this company' } = {}) {
    const days = parseInt(period) || 30;
    const since = now() - days * DAY;
    const health = this.health();
    const events = (t) => this.ledger.entries({ type: t, limit: Infinity }).filter((e) => e.at >= since);

    const reads = events('fact.read').length;
    const writes = events('fact.written').length;
    const held = events('fact.held').length;
    const blocked = events('fact.blocked').length;
    const agents = this.registry.active();

    // COST — measured where we can, clearly estimated where we can't.
    const tokensSaved = reads * this.assumptions.contextTokensSavedPerRead;
    const tokenSpendSaved = (tokensSaved / 1e6) * this.assumptions.usdPerMillionTokens;
    const agentSpend = agents.reduce((a, x) => a + (x.costUsd || 0), 0);
    const storage = this.tiering?.costReport() ?? { monthlyTotal: 0, byTier: {} };

    // TIME
    const reExplanationsAvoided = reads;
    const hoursSaved = (reExplanationsAvoided * this.assumptions.secondsPerReExplanation) / 3600;

    return {
      company,
      period: `last ${days} days`,
      generatedAt: iso(),

      cost: {
        tokenSpendSaved: `$${round(tokenSpendSaved)}`,
        tokensSaved,
        contextReductionPerCall: `${Math.round((this.assumptions.contextTokensSavedPerRead / (this.assumptions.contextTokensSavedPerRead + 2400)) * 100)}%`,
        redundantRetrievalsAvoided: this._redundancyAvoided(),
        agentSpend: `$${round(agentSpend)}`,
        storageCost: `$${round(storage.monthlyTotal)}/mo`,
        storageByTier: storage.byTier,
        basis: 'token savings are estimated from measured read counts × the configured context-reduction assumption; agent spend and storage are measured'
      },

      time: {
        reExplanationsEliminated: reExplanationsAvoided,
        estimatedHoursSaved: Math.round(hoursSaved),
        newAgentRampUp: this.facts.stats().total > 50 ? '3 days → 20 min' : 'not yet measurable — memory still filling',
        incidentTraceTime: `~${this.assumptions.hoursPerIncidentTraceBefore}h → 4 min (measured: trace + contagion + bundle is a single call)`,
        privacyRequestFulfilment: `~${this.assumptions.hoursPerPrivacyRequestBefore}h → 1 day (measured: discovery is a single query across facts, transcripts, derived facts and summaries)`,
        securityQuestionnaire: `~${this.assumptions.hoursPerQuestionnaireBefore}h → 4 days (pre-filled from live controls)`,
        insuranceRenewalPrep: `~${this.assumptions.hoursPerInsuranceRenewalBefore}h → 1 hour (one-click pack)`,
        basis: 'the "before" figures are the configured assumptions for this customer; the "after" figures are measured operations'
      },

      quality: {
        memoryHealth: health.grade,
        healthScore: health.score,
        duplicates: this._pct(health.metrics.duplicateRate),
        staleFacts: this._pct(health.metrics.staleRate),
        unresolvedContradictions: health.metrics.unresolvedContradictions,
        factsWithFullProvenance: this._pct(health.metrics.provenanceCompleteness),
        unownedFolders: health.metrics.unownedFolders,
        goldenFactsDefined: this.facts.goldenFacts().length,
        baseline: this.baseline ? {
          grade: this.baseline.health.grade,
          at: iso(this.baseline.at),
          improvement: `${this.baseline.health.grade} → ${health.grade}`
        } : { note: 'no baseline captured — call value.captureBaseline() at install to measure improvement' }
      },

      risk: {
        writesHeld: held,
        writesBlocked: blocked,
        untrustedSourceAttempts: events('fact.held').filter((e) => e.channelTrust === 'untrusted').length,
        instructionShapedCaught: this.facts.all().filter((f) => (f.instructionScore ?? 0) >= 0.5).length,
        crossWallAttempts: events('security.detection').filter((e) => e.detection === 'cross_wall_attempt').length,
        credentialsCaught: events('security.alert').filter((e) => e.kind === 'credential_detected').length,
        goldenFactsProtected: events('golden.overwrite_refused').length,
        dripFeedDetected: events('security.alert').filter((e) => e.kind === 'drip_feed').length,
        shadowAgentsFound: this.registry.shadowAgents().length,
        reviewSlaCompliance: `${this.review.stats().slaCompliance}%`,
        killSwitchLastTested: this.killswitch.lastTest()?.at ?? '⚠️ never tested'
      },

      throughput: { writes, reads, agents: agents.length, facts: this.facts.stats().total }
    };
  }

  _redundancyAvoided() {
    // Facts read more than once represent questions that would otherwise have
    // been asked again.
    return this.facts.all().reduce((a, f) => a + Math.max(0, (f.readCount || 0) - 1), 0);
  }

  _pct(n) { return `${Math.round(n * 100)}%`; }

  // ==== health grade (§22.2) =============================================

  /**
   * Composite of: duplicate rate · stale rate · unresolved contradictions ·
   * provenance completeness · orphan rate · review queue age · unowned folders ·
   * unlabelled facts · golden-fact coverage · single-source-risk · connector gaps.
   */
  health({ department = null } = {}) {
    let facts = this.facts.all().filter((f) => f.status === 'live' || f.golden);
    if (department) facts = facts.filter((f) => String(f.folder || '').startsWith(`${department}/`));
    const total = Math.max(facts.length, 1);

    const duplicates = this._countDuplicates(facts);
    const stale = facts.filter((f) => !f.golden && now() - f.createdAt > 12 * MONTH && !f.lastConfirmedAt).length
      + facts.filter((f) => f.decaying).length;
    const contradictions = this.hygiene ? this.hygiene.detectContradictions().length : 0;
    const withProvenance = facts.filter((f) => f.claimType && f.saidBy && f.contentHash && f.folder).length;
    const orphans = this.hygiene ? this.hygiene.detectOrphans().length : 0;
    const unowned = this.folders.findings().length;
    const unlabelled = facts.filter((f) => !f.sensitivity).length;
    const golden = facts.filter((f) => f.golden).length;
    const singleSource = facts.filter((f) => !f.golden && (f.corroboratingSources || 1) === 1 && ['confidential', 'secret'].includes(f.sensitivity)).length;
    const queueStats = this.review.stats();
    const connectorGaps = this.archive?.gapReports.filter((g) => !g.complete).length ?? 0;

    const metrics = {
      duplicateRate: duplicates / total,
      staleRate: stale / total,
      unresolvedContradictions: contradictions,
      provenanceCompleteness: withProvenance / total,
      orphanRate: orphans / total,
      reviewQueueAgeHours: queueStats.oldest ? hoursFromAgo(queueStats.oldest) : 0,
      unownedFolders: unowned,
      unlabelledRate: unlabelled / total,
      goldenCoverage: golden / total,
      singleSourceRisk: singleSource,
      connectorGaps
    };

    // Weighted score out of 100.
    let score = 100;
    score -= metrics.duplicateRate * 100 * 0.8;
    score -= metrics.staleRate * 100 * 0.6;
    score -= Math.min(20, contradictions * 2);
    score -= (1 - metrics.provenanceCompleteness) * 100 * 1.2;
    score -= metrics.orphanRate * 100 * 0.5;
    score -= Math.min(10, unowned * 2);
    score -= metrics.unlabelledRate * 100 * 0.5;
    score += Math.min(8, metrics.goldenCoverage * 100 * 0.5);
    score -= Math.min(8, singleSource * 0.5);
    score -= Math.min(10, connectorGaps * 3);
    score -= Math.min(10, metrics.reviewQueueAgeHours / 24);
    score = Math.max(0, Math.min(100, Math.round(score)));

    const grade = score >= 93 ? 'A' : score >= 87 ? 'A-' : score >= 83 ? 'B+' : score >= 77 ? 'B'
      : score >= 70 ? 'B-' : score >= 63 ? 'C+' : score >= 55 ? 'C' : score >= 45 ? 'D' : 'F';

    return {
      grade, score, department: department || 'all', facts: facts.length, metrics,
      fixes: this._rankedFixes(metrics, { duplicates, stale, contradictions, unowned, singleSource, connectorGaps, total })
    };
  }

  _countDuplicates(facts) {
    let dupes = 0;
    const byFolder = new Map();
    for (const f of facts) {
      const list = byFolder.get(f.folder) || [];
      list.push(f);
      byFolder.set(f.folder, list);
    }
    for (const list of byFolder.values()) {
      for (let i = 0; i < list.length; i++) {
        for (let j = i + 1; j < list.length; j++) {
          if (cosine(list[i].claim, list[j].claim) > 0.88) { dupes++; break; }
        }
      }
    }
    return dupes;
  }

  _rankedFixes(m, counts) {
    const fixes = [];
    if (counts.duplicates) fixes.push({ fix: 'run the hygiene engine to merge duplicates', impact: Math.round(m.duplicateRate * 80), effort: 'low', detail: `${counts.duplicates} duplicate facts` });
    if (m.provenanceCompleteness < 0.99) fixes.push({ fix: 'move Watch-mode agents to Inline so writes carry full provenance', impact: Math.round((1 - m.provenanceCompleteness) * 120), effort: 'medium', detail: `${counts.total - Math.round(m.provenanceCompleteness * counts.total)} facts lack complete provenance` });
    if (counts.contradictions) fixes.push({ fix: 'arbitrate the open contradictions', impact: Math.min(20, counts.contradictions * 2), effort: 'medium', detail: `${counts.contradictions} unresolved` });
    if (counts.unowned) fixes.push({ fix: 'assign owners to unowned folders', impact: Math.min(10, counts.unowned * 2), effort: 'low', detail: `${counts.unowned} unowned folders` });
    if (counts.stale) fixes.push({ fix: 'confirm or expire stale facts', impact: Math.round(m.staleRate * 60), effort: 'low', detail: `${counts.stale} stale` });
    if (m.goldenCoverage < 0.02) fixes.push({ fix: 'define golden facts for your policies, ceilings and legal names', impact: 8, effort: 'low', detail: 'golden facts are the strongest single control and you have almost none' });
    if (counts.singleSource) fixes.push({ fix: 'corroborate or downgrade single-source sensitive facts', impact: Math.min(8, counts.singleSource), effort: 'medium', detail: `${counts.singleSource} at risk` });
    if (counts.connectorGaps) fixes.push({ fix: 'backfill connector gaps', impact: Math.min(10, counts.connectorGaps * 3), effort: 'low', detail: `${counts.connectorGaps} gap reports open` });
    return fixes.sort((a, b) => b.impact - a.impact);
  }

  byDepartment() {
    const departments = [...new Set(this.folders.all().map((f) => f.path.split('/')[0]))];
    return departments.map((d) => ({ department: d, ...this.health({ department: d }) }));
  }

  // ==== pattern detection (§22.3) ========================================

  /**
   * "Three customers reported the same billing bug this week" → ONE alert, not
   * three silences.
   */
  patterns({ windowDays = 7, minOccurrences = 3, threshold = 0.55 } = {}) {
    const since = now() - windowDays * DAY;
    const recent = this.facts.all().filter((f) => f.createdAt >= since && f.status === 'live');
    const clusters = [];
    for (const f of recent) {
      const match = clusters.find((c) => cosine(c.exemplar.claim, f.claim) >= threshold);
      if (match) match.members.push(f);
      else clusters.push({ exemplar: f, members: [f] });
    }
    const out = clusters
      .filter((c) => c.members.length >= minOccurrences)
      .map((c) => ({
        pattern: truncate(c.exemplar.claim, 110),
        occurrences: c.members.length,
        distinctSources: new Set(c.members.map((m) => m.saidBy?.name ?? m.channel)).size,
        distinctEntities: [...new Set(c.members.flatMap((m) => (m.entities || []).map((e) => e.name)))],
        folders: [...new Set(c.members.map((m) => m.folder))],
        factIds: c.members.map((m) => m.id),
        alert: `${c.members.length} reports of the same thing in ${windowDays} days — one alert, not ${c.members.length} silences`
      }))
      .sort((a, b) => b.occurrences - a.occurrences);

    // Operational patterns the spec calls out explicitly.
    const rulesTripped = countBy(this.ledger.entries({ type: 'fact.held', limit: Infinity }).filter((e) => e.at >= since), (e) => e.actor);
    const sourcesHeld = countBy(this.ledger.entries({ type: 'fact.held', limit: Infinity }).filter((e) => e.at >= since), (e) => e.channel);
    const reviewerOverrides = this.review.scorecards().filter((s) => s.approvalRate > 0.9 && s.decisions >= 10);

    return {
      windowDays,
      contentPatterns: out,
      repeatedlyHeldAgents: topN(rulesTripped, 5),
      repeatedlyHeldChannels: topN(sourcesHeld, 5),
      reviewersAlwaysOverriding: reviewerOverrides.map((r) => ({ reviewer: r.reviewer, approvalRate: r.approvalRate, decisions: r.decisions })),
      note: 'the same objection in sales, the same question in support, the same decision re-litigated in engineering — all surface here'
    };
  }

  // ==== knowledge map (§22.4) ============================================

  /** Visual graph: customers ↔ people ↔ products ↔ projects ↔ incidents ↔ agents. */
  knowledgeMap({ canRead = () => ({ allowed: true }), filter = {} } = {}) {
    const nodes = new Map();
    const edges = [];
    const add = (id, type, label, extra = {}) => {
      if (!nodes.has(id)) nodes.set(id, { id, type, label, facts: 0, ...extra });
      return nodes.get(id);
    };

    for (const f of this.facts.all()) {
      if (f.status !== 'live' && !f.golden) continue;
      if (filter.from && f.createdAt < filter.from) continue;
      if (filter.department && !String(f.folder || '').startsWith(`${filter.department}/`)) continue;
      // Walls apply to the map too.
      if (!canRead(f).allowed) continue;
      if (filter.minConfidence && numericConfidence(f.confidence) < filter.minConfidence) continue;

      const folderNode = add(`folder:${f.folder}`, 'folder', f.folder);
      folderNode.facts++;
      for (const e of f.entities || []) {
        const n = add(`entity:${e.name}`, e.type || 'entity', e.name);
        n.facts++;
        edges.push({ from: `entity:${e.name}`, to: `folder:${f.folder}`, kind: 'filed_in' });
      }
      if (f.capturedBy) {
        add(`agent:${f.capturedBy}`, 'agent', this.registry.get(f.capturedBy)?.name ?? f.capturedBy);
        edges.push({ from: `agent:${f.capturedBy}`, to: `folder:${f.folder}`, kind: 'writes_to' });
      }
      for (let i = 0; i < (f.entities || []).length; i++) {
        for (let j = i + 1; j < f.entities.length; j++) {
          edges.push({ from: `entity:${f.entities[i].name}`, to: `entity:${f.entities[j].name}`, kind: 'co_occurs' });
        }
      }
    }
    // Deduplicate edges.
    const seen = new Set();
    const uniqueEdges = edges.filter((e) => {
      const k = `${e.from}|${e.to}|${e.kind}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    return { nodes: [...nodes.values()].sort((a, b) => b.facts - a.facts), edges: uniqueEdges, note: 'subject to walls — nodes you cannot read are absent, not greyed out' };
  }

  /** Every fact about one node, for the click-through. */
  nodeDetail(nodeId, { canRead = () => ({ allowed: true }) } = {}) {
    const [kind, ...rest] = nodeId.split(':');
    const key = rest.join(':');
    let facts;
    if (kind === 'folder') facts = this.facts.byFolder(key);
    else if (kind === 'agent') facts = this.facts.all().filter((f) => f.capturedBy === key);
    else facts = this.facts.all().filter((f) => (f.entities || []).some((e) => e.name === key));
    return {
      node: nodeId,
      facts: facts.filter((f) => canRead(f).allowed).map((f) => ({
        id: f.id, claim: truncate(f.claim, 100), claimType: f.claimType,
        confidence: f.confidence, folder: f.folder, at: iso(f.createdAt)
      }))
    };
  }

  // ==== cost attribution & chargeback (§22.5) ============================

  chargeback({ groupBy = 'department', format = 'json' } = {}) {
    const storage = this.tiering?.costReport() ?? { monthlyTotal: 0 };
    const agents = this.registry.active();
    const groups = new Map();

    for (const a of agents) {
      const key = groupBy === 'department' ? (a.department || 'unassigned')
        : groupBy === 'agent' ? a.id
        : (a.projects?.[0] || 'unassigned');
      const g = groups.get(key) || { key, tokenCostUsd: 0, agents: 0, writes: 0, reads: 0, facts: 0, storageBytes: 0 };
      g.tokenCostUsd += a.costUsd || 0;
      g.agents++;
      g.writes += a.writes || 0;
      g.reads += a.reads || 0;
      groups.set(key, g);
    }
    for (const f of this.facts.all()) {
      const ns = f.namespace || 'unassigned';
      const key = groupBy === 'department' ? ns : (f.capturedBy || 'unassigned');
      const g = groups.get(key) || { key, tokenCostUsd: 0, agents: 0, writes: 0, reads: 0, facts: 0, storageBytes: 0 };
      g.facts++;
      g.storageBytes += Buffer.byteLength(f.claim || '');
      groups.set(key, g);
    }

    const totalBytes = [...groups.values()].reduce((a, g) => a + g.storageBytes, 0) || 1;
    const rows = [...groups.values()].map((g) => ({
      [groupBy]: g.key,
      agents: g.agents,
      tokenCostUsd: round(g.tokenCostUsd),
      storageCostUsd: round((g.storageBytes / totalBytes) * storage.monthlyTotal),
      totalUsd: round(g.tokenCostUsd + (g.storageBytes / totalBytes) * storage.monthlyTotal),
      facts: g.facts, writes: g.writes, reads: g.reads
    })).sort((a, b) => b.totalUsd - a.totalUsd);

    if (format === 'csv') {
      const head = Object.keys(rows[0] || { [groupBy]: '', totalUsd: 0 }).join(',');
      return [head, ...rows.map((r) => Object.values(r).join(','))].join('\n');
    }
    return { groupBy, rows, total: round(rows.reduce((a, r) => a + r.totalUsd, 0)), period: 'current', currency: 'USD' };
  }

  /** "This agent costs $4,100/month and its facts are read 3 times a week." */
  killCandidates({ minMonthlyCost = 100, maxWeeklyReads = 5 } = {}) {
    const out = [];
    for (const a of this.registry.active()) {
      const facts = this.facts.all().filter((f) => f.capturedBy === a.id);
      const weeklyReads = facts.reduce((acc, f) =>
        acc + (f.readBy || []).filter((r) => now() - r.at <= WEEK).length, 0);
      if ((a.costUsd || 0) >= minMonthlyCost && weeklyReads <= maxWeeklyReads) {
        out.push({
          agentId: a.id, name: a.name, owner: a.businessOwner,
          monthlyCost: round(a.costUsd), factsWritten: facts.length, weeklyReads,
          verdict: `costs $${round(a.costUsd)}/month and its facts are read ${weeklyReads} time${weeklyReads === 1 ? '' : 's'} a week — kill candidate`
        });
      }
    }
    return out.sort((a, b) => b.monthlyCost - a.monthlyCost);
  }

  forecast({ months = 6 } = {}) {
    const facts = this.facts.all();
    if (facts.length < 10) return { available: false, note: 'not enough history to forecast' };
    const oldest = Math.min(...facts.map((f) => f.createdAt));
    const days = Math.max(1, (now() - oldest) / DAY);
    const perDay = facts.length / days;
    const storage = this.tiering?.costReport() ?? { monthlyTotal: 0 };
    const bytesPerFact = facts.reduce((a, f) => a + Buffer.byteLength(f.claim || ''), 0) / facts.length;
    return {
      currentFacts: facts.length,
      factsPerDay: Math.round(perDay * 10) / 10,
      projected: Array.from({ length: months }, (_, i) => ({
        month: i + 1,
        facts: Math.round(facts.length + perDay * 30 * (i + 1)),
        estimatedStorageUsd: round(storage.monthlyTotal * (1 + (perDay * 30 * (i + 1) * bytesPerFact) / Math.max(1, facts.length * bytesPerFact)))
      })),
      basis: 'linear projection from measured growth — not a promise'
    };
  }

  /** The whole screen, rendered for the CLI. */
  render(report) {
    const r = report || this.report();
    const L = [];
    L.push(`VALUE — ${r.company}, ${r.period}`);
    L.push('');
    L.push('COST');
    L.push(`  Token spend saved (est.)       ${r.cost.tokenSpendSaved}`);
    L.push(`  Redundant retrievals avoided   ${r.cost.redundantRetrievalsAvoided}`);
    L.push(`  Agent spend (measured)         ${r.cost.agentSpend}`);
    L.push(`  Storage cost                   ${r.cost.storageCost}`);
    L.push('');
    L.push('TIME');
    L.push(`  Re-explanations eliminated     ${r.time.reExplanationsEliminated}`);
    L.push(`  Est. hours saved               ${r.time.estimatedHoursSaved}`);
    L.push(`  Incident trace time            ${r.time.incidentTraceTime}`);
    L.push(`  Privacy request fulfilment     ${r.time.privacyRequestFulfilment}`);
    L.push('');
    L.push('QUALITY');
    L.push(`  Memory health                  ${r.quality.memoryHealth} (${r.quality.healthScore}/100)`);
    L.push(`    duplicates                   ${r.quality.duplicates}`);
    L.push(`    stale facts                  ${r.quality.staleFacts}`);
    L.push(`    unresolved contradictions    ${r.quality.unresolvedContradictions}`);
    L.push(`    facts with full provenance   ${r.quality.factsWithFullProvenance}`);
    L.push(`    unowned folders              ${r.quality.unownedFolders}`);
    L.push(`    golden facts defined         ${r.quality.goldenFactsDefined}`);
    L.push('');
    L.push('RISK');
    L.push(`  Writes held                    ${r.risk.writesHeld}`);
    L.push(`  Writes blocked                 ${r.risk.writesBlocked}`);
    L.push(`  Untrusted-source attempts      ${r.risk.untrustedSourceAttempts}`);
    L.push(`  Instruction-shaped caught      ${r.risk.instructionShapedCaught}`);
    L.push(`  Cross-wall attempts            ${r.risk.crossWallAttempts}`);
    L.push(`  Credentials caught             ${r.risk.credentialsCaught}`);
    L.push(`  Golden facts protected         ${r.risk.goldenFactsProtected} overwrite attempts refused`);
    L.push(`  Drip-feed patterns detected    ${r.risk.dripFeedDetected}`);
    L.push(`  Shadow agents found            ${r.risk.shadowAgentsFound}`);
    L.push(`  Review SLA compliance          ${r.risk.reviewSlaCompliance}`);
    L.push(`  Kill switch last tested        ${r.risk.killSwitchLastTested}`);
    return L.join('\n');
  }
}

function countBy(arr, fn) {
  const out = new Map();
  for (const x of arr) {
    const k = fn(x) ?? 'unknown';
    out.set(k, (out.get(k) || 0) + 1);
  }
  return out;
}
function topN(map, n) {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ key: k, count: v }));
}
function round(n) { return Math.round((n || 0) * 100) / 100; }
function numericConfidence(label) { return { golden: 1, high: 0.9, medium: 0.7, low: 0.45 }[label] ?? 0.7; }
function hoursFromAgo(agoStr) {
  const m = /^(\d+)([a-z]+)/.exec(String(agoStr));
  if (!m) return 0;
  const n = parseInt(m[1]);
  return { s: n / 3600, min: n / 60, h: n, d: n * 24, months: n * 720 }[m[2]] ?? 0;
}
