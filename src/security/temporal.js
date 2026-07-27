/**
 * Layer 4 — temporal & behavioural detection (§9.6).
 *
 * Single-write checks miss patient attackers. These watch over time: drip-feed,
 * slow-boil, coordinated corroboration, sleepers, confidence laundering,
 * reviewer fatigue, queue flooding, retrieval patterns.
 */
import { cosine, jaccard, contentTokens, truncate } from '../util/text.js';
import { now, iso, ago, MINUTE, HOUR, DAY, WEEK, MONTH } from '../util/time.js';

export class TemporalDetector {
  /**
   * @param {object} opts
   * @param {import('../registry/registry.js').Registry} [opts.registry]
   * @param {()=>object[]} [opts.recentFacts]
   * @param {number} [opts.dripWindowMs]
   */
  constructor({ registry = null, recentFacts = () => [], dripWindowMs = 14 * DAY, coordinationWindowMs = 6 * HOUR } = {}) {
    this.registry = registry;
    this.recentFacts = recentFacts;
    this.dripWindowMs = dripWindowMs;
    this.coordinationWindowMs = coordinationWindowMs;
    /** @type {Array<{claim:string, at:number, source:string, agentId:string, tokens:Set<string>, attribute:string|null, value:any, folder:string|null}>} */
    this.observations = [];
    /**
     * token → the observations containing it.
     *
     * Every window scan below needs shared vocabulary to fire at all: drip-feed
     * requires two overlapping content tokens, and both cosine tests are zero
     * without overlap. So retrieving by token is not a narrowing of what the
     * detector examines — it is the same set, reached without walking
     * observations that could never have matched. The benchmark harness caught
     * the previous full-array scan making ingest linear in the number of writes.
     * @type {Map<string, Set<object>>}
     */
    this.byToken = new Map();
    /** @type {Map<string, Array<{at:number, value:number, source:string}>>} attribute → trend */
    this.trends = new Map();
    /** @type {Map<string, {approvals:number, rejections:number, totalMs:number, decisions:number, fastDecisions:number}>} */
    this.reviewers = new Map();
    this.queueSamples = [];
    /** @type {Map<string, Array<{at:number, query:string}>>} */
    this.queries = new Map();
    this.crossWallAttempts = new Map();
    this.factReads = new Map();
  }

  /**
   * Called by the gate on every write attempt.
   * @returns {{detections:object[]}}
   */
  observe(candidate, ctx = {}) {
    const detections = [];
    const at = now();
    const source = (typeof ctx.source === 'string' ? ctx.source : null)
      || ctx.source?.sender || ctx.source?.domain || ctx.channel || 'unknown';
    const tokens = new Set(contentTokens(candidate.claim));

    // -- drip-feed: fragments that assemble into a single claim --------------
    const window = this._windowSharingTokens(tokens, at, this.dripWindowMs);
    const fragments = window.filter((o) => {
      const overlap = [...tokens].filter((t) => o.tokens.has(t)).length;
      const sim = cosine(o.claim, candidate.claim);
      // Individually innocuous, collectively assembling: partial overlap, not
      // duplication, and crucially arriving from different sessions.
      return overlap >= 2 && sim > 0.18 && sim < 0.72 && o.source !== source;
    });
    if (fragments.length >= 2) {
      const assembled = [...fragments.map((f) => f.claim), candidate.claim];
      detections.push({
        kind: 'drip_feed',
        severity: 'high',
        action: 'hold',
        sources: [...new Set([...fragments.map((f) => f.source), source])],
        fragments: assembled.map((a) => truncate(a, 90)),
        explanation: `drip-feed pattern: ${assembled.length} fragments from ${new Set([...fragments.map((f) => f.source), source]).size} sources over ${ago(Math.min(...fragments.map((f) => f.at)))} assemble into one claim. Each is innocuous alone.`,
        claimSubject: candidate.structured?.entity || candidate.entities?.[0]?.name || null
      });
    }

    // -- slow-boil: a threshold nudged upward over weeks ---------------------
    const attr = candidate.structured?.attribute;
    const val = candidate.structured?.value;
    if (attr && typeof val === 'number') {
      const key = `${candidate.structured.entity || '*'}::${attr}`;
      const trend = this.trends.get(key) || [];
      trend.push({ at, value: val, source });
      while (trend.length && at - trend[0].at > 90 * DAY) trend.shift();
      this.trends.set(key, trend);
      if (trend.length >= 3) {
        const monotonic = trend.every((p, i) => i === 0 || p.value >= trend[i - 1].value);
        const growth = trend[trend.length - 1].value / Math.max(trend[0].value, 1e-9);
        if (monotonic && growth >= 1.25) {
          detections.push({
            kind: 'slow_boil',
            severity: 'high',
            action: 'hold',
            attribute: attr,
            trail: trend.map((p) => ({ value: p.value, at: iso(p.at), source: p.source })),
            explanation: `slow-boil: "${attr}" has been nudged upward ${trend.length} times (${trend.map((p) => p.value).join(' → ')}), a ${Math.round((growth - 1) * 100)}% rise over ${ago(trend[0].at)}. No single step looks wrong.`
          });
        }
      }
    }

    // -- coordinated: multiple sources asserting the same NOVEL claim --------
    const recentSame = this._windowSharingTokens(tokens, at, this.coordinationWindowMs)
      .filter((o) => o.source !== source && cosine(o.claim, candidate.claim) > 0.72);
    const distinctSources = new Set(recentSame.map((o) => o.source));
    if (distinctSources.size >= 2) {
      const priorKnowledge = this.recentFacts().some((f) => cosine(f.claim, candidate.claim) > 0.72 && f.createdAt < at - this.coordinationWindowMs);
      if (!priorKnowledge) {
        detections.push({
          kind: 'coordinated',
          severity: 'high',
          action: 'hold',
          sources: [...distinctSources, source],
          explanation: `coordinated assertion: ${distinctSources.size + 1} sources asserted the same novel claim within ${Math.round(this.coordinationWindowMs / HOUR)}h. Corroboration from coordinated sources is not corroboration.`
        });
      }
    }

    // -- confidence laundering: a guess re-asserted until it looks corroborated
    if (candidate.claimType === 'guessed' || candidate.claimType === 'heard') {
      const priorGuesses = window.filter((o) => o.claimType === 'guessed' && cosine(o.claim, candidate.claim) > 0.7);
      if (priorGuesses.length >= 2) {
        detections.push({
          kind: 'confidence_laundering',
          severity: 'medium',
          action: 'hold',
          explanation: `confidence laundering: the same AI-inferred claim has been re-asserted ${priorGuesses.length + 1} times. Repetition is not corroboration — a guess stays a guess.`
        });
      }
    }

    // -- trigger-word watch: facts that reference future conditions ----------
    if (/\b(?:when|whenever|if|next time)\b[^.]{0,60}\b(?:ask|asks|asked|requests?|mentions?)\b/i.test(candidate.claim)) {
      detections.push({
        kind: 'sleeper_trigger',
        severity: 'medium',
        action: 'hold',
        explanation: 'this claim references a future condition ("when asked about…") — the shape of a sleeper payload, not a description of the world'
      });
    }

    // -- novel channel / timing / volume via the registry baseline ----------
    if (this.registry && ctx.agentId) {
      const dev = this.registry.checkDeviation(ctx.agentId, {
        folder: ctx.folderHint || candidate.proposedFolder, claimType: candidate.claimType, channel: ctx.channel, at
      });
      for (const d of dev.deviations) {
        detections.push({
          kind: d.kind, severity: d.severity,
          action: d.severity === 'high' ? 'hold' : null,
          explanation: `${d.detail} (agent behavioural baseline)`
        });
      }
      this.registry.observeBehaviour(ctx.agentId, {
        folder: ctx.folderHint || candidate.proposedFolder, claimType: candidate.claimType,
        channel: ctx.channel, at, outcome: ctx.outcome
      });
    }

    // -- semantic drift: an agent's topics drifting from its stated purpose --
    if (this.registry && ctx.agentId) {
      const agent = this.registry.get(ctx.agentId);
      if (agent?.purpose && agent.writes > 25) {
        const rel = cosine(agent.purpose, candidate.claim);
        const recentForAgent = window.filter((o) => o.agentId === ctx.agentId).slice(-20);
        if (rel < 0.02 && recentForAgent.length >= 10) {
          const avgRel = recentForAgent.reduce((a, o) => a + cosine(agent.purpose, o.claim), 0) / recentForAgent.length;
          if (avgRel < 0.05) {
            detections.push({
              kind: 'semantic_drift', severity: 'medium', action: null,
              explanation: `semantic drift: this agent's recent writes have little to do with its stated purpose ("${truncate(agent.purpose, 60)}")`
            });
          }
        }
      }
    }

    const observation = {
      claim: candidate.claim, at, source, agentId: ctx.agentId, tokens,
      attribute: attr ?? null, value: val ?? null, claimType: candidate.claimType,
      folder: ctx.folderHint || candidate.proposedFolder || null
    };
    this.observations.push(observation);
    for (const t of tokens) {
      let bucket = this.byToken.get(t);
      if (!bucket) { bucket = new Set(); this.byToken.set(t, bucket); }
      bucket.add(observation);
    }

    const evicted = [];
    while (this.observations.length && at - this.observations[0].at > 90 * DAY) evicted.push(this.observations.shift());
    if (this.observations.length > 20000) evicted.push(...this.observations.splice(0, 5000));
    this._forget(evicted);

    return { detections };
  }

  /**
   * Observations within `windowMs` that share at least one content token.
   *
   * Returned in time order, because two of the callers report "over ${ago(...)}"
   * from the earliest fragment and would otherwise narrate the wrong span.
   */
  _windowSharingTokens(tokens, at, windowMs) {
    const seen = new Set();
    for (const t of tokens) {
      const bucket = this.byToken.get(t);
      if (!bucket) continue;
      for (const o of bucket) if (at - o.at <= windowMs) seen.add(o);
    }
    return [...seen].sort((a, b) => a.at - b.at);
  }

  /** Drop evicted observations from the token index, so it cannot outgrow the array. */
  _forget(evicted) {
    for (const o of evicted) {
      for (const t of o.tokens) {
        const bucket = this.byToken.get(t);
        if (!bucket) continue;
        bucket.delete(o);
        if (!bucket.size) this.byToken.delete(t);
      }
    }
  }

  /** Sleepers: written, never read for months, then suddenly hot (§9.6). */
  observeRead(factId, { at = now() } = {}) {
    const reads = this.factReads.get(factId) || [];
    reads.push(at);
    this.factReads.set(factId, reads);
    return reads.length;
  }

  detectSleepers(facts, { dormantFor = 60 * DAY, burstReads = 3, burstWindow = DAY } = {}) {
    const out = [];
    for (const f of facts) {
      const reads = this.factReads.get(f.id) || [];
      if (!reads.length) continue;
      const first = reads[0];
      const dormancy = first - (f.createdAt ?? f._created ?? first);
      const recent = reads.filter((r) => now() - r <= burstWindow).length;
      if (dormancy >= dormantFor && recent >= burstReads) {
        out.push({
          kind: 'sleeper', severity: 'high', factId: f.id,
          dormantFor: ago(f.createdAt ?? f._created, first),
          recentReads: recent,
          explanation: `fact ${f.id} sat unread for ${ago(f.createdAt ?? f._created, first)} and has been read ${recent} times in the last day — the shape of a sleeper waking up`
        });
      }
    }
    return out;
  }

  /** Cross-wall probing: repeated denied attempts from one agent (§9.6). */
  observeCrossWall(agentId, folder) {
    const key = agentId;
    const list = this.crossWallAttempts.get(key) || [];
    list.push({ at: now(), folder });
    this.crossWallAttempts.set(key, list);
    const recent = list.filter((x) => now() - x.at <= HOUR);
    if (recent.length >= 3) {
      return {
        kind: 'cross_wall_probing', severity: 'high', action: 'hold',
        folders: [...new Set(recent.map((r) => r.folder))],
        explanation: `${recent.length} denied cross-wall attempts from ${agentId} in the last hour — this is probing, not a misconfiguration`
      };
    }
    return null;
  }

  /** Retrieval manipulation: repeated querying for a specific poisoned fact. */
  observeQuery(agentId, query) {
    const list = this.queries.get(agentId) || [];
    list.push({ at: now(), query });
    while (list.length && now() - list[0].at > DAY) list.shift();
    this.queries.set(agentId, list);
    const similar = list.filter((q) => jaccard(q.query, query) > 0.8);
    if (similar.length >= 5) {
      return {
        kind: 'retrieval_manipulation', severity: 'medium',
        explanation: `${similar.length} near-identical queries from ${agentId} in 24h — consistent with probing for a specific fact`,
        query: truncate(query, 80)
      };
    }
    return null;
  }

  /** Reviewer fatigue — flag the REVIEWER, not just the write (§9.6, §12). */
  observeReview({ reviewer, decision, tookMs }) {
    const r = this.reviewers.get(reviewer) || { approvals: 0, rejections: 0, totalMs: 0, decisions: 0, fastDecisions: 0 };
    r.decisions++;
    r.totalMs += tookMs || 0;
    if (decision === 'approve') r.approvals++;
    if (decision === 'reject') r.rejections++;
    if ((tookMs || 0) < 3000) r.fastDecisions++;
    this.reviewers.set(reviewer, r);

    const approvalRate = r.approvals / Math.max(r.decisions, 1);
    const avgMs = r.totalMs / Math.max(r.decisions, 1);
    if (r.decisions >= 20 && approvalRate > 0.95 && avgMs < 5000) {
      return {
        kind: 'reviewer_fatigue', severity: 'medium', reviewer,
        stats: { decisions: r.decisions, approvalRate: Math.round(approvalRate * 100) / 100, avgSeconds: Math.round(avgMs / 100) / 10 },
        explanation: `${reviewer} has approved ${Math.round(approvalRate * 100)}% of ${r.decisions} items at a median of ${Math.round(avgMs / 1000)}s each — rubber-stamping, not reviewing`
      };
    }
    return null;
  }

  /** Queue flooding: submission volume spike designed to drown real threats. */
  observeQueueDepth(depth) {
    this.queueSamples.push({ at: now(), depth });
    while (this.queueSamples.length && now() - this.queueSamples[0].at > WEEK) this.queueSamples.shift();
    if (this.queueSamples.length < 10) return null;
    const recent = this.queueSamples.slice(-5).reduce((a, s) => a + s.depth, 0) / 5;
    const baseline = this.queueSamples.slice(0, -5).reduce((a, s) => a + s.depth, 0) / Math.max(this.queueSamples.length - 5, 1);
    if (baseline > 0 && recent > baseline * 5 && recent > 20) {
      return {
        kind: 'queue_flooding', severity: 'high',
        explanation: `review queue depth is ${Math.round(recent / baseline)}× its baseline (${Math.round(recent)} vs ${Math.round(baseline)}) — this is how real threats get rubber-stamped`,
        action: 'raise reviewer capacity and treat approvals in this window as suspect'
      };
    }
    return null;
  }

  reviewerScorecards() {
    return [...this.reviewers.entries()].map(([reviewer, r]) => ({
      reviewer,
      decisions: r.decisions,
      approvalRate: Math.round((r.approvals / Math.max(r.decisions, 1)) * 100) / 100,
      rejectionRate: Math.round((r.rejections / Math.max(r.decisions, 1)) * 100) / 100,
      avgSeconds: Math.round(r.totalMs / Math.max(r.decisions, 1) / 100) / 10,
      fastDecisions: r.fastDecisions,
      flag: r.decisions >= 20 && r.approvals / r.decisions > 0.95 && r.totalMs / r.decisions < 5000
        ? 'possible reviewer fatigue' : null
    }));
  }

  stats() {
    return {
      observations: this.observations.length,
      trendedAttributes: this.trends.size,
      reviewers: this.reviewers.size,
      trackedQueries: [...this.queries.values()].reduce((a, l) => a + l.length, 0)
    };
  }
}
