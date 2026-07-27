/**
 * 🟢 VAULT TRACE — our own observability & evals (§17).
 *
 * The thing no competitor has: MEMORY-AWARE TRACES. Every trace shows which
 * facts were read, which were withheld, and which were written, held or blocked
 * — inline with the reasoning. Everything else here is table stakes; that line
 * is the product.
 *
 * OpenTelemetry-native: spans map to the GenAI semantic conventions and can be
 * exported over OTLP to whatever the platform team already runs.
 */
import { newId } from '../util/id.js';
import { now, iso, ago, DAY } from '../util/time.js';
import { VaultError, notFound } from '../util/errors.js';
import { cosine, truncate, jaccard } from '../util/text.js';

export const SPAN_KINDS = ['agent', 'llm', 'tool', 'retrieval', 'memory_read', 'memory_write', 'gate', 'plan', 'subagent', 'error'];

export class VaultTrace {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.spans
   * @param {import('../storage/db.js').Collection} opts.evals
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {import('../modules/modules.js').ModuleRegistry} [opts.modules]
   */
  constructor({ spans, evals, ledger, modules = null, state = null }) {
    // 'active -> acknowledged -> resolved -> regressed, tracked' is not tracking
    // if the lifecycle resets whenever the process does.
    this._state = state;
    this.spans = spans;
    this.evalsCol = evals;
    this.ledger = ledger;
    this.modules = modules;
    this.spans.index('byTrace', (s) => s.traceId);
    this.spans.index('byAgent', (s) => s.agentId);
    this.spans.index('byParent', (s) => s.parentId);
    /** @type {Map<string, object>} open spans */
    this.open = new Map();
    this.goldenSets = new Map(Object.entries(state?.get('state')?.goldenSets ?? {}));
    this.issues = new Map(Object.entries(state?.get('state')?.issues ?? {}));
    this.otelExporters = [];
  }

  _persistState() {
    this._state?.put({
      id: 'state',
      goldenSets: Object.fromEntries(this.goldenSets),
      issues: Object.fromEntries(this.issues)
    });
  }


  // ==== tracing (§17.1) ==================================================

  startTrace({ agentId, name, input = null, sessionId = null, model = null, metadata = {} }) {
    const traceId = newId('trace');
    const root = this.startSpan({
      traceId, parentId: null, kind: 'agent', name: name || agentId,
      agentId, input, model, metadata: { ...metadata, sessionId }
    });
    return { traceId, rootSpanId: root.id };
  }

  /**
   * @returns {{id:string, end:(o?:object)=>object}}
   */
  startSpan({ traceId, parentId = null, kind = 'llm', name, agentId = null, input = null, model = null, metadata = {} }) {
    if (!SPAN_KINDS.includes(kind)) throw new VaultError('validation', `span kind must be one of ${SPAN_KINDS.join(', ')}`);
    const span = {
      id: newId('span'),
      traceId,
      parentId,
      kind,
      name,
      agentId,
      startedAt: now(),
      startedHr: process.hrtime.bigint().toString(),
      endedAt: null,
      durationMs: null,
      input: input ? truncate(JSON.stringify(input), 4000) : null,
      output: null,
      model,
      tokensIn: null,
      tokensOut: null,
      costUsd: null,
      error: null,
      retries: 0,
      metadata,
      // MEMORY AWARENESS — the differentiator
      memory: { read: [], withheld: [], written: [], held: [], blocked: [], goldenUsed: [] }
    };
    const stored = this.spans.insert(span);
    this.open.set(stored.id, stored);
    return {
      id: stored.id,
      end: (o = {}) => this.endSpan(stored.id, o),
      child: (spec) => this.startSpan({ ...spec, traceId, parentId: stored.id, agentId: spec.agentId ?? agentId })
    };
  }

  endSpan(spanId, { output = null, tokensIn = null, tokensOut = null, costUsd = null, error = null, retries = 0 } = {}) {
    const span = this.spans.get(spanId);
    if (!span) throw notFound('span', spanId);
    const ended = now();
    const updated = this.spans.update(spanId, {
      endedAt: ended,
      durationMs: ended - span.startedAt,
      output: output ? truncate(JSON.stringify(output), 4000) : null,
      tokensIn, tokensOut, costUsd, error, retries
    });
    this.open.delete(spanId);
    this._emitOtel(updated);
    return updated;
  }

  /** Attach memory events to the span that caused them. This is the point. */
  recordMemory(spanId, { read = [], withheld = [], written = [], held = [], blocked = [], goldenUsed = [] }) {
    const span = this.spans.get(spanId);
    if (!span) return null;
    const m = span.memory;
    return this.spans.update(spanId, {
      memory: {
        read: [...m.read, ...read],
        withheld: [...m.withheld, ...withheld],
        written: [...m.written, ...written],
        held: [...m.held, ...held],
        blocked: [...m.blocked, ...blocked],
        goldenUsed: [...m.goldenUsed, ...goldenUsed]
      }
    });
  }

  /** Full trace as a tree, with memory events inline. */
  getTrace(traceId) {
    const spans = this.spans.by('byTrace', traceId).sort((a, b) => a.startedAt - b.startedAt);
    if (!spans.length) throw notFound('trace', traceId);
    const byId = new Map(spans.map((s) => [s.id, { ...s, children: [] }]));
    let root = null;
    for (const s of byId.values()) {
      if (s.parentId && byId.has(s.parentId)) byId.get(s.parentId).children.push(s);
      else root = root || s;
    }
    const memory = spans.reduce((acc, s) => ({
      read: acc.read + s.memory.read.length,
      withheld: acc.withheld + s.memory.withheld.length,
      written: acc.written + s.memory.written.length,
      held: acc.held + s.memory.held.length,
      blocked: acc.blocked + s.memory.blocked.length,
      goldenUsed: acc.goldenUsed + s.memory.goldenUsed.length
    }), { read: 0, withheld: 0, written: 0, held: 0, blocked: 0, goldenUsed: 0 });

    return {
      traceId,
      root,
      spans: spans.length,
      startedAt: iso(spans[0].startedAt),
      durationMs: Math.max(...spans.map((s) => s.endedAt || now())) - spans[0].startedAt,
      totalCostUsd: round4(spans.reduce((a, s) => a + (s.costUsd || 0), 0)),
      totalTokens: spans.reduce((a, s) => a + (s.tokensIn || 0) + (s.tokensOut || 0), 0),
      errors: spans.filter((s) => s.error).length,
      retries: spans.reduce((a, s) => a + (s.retries || 0), 0),
      memory,
      live: spans.some((s) => !s.endedAt)
    };
  }

  /** Long-run support: thousands of spans, streamed and viewable live. */
  liveSpans(traceId) {
    return this.spans.by('byTrace', traceId).filter((s) => !s.endedAt)
      .map((s) => ({ id: s.id, kind: s.kind, name: s.name, runningFor: ago(s.startedAt) }));
  }

  /** Render the tree — this is the view that sells the product. */
  render(traceId) {
    const t = this.getTrace(traceId);
    const lines = [];
    lines.push(`TRACE ${traceId} · ${t.spans} spans · ${t.durationMs}ms · $${t.totalCostUsd} · ${t.totalTokens} tokens`);
    lines.push(`MEMORY  ${t.memory.read} read · ${t.memory.withheld} withheld · ${t.memory.written} written · ${t.memory.held} held · ${t.memory.blocked} blocked · ${t.memory.goldenUsed} golden used`);
    lines.push('');
    const walk = (span, depth) => {
      const pad = '  '.repeat(depth);
      const dur = span.durationMs != null ? `${span.durationMs}ms` : 'running';
      lines.push(`${pad}${ICONS[span.kind] || '·'} ${span.name} (${span.kind}) — ${dur}${span.costUsd ? ` · $${span.costUsd}` : ''}${span.error ? ` · ERROR: ${span.error}` : ''}`);
      for (const m of span.memory.read) lines.push(`${pad}    ↳ read   ${m.id ?? m} ${m.claimType ? `[${m.claimType}]` : ''}`);
      for (const m of span.memory.goldenUsed) lines.push(`${pad}    ★ golden ${m.id ?? m} — used`);
      for (const m of span.memory.withheld) lines.push(`${pad}    ✗ withheld ${m.reason ?? m}`);
      for (const m of span.memory.written) lines.push(`${pad}    ✓ wrote  ${m.id ?? m}`);
      for (const m of span.memory.held) lines.push(`${pad}    ⏳ HELD   ${m.reason ?? m}`);
      for (const m of span.memory.blocked) lines.push(`${pad}    ⛔ BLOCKED ${m.reason ?? m}`);
      for (const c of span.children || []) walk(c, depth + 1);
    };
    walk(t.root, 0);
    return lines.join('\n');
  }

  /** Diff two runs of the same task (§17.1). */
  diff(traceIdA, traceIdB) {
    const a = this.getTrace(traceIdA);
    const b = this.getTrace(traceIdB);
    const spansA = this.spans.by('byTrace', traceIdA);
    const spansB = this.spans.by('byTrace', traceIdB);
    const names = (s) => s.map((x) => `${x.kind}:${x.name}`);
    const na = names(spansA);
    const nb = names(spansB);
    return {
      a: { traceId: traceIdA, spans: a.spans, durationMs: a.durationMs, cost: a.totalCostUsd, memory: a.memory },
      b: { traceId: traceIdB, spans: b.spans, durationMs: b.durationMs, cost: b.totalCostUsd, memory: b.memory },
      stepsOnlyInA: na.filter((x) => !nb.includes(x)),
      stepsOnlyInB: nb.filter((x) => !na.includes(x)),
      deltas: {
        durationMs: b.durationMs - a.durationMs,
        costUsd: round4(b.totalCostUsd - a.totalCostUsd),
        toolCalls: spansB.filter((s) => s.kind === 'tool').length - spansA.filter((s) => s.kind === 'tool').length,
        factsRead: b.memory.read - a.memory.read,
        goldenUsed: b.memory.goldenUsed - a.memory.goldenUsed
      },
      note: 'non-deterministic flows produce different trace shapes every run; the diff compares step sets, not positions'
    };
  }

  /** Time-travel replay against a different model or memory snapshot. */
  replay(traceId, { model = null, memorySnapshotAt = null, runner }) {
    const t = this.getTrace(traceId);
    const spans = this.spans.by('byTrace', traceId).sort((a, b) => a.startedAt - b.startedAt);
    const inputs = spans.filter((s) => s.kind === 'llm' || s.kind === 'agent').map((s) => s.input);
    if (typeof runner !== 'function') {
      return {
        replayable: true,
        originalTraceId: traceId,
        wouldReplay: inputs.length,
        withModel: model || 'original',
        againstMemoryAt: memorySnapshotAt ? iso(memorySnapshotAt) : 'current',
        note: 'supply a runner function to execute the replay; without one this reports what would run'
      };
    }
    const started = now();
    const result = runner({ inputs, model, memorySnapshotAt });
    return { originalTraceId: traceId, replayedAt: iso(started), model: model || 'original', result };
  }

  // ==== OpenTelemetry ====================================================

  addOtelExporter(fn) { this.otelExporters.push(fn); return this; }

  _emitOtel(span) {
    const otel = this.toOtel(span);
    for (const fn of this.otelExporters) {
      try { fn(otel); } catch { /* an exporter must never break tracing */ }
    }
    // 🔵/🟣 push to a connected observability platform, enriched with memory
    // events they cannot get anywhere else.
    this.modules?.dispatch('tracing', 'span', otel);
  }

  /** GenAI semantic conventions. */
  toOtel(span) {
    return {
      traceId: span.traceId,
      spanId: span.id,
      parentSpanId: span.parentId,
      name: span.name,
      startTimeUnixNano: span.startedAt * 1e6,
      endTimeUnixNano: (span.endedAt || now()) * 1e6,
      kind: span.kind === 'llm' ? 'CLIENT' : 'INTERNAL',
      status: span.error ? { code: 'ERROR', message: span.error } : { code: 'OK' },
      attributes: {
        'gen_ai.system': 'vault',
        'gen_ai.operation.name': span.kind,
        'gen_ai.request.model': span.model,
        'gen_ai.usage.input_tokens': span.tokensIn,
        'gen_ai.usage.output_tokens': span.tokensOut,
        'gen_ai.usage.cost': span.costUsd,
        'vault.agent.id': span.agentId,
        // memory attributes — the enrichment nobody else can emit
        'vault.memory.facts_read': span.memory.read.length,
        'vault.memory.facts_withheld': span.memory.withheld.length,
        'vault.memory.facts_written': span.memory.written.length,
        'vault.memory.writes_held': span.memory.held.length,
        'vault.memory.writes_blocked': span.memory.blocked.length,
        'vault.memory.golden_used': span.memory.goldenUsed.length
      }
    };
  }

  // ==== evaluation (§17.2) ===============================================

  /** Curated task sets per agent, per department. */
  createGoldenSet(name, cases, { actor, agentId = null, department = null }) {
    const set = {
      id: newId('eval'), name, agentId, department, actor, createdAt: now(),
      cases: cases.map((c, i) => ({ id: `${name}-${i}`, ...c }))
    };
    this.goldenSets.set(set.id, set);
    this._persistState();
    return set;
  }

  /**
   * Run a golden set. Scorers include memory-specific ones no other tool has.
   * @param {string} setId
   * @param {(input:any)=>{output:string, factsRead?:object[], citations?:string[], traceId?:string}} runner
   */
  runEval(setId, runner, { actor, label = 'ad-hoc' } = {}) {
    const set = this.goldenSets.get(setId);
    if (!set) throw notFound('golden set', setId);
    const results = [];
    for (const c of set.cases) {
      let out;
      let error = null;
      try { out = runner(c.input); } catch (e) { error = e.message; out = { output: '' }; }
      const scores = this.score(c, out);
      results.push({ caseId: c.id, input: truncate(String(c.input), 120), output: truncate(String(out.output), 200), scores, error, passed: Object.values(scores).every((s) => s.pass !== false) });
    }
    const run = this.evalsCol.insert({
      id: newId('eval'), setId, setName: set.name, label, actor, at: now(),
      total: results.length,
      passed: results.filter((r) => r.passed).length,
      results,
      aggregate: aggregateScores(results)
    });
    this.modules?.dispatch('tracing', 'eval', run);
    return run;
  }

  /**
   * Scorers. The memory-specific ones are the reason this exists:
   *  - did the agent use the golden fact?
   *  - did it repeat a `guessed` fact as truth?
   *  - did it cite provenance?
   */
  score(testCase, result) {
    const output = String(result.output ?? '');
    const scores = {};

    if (testCase.expected) {
      const sim = cosine(output, testCase.expected);
      scores.relevance = { value: round2(sim), pass: sim >= (testCase.threshold ?? 0.3) };
    }
    if (testCase.mustContain) {
      const hit = testCase.mustContain.every((s) => output.toLowerCase().includes(String(s).toLowerCase()));
      scores.instructionFollowing = { value: hit ? 1 : 0, pass: hit };
    }
    if (testCase.mustNotContain) {
      const bad = testCase.mustNotContain.filter((s) => output.toLowerCase().includes(String(s).toLowerCase()));
      scores.safety = { value: bad.length ? 0 : 1, pass: bad.length === 0, violations: bad };
    }
    // Faithfulness / hallucination: is every assertion grounded in a fact read?
    if (result.factsRead) {
      const grounded = result.factsRead.some((f) => cosine(output, f.claim) > 0.25);
      scores.faithfulness = { value: grounded ? 1 : 0, pass: grounded || !result.factsRead.length };
      scores.hallucination = { value: grounded ? 0 : 1, pass: grounded || !result.factsRead.length };
    }
    // MEMORY-SPECIFIC
    if (testCase.expectGoldenFact) {
      const used = (result.factsRead || []).some((f) => f.id === testCase.expectGoldenFact || f.golden);
      const quoted = testCase.goldenClaim ? cosine(output, testCase.goldenClaim) > 0.3 : used;
      scores.usedGoldenFact = { value: used && quoted ? 1 : 0, pass: used && quoted, detail: 'did the agent use the approved policy rather than an inference?' };
    }
    const guessed = (result.factsRead || []).filter((f) => f.claimType === 'guessed');
    if (guessed.length) {
      const repeatedAsTruth = guessed.some((g) =>
        cosine(output, g.claim) > 0.35 && !/\b(unconfirmed|may|might|possibly|not confirmed|signal|inferred|unverified)\b/i.test(output));
      scores.guessedAsTruth = { value: repeatedAsTruth ? 1 : 0, pass: !repeatedAsTruth, detail: 'did it repeat an AI guess as if it were established?' };
    }
    if (result.citations !== undefined) {
      const cited = (result.citations || []).length > 0;
      scores.citationAccuracy = { value: cited ? 1 : 0, pass: cited || !(result.factsRead || []).length, detail: 'did it cite provenance?' };
    }
    if (testCase.expectToolCalls && result.traceId) {
      const tools = this.spans.by('byTrace', result.traceId).filter((s) => s.kind === 'tool').map((s) => s.name);
      const correct = testCase.expectToolCalls.every((t) => tools.includes(t));
      scores.toolSelection = { value: correct ? 1 : 0, pass: correct, called: tools };
      scores.planningQuality = { value: tools.length <= (testCase.maxToolCalls ?? 99) ? 1 : 0, pass: tools.length <= (testCase.maxToolCalls ?? 99) };
    }
    return scores;
  }

  /**
   * A/B: memory on vs off. Proves the accuracy and tool-call improvement on
   * THEIR data, not ours (§17.2).
   */
  abTest(setId, { withMemory, withoutMemory, actor }) {
    const on = this.runEval(setId, withMemory, { actor, label: 'memory-on' });
    const off = this.runEval(setId, withoutMemory, { actor, label: 'memory-off' });
    const accOn = on.passed / Math.max(on.total, 1);
    const accOff = off.passed / Math.max(off.total, 1);
    return {
      setId,
      withMemory: { runId: on.id, passed: on.passed, total: on.total, accuracy: round2(accOn), aggregate: on.aggregate },
      withoutMemory: { runId: off.id, passed: off.passed, total: off.total, accuracy: round2(accOff), aggregate: off.aggregate },
      delta: {
        accuracy: `${accOff ? (accOn - accOff >= 0 ? '+' : '') + Math.round(((accOn - accOff) / Math.max(accOff, 0.01)) * 100) : '—'}%`,
        absolute: round2(accOn - accOff)
      },
      verdict: accOn > accOff
        ? `memory improved accuracy by ${Math.round(((accOn - accOff) / Math.max(accOff, 0.01)) * 100)}% on your own golden set`
        : 'memory did not improve accuracy on this set — worth investigating which facts were surfaced'
    };
  }

  /** Regression gates: block a change if it degrades a golden set (CI). */
  regressionGate(setId, runner, { baselineRunId = null, tolerance = 0.02, actor = 'ci' }) {
    const run = this.runEval(setId, runner, { actor, label: 'regression-gate' });
    const prior = baselineRunId
      ? this.evalsCol.get(baselineRunId)
      : this.evalsCol.find((r) => r.setId === setId && r.id !== run.id).sort((a, b) => b.at - a.at)[0];
    if (!prior) return { pass: true, run: run.id, note: 'no baseline yet — this run becomes the baseline' };
    const now_ = run.passed / Math.max(run.total, 1);
    const then = prior.passed / Math.max(prior.total, 1);
    const pass = now_ >= then - tolerance;
    const regressed = run.results.filter((r) => !r.passed && prior.results.find((p) => p.caseId === r.caseId)?.passed);
    if (!pass) {
      this.ledger.append('security.detection', { subject: setId, actor, detection: 'eval_regression', from: round2(then), to: round2(now_) });
    }
    return {
      pass,
      run: run.id,
      baseline: prior.id,
      accuracy: { baseline: round2(then), current: round2(now_), delta: round2(now_ - then) },
      regressedCases: regressed.map((r) => ({ caseId: r.caseId, output: r.output })),
      verdict: pass ? 'no regression — change may proceed' : `BLOCKED: accuracy dropped from ${round2(then)} to ${round2(now_)}`
    };
  }

  /** Turn an annotated production failure into a permanent regression test. */
  promoteToTest(setId, { input, expected, mustNotContain = [], actor, note = 'promoted from a production failure' }) {
    const set = this.goldenSets.get(setId);
    if (!set) throw notFound('golden set', setId);
    const testCase = { id: `${set.name}-${set.cases.length}`, input, expected, mustNotContain, note, addedBy: actor, addedAt: iso() };
    set.cases.push(testCase);
    return { setId, added: testCase.id, totalCases: set.cases.length };
  }

  /** Human review sampling with an annotation workflow (§17.2). */
  sampleForHumanReview(runId, { rate = 0.1, reviewers = [] } = {}) {
    const run = this.evalsCol.get(runId);
    if (!run) throw notFound('eval run', runId);
    const sampled = run.results.filter(() => Math.random() < rate);
    return sampled.map((r, i) => ({
      caseId: r.caseId,
      output: r.output,
      assignedTo: reviewers.length ? reviewers[i % reviewers.length] : null,
      annotations: [],
      status: 'awaiting_human_score'
    }));
  }

  /** Drift detection: output quality drifting over time, with alerting. */
  drift(setId, { windowDays = 30 } = {}) {
    const runs = this.evalsCol.find((r) => r.setId === setId && r.at >= now() - windowDays * DAY)
      .sort((a, b) => a.at - b.at);
    if (runs.length < 3) return { detected: false, note: 'not enough runs to assess drift' };
    const acc = runs.map((r) => r.passed / Math.max(r.total, 1));
    const first = acc.slice(0, Math.ceil(acc.length / 3)).reduce((a, b) => a + b, 0) / Math.ceil(acc.length / 3);
    const last = acc.slice(-Math.ceil(acc.length / 3)).reduce((a, b) => a + b, 0) / Math.ceil(acc.length / 3);
    const detected = last < first - 0.05;
    return {
      detected,
      from: round2(first), to: round2(last), delta: round2(last - first), runs: runs.length,
      message: detected ? `quality has drifted down ${Math.round((first - last) * 100)} points over ${windowDays} days` : 'no meaningful drift'
    };
  }

  // ==== issues (§17.2) ===================================================

  openIssue({ title, traceId = null, caseId = null, actor, severity = 'medium', detail = '' }) {
    const issue = {
      id: newId('incident'), title, traceId, caseId, actor, severity, detail,
      status: 'active', openedAt: now(), history: [{ at: now(), status: 'active', actor }],
      cluster: null
    };
    this.issues.set(issue.id, issue);
    this._persistState();
    return issue;
  }

  /** active → acknowledged → resolved → regressed. */
  updateIssue(id, status, { actor, note = null }) {
    const issue = this.issues.get(id);
    if (!issue) throw notFound('issue', id);
    if (!['active', 'acknowledged', 'resolved', 'regressed'].includes(status)) {
      throw new VaultError('validation', 'issue status must be active, acknowledged, resolved or regressed');
    }
    issue.status = status;
    issue.history.push({ at: now(), status, actor, note });
    return issue;
  }

  /** Failure clustering: group similar failures so you fix categories. */
  clusterFailures({ threshold = 0.55 } = {}) {
    const failures = [];
    for (const run of this.evalsCol.all()) {
      for (const r of run.results) {
        if (!r.passed) failures.push({ runId: run.id, caseId: r.caseId, output: r.output, scores: r.scores });
      }
    }
    const clusters = [];
    for (const f of failures) {
      const match = clusters.find((c) => jaccard(c.exemplar, f.output) >= threshold);
      if (match) { match.members.push(f); match.count++; }
      else clusters.push({ id: `cluster-${clusters.length + 1}`, exemplar: f.output, members: [f], count: 1 });
    }
    return clusters
      .sort((a, b) => b.count - a.count)
      .map((c) => ({
        id: c.id, count: c.count, exemplar: truncate(c.exemplar, 140),
        failingScorers: [...new Set(c.members.flatMap((m) => Object.entries(m.scores).filter(([, s]) => s.pass === false).map(([k]) => k)))],
        fix: 'fix this category once rather than each instance'
      }));
  }

  stats() {
    const spans = this.spans.all();
    return {
      traces: new Set(spans.map((s) => s.traceId)).size,
      spans: spans.length,
      openSpans: this.open.size,
      totalCostUsd: round4(spans.reduce((a, s) => a + (s.costUsd || 0), 0)),
      memoryEvents: spans.reduce((a, s) => a + s.memory.read.length + s.memory.written.length + s.memory.held.length + s.memory.blocked.length, 0),
      goldenSets: this.goldenSets.size,
      evalRuns: this.evalsCol.size,
      issues: this.issues.size
    };
  }
}

const ICONS = {
  agent: '🤖', llm: '🧠', tool: '🔧', retrieval: '🔍', memory_read: '📖',
  memory_write: '✍️', gate: '🚪', plan: '🗺️', subagent: '👥', error: '💥'
};

function aggregateScores(results) {
  const agg = {};
  for (const r of results) {
    for (const [k, v] of Object.entries(r.scores)) {
      const a = agg[k] || { total: 0, sum: 0, passed: 0 };
      a.total++;
      a.sum += typeof v.value === 'number' ? v.value : 0;
      if (v.pass !== false) a.passed++;
      agg[k] = a;
    }
  }
  const out = {};
  for (const [k, a] of Object.entries(agg)) {
    out[k] = { mean: round2(a.sum / a.total), passRate: round2(a.passed / a.total), n: a.total };
  }
  return out;
}

const round2 = (n) => Math.round(n * 100) / 100;
const round4 = (n) => Math.round(n * 10000) / 10000;
