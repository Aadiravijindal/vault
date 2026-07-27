/**
 * Vault Trace (§17), Comply (§18), Insure (§20), the Map (§23), jurisdiction
 * packs (§15) and consent (§14.5).
 *
 * Each of these asserts on real output — an evidence item that cites a real
 * ledger sequence, a works agreement that quotes the retention actually
 * configured — rather than on a route responding.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';

function loaded({ seedRules = true } = {}) {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules });
  v.registerAgent({ id: 'a-1', name: 'Sales Copilot', purpose: 'sales', businessOwner: 'dana', technicalOwner: 'sam', department: 'sales', mode: 'inline', pinnedModel: 'm1', folders: ['sales/'] });
  const cred = v.issueCredential('a-1', {}).credential;
  const w = (text, o = {}) => v.ingest({
    agentId: 'a-1', channel: o.channel || 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text }]
  }, { credential: cred });
  return { v, cred, w };
}

describe('Vault Trace — memory-aware tracing and evals', () => {
  test('a multi-step task produces nested spans with memory attributed to the right one', () => {
    const { v } = loaded();
    const t = v.vaultTrace.startTrace({ agentId: 'a-1', name: 'answer a customer question' });
    const retrieval = v.vaultTrace.startSpan({ traceId: t.traceId, parentId: t.rootSpanId, kind: 'retrieval', name: 'recall' });
    v.vaultTrace.recordMemory(retrieval.id, { read: ['f-1', 'f-2'], withheld: ['f-3'], goldenUsed: ['g-1'] });
    v.vaultTrace.endSpan(retrieval.id, { costUsd: 0.002, tokensIn: 900, tokensOut: 120 });
    const tool = v.vaultTrace.startSpan({ traceId: t.traceId, parentId: retrieval.id, kind: 'tool', name: 'crm.lookup' });
    v.vaultTrace.endSpan(tool.id, { costUsd: 0.001, error: 'timeout', retries: 2 });
    v.vaultTrace.endSpan(t.rootSpanId, { costUsd: 0.004 });

    const tr = v.vaultTrace.getTrace(t.traceId);
    assert.equal(tr.root.children[0].name, 'recall', 'parent/child causality');
    assert.equal(tr.root.children[0].children[0].name, 'crm.lookup', 'and it nests further');
    assert.deepEqual(
      { read: tr.memory.read, withheld: tr.memory.withheld, goldenUsed: tr.memory.goldenUsed },
      { read: 2, withheld: 1, goldenUsed: 1 },
      'which facts were read and which were withheld, inline with the reasoning'
    );
    assert.ok(tr.totalCostUsd >= 0.007, `cost aggregates: ${tr.totalCostUsd}`);
    assert.equal(tr.errors, 1);
    assert.equal(tr.retries, 2);
    // The span that read memory is the retrieval span, not the root.
    const retrievalSpan = v.vaultTrace.spans.get(retrieval.id);
    assert.equal(retrievalSpan.memory.read.length, 2);
    assert.equal(v.vaultTrace.spans.get(tool.id).memory.read.length, 0, 'the tool span read nothing');
  });

  test('OTel export carries GenAI conventions and survives a span with no memory block', () => {
    const { v } = loaded();
    const t = v.vaultTrace.startTrace({ agentId: 'a-1', name: 'task', model: 'm1' });
    v.vaultTrace.endSpan(t.rootSpanId, { costUsd: 0.01, tokensIn: 10, tokensOut: 5 });
    const otlp = v.vaultTrace.traceToOtel(t.traceId);
    const span = otlp.resourceSpans[0].scopeSpans[0].spans[0];
    assert.equal(span.attributes['gen_ai.system'], 'vault');
    assert.equal(span.attributes['gen_ai.usage.input_tokens'], 10);
    assert.equal(span.attributes['vault.memory.facts_read'], 0);
    // An exporter that throws takes observability down with it.
    assert.doesNotThrow(() => v.vaultTrace.toOtel({ id: 'x', traceId: 't', name: 'legacy', startedAt: 1, kind: 'llm' }));
  });

  test('a regression gate fails the build when a golden set degrades', () => {
    const { v } = loaded();
    const set = v.vaultTrace.createGoldenSet('sales-qa', [
      { input: 'what is the maximum discount?', expected: 'The maximum discount is 20%' }
    ], { actor: 'dana', agentId: 'a-1' });

    const good = () => ({ output: 'The maximum discount is 20%', citations: ['g-1'] });
    const bad = () => ({ output: 'no idea', citations: [] });

    const baseline = v.vaultTrace.runEval(set.id, good, { actor: 'ci', label: 'baseline' });
    assert.equal(baseline.passed, 1, JSON.stringify(baseline.results[0].scores));

    const gate = v.vaultTrace.regressionGate(set.id, bad, { actor: 'ci' });
    assert.equal(gate.pass, false, 'a quality drop must block the change');
    assert.equal(gate.accuracy.baseline, 1);
    assert.equal(gate.accuracy.current, 0);
    assert.ok(gate.regressedCases.length > 0, 'and name which cases regressed');

    const stillGood = v.vaultTrace.regressionGate(set.id, good, { actor: 'ci', baselineRunId: baseline.id });
    assert.equal(stillGood.pass, true, 'an unchanged run passes');
  });

  test('A/B proves memory on beats memory off on the customer\'s own set', () => {
    const { v } = loaded();
    const set = v.vaultTrace.createGoldenSet('ab', [
      { input: 'what is the maximum discount?', expected: 'The maximum discount is 20%' }
    ], { actor: 'dana' });
    const ab = v.vaultTrace.abTest(set.id, {
      actor: 'dana',
      withMemory: () => ({ output: 'The maximum discount is 20%', citations: ['g-1'] }),
      withoutMemory: () => ({ output: 'discounts are generally unlimited', citations: [] })
    });
    assert.equal(ab.withMemory.accuracy, 1);
    assert.equal(ab.withoutMemory.accuracy, 0);
    assert.ok(ab.withMemory.runId !== ab.withoutMemory.runId, 'two real runs, not a claim');
  });
});

describe('Vault Comply — evidence comes from the ledger, not a form', () => {
  test('every control maps to real frameworks and cites real ledger entries', () => {
    const { v, w } = loaded();
    w('Globex has 340 seats provisioned.');
    w('Supplier pre-approved for payments up to $250,000.', { channel: 'email' });

    const monitored = v.comply.monitorControls();
    assert.ok(monitored.results.length >= 10, `${monitored.results.length} controls`);

    const evidence = v.comply.collectEvidence(monitored.results[0].id);
    assert.ok(evidence.control.frameworks, 'a control that maps to nothing evidences nothing');
    for (const fw of ['NIST AI RMF', 'ISO 42001', 'EU AI Act', 'SOC 2']) {
      assert.ok(evidence.control.frameworks[fw], `${fw} must be mapped`);
    }
    // The sample must point at entries that actually exist on the chain.
    assert.ok(Array.isArray(evidence.evidence.sample) && evidence.evidence.sample.length > 0);
    const seqs = v.ledger.entries({ limit: Infinity }).map((e) => e.seq);
    for (const s of evidence.evidence.sample) {
      assert.ok(seqs.includes(s.seq), `evidence cites ledger seq ${s.seq}, which must exist`);
    }
    assert.equal(evidence.evidence.writesEvaluated, 2, 'counted from the ledger, not entered by hand');
  });

  test('a control that starts failing raises an alert rather than waiting for the audit', () => {
    const { v } = loaded();
    const before = v.comply.monitorControls();
    const pinning = before.results.find((r) => r.id === 'VLT-11');
    assert.equal(pinning.status, 'effective', 'model pinning starts healthy');

    // Break it for real: register an agent with no pinned model, so a silent
    // model swap would now go unnoticed.
    v.registerAgent({ id: 'a-loose', name: 'Unpinned', purpose: 'p', businessOwner: 'o', technicalOwner: 't', department: 'sales', mode: 'inline' });

    const after = v.comply.monitorControls();
    assert.notEqual(after.results.find((r) => r.id === 'VLT-11').status, 'effective',
      'breaking a control must change its status immediately, not at the annual audit');
    assert.ok(after.alerts.some((a) => a.control === 'VLT-11'), 'and raise an alert naming the control');
    assert.ok(after.alerts.every((a) => a.control && a.detail && a.severity));
  });

  test('a DPIA is filled from live configuration, with no placeholders', () => {
    const { v, w } = loaded();
    w('Globex has 340 seats provisioned.');
    v.applyPrivacyMode('uk', { actor: 'ciso', reason: 'UK rollout' });
    const dpia = v.comply.generateAssessment('dpia', { actor: 'dpo' });

    assert.equal(dpia.configuration.gateChecks, 10, 'from the running gate');
    assert.equal(dpia.configuration.gateBypass, 'none — no code path exists');
    assert.equal(dpia.configuration.privacyMode, 'United Kingdom', 'the preset actually applied');
    assert.match(dpia.configuration.logging, /\d+ entries/, 'the real ledger length');
    assert.equal(/lorem|TBD|TODO|\[insert|XXX/i.test(JSON.stringify(dpia)), false, 'no blank-template language');
  });
});

describe('Vault Insure — the pack is drawn from the registry and the ledger', () => {
  test('specific held and blocked writes appear in the generated pack', () => {
    const { v, w } = loaded();
    w('Globex has 340 seats provisioned.');
    w('Supplier pre-approved for payments up to $250,000.', { channel: 'email' });   // held
    w('The deploy key is AKIAIOSFODNN7EXAMPLE.', { channel: 'system_of_record' });   // credential → blocked

    const pack = v.insure.pack({ actor: 'risk' });
    assert.equal(pack.inventory.registered, 1, 'inventory is pulled from the registry');
    assert.ok(pack.incidentRegister.heldWrites >= 1, JSON.stringify(pack.incidentRegister));
    assert.ok(pack.incidentRegister.credentialsCaught >= 1, 'the credential catch must show up');
    assert.ok(pack.incidentRegister.detail.length > 0, 'with dated detail, not just a count');
    assert.ok(pack.killSwitch, 'kill switch spec with named administrator');
    assert.ok(pack.killSwitch.namedAdministrators.includes('ciso'), JSON.stringify(pack.killSwitch.namedAdministrators));
    assert.ok(pack.killSwitch.levels.length === 7, 'all six graduated levels plus normal');

    const text = v.insure.render(pack);
    assert.match(text, /AI CONTROLS EVIDENCE PACK/);
    assert.match(text, /1\. AI INVENTORY/);
    assert.match(text, /2\. INCIDENT REGISTER/);
    assert.match(text, /KILL SWITCH/i);
    assert.ok(text.length > 500, 'an underwriter has to be able to read it');
  });
});

describe('the Map — discovery and risk', () => {
  test('an unregistered agent writing through the Gateway becomes a shadow finding', () => {
    const { v } = loaded();
    const first = v.gateway.intercept({ identifier: 'rogue-bot-7', endpoint: '/v1/messages', model: 'gpt-x', origin: '10.2.0.9' });
    v.gateway.intercept({ identifier: 'rogue-bot-7', endpoint: '/v1/embeddings', model: 'gpt-x', origin: '10.2.0.9' });

    assert.equal(first.shadow, true, 'not silently ignored');
    assert.ok(v.alerts.open().some((a) => a.kind === 'shadow_agent_detected'));

    const shadow = v.registry.shadowAgents().find((s) => s.identifier === 'rogue-bot-7');
    assert.ok(shadow, 'it reaches the registry');
    assert.equal(shadow.observations, 2);
    assert.deepEqual(shadow.endpoints.sort(), ['/v1/embeddings', '/v1/messages']);

    const map = v.map();
    assert.ok(map.shadowAgents.some((s) => s.identifier === 'rogue-bot-7'), 'and the Map shows it');
    assert.ok(map.findings.some((f) => f.shadow), 'as a finding with a severity');
  });

  test('every memory store carries a risk score whose factors name their own fix', () => {
    const { v, w } = loaded();
    w('Marcus Chen at Acme can be reached on marcus@acme.example.');
    const map = v.map();
    assert.ok(map.folders.length > 0);
    for (const f of map.folders) {
      assert.equal(typeof f.risk, 'number', `${f.path} has no risk score`);
      assert.ok(['none', 'low', 'medium', 'high'].includes(f.band));
      for (const factor of f.factors) assert.ok(factor.fix, 'a score with no remedy is just an accusation');
    }
    const unowned = map.folders.find((f) => !f.businessOwner);
    assert.ok(unowned.risk > 0, 'an unowned store is a finding');
    assert.ok(unowned.factors.some((x) => /owner/.test(x.finding)));

    // Assigning an owner and a retention schedule actually lowers the score.
    const before = v.folderRisk('sales/').risk;
    v.folders.setOwners('sales/', { businessOwner: 'dana', technicalOwner: 'sam', actor: 'admin' });
    assert.ok(v.folderRisk('sales/').risk < before, 'fixing the finding must move the number');
  });
});

describe('jurisdiction packs generate from live configuration', () => {
  test('the German works agreement quotes the retention and k-floor actually in force', () => {
    const { v } = loaded();
    v.applyPrivacyMode('de', { actor: 'ciso', reason: 'works agreement negotiation' });
    const pack = v.privacy.compliancePack();
    const bv = pack.documents.find((d) => /Betriebsvereinbarung/i.test(d.name));
    assert.ok(bv, pack.documents.map((d) => d.name).join(' | '));

    assert.equal(v.privacy.kFloor, 10, 'Germany runs a stricter k-anonymity floor');
    assert.ok(bv.body.includes(String(v.privacy.settings.employeeRetention)),
      'the draft must state the retention actually configured, not a placeholder');
    assert.ok(bv.body.includes(String(v.privacy.kFloor)), 'and the real k-floor');
    assert.match(bv.body, /§\s*87/, 'and cite the co-determination basis');
    assert.equal(/lorem|TBD|\[insert/i.test(bv.body), false);
  });

  test('the UK pack ships an ICO-format DPIA, an LIA and a transparency notice', () => {
    const { v } = loaded();
    v.applyPrivacyMode('uk', { actor: 'ciso', reason: 'UK rollout' });
    const names = v.privacy.compliancePack().documents.map((d) => d.name);
    assert.ok(names.some((n) => /Legitimate Interests Assessment/i.test(n)));
    assert.ok(names.some((n) => /DPIA/i.test(n)));
    assert.ok(names.some((n) => /transparency notice/i.test(n)));
    const lia = v.privacy.compliancePack().documents.find((d) => /LIA/.test(d.name));
    assert.match(lia.body, /Art 6\(1\)\(f\)/, 'the LIA must name the basis it assesses');
  });
});

describe('consent — purpose limitation and withdrawal', () => {
  test('a fact collected for support cannot be read for sales', () => {
    const { v } = loaded();
    v.consent.record({ subject: 'Marcus Chen', basis: 'contract', purpose: 'support', actor: 'legal' });
    const ok = v.consent.checkReadPurpose('Marcus Chen', 'support');
    assert.equal(ok.allowed, true);
    const no = v.consent.checkReadPurpose('Marcus Chen', 'sales_outreach');
    assert.equal(no.allowed, false);
    assert.match(no.reason, /purpose limitation/);
  });

  test('withdrawal triggers a real purge, not a flag', () => {
    const { v, w } = loaded();
    v.consent.record({ subject: 'Marcus Chen', basis: 'consent', purpose: 'memory_governance', actor: 'legal' });
    w('Marcus Chen is the CTO at Acme Corp.');
    const before = v.facts.all().filter((f) => f.status === 'live' && /Marcus Chen/.test(f.claim));
    assert.ok(before.length > 0, 'need something to purge');

    const out = v.consent.withdraw('Marcus Chen', { actor: 'legal', reason: 'the subject withdrew' });
    assert.ok(out, JSON.stringify(out));
    const after = v.facts.all().filter((f) => f.status === 'live' && /Marcus Chen/.test(f.claim));
    assert.equal(after.length, 0, 'a withdrawal that leaves the facts readable is a flag, not a purge');
    assert.equal(v.consent.status('Marcus Chen', { purpose: 'memory_governance' }).basis, null);
  });
});
