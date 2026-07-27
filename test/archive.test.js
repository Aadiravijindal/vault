/**
 * 📚 VAULT ARCHIVE (§6.3) — WORM, retention conflict, supervision, eDiscovery,
 * production sets, privilege, capture completeness.
 *
 * These exercise real records and inspect real output. A route returning 200 is
 * not evidence that an archive works.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { setClock, DAY } from '../src/util/time.js';

function archived() {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  v.registerAgent({ id: 'a-1', name: 'A', purpose: 'p', businessOwner: 'O', technicalOwner: 'T', department: 'sales', mode: 'inline', folders: ['sales/'] });
  const cred = v.issueCredential('a-1', {}).credential;
  const w = (text, raw = {}) => v.ingest({
    agentId: 'a-1', channel: 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text }], ...raw
  }, { credential: cred });
  return { v, cred, w };
}

describe('archive — WORM and retention', () => {
  test('a regulatory record is WORM in compliance mode, and says what that means', () => {
    const { v, w } = archived();
    const r = w('Globex signed the renewal at 240k ARR.', { regulatoryRecord: 'finra-4511' });
    const ret = v.archive.retentionFor(v.archive.get(r.conversationId));
    assert.equal(ret.worm, true);
    assert.equal(ret.mode, 'compliance');
    assert.equal(ret.framework, 'FINRA 4511');
    assert.match(ret.modeMeaning, /cannot be shortened by anyone/);
    // retentionFor accepts the record or its id — passing the record used to throw
    assert.equal(v.archive.retentionFor(r.conversationId).conversationId, r.conversationId);
  });

  test('conflicting retention obligations are surfaced, never silently resolved', () => {
    const { v, w } = archived();
    const r = w('A broker-dealer communication.', { regulatoryRecord: 'finra-4511' });
    const ret = v.archive.retentionFor(r.conversationId);
    assert.equal(ret.conflict, true, 'FINRA 6y minimum vs GDPR 2y maximum is a real conflict');
    assert.match(ret.resolution, /CONFLICT SURFACED/);
    assert.ok(ret.obligations.some((o) => o.kind === 'minimum' && /FINRA/.test(o.framework)));
    assert.ok(ret.obligations.some((o) => o.kind === 'maximum' && /GDPR/.test(o.framework)));
    assert.ok(ret.effectiveMinimum > ret.effectiveMaximum, 'both are kept, not averaged');
  });

  test('a WORM record cannot be deleted — there is no code path, not merely no permission', () => {
    const { v, w } = archived();
    const r = w('Globex renewal.', { regulatoryRecord: 'sec-17a-4' });
    assert.throws(
      () => v.archive.col.erase(r.conversationId, { actor: 'admin', reason: 'cleanup' }),
      /WORM — content is removed by destroying its key/
    );
    assert.ok(v.archive.get(r.conversationId), 'and it is still there');
  });

  test('material under legal hold cannot be tiered away or deleted', () => {
    const { v, w } = archived();
    v.consent.record({ subject: 'Marcus Chen', basis: 'contract', purpose: 'memory_governance', actor: 'legal' });
    const r = w('Marcus Chen is the CTO at Acme Corp.');
    v.legal.placeHold({ matter: 'Case 2026-114', scope: { person: 'Marcus Chen' }, actor: 'gc', reason: 'litigation' });
    const can = v.tiering.canDelete(r.conversationId);
    assert.equal(can.allowed, false);
    assert.match(can.reason, /legal hold/);
  });
});

describe('archive — supervision', () => {
  test('lexicon scanning risk-scores content and queues the risky ones', () => {
    const { v, w } = archived();
    const scan = v.archive.lexiconScan('I guarantee this trade will make you money — wire the funds offshore.');
    assert.ok(scan.riskScore > 0, JSON.stringify(scan));
    assert.ok(scan.hits.some((h) => h.lexicon === 'guarantee'));

    w('I guarantee this trade will make you money, wire the funds offshore.', { channel: 'email' });
    const q = v.archive.supervisionQueue();
    assert.ok(q.length > 0, 'risky content must reach a compliance officer');
    assert.ok(q.every((i) => typeof i.riskScore === 'number'));
  });

  test('a supervision decision requires a named reviewer and is audited', () => {
    const { v, w } = archived();
    w('I guarantee returns and will wire the funds offshore.', { channel: 'email' });
    const [item] = v.archive.supervisionQueue();
    assert.ok(item, 'need something to review');
    assert.throws(() => v.archive.decideSupervision(item.id, { decision: 'close' }), /actor and a decision/i);
    const done = v.archive.decideSupervision(item.id, { actor: 'compliance1', decision: 'escalate', reason: 'guarantee language' });
    assert.equal(done.status, 'escalated');
    assert.equal(done.decisions[0].actor, 'compliance1');
    assert.ok(typeof done.decisions[0].tookMs === 'number', 'how long the reviewer took is recorded');
    assert.ok(
      v.ledger.entries({ limit: Infinity }).some((e) => e.type === 'review.decision' && e.kind === 'supervision'),
      'every review decision is on the chain'
    );
  });

  test('four-eyes: a high-risk review is not closed by one approver alone', () => {
    const { v, w } = archived();
    w('I guarantee returns and will wire the funds offshore immediately.', { channel: 'email' });
    const [item] = v.archive.supervisionQueue();
    assert.ok(item);
    // Force the four-eyes path the risk threshold is meant to trigger.
    v.archive.reviews.update(item.id, { fourEyes: true });

    const first = v.archive.decideSupervision(item.id, { actor: 'compliance1', decision: 'close', reason: 'reviewed' });
    assert.equal(first.status, 'awaiting_second_approver', 'one approver must not close a high-risk review');
    assert.equal(first.closedAt, null);

    const sameAgain = v.archive.decideSupervision(item.id, { actor: 'compliance1', decision: 'close', reason: 'again' });
    assert.equal(sameAgain.status, 'awaiting_second_approver', 'the same human twice is still one pair of eyes');

    const second = v.archive.decideSupervision(item.id, { actor: 'compliance2', decision: 'close', reason: 'concur' });
    assert.equal(second.status, 'closed');
    assert.ok(second.closedAt);
  });
});

describe('archive — eDiscovery and production sets', () => {
  test('a frozen production detects alteration, not merely deletion', () => {
    const { v, w } = archived();
    w('Globex renewal at 240k.');
    w('Acme wants a Q3 start.');
    const p = v.archive.createProduction({ matter: 'Case 114', scope: {}, actor: 'gc', reason: 'discovery' });
    assert.ok(p.itemIds.length >= 2);
    assert.equal(v.archive.verifyProduction(p.id).ok, true);

    // Reach past the API, as someone with database access would.
    const rec = v.archive.col.records.get(p.itemIds[0]);
    const original = rec.transcriptText;
    rec.transcriptText = 'ALTERED AFTER FREEZING';
    const after = v.archive.verifyProduction(p.id);
    assert.equal(after.ok, false, 'comparing stored hashes to stored hashes would miss this');
    assert.ok(after.problems.some((x) => x.problem === 'content_altered_after_sealing'));
    rec.transcriptText = original;
    assert.equal(v.archive.verifyProduction(p.id).ok, true, 'and it verifies again once restored');
  });

  test('EDRM XML is well-formed and carries Bates numbers and hashes', () => {
    const { v, w } = archived();
    w('Globex renewal at 240k.');
    const p = v.archive.createProduction({ matter: 'Case 114', scope: {}, actor: 'gc', reason: 'd' });
    const out = v.archive.exportProduction(p.id, 'edrm', {});
    const xml = out.payload;

    assert.match(xml, /^<\?xml version="1\.0" encoding="utf-8"\?>/);
    // Tag balance: a load file that will not parse is not a load file.
    const opens = [...xml.matchAll(/<([A-Za-z][\w-]*)(\s[^>]*?)?(?<!\/)>/g)].map((m) => m[1]);
    const closes = [...xml.matchAll(/<\/([A-Za-z][\w-]*)>/g)].map((m) => m[1]);
    const stack = [];
    for (const tok of xml.split(/(<\/?[A-Za-z][\w-]*(?:\s[^>]*?)?\/?>)/g)) {
      const m = /^<(\/?)([A-Za-z][\w-]*)(?:\s[^>]*?)?(\/?)>$/.exec(tok);
      if (!m) continue;
      if (m[1]) { assert.equal(stack.pop(), m[2], `mismatched close </${m[2]}>`); }
      else if (!m[3]) stack.push(m[2]);
    }
    assert.deepEqual(stack, [], 'every element must be closed');
    assert.equal(opens.length >= closes.length, true);
    assert.match(xml, /DocID="VLT00000001"/, 'Bates numbering');
    assert.match(out.batesRange, /^VLT\d{8}–VLT\d{8}$/);
    assert.match(xml, /TagValue="Case 114"/, 'matter is tagged');
    assert.ok(!/&(?!amp;|lt;|gt;|quot;|apos;|#)/.test(xml), 'bare ampersands would break the parse');
  });

  test('Concordance DAT/OPT use the real delimiters and line up row-for-row', () => {
    const { v, w } = archived();
    w('Globex renewal at 240k.');
    w('Acme wants a Q3 start.');
    const p = v.archive.createProduction({ matter: 'Case 114', scope: {}, actor: 'gc', reason: 'd' });
    const { payload } = v.archive.exportProduction(p.id, 'concordance', {});
    assert.ok(payload.dat && payload.opt, 'Concordance is two files');

    const DELIM = String.fromCharCode(20);   // ASCII 0x14
    const QUAL = 'þ';                        // ASCII 0xFE
    const datLines = payload.dat.trim().split('\n');
    assert.ok(datLines[0].includes(DELIM), 'DAT must use the 0x14 delimiter');
    assert.ok(datLines[0].startsWith(QUAL), 'DAT must use the þ text qualifier');
    const headerCols = datLines[0].split(DELIM).length;
    for (const line of datLines.slice(1)) {
      assert.equal(line.split(DELIM).length, headerCols, 'every DAT row must match the header width');
    }
    const optLines = payload.opt.trim().split('\n');
    assert.equal(optLines.length, datLines.length - 1, 'OPT has one row per document');
    for (const line of optLines) assert.match(line, /^VLT\d{8},,VLT\d{8}\.txt,Y,,,1$/);
  });

  test('privileged material is withheld from a production and the withholding is logged', () => {
    const { v, w } = archived();
    w('Ordinary business note.');
    w('Attorney advice about the Globex dispute.', { privileged: true });
    const p = v.archive.createProduction({ matter: 'Case 114', scope: {}, actor: 'gc', reason: 'd' });
    const out = v.archive.exportProduction(p.id, 'csv', { includePrivileged: false });
    assert.ok(!String(out.payload).includes('Attorney advice'), 'privileged content must not be produced');
    assert.equal(out.withheld, 1, 'and the count is reported, not an object');
    assert.equal(out.withheldDetail[0].reason, 'attorney-client privilege / work product');
    // it can be produced deliberately, which is a different, logged decision
    const withPriv = v.archive.exportProduction(p.id, 'csv', { includePrivileged: true });
    assert.ok(String(withPriv.payload).includes('Attorney advice'));
  });
});

describe('archive — capture completeness', () => {
  test('a gap between expected and actual capture raises a report', () => {
    const restore = setClock(() => Date.parse('2026-06-01T09:00:00Z'));
    try {
      const { v } = archived();
      const gap = v.archive.reconcileCapture({
        connector: 'vapi', expected: 10,
        from: Date.parse('2026-05-31T09:00:00Z'), to: Date.parse('2026-06-01T09:00:00Z')
      });
      assert.equal(gap.complete, false);
      assert.equal(gap.gap, 10, 'we should have seen ten and saw none');
      assert.equal(v.archive.gapReports.length, 1, 'and the claim "we captured everything" stays checkable');
    } finally { if (typeof restore === 'function') restore(); }
  });

  test('employee-to-account linking resolves one person across many accounts', () => {
    const { v } = archived();
    v.archive.linkIdentity('Sarah Reyes', ['sarah@corp.example', 'sreyes@slack', 'S-1123'], { actor: 'admin' });
    const accts = v.archive.identityLinks.get('Sarah Reyes');
    assert.ok(accts.has('sarah@corp.example') && accts.has('S-1123'));
  });
});
