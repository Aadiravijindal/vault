/**
 * The continuous red team — the suite as a control that can fail, not a report.
 *
 * The real run takes seconds and is already covered by redteam.test.js, so
 * these inject reports instead. What is under test is the judgement: does a
 * breach alert, does a regression that is still inside threshold alert, does a
 * broken harness alert rather than passing silently, and can the thing answer
 * "when did this last pass" without relying on anyone's memory.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { RedTeamWatchdog, THRESHOLDS, runOnce } from '../src/security/watchdog.js';

const report = ({ catchRate = 1, fpRate = 0, contaminated = false, rateLimited = 0 } = {}) => ({
  runId: 'rt-test', ranAt: new Date().toISOString(), durationMs: 1,
  contaminated, rateLimitedWrites: rateLimited, channel: 'phone_call_authenticated',
  attacks: { total: 576, caught: Math.round(576 * catchRate), missed: 576 - Math.round(576 * catchRate), catchRate },
  benign: { total: 30, falsePositives: Math.round(30 * fpRate), falsePositiveRate: fpRate, heldByAccessControl: 0 },
  byFamily: {}, byEvasion: {}, byOwasp: {}, missed: [], falsePositives: [], accessControlHolds: [],
  statement: 'test report'
});

function watchdogOn(reports) {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false });
  const raised = [];
  const realRaise = v.alerts.raise.bind(v.alerts);
  v.alerts.raise = (a) => { raised.push(a); return realRaise(a); };
  let i = 0;
  const w = new RedTeamWatchdog({
    vault: v,
    run: () => {
      const r = reports[Math.min(i, reports.length - 1)];
      i++;
      if (r instanceof Error) throw r;
      return r;
    }
  });
  return { v, w, raised };
}

describe('a breach of a published threshold is a control failure', () => {
  test('a clean run passes and raises nothing', () => {
    const { w, raised } = watchdogOn([report()]);
    const r = w.check();
    assert.equal(r.ok, true);
    assert.equal(raised.filter((a) => a.kind.startsWith('redteam_')).length, 0);
  });

  test('a catch rate below the published number alerts HIGH', () => {
    const { w, raised } = watchdogOn([report({ catchRate: 0.90 })]);
    const r = w.check();
    assert.equal(r.ok, false);
    const alert = raised.find((a) => a.kind === 'redteam_threshold_breached');
    assert.ok(alert, 'a gate that stopped catching attacks must alert');
    assert.equal(alert.severity, 'high');
    assert.match(alert.detail, /below the published/);
  });

  test('a false-positive rate above the published number alerts too', () => {
    const { w, raised } = watchdogOn([report({ fpRate: 0.4 })]);
    const r = w.check();
    assert.equal(r.ok, false);
    assert.ok(raised.some((a) => /cries wolf/.test(a.detail)),
      'a noisy detector gets switched off, so noise is a failure not a nuisance');
  });

  test('a contaminated run fails rather than reporting a flattering number', () => {
    const { w } = watchdogOn([report({ catchRate: 1, contaminated: true, rateLimited: 12 })]);
    const r = w.check();
    assert.equal(r.ok, false, 'a 100% catch rate from a rate-limited run is junk, not a pass');
    assert.match(r.failures[0], /not measuring content/);
  });
});

describe('a regression still inside threshold is still a regression', () => {
  test('a drop from 100% to 98.2% passes and still alerts', () => {
    const { w, raised } = watchdogOn([report({ catchRate: 1.0 }), report({ catchRate: 0.982 })]);
    w.check();
    const second = w.check();
    assert.equal(second.ok, true, '98.2% is above the 98% threshold, so the run passes');
    assert.equal(second.drifts.length, 1, 'and the fall is still the most important thing that happened');
    const alert = raised.find((a) => a.kind === 'redteam_regression');
    assert.ok(alert);
    assert.equal(alert.severity, 'medium');
  });

  test('a jump in false positives alerts even while both numbers pass', () => {
    const { w, raised } = watchdogOn([report({ fpRate: 0.0 }), report({ fpRate: 0.06 })]);
    w.check();
    w.check();
    assert.ok(raised.some((a) => a.kind === 'redteam_regression' && /false positives rose/.test(a.detail)));
  });

  test('a stable run raises nothing the second time', () => {
    const { w, raised } = watchdogOn([report(), report()]);
    w.check();
    w.check();
    assert.equal(raised.filter((a) => a.kind.startsWith('redteam_')).length, 0);
  });

  test('drift is measured against the last run that produced numbers, not a crashed one', () => {
    const { w, raised } = watchdogOn([report({ catchRate: 1.0 }), new Error('harness broke'), report({ catchRate: 0.98 })]);
    w.check();
    w.check();
    const third = w.check();
    assert.equal(third.drifts.length, 1, 'a crashed run in between must not reset the baseline');
    assert.ok(raised.some((a) => a.kind === 'redteam_regression'));
  });
});

describe('a harness that cannot run is itself a finding', () => {
  test('a thrown error alerts instead of passing silently', () => {
    const { w, raised } = watchdogOn([new Error('corpus failed to build')]);
    const r = w.check();
    assert.equal(r.ok, false);
    const alert = raised.find((a) => a.kind === 'redteam_harness_failed');
    assert.ok(alert, 'silence must never be indistinguishable from a clean run');
    assert.equal(alert.severity, 'high');
  });
});

describe('"when did this last pass" has an answer', () => {
  test('before any run it says so rather than implying pass', () => {
    const { w } = watchdogOn([report()]);
    const s = w.status();
    assert.equal(s.lastResult, 'never run');
    assert.equal(s.lastPassAt, null);
    assert.match(s.statement, /not evidence of anything/);
  });

  test('after a pass and then a failure it still knows when it last passed', () => {
    const { w } = watchdogOn([report(), report({ catchRate: 0.5 })]);
    w.check();
    w.check();
    const s = w.status();
    assert.equal(s.lastResult, 'fail');
    assert.ok(s.lastPassAt, 'the date of the last passing run is exactly what an auditor asks for');
    assert.ok(s.openFailures.length);
  });

  test('the published thresholds are reported with the status, not buried in code', () => {
    const { w } = watchdogOn([report()]);
    assert.deepEqual(w.status().thresholds, THRESHOLDS);
  });

  test('start runs immediately rather than waiting a full interval, and stops cleanly', () => {
    const { w } = watchdogOn([report()]);
    w.start();
    assert.equal(w.history.length, 1, 'a watchdog that waits six hours to first run is not watching');
    assert.equal(w.status().running, true);
    w.stop();
    assert.equal(w.status().running, false);
  });
});

describe('the real suite runs against a throwaway, never the customer vault', () => {
  test('a live run passes its own published thresholds', () => {
    const r = runOnce();
    assert.ok(r.attacks.total > 100, 'the corpus must actually be built');
    assert.ok(r.attacks.catchRate >= THRESHOLDS.catchRate,
      `catch rate ${r.attacks.catchRate} fell below the published ${THRESHOLDS.catchRate}`);
    assert.ok(r.benign.falsePositiveRate <= THRESHOLDS.falsePositiveRate,
      `false-positive rate ${r.benign.falsePositiveRate} rose above the published ${THRESHOLDS.falsePositiveRate}`);
    assert.equal(r.contaminated, false);
  });

  test('the customer vault is left with no attack payloads in it', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), seedRules: false });
    const w = new RedTeamWatchdog({ vault: v });
    w.check();
    assert.equal(v.facts.all().length, 0,
      'firing 576 attacks at the real gate would fill the real archive with attack payloads');
    assert.equal(v.review.list({ status: 'open' }).length, 0,
      'and would fill the real review queue with fabricated poisoning attempts');
  });
});
