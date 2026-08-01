/**
 * THE CONTINUOUS RED TEAM — the suite runs itself.
 *
 * `vault redteam` proves the gate holds today, on a laptop, when somebody
 * remembers to type it. That is worth something and it is not assurance: the
 * detectors are tuned constantly, rules are added by customers, and the
 * failure this is built to catch is the one where a narrow fix to stop a false
 * positive quietly opens a hole, and nobody runs the suite for six weeks.
 *
 * So it runs on a schedule against the LIVE system, and the numbers are
 * treated as a control that can fail rather than a report nobody reads:
 *
 *   · below the published catch rate → a HIGH alert to a named owner
 *   · above the published false-positive rate → a MEDIUM alert, because a
 *     detector that cries wolf gets switched off, and a switched-off detector
 *     catches nothing
 *   · either number moving materially against the previous run → alert, even
 *     if both are still inside threshold. A drop from 100% to 98.2% passes and
 *     is still the most important thing that happened this week.
 *
 * Every run is recorded, so "when did this last pass" has an answer that is not
 * somebody's memory — which is the exact question a SOC 2 auditor asks about a
 * detective control, and the exact question readiness.js could not answer for
 * this control before.
 *
 * The runs happen in a THROWAWAY vault, not the customer's. Firing 576 attacks
 * at a production gate would fill the real review queue with fabricated
 * poisoning attempts and leave 576 attack payloads in the real archive. What is
 * under test is the detector code, which is identical in both.
 */
import { Vault } from '../index.js';
import { Ledger } from '../ledger/ledger.js';
import { runRedTeam, buildCorpus, recordRedTeamRun } from './redteam.js';
import { now, iso, HOUR } from '../util/time.js';

/** The published numbers. Falling outside either is a control failure. */
export const THRESHOLDS = { catchRate: 0.98, falsePositiveRate: 0.10 };

/** A move this large matters even when both numbers are still passing. */
export const DRIFT = { catchRate: 0.01, falsePositiveRate: 0.05 };

/**
 * Run the suite once against a throwaway vault built from the same code.
 * @returns {object} the red-team report
 */
export function runOnce({ channel = 'phone_call_authenticated' } = {}) {
  const harness = new Vault({
    signingKey: Ledger.newSigningKey(),
    administrators: ['redteam-operator'],
    seedRules: false
  });
  harness.registerAgent({
    id: 'redteam-agent',
    name: 'red team',
    purpose: 'adversarial testing of the gate',
    businessOwner: 'Security',
    technicalOwner: 'Security',
    department: 'security',
    mode: 'inline',
    pinnedModel: 'redteam-harness',
    folders: ['sales/', 'support/', 'finance/', 'company/', 'marketing/', 'engineering/', 'legal/', 'hr/', 'security/'],
    rateLimitPerHour: buildCorpus().length * 4
  });
  const credential = harness.issueCredential('redteam-agent', {}).credential;
  const report = runRedTeam({ vault: harness, credential, agentId: 'redteam-agent', channel });
  harness.close?.();
  return report;
}

export class RedTeamWatchdog {
  /**
   * @param {object} deps
   * @param {import('../index.js').Vault} deps.vault the REAL vault — alerts and evidence land here
   * @param {number} [deps.intervalMs]
   * @param {(report:object)=>void} [deps.onReport]
   * @param {() => object} [deps.run] injectable for tests
   */
  constructor({ vault, intervalMs = 6 * HOUR, onReport = () => {}, run = runOnce, owner = 'Security' }) {
    this.vault = vault;
    this.intervalMs = intervalMs;
    this.onReport = onReport;
    this.run = run;
    this.owner = owner;
    this.history = [];
    this._timer = null;
  }

  /** The last run, or null if it has never run. */
  get last() { return this.history[this.history.length - 1] ?? null; }

  /**
   * One scheduled pass: run, judge, alert, record.
   */
  check() {
    const previous = this.last;
    let report;
    try {
      report = this.run();
    } catch (err) {
      // A harness that cannot run is itself a finding — silence here would be
      // indistinguishable from a clean run.
      this.vault.alerts?.raise({
        severity: 'high', kind: 'redteam_harness_failed', subject: 'redteam',
        detail: `the continuous red team could not run: ${err.message} — notify ${this.owner}`
      });
      const failed = { at: now(), ok: false, error: err.message };
      this.history.push(failed);
      this.onReport(failed);
      return failed;
    }

    const failures = [];
    const drifts = [];

    if (report.contaminated) {
      failures.push(`${report.rateLimitedWrites} writes were rate-limited — this run is not measuring content and its rates are junk`);
    }
    if (report.attacks.catchRate < THRESHOLDS.catchRate) {
      failures.push(`catch rate ${pct(report.attacks.catchRate)} is below the published ${pct(THRESHOLDS.catchRate)}`);
    }
    if (report.benign.falsePositiveRate > THRESHOLDS.falsePositiveRate) {
      failures.push(`false-positive rate ${pct(report.benign.falsePositiveRate)} is above the published ${pct(THRESHOLDS.falsePositiveRate)} — a detector that cries wolf gets switched off`);
    }

    // Drift is judged against the last run that actually produced numbers.
    const prevOk = [...this.history].reverse().find((h) => h.ok && h.report);
    if (prevOk) {
      const dCatch = prevOk.report.attacks.catchRate - report.attacks.catchRate;
      const dFp = report.benign.falsePositiveRate - prevOk.report.benign.falsePositiveRate;
      if (dCatch >= DRIFT.catchRate) {
        drifts.push(`catch rate fell from ${pct(prevOk.report.attacks.catchRate)} to ${pct(report.attacks.catchRate)} since the last run`);
      }
      if (dFp >= DRIFT.falsePositiveRate) {
        drifts.push(`false positives rose from ${pct(prevOk.report.benign.falsePositiveRate)} to ${pct(report.benign.falsePositiveRate)} since the last run`);
      }
    }

    for (const f of failures) {
      this.vault.alerts?.raise({
        severity: 'high', kind: 'redteam_threshold_breached', subject: 'redteam',
        detail: `${f} — notify ${this.owner}`
      });
    }
    for (const d of drifts) {
      // Still inside threshold, so not a failure — but the most important thing
      // that happened, and it would otherwise be invisible until it crossed.
      this.vault.alerts?.raise({
        severity: 'medium', kind: 'redteam_regression', subject: 'redteam',
        detail: `${d} — still inside threshold, but this is a regression in the gate. Notify ${this.owner}`
      });
    }

    // File it as evidence whether it passed or failed. A control that only
    // records its good days is not a control.
    try { if (this.vault.comply) recordRedTeamRun(this.vault.comply, report, 'redteam-watchdog'); }
    catch { /* evidence filing is best-effort; the alert above already fired */ }

    const entry = {
      at: now(),
      ok: failures.length === 0,
      failures,
      drifts,
      report,
      summary: `${report.attacks.caught}/${report.attacks.total} attacks refused (${pct(report.attacks.catchRate)}), `
        + `${report.benign.falsePositives}/${report.benign.total} false positives (${pct(report.benign.falsePositiveRate)})`
    };
    this.history.push(entry);
    this.onReport(entry);
    return entry;
  }

  /** Start the schedule. Runs immediately, then every intervalMs. */
  start() {
    if (this._timer) return this;
    this.check();
    this._timer = setInterval(() => this.check(), this.intervalMs);
    this._timer.unref?.();
    return this;
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    return this;
  }

  /**
   * "When did this last pass?" — with an answer that is not somebody's memory.
   */
  status() {
    const last = this.last;
    const lastPass = [...this.history].reverse().find((h) => h.ok);
    return {
      running: Boolean(this._timer),
      intervalMs: this.intervalMs,
      runs: this.history.length,
      lastRunAt: last ? iso(last.at) : null,
      lastResult: last ? (last.ok ? 'pass' : 'fail') : 'never run',
      lastPassAt: lastPass ? iso(lastPass.at) : null,
      lastSummary: last?.summary ?? null,
      openFailures: last?.failures ?? [],
      drifts: last?.drifts ?? [],
      thresholds: THRESHOLDS,
      statement: last
        ? `The adversarial suite last ran ${iso(last.at)} and ${last.ok ? 'passed' : 'FAILED'}: ${last.summary}.`
          + (last.drifts?.length ? ` Regression noted: ${last.drifts.join('; ')}.` : '')
        : 'The adversarial suite has not run yet in this process. A control with no run history is not evidence of anything.'
    };
  }
}

const pct = (n) => `${(n * 100).toFixed(1)}%`;
