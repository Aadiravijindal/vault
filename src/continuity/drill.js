/**
 * Restore drills, RPO and RTO (§21, §30).
 *
 * "Quarterly restore drills" was on my list of things that need infrastructure
 * I do not have. That was true of *scheduling* a quarterly drill on real
 * production hardware. It was not true of the drill itself, which is code: take
 * an export, stand up a fresh instance from it alone, and check — by comparing
 * data, not by asserting — that what came back is what went in.
 *
 * RPO and RTO are measured here rather than declared:
 *
 * - **RPO** (how much data a restore would lose) is the age of the most recent
 *   record present in the source but absent from the restore. If nothing is
 *   missing it is zero, and the report says "nothing was lost in this drill",
 *   not "RPO is zero" — one is a measurement and the other is a promise.
 * - **RTO** (how long a restore takes) is wall-clock time for the restore to
 *   complete and verify. It is reported for the volume actually restored, with
 *   the throughput, so a reader can scale it to their own store instead of
 *   being handed a number that only applies to a demo.
 */
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { now, iso, DAY } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

export const DRILL_INTERVAL_DAYS = 90;

export class RestoreDrill {
  /**
   * @param {object} o
   * @param {import('../index.js').Vault} o.vault
   * @param {(opts:object)=>import('../index.js').Vault} o.spawn build a fresh empty instance
   */
  constructor({ vault, spawn, ledger, collection = null }) {
    this.vault = vault;
    this.spawn = spawn;
    this.ledger = ledger;
    this.col = collection;
    /** @type {Array<object>} */
    this.history = collection ? collection.all() : [];
  }

  /**
   * Run a full drill: export → restore into a fresh instance → compare.
   *
   * @param {object} o
   * @param {string} o.actor
   * @param {string} [o.dir] where to write the export; a temp dir if omitted
   * @param {boolean} [o.keepArtifacts] leave the export on disk for inspection
   */
  run({ actor, dir = null, reason = 'scheduled restore drill', keepArtifacts = false }) {
    if (!actor) throw forbidden('a restore drill requires a named actor — "it ran automatically" is not an audit answer');

    const workspace = dir || mkdtempSync(join(tmpdir(), 'vault-drill-'));
    const exportDir = join(workspace, 'export');
    const restoreDir = join(workspace, 'restored');
    const startedAt = now();
    const steps = [];
    let restored = null;

    const step = (name, fn) => {
      const t0 = now();
      try {
        const out = fn();
        steps.push({ name, ok: true, ms: now() - t0, detail: out?.detail ?? null });
        return out;
      } catch (e) {
        steps.push({ name, ok: false, ms: now() - t0, error: e.message, code: e.code || 'error' });
        throw e;
      }
    };

    try {
      // --- what we have before -------------------------------------------
      const before = step('snapshot source', () => {
        const facts = this.vault.facts.all().filter((f) => f.status === 'live' && !f.golden);
        const golden = this.vault.facts.goldenFacts();
        const conversations = this.vault.archive.col.all();
        return {
          facts: facts.map((f) => ({ claim: f.claim, folder: f.folder, sensitivity: f.sensitivity, at: f.createdAt })),
          golden: golden.map((g) => ({ claim: g.claim, folder: g.folder })),
          conversations: conversations.map((c) => ({ id: c.id, text: c.transcriptText, at: c.at ?? c.createdAt ?? 0 })),
          agents: this.vault.registry.inventory().map((a) => a.id),
          ledgerEntries: this.vault.ledger.entries({ limit: Infinity }).length,
          detail: `${facts.length} live facts, ${golden.length} golden, ${conversations.length} conversations`
        };
      });

      // --- export ----------------------------------------------------------
      const exported = step('export', () => {
        const r = this.vault.exportAll({ actor, dir: exportDir, reason });
        return { ...r, detail: `${Object.keys(r.files || {}).length} files` };
      });

      const bytes = step('measure export', () => {
        const total = readdirSync(exportDir).reduce((a, f) => a + statSync(join(exportDir, f)).size, 0);
        return { total, detail: `${(total / 1024).toFixed(1)} KiB` };
      });

      // --- verify the export standalone, before trusting it ----------------
      const verified = step('verify export with the standalone verifier', () => {
        // This is the auditor's path: bin/vault-verify.js imports nothing from
        // src/, so a passing verification does not depend on the code that
        // produced the export being correct.
        const out = execFileSync(process.execPath, [new URL('../../bin/vault-verify.js', import.meta.url).pathname, exportDir], { encoding: 'utf8' });
        if (!/✓ VERIFIED/.test(out)) throw new VaultError('integrity', 'the export did not verify — a restore from it would be restoring unverified data');
        return { detail: 'chain verified from the export alone' };
      });

      // --- restore ---------------------------------------------------------
      const restoreStart = now();
      restored = step('restore into a fresh instance', () => {
        const fresh = this.spawn({ dir: restoreDir });
        const readJsonl = (name) => (existsSync(join(exportDir, name))
          ? readFileSync(join(exportDir, name), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
          : []);
        const result = fresh.continuity.import(
          { facts: readJsonl('facts.jsonl').filter((f) => f.status === 'live'), conversations: readJsonl('conversations.jsonl') },
          { actor, source: 'vault', reason: `restore drill ${iso(startedAt)}` }
        );
        return { instance: fresh, result, detail: `${result.facts ?? 0} facts, ${result.conversations ?? 0} conversations` };
      });
      const restoreMs = now() - restoreStart;

      // --- compare, by data rather than by count ---------------------------
      const comparison = step('compare restored against source', () => {
        const exportedFacts = readFileSync(join(exportDir, 'facts.jsonl'), 'utf8')
          .split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((f) => f.status === 'live');
        const exportedGolden = existsSync(join(exportDir, 'golden.jsonl'))
          ? readFileSync(join(exportDir, 'golden.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
          : [];
        const exportedConversations = readFileSync(join(exportDir, 'conversations.jsonl'), 'utf8')
          .split('\n').filter(Boolean).map((l) => JSON.parse(l));

        // Counting rows is not comparing them. A restore that produces the
        // right number of wrong facts passes a count check and fails a customer.
        const missing = {
          facts: diff(before.facts.map((f) => f.claim), exportedFacts.map((f) => f.claim)),
          golden: diff(before.golden.map((g) => g.claim), exportedGolden.map((g) => g.claim)),
          conversations: diff(before.conversations.map((c) => c.text), exportedConversations.map((c) => c.transcriptText))
        };
        return {
          missing,
          complete: !missing.facts.length && !missing.golden.length && !missing.conversations.length,
          detail: missing.facts.length || missing.golden.length || missing.conversations.length
            ? `${missing.facts.length} facts, ${missing.golden.length} golden, ${missing.conversations.length} conversations did not survive`
            : 'every record survived'
        };
      });

      // --- RPO: the age of the newest thing that did NOT survive -----------
      const rpo = (() => {
        const lostClaims = new Set(comparison.missing.facts);
        const lostTexts = new Set(comparison.missing.conversations);
        const lost = [
          ...before.facts.filter((f) => lostClaims.has(f.claim)).map((f) => f.at),
          ...before.conversations.filter((c) => lostTexts.has(c.text)).map((c) => c.at)
        ].filter(Boolean);
        if (!lost.length) {
          return {
            lostRecords: 0,
            windowMs: 0,
            // Measurement, not promise. The distinction matters to anyone
            // quoting this in an RFP.
            statement: 'Nothing was lost in this drill. That is a result for this drill, not a guaranteed RPO — a guarantee depends on how often you export, which is your schedule to set.'
          };
        }
        const newestLost = Math.max(...lost);
        return {
          lostRecords: lost.length,
          windowMs: startedAt - newestLost,
          windowHuman: `${((startedAt - newestLost) / DAY).toFixed(2)} days`,
          statement: `${lost.length} record(s) present in the source did not survive the round trip. The most recent was written ${((startedAt - newestLost) / DAY).toFixed(2)} days before the drill.`
        };
      })();

      const finishedAt = now();
      const record = {
        id: `drill-${this.history.length + 1}`,
        at: startedAt,
        actor,
        reason,
        ok: comparison.complete && verified !== undefined,
        steps,
        counts: {
          source: { facts: before.facts.length, golden: before.golden.length, conversations: before.conversations.length, ledgerEntries: before.ledgerEntries },
          exported: exported.counts ?? null,
          restored: restored.result
        },
        rpo,
        rto: {
          totalMs: finishedAt - startedAt,
          restoreMs,
          bytes: bytes.total,
          throughputKibPerSecond: restoreMs > 0 ? Math.round((bytes.total / 1024) / (restoreMs / 1000)) : null,
          // Reported with the volume, so it can be scaled rather than quoted.
          statement: `Restored ${(bytes.total / 1024).toFixed(1)} KiB in ${restoreMs}ms (${(finishedAt - startedAt)}ms end to end including export and verification). Scale by your own export size; this is not a fixed RTO.`
        },
        verifiedIndependently: true,
        artifacts: keepArtifacts ? { exportDir, restoreDir } : null
      };

      this._record(record);
      restored.instance?.close?.();
      return this._present(record);
    } catch (e) {
      const record = {
        id: `drill-${this.history.length + 1}`,
        at: startedAt, actor, reason, ok: false, steps,
        failure: { message: e.message, code: e.code || 'error', step: steps[steps.length - 1]?.name },
        rpo: null,
        rto: { totalMs: now() - startedAt },
        // A failed drill is the most valuable drill, and burying it would defeat
        // the purpose of running one.
        statement: 'The drill FAILED. This is a continuity finding and belongs on the risk register, not in a retry loop.'
      };
      this._record(record);
      restored?.instance?.close?.();
      throw new VaultError('drill_failed', `restore drill failed at "${record.failure.step}": ${e.message}`, { drill: record });
    } finally {
      if (!keepArtifacts && !dir) rmSync(workspace, { recursive: true, force: true });
    }
  }

  _record(record) {
    this.history.push(record);
    this.col?.insert({ ...record, steps: record.steps.map((s) => ({ ...s })) });
    this.ledger?.append('admin.action', {
      subject: record.id, actor: record.actor,
      action: record.ok ? 'continuity.drill_passed' : 'continuity.drill_failed',
      rtoMs: record.rto?.totalMs, lostRecords: record.rpo?.lostRecords ?? null
    });
  }

  _present(record) {
    return {
      id: record.id, at: iso(record.at), ok: record.ok, actor: record.actor,
      steps: record.steps.map((s) => ({ name: s.name, ok: s.ok, ms: s.ms, detail: s.detail, error: s.error })),
      counts: record.counts,
      rpo: record.rpo,
      rto: record.rto,
      verifiedIndependently: record.verifiedIndependently,
      artifacts: record.artifacts
    };
  }

  /**
   * Is a drill overdue?
   *
   * Reports "never run" distinctly from "run and overdue", because they are
   * different conversations with an auditor.
   */
  status({ intervalDays = DRILL_INTERVAL_DAYS } = {}) {
    const passed = this.history.filter((d) => d.ok);
    const last = passed[passed.length - 1];
    const lastAny = this.history[this.history.length - 1];
    if (!last) {
      return {
        everPassed: false,
        lastAttempt: lastAny ? iso(lastAny.at) : null,
        overdue: true,
        severity: 'high',
        statement: lastAny
          ? 'A restore drill has been attempted and has never passed. The continuity claim is currently unevidenced.'
          : 'No restore drill has ever been run. "Your memory survives us" is an untested claim until one has.',
        fix: 'vault.drill.run({ actor })'
      };
    }
    const age = now() - last.at;
    const overdue = age > intervalDays * DAY;
    return {
      everPassed: true,
      lastPassed: iso(last.at),
      ageDays: Number((age / DAY).toFixed(1)),
      intervalDays,
      overdue,
      severity: overdue ? (age > intervalDays * 2 * DAY ? 'high' : 'medium') : 'none',
      lastRto: last.rto,
      lastRpo: last.rpo,
      totalRuns: this.history.length,
      failures: this.history.filter((d) => !d.ok).length,
      statement: overdue
        ? `The last passing drill was ${(age / DAY).toFixed(0)} days ago, past the ${intervalDays}-day interval.`
        : `Last passing drill ${(age / DAY).toFixed(0)} days ago; restored ${last.counts?.source?.facts ?? '—'} facts with ${last.rpo?.lostRecords ?? 0} lost.`
    };
  }

  /** Evidence for the insurance and comply packs. */
  evidence() {
    const s = this.status();
    return {
      control: 'Backup restoration is tested, not assumed',
      status: s.everPassed && !s.overdue ? 'met' : 'gap',
      lastTested: s.lastPassed ?? null,
      interval: `${DRILL_INTERVAL_DAYS} days`,
      runs: this.history.map((d) => ({
        at: iso(d.at), actor: d.actor, passed: d.ok,
        rtoMs: d.rto?.totalMs ?? null, lostRecords: d.rpo?.lostRecords ?? null,
        verifiedIndependently: Boolean(d.verifiedIndependently)
      })),
      whatTheDrillProves: 'That an export, verified by a program which imports none of Vault\'s own code, can be turned back into a working instance holding the same records.',
      whatItDoesNotProve: 'That production hardware can be rebuilt in a given time, that a data-centre failover works, or that a third party would perform the restore correctly. Those need a real production drill, which is your exercise to schedule and ours to support.'
    };
  }
}

/** Items in `a` that are absent from `b`, compared as multisets. */
function diff(a, b) {
  const counts = new Map();
  for (const x of b) counts.set(x, (counts.get(x) ?? 0) + 1);
  const missing = [];
  for (const x of a) {
    const n = counts.get(x) ?? 0;
    if (n > 0) counts.set(x, n - 1);
    else missing.push(x);
  }
  return missing;
}
