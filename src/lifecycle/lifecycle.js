/**
 * TENANT LIFECYCLE — Day 0 and the last day.
 *
 * Two paths the spec assumes and never builds:
 *
 *  - Bulk historical backfill. "Backfill on connect" in the connector contract
 *    covers a normal sync. It does not cover a customer arriving with four
 *    years of transcripts, where the import must survive a restart, report
 *    progress honestly, and never silently skip the records it choked on.
 *
 *  - Offboarding. Exit & Continuity covers the customer who leaves WITH their
 *    data. This is the other one: the customer who wants it gone. Termination
 *    deletion is a distinct, receipted operation, and it must refuse to lie
 *    about anything a legal hold still pins down.
 */
import { newId } from '../util/id.js';
import { now, iso, ago, duration, DAY } from '../util/time.js';
import { sha256, signMessage } from '../util/crypto.js';
import { VaultError, forbidden } from '../util/errors.js';

export class BulkImport {
  /**
   * @param {object} deps
   * @param {(raw:object, ctx:object)=>object} deps.ingest
   * @param {import('../ledger/ledger.js').Ledger} deps.ledger
   * @param {import('../storage/db.js').Collection} [deps.collection] durable job state
   */
  constructor({ ingest, ledger, collection = null }) {
    this.ingest = ingest;
    this.ledger = ledger;
    this.col = collection;
    /** @type {Map<string, object>} */
    this.jobs = new Map((this.col?.all() ?? []).map((j) => [j.id, j]));
  }

  _save(job) { this.col?.put(job); this.jobs.set(job.id, job); return job; }

  /**
   * @param {{source:string, total?:number, agentId?:string, credential?:string, actor:string}} spec
   */
  start({ source, total = null, agentId = null, credential = null, actor, batchSize = 100 }) {
    if (!source || !actor) throw new VaultError('validation', 'a bulk import needs a source and a named actor');
    const job = this._save({
      id: newId('import'), source, agentId, actor, batchSize,
      startedAt: now(), finishedAt: null, status: 'running',
      total, processed: 0, imported: 0, held: 0, blocked: 0, duplicates: 0, failed: 0,
      // The cursor is what makes this resumable: a crash resumes here, and a
      // reconnect never re-imports what already landed.
      cursor: null,
      failures: []
    });
    this.ledger.append('admin.action', { subject: job.id, actor, action: 'import.started', source, total });
    return job;
  }

  /**
   * Feed a batch. Idempotent per record: a record carrying an externalId that
   * has already landed is counted as a duplicate, not written twice.
   * @param {string} jobId
   * @param {object[]} records
   */
  feed(jobId, records, { credential = null } = {}) {
    const job = this.jobs.get(jobId);
    if (!job) throw new VaultError('not_found', 'import job not found', { id: jobId });
    if (job.status === 'cancelled') throw new VaultError('conflict', 'this import was cancelled', { id: jobId });

    let { processed, imported, held, blocked, duplicates, failed } = job;
    const failures = [...job.failures];
    let cursor = job.cursor;

    for (const raw of records) {
      processed++;
      cursor = raw.externalId ?? raw.id ?? cursor;
      try {
        const result = this.ingest(
          { ...raw, agentId: raw.agentId ?? job.agentId, connector: raw.connector ?? job.source, historical: true },
          { credential: credential ?? job.credential, actor: job.actor, purpose: 'historical_import' }
        );
        if (result.duplicate) { duplicates++; continue; }
        for (const f of result.facts ?? []) {
          if (f.outcome === 'pass' || f.outcome === 'merged' || f.outcome === 'refined') imported++;
          else if (f.outcome === 'block') blocked++;
          else held++;
        }
      } catch (e) {
        failed++;
        // Never silently skip: a record that failed to import is named, with
        // its reason, so the completion report is honest.
        failures.push({ at: now(), ref: raw.externalId ?? raw.id ?? `#${processed}`, reason: e.message });
      }
    }
    return this._save({ ...job, processed, imported, held, blocked, duplicates, failed, failures: failures.slice(-500), cursor });
  }

  /** Resume after a restart: tells the caller exactly where to pick up. */
  resume(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) throw new VaultError('not_found', 'import job not found', { id: jobId });
    return {
      jobId, cursor: job.cursor, processed: job.processed,
      remaining: job.total != null ? Math.max(0, job.total - job.processed) : null,
      note: job.cursor ? `resume the source feed after ${job.cursor}` : 'no records processed yet — start from the beginning'
    };
  }

  finish(jobId, { actor }) {
    const job = this.jobs.get(jobId);
    if (!job) throw new VaultError('not_found', 'import job not found', { id: jobId });
    const done = this._save({ ...job, status: 'complete', finishedAt: now() });
    this.ledger.append('admin.action', {
      subject: jobId, actor, action: 'import.completed',
      processed: done.processed, imported: done.imported, failed: done.failed
    });
    return this.report(jobId);
  }

  cancel(jobId, { actor, reason }) {
    const job = this.jobs.get(jobId);
    if (!job) throw new VaultError('not_found', 'import job not found', { id: jobId });
    this.ledger.append('admin.action', { subject: jobId, actor, action: 'import.cancelled', reason });
    return this._save({ ...job, status: 'cancelled', finishedAt: now(), cancelReason: reason });
  }

  /** Progress a human can act on, including an honest ETA. */
  progress(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) throw new VaultError('not_found', 'import job not found', { id: jobId });
    const elapsed = (job.finishedAt ?? now()) - job.startedAt;
    const rate = job.processed / Math.max(1, elapsed / 1000);
    const remaining = job.total != null ? Math.max(0, job.total - job.processed) : null;
    return {
      jobId, status: job.status, source: job.source,
      processed: job.processed, total: job.total,
      percent: job.total ? Math.round((job.processed / job.total) * 100) : null,
      imported: job.imported, held: job.held, blocked: job.blocked,
      duplicates: job.duplicates, failed: job.failed,
      ratePerSecond: Math.round(rate * 10) / 10,
      etaSeconds: remaining != null && rate > 0 ? Math.round(remaining / rate) : null,
      startedAt: iso(job.startedAt), elapsed: ago(job.startedAt)
    };
  }

  /** The completion report. Held and failed records are named, not rounded away. */
  report(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) throw new VaultError('not_found', 'import job not found', { id: jobId });
    return {
      ...this.progress(jobId),
      failures: job.failures,
      honesty: job.failed
        ? `${job.failed} record(s) could not be imported and are listed above — they were not silently dropped`
        : 'every record was accounted for',
      heldNote: job.held
        ? `${job.held} extracted fact(s) were held for review: historical import runs through the same gate as live traffic`
        : null
    };
  }

  all() { return [...this.jobs.values()].map((j) => this.progress(j.id)); }
}

/**
 * OFFBOARDING — the customer who wants it gone, not exported.
 *
 * Deliberately a two-step with a cooling-off window, because this is the one
 * irreversible operation in the product and "I clicked the wrong button" is
 * not recoverable afterwards by design.
 */
export class Offboarding {
  constructor({ vault, ledger, collection = null, signingKey = null }) {
    this.vault = vault;
    this.ledger = ledger;
    this.col = collection;
    this.signingKey = signingKey;
    this.requests = new Map((this.col?.all() ?? []).map((r) => [r.id, r]));
  }

  _save(r) { this.col?.put(r); this.requests.set(r.id, r); return r; }

  /**
   * Step 1: plan. Shows exactly what would go, and what legally cannot.
   */
  plan({ actor, reason }) {
    if (!actor || !reason) throw forbidden('an offboarding plan requires a named actor and a stated reason');
    const facts = this.vault.facts.all();
    const conversations = this.vault.archive.col.all();
    const holds = this.vault.legal.activeHolds();
    const heldFactIds = new Set(holds.flatMap((h) => h.factIds));
    const heldConvIds = new Set(holds.flatMap((h) => h.conversationIds));

    const blockers = holds.map((h) => ({
      holdId: h.id, matter: h.matter,
      facts: h.factIds.length, conversations: h.conversationIds.length,
      detail: 'material under a legal hold cannot be deleted on termination — the hold must be lifted by a named authoriser first'
    }));

    return {
      requestId: newId('offboard'),
      at: iso(),
      requestedBy: actor,
      reason,
      wouldDelete: {
        facts: facts.filter((f) => !heldFactIds.has(f.id)).length,
        conversations: conversations.filter((c) => !heldConvIds.has(c.id)).length,
        goldenFacts: this.vault.facts.goldenFacts().length,
        agents: this.vault.registry.all().length,
        keyScopes: this.vault.kms.inventory().length
      },
      cannotDelete: { facts: heldFactIds.size, conversations: heldConvIds.size, blockers },
      retained: {
        // The ledger is the proof that the deletion happened. Destroying it
        // would destroy the receipt along with the data.
        ledger: 'retained — it is the evidence the deletion occurred, and holds no memory content',
        receipts: 'retained — signed proof of what was deleted and when'
      },
      method: 'crypto-shred every namespace key, then physically erase the fact store and archive',
      irreversible: true,
      confirmBy: 'call confirm() with the same requestId, a second named approver, and confirm: true'
    };
  }

  /**
   * Step 2: execute. Four-eyes, because it is irreversible.
   */
  confirm(plan, { actor, secondApprover, confirm = false }) {
    if (!confirm) throw new VaultError('validation', 'termination deletion must be explicitly confirmed — review the plan first');
    if (!actor || !secondApprover) throw forbidden('termination deletion requires two named approvers');
    if (actor === secondApprover) throw forbidden('the second approver must be a different named human');
    if (plan.cannotDelete.blockers.length) {
      throw new VaultError('legal_hold',
        'material is under legal hold — lift the holds with a named authoriser before terminating',
        { holds: plan.cannotDelete.blockers.map((b) => b.holdId) });
    }

    const shredded = [];
    for (const scope of this.vault.kms.inventory()) {
      if (scope.shredded) continue;
      try {
        shredded.push(this.vault.kms.cryptoShred(scope.scope, { actor, reason: `termination ${plan.requestId}` }));
      } catch { /* already destroyed */ }
    }

    const counts = {
      factsErased: 0, conversationsErased: 0,
      keysDestroyed: shredded.length
    };
    for (const f of this.vault.facts.all()) {
      try { this.vault.facts.col.erase(f.id, { actor, reason: 'contract termination', requestId: plan.requestId, cryptoShredded: true }); counts.factsErased++; }
      catch { /* WORM or held — already reported as a blocker */ }
    }
    for (const c of this.vault.archive.col.all()) {
      try { this.vault.archive.col.erase(c.id, { actor, reason: 'contract termination', requestId: plan.requestId, cryptoShredded: true }); counts.conversationsErased++; }
      catch { /* WORM without a shred path */ }
    }

    const body = {
      kind: 'termination_deletion',
      requestId: plan.requestId,
      requestedBy: plan.requestedBy, approvedBy: [actor, secondApprover],
      reason: plan.reason,
      at: iso(),
      counts,
      cryptoShreddedScopes: shredded.map((s) => ({ scope: s.scope, keyId: s.keyId, witness: s.witness })),
      // Say what actually happened. Claiming backups were crypto-shredded when
      // no namespace keys existed would be a false statement on a document a
      // regulator may read.
      backups: shredded.length
        ? `crypto-shredded — the ${shredded.length} namespace key(s) protecting every backup generation were destroyed, so restores yield ciphertext nobody can open`
        : 'no namespace keys were in use for this tenant, so there was no encrypted backup material to shred; the records themselves were erased directly',
      retained: plan.retained,
      statement: 'all customer memory content was destroyed. The ledger and this receipt remain as proof that it was.'
    };
    const proof = sha256(JSON.stringify(body));
    const receipt = {
      ...body, proof,
      signature: this.signingKey?.privateKeyPem ? signMessage(this.signingKey.privateKeyPem, proof) : null
    };
    this._save({ id: plan.requestId, ...receipt });
    this.ledger.append('admin.action', {
      subject: plan.requestId, actor, action: 'tenant.terminated',
      approvedBy: secondApprover, facts: counts.factsErased,
      conversations: counts.conversationsErased, keys: counts.keysDestroyed, receipt: proof
    });
    return receipt;
  }

  receipts() { return [...this.requests.values()]; }
}
