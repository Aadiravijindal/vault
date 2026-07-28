/**
 * L13 — BACKUP AND DISASTER RECOVERY (§5.10, §28).
 *
 * The storage layer is append-only JSONL, and that shapes everything here.
 *
 * Because collections only ever grow, an incremental backup is literally the
 * tail of each file past the offset the last backup reached — no diffing, no
 * change tracking, no write amplification. And because every operation line
 * carries its own timestamp in the clear (`t`), a point-in-time restore is a
 * truncation: replay the chain, then drop every line stamped after the moment
 * asked for. The result is not "the data with the later rows hidden" — the
 * later bytes are not written at all, which is what someone restoring to before
 * a bad ingest actually needs.
 *
 * Two things this refuses to be sloppy about.
 *
 * `compact()` rewrites a collection file in place, which invalidates every
 * offset. An incremental that kept counting from the old offset would append a
 * fragment of the new file to a stale prefix and produce a restore that is
 * silently missing data — the worst failure a backup system has, because it
 * looks like success. So each incremental re-hashes the prefix it thinks it
 * already has, and re-copies the whole file the moment that hash disagrees.
 *
 * And backups are the thing ransomware goes for. The store here has no update
 * path and no delete path reachable with the credential the primary holds;
 * deletion needs a separate credential AND an expired retention lock, which is
 * what compliance-mode object lock means. Manifests are hash-chained so that
 * excising one is visible rather than merely absent.
 *
 * Backups contain ciphertext. The keys live in the KMS, not in the backup, so
 * crypto-shredding a scope reaches every backup ever taken of it — an old
 * backup of erased data restores as unreadable rather than as a quiet
 * resurrection of what was erased.
 */
import {
  mkdirSync, existsSync, readFileSync, writeFileSync, readdirSync, statSync,
  openSync, readSync, closeSync, appendFileSync, rmSync, copyFileSync
} from 'node:fs';
import { join, basename } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { now, iso, MINUTE, HOUR } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { constantTimeEqual } from '../util/crypto.js';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** Files that are keys, not data. Backed up only when explicitly asked for. */
const KEY_FILES = new Set(['root.key']);

/**
 * The immutable backup target.
 *
 * Modelled on object-lock storage (S3 Object Lock in compliance mode, Azure
 * immutable blobs) rather than a filesystem, because a filesystem the primary
 * can write to is a filesystem ransomware can encrypt. The two credentials are
 * the whole point: the backup agent can only add, and the thing that could
 * remove is not present on the machine being backed up.
 */
export class BackupStore {
  /**
   * @param {object} o
   * @param {string} o.dir where objects land
   * @param {string} o.writeCredential the credential the backup agent holds
   * @param {string} o.deleteCredential a DIFFERENT credential, held offline
   * @param {number} [o.retentionMs] object lock duration
   * @param {string|null} [o.region] required before anything may be replicated here
   * @param {string|null} [o.residencyZone] e.g. 'eu' — what this region satisfies
   */
  constructor({ dir, writeCredential, deleteCredential, retentionMs = 30 * 24 * HOUR, region = null, residencyZone = null }) {
    if (!dir) throw new VaultError('config', 'a backup store needs a directory');
    if (!writeCredential || !deleteCredential) {
      throw new VaultError('config',
        'a backup store needs separate write and delete credentials — one credential that can both add and remove is one credential ransomware needs');
    }
    if (constantTimeEqual(String(writeCredential), String(deleteCredential))) {
      throw new VaultError('config', 'the write and delete credentials are the same secret, which defeats the point of having two');
    }
    this.dir = dir;
    this.writeCredential = String(writeCredential);
    this.deleteCredential = String(deleteCredential);
    this.retentionMs = retentionMs;
    this.region = region;
    this.residencyZone = residencyZone ?? zoneOf(region);
    mkdirSync(join(dir, 'objects'), { recursive: true });
    this.lockPath = join(dir, 'locks.jsonl');
    /** @type {Map<string, number>} object → the instant it becomes deletable */
    this.locks = new Map();
    if (existsSync(this.lockPath)) {
      for (const line of readFileSync(this.lockPath, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try { const l = JSON.parse(line); this.locks.set(l.object, l.until); } catch { /* a torn line is not a lock */ }
      }
    }
  }

  pathFor(object) { return join(this.dir, 'objects', object); }

  /** Write-once. There is no update path, by construction rather than by policy. */
  put(object, bytes, { credential, at = now() }) {
    this._assertWrite(credential);
    const path = this.pathFor(object);
    if (existsSync(path)) {
      throw new VaultError('immutable', `backup object ${object} already exists and this store has no overwrite path`, { object });
    }
    writeFileSync(path, bytes);
    const until = at + this.retentionMs;
    this.locks.set(object, until);
    appendFileSync(this.lockPath, JSON.stringify({ object, until, at, sha256: sha256(bytes) }) + '\n');
    return { object, bytes: bytes.length, immutableUntil: iso(until) };
  }

  get(object) {
    const path = this.pathFor(object);
    if (!existsSync(path)) throw new VaultError('not_found', `no backup object ${object}`, { object });
    return readFileSync(path);
  }

  has(object) { return existsSync(this.pathFor(object)); }

  list() { return readdirSync(join(this.dir, 'objects')); }

  /**
   * Deletion, which is deliberately hard.
   *
   * The backup agent's credential is refused outright — it is an append-only
   * identity. The custodian's credential is refused too until the retention
   * lock expires, because an object lock that the owner can lift on demand is
   * not a lock, it is a preference.
   */
  delete(object, { credential, at = now() }) {
    if (constantTimeEqual(String(credential ?? ''), this.writeCredential)) {
      throw forbidden('the backup write credential is not permitted to delete — that is the entire reason there are two credentials', { object });
    }
    if (!constantTimeEqual(String(credential ?? ''), this.deleteCredential)) {
      throw forbidden('that credential cannot delete from this backup store', { object });
    }
    const until = this.locks.get(object);
    if (until != null && at < until) {
      throw new VaultError('immutable',
        `${object} is immutable until ${iso(until)} — object lock is refused even to the custodian, which is what makes it a lock`,
        { object, immutableUntil: iso(until) });
    }
    const path = this.pathFor(object);
    if (!existsSync(path)) return { deleted: false, object };
    rmSync(path);
    appendFileSync(this.lockPath, JSON.stringify({ object, deleted: true, at }) + '\n');
    return { deleted: true, object };
  }

  _assertWrite(credential) {
    if (!constantTimeEqual(String(credential ?? ''), this.writeCredential)) {
      throw forbidden('that credential cannot write to this backup store');
    }
  }
}

/** Which residency zone a region satisfies. Unknown regions satisfy none. */
function zoneOf(region) {
  if (!region) return null;
  const r = String(region).toLowerCase();
  if (r.startsWith('eu-')) return 'eu';
  if (r.startsWith('us-')) return 'us';
  if (r.startsWith('uk-') || r.startsWith('eu-west-2')) return 'uk';
  if (r.startsWith('ap-south')) return 'in';
  if (r.startsWith('ap-')) return 'apac';
  if (r.startsWith('me-')) return 'me';
  if (r.startsWith('ca-')) return 'ca';
  return null;
}

export class BackupEngine {
  /**
   * @param {object} o
   * @param {string} o.source the vault data directory
   * @param {import('../storage/db.js').Db} o.db
   * @param {BackupStore} o.store
   * @param {string} o.credential must match the store's write credential
   */
  constructor({ source, db, store, credential, ledger = null, kms = null, folders = null, alerts = null,
    region = null, incrementalIntervalMs = 15 * MINUTE, fullIntervalMs = 24 * HOUR, verifier = null }) {
    if (!source) throw new VaultError('config', 'a backup engine needs the directory it is backing up');
    if (!store) throw new VaultError('config', 'a backup engine needs a store to write to');
    this.source = source;
    this.db = db;
    this.store = store;
    this.credential = credential;
    this.ledger = ledger;
    this.kms = kms;
    this.folders = folders;
    this.alerts = alerts;
    this.region = region;
    this.incrementalIntervalMs = incrementalIntervalMs;
    this.fullIntervalMs = fullIntervalMs;
    this.verifier = verifier;
    /** @type {Array<object>} the hash-chained manifest log */
    this.manifests = [];
    /** @type {Map<string,{size:number, prefixSha:string}>} what the last backup covered */
    this.state = new Map();

    /**
     * The suppression list: every key scope ever crypto-shredded.
     *
     * This exists because crypto-shredding a KEK that is *derived* from the
     * root key is only durable while the tombstone recording it survives. A
     * backup taken before an erasure contains the ciphertext and the root key
     * and no tombstone — restoring it re-derives the KEK and hands back exactly
     * the data the erasure receipt said was unrecoverable.
     *
     * So erasure is applied forward onto every restore, and deliberately is NOT
     * subject to the point-in-time cutoff: restoring the vault to last Tuesday
     * must not un-erase someone who exercised their right to erasure on
     * Wednesday. The list only ever grows.
     *
     * @type {Map<string, object>} scope → tombstone
     */
    this.suppressions = new Map();
    // Catch shreds as they happen, so one occurring between two backups is
    // still applied to a restore.
    if (kms?.onEvent) {
      const previous = kms.onEvent.bind(kms);
      kms.onEvent = (e) => {
        if (e?.type === 'key.destroyed') this.recordSuppression(e);
        return previous(e);
      };
    }
    this._absorbSuppressions();
  }

  /** Note a crypto-shred. Idempotent, and there is no un-record. */
  recordSuppression(record) {
    if (!record?.scope) return null;
    if (!this.suppressions.has(record.scope)) {
      this.suppressions.set(record.scope, {
        scope: record.scope, keyId: record.keyId, destroyedAt: record.destroyedAt ?? iso(),
        actor: record.actor ?? 'unknown', reason: record.reason ?? 'crypto-shredded',
        requestId: record.requestId ?? null, version: record.version ?? 1, created: record.created ?? 0
      });
    }
    return this.suppressions.get(record.scope);
  }

  /** Pick up shreds that happened before this engine existed. */
  _absorbSuppressions() {
    if (!this.kms) return;
    for (const k of this.kms.inventory()) {
      if (k.destroyed) this.recordSuppression({ scope: k.scope, keyId: k.keyId, destroyedAt: k.destroyed, version: k.version });
    }
  }

  // -- taking backups ------------------------------------------------------

  full({ actor, reason = 'scheduled full backup', at = now(), includeKeys = true } = {}) {
    return this._run({ kind: 'full', actor, reason, at, includeKeys, forceFull: true });
  }

  incremental({ actor, reason = 'scheduled incremental', at = now(), includeKeys = false } = {}) {
    if (!this.manifests.length) {
      throw new VaultError('conflict', 'there is no full backup to be incremental against — take a full first');
    }
    return this._run({ kind: 'incremental', actor, reason, at, includeKeys, forceFull: false });
  }

  _run({ kind, actor, reason, at, includeKeys, forceFull }) {
    if (!actor) throw forbidden('a backup requires a named actor — "it ran automatically" is not an audit answer');
    this.store._assertWrite(this.credential);

    const id = `bk-${iso(at).replace(/[:.]/g, '-')}-${randomBytes(4).toString('hex')}`;
    const files = [];
    let unchanged = true;

    for (const name of this._sourceFiles({ includeKeys })) {
      const path = join(this.source, name);
      const size = statSync(path).size;
      const prior = forceFull ? null : this.state.get(name);

      // The offset is only meaningful if the bytes we already hold are still
      // the prefix of this file. `compact()` rewrites in place, so this check
      // is what stands between an incremental and silent data loss.
      const rewritten = prior && (size < prior.size || prefixSha(path, prior.size) !== prior.prefixSha);
      const mode = (!prior || rewritten) ? 'full' : 'append';
      const offset = mode === 'full' ? 0 : prior.size;
      const length = size - offset;

      if (length === 0 && mode === 'append') {
        // Nothing appended. Carry the state forward and copy nothing.
        continue;
      }
      unchanged = false;

      const bytes = readRange(path, offset, length);
      const object = `${id}--${name}--${offset}`;
      this.store.put(object, bytes, { credential: this.credential, at });
      files.push({
        name, object, mode, offset, size: length, sha256: sha256(bytes),
        wholeFileSha256: mode === 'full' ? sha256(bytes) : null,
        rewritten: Boolean(rewritten),
        // The last record timestamp in this chunk. This is what an RPO is
        // measured against, and it has to come from the data, not the clock.
        lastRecordAt: lastRecordTimestamp(bytes)
      });
      this.state.set(name, { size, prefixSha: prefixSha(path, size) });
    }

    const prev = this.manifests.length ? this.manifests[this.manifests.length - 1].hash : null;
    const manifest = {
      id, kind, actor, reason, at, takenAt: iso(at),
      region: this.region,
      files,
      unchanged,
      // Residency is recorded at backup time, not consulted at replication
      // time, so a folder re-pinned later cannot retroactively legitimise a
      // copy that has already been made.
      residency: this._residencyZones(),
      coversUpTo: files.reduce((a, f) => Math.max(a, f.lastRecordAt ?? 0), 0) || at,
      prev
    };
    manifest.hash = sha256(Buffer.from(JSON.stringify({ ...manifest, hash: undefined })));
    this.manifests.push(manifest);

    this.ledger?.append('admin.action', {
      subject: id, actor, action: 'backup.completed', reason,
      kind, files: files.length, bytes: files.reduce((a, f) => a + f.size, 0),
      manifestHash: manifest.hash, prev
    });
    return manifest;
  }

  _sourceFiles({ includeKeys }) {
    if (!existsSync(this.source)) throw new VaultError('not_found', 'the source directory does not exist', { source: this.source });
    return readdirSync(this.source, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => e.name)
      .filter((n) => includeKeys || !KEY_FILES.has(n))
      .sort();
  }

  /** Every residency zone the source's folders pin data to. */
  _residencyZones() {
    if (!this.folders) return [];
    return [...new Set(this.folders.all().map((f) => f.residency).filter(Boolean))];
  }

  // -- verification --------------------------------------------------------

  /** Re-hash what is actually on the backup store's disk, right now. */
  verify(manifestId = null) {
    const targets = manifestId ? this.manifests.filter((m) => m.id === manifestId) : this.manifests;
    if (manifestId && !targets.length) throw new VaultError('not_found', `no backup ${manifestId}`, { manifestId });
    const failures = [];
    let checked = 0;
    for (const m of targets) {
      for (const f of m.files) {
        checked++;
        if (!this.store.has(f.object)) {
          failures.push({ backup: m.id, object: f.object, reason: 'the object is missing from the store' });
          continue;
        }
        const actual = sha256(this.store.get(f.object));
        if (actual !== f.sha256) {
          failures.push({ backup: m.id, object: f.object, reason: `digest mismatch — recorded ${f.sha256.slice(0, 12)}…, found ${actual.slice(0, 12)}…` });
        }
      }
    }
    return { ok: failures.length === 0, checked, failures };
  }

  /**
   * The manifest chain. Each manifest names its predecessor's hash, so a
   * backup removed from the middle of the history is visible as a break rather
   * than merely absent — the same argument as the fact ledger.
   */
  verifyChain() {
    let prev = null;
    for (const [i, m] of this.manifests.entries()) {
      const recomputed = sha256(Buffer.from(JSON.stringify({ ...m, hash: undefined })));
      if (recomputed !== m.hash) {
        return { ok: false, reason: `backup ${m.id} does not hash to its recorded value — the manifest was altered`, at: i };
      }
      if (m.prev !== prev) {
        return { ok: false, reason: `the manifest chain breaks at ${m.id}: it follows ${m.prev ?? 'nothing'}, but the previous backup hashes to ${prev ?? 'nothing'}`, at: i };
      }
      prev = m.hash;
    }
    return { ok: true, length: this.manifests.length, head: prev };
  }

  // -- restoring -----------------------------------------------------------

  /**
   * Rebuild the source directory, optionally as it stood at a given instant.
   *
   * @param {object} o
   * @param {string} o.into an empty directory to restore into
   * @param {number} [o.to] point in time; omit for "everything backed up"
   */
  restore({ into, to = null, actor, reason = 'restore', includeKeys = true, at = now() }) {
    if (!actor) throw forbidden('a restore requires a named actor');
    if (!into) throw new VaultError('invalid', 'a restore needs a destination directory');
    if (!this.manifests.length) throw new VaultError('not_found', 'there are no backups to restore from');

    const t0 = process.hrtime.bigint();
    // A backup taken at 10:33 contains everything written up to 10:33, so it
    // serves a restore to 10:31 — truncation does the rest. The chain therefore
    // runs up to and including the FIRST backup taken at or after the moment
    // asked for. What genuinely cannot be served is a moment after the last
    // backup: those records are on the primary and nowhere else.
    const last = this.manifests[this.manifests.length - 1];
    if (to != null && to > last.at) {
      throw new VaultError('not_found',
        `no backup covers ${iso(to)} — the most recent backup was taken at ${last.takenAt}, and anything written since then exists only on the primary`,
        { requested: iso(to), latest: last.takenAt, gapMs: to - last.at });
    }
    const chain = [];
    for (const m of this.manifests) {
      chain.push(m);
      if (to != null && m.at >= to) break;
    }
    // Restoring corrupted data is worse than failing to restore: the operator
    // would carry on believing they had recovered.
    const integrity = this.verify();
    if (!integrity.ok) {
      throw new VaultError('integrity',
        `the backup did not verify — ${integrity.failures.length} object(s) do not match their recorded digest, and restoring them would be restoring corruption`,
        { failures: integrity.failures.map((f) => f.object) });
    }

    mkdirSync(into, { recursive: true });

    /** @type {Map<string, Buffer[]>} file → the pieces, in order */
    const assembled = new Map();
    for (const m of chain) {
      for (const f of m.files) {
        if (!includeKeys && KEY_FILES.has(f.name)) continue;
        const bytes = this.store.get(f.object);
        if (f.mode === 'full') assembled.set(f.name, [bytes]);
        else (assembled.get(f.name) ?? assembled.set(f.name, []).get(f.name)).push(bytes);
      }
    }

    let recordsRestored = 0;
    let recordsDropped = 0;
    const notes = [];
    for (const [name, pieces] of assembled) {
      let content = Buffer.concat(pieces);
      if (to != null && name.endsWith('.jsonl')) {
        const truncated = truncateTo(content, to);
        recordsRestored += truncated.kept;
        recordsDropped += truncated.dropped;
        content = truncated.bytes;
      } else if (name.endsWith('.jsonl')) {
        recordsRestored += countLines(content);
      }
      writeFileSync(join(into, name), content);
    }

    // Erasure applied forward.
    //
    // The suppression list is written into the restored directory regardless of
    // the point in time asked for, and merged with whatever tombstones the
    // backup itself carried. Without this step a restore from a backup taken
    // before an erasure would re-derive the destroyed KEK from the root key and
    // hand back the very data the erasure receipt called unrecoverable — the
    // receipt would be a false statement on a document a regulator reads.
    this._absorbSuppressions();
    let unreadable = 0;
    if (this.suppressions.size) {
      const tombstonePath = join(into, 'shredded.jsonl');
      const already = new Set();
      if (existsSync(tombstonePath)) {
        for (const line of readFileSync(tombstonePath, 'utf8').split('\n')) {
          if (!line.trim()) continue;
          try { already.add(JSON.parse(line).scope); } catch { /* torn line */ }
        }
      }
      const added = [...this.suppressions.values()].filter((t) => !already.has(t.scope));
      if (added.length) appendFileSync(tombstonePath, added.map((t) => JSON.stringify(t)).join('\n') + '\n');
      unreadable = this.suppressions.size;
      notes.push(`${this.suppressions.size} key scope(s) were crypto-shredded; the suppression list is applied to this restore regardless of the point in time, so records sealed under them come back as ciphertext with no key — erasure is not undone by restoring to an earlier moment`);
    }
    if (!includeKeys) {
      notes.push('the root key was withheld from this restore — the restored directory is ciphertext until a key is supplied');
    }

    const rtoMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const result = {
      into, actor, reason,
      pointInTime: to == null ? null : iso(to),
      chain: chain.map((m) => ({ id: m.id, kind: m.kind, at: m.takenAt })),
      files: [...assembled.keys()],
      recordsRestored, recordsDropped, unreadable, notes,
      measured: {
        rtoMs,
        bytes: [...assembled.values()].reduce((a, ps) => a + ps.reduce((b, p) => b + p.length, 0), 0),
        // RPO actually achieved by this restore: how far behind the last
        // backed-up record the requested moment was.
        rpoMs: Math.max(0, at - chain[chain.length - 1].coversUpTo)
      }
    };
    try {
      this.ledger?.append('admin.action', {
        subject: chain[chain.length - 1].id, actor, action: 'backup.restored', reason,
        pointInTime: result.pointInTime, rtoMs: Math.round(rtoMs), files: result.files.length
      });
    } catch (e) {
      // A real disaster recovery runs with the primary destroyed, and the
      // primary is where that ledger lives. Failing the restore because the
      // audit line could not be written would be exactly the wrong trade.
      result.notes.push(`the restore could not be recorded in the source ledger (${e.code ?? 'error'}) — expected when recovering from total loss of the primary`);
    }
    return result;
  }

  // -- replication ---------------------------------------------------------

  /**
   * Copy backups to another store, refusing anything residency forbids.
   *
   * A file is refused as a whole when any folder in the source pins data to a
   * zone the target cannot satisfy. Copying "just the allowed rows" out of a
   * JSONL collection is not a backup — it is a partial file that would restore
   * into a vault missing records with no indication of which — so the
   * conservative answer is the only correct one.
   */
  replicate(target, { actor, reason = 'cross-region replication', at = now(), credential = null } = {}) {
    if (!actor) throw forbidden('replication requires a named actor');
    if (!target?.region) {
      throw new VaultError('config',
        'a replication target must declare a region — residency cannot be checked against an unknown location, and unchecked is the same as unlawful here',
        { target: target?.dir ?? null });
    }
    const zones = this._residencyZones();
    const targetZone = target.residencyZone;
    const refused = [];
    const blocking = zones.filter((z) => !satisfies(targetZone, z, target.region));

    let replicated = 0;
    for (const m of this.manifests) {
      for (const f of m.files) {
        if (blocking.length) {
          refused.push({
            backup: m.id, object: f.object,
            reason: `residency: this vault pins data to ${blocking.join(', ')}, and ${target.region} does not satisfy that`
          });
          continue;
        }
        if (target.has(f.object)) continue;
        target.put(f.object, this.store.get(f.object), { credential: credential ?? target.writeCredential, at });
        replicated++;
      }
    }
    this.ledger?.append('admin.action', {
      subject: target.region, actor, action: 'backup.replicated', reason,
      replicated, refused: refused.length, residency: zones.join(',') || 'none'
    });
    if (refused.length) {
      this.alerts?.raise({
        severity: 'medium', kind: 'replication_refused', subject: target.region, actor,
        detail: `${refused.length} backup object(s) were not replicated to ${target.region} because this vault pins data to ${blocking.join(', ')}`
      });
    }
    return { target: target.region, replicated, refused, encrypted: true };
  }

  // -- the operator's view -------------------------------------------------

  /**
   * What RPO and RTO this configuration can actually deliver.
   *
   * The RPO target is the incremental interval and nothing else: data written
   * between two incrementals is not anywhere but the primary, so any smaller
   * number would be a wish.
   */
  objectives() {
    const restores = this.manifests.length ? this.manifests[this.manifests.length - 1] : null;
    return {
      rpoTargetMs: this.incrementalIntervalMs,
      basis: `the achievable RPO is the incremental interval (${Math.round(this.incrementalIntervalMs / MINUTE)} minutes) — data written between two incrementals exists only on the primary`,
      fullIntervalMs: this.fullIntervalMs,
      retentionMs: this.store.retentionMs,
      lastBackupAt: restores ? restores.takenAt : null,
      rtoMs: this._lastRtoMs ?? null
    };
  }

  status({ at = now() } = {}) {
    const last = this.manifests.length ? this.manifests[this.manifests.length - 1] : null;
    const dueAt = last ? last.at + this.incrementalIntervalMs : at;
    const overdue = Boolean(last) && at > dueAt;
    const lastFull = [...this.manifests].reverse().find((m) => m.kind === 'full') ?? null;
    return {
      backups: this.manifests.length,
      lastBackupAt: last ? last.takenAt : null,
      lastBackupKind: last ? last.kind : null,
      lastFullAt: lastFull ? lastFull.takenAt : null,
      nextDueAt: iso(dueAt),
      overdue,
      chain: this.verifyChain(),
      objects: this.store.list().length,
      detail: !last
        ? 'no backup has ever been taken'
        : overdue
          ? `the last backup was ${Math.round((at - last.at) / MINUTE)} minutes ago and one was due every ${Math.round(this.incrementalIntervalMs / MINUTE)} — overdue`
          : `last backup ${last.takenAt}, next due ${iso(dueAt)}`
    };
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Does a target region satisfy a residency pin? Unknown zones satisfy nothing. */
function satisfies(targetZone, pinned, targetRegion) {
  if (!pinned) return true;
  if (String(pinned).toLowerCase() === String(targetRegion).toLowerCase()) return true;
  const pinnedZone = zoneOf(pinned) ?? String(pinned).toLowerCase();
  return Boolean(targetZone) && targetZone === pinnedZone;
}

function readRange(path, offset, length) {
  if (length <= 0) return Buffer.alloc(0);
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const n = readSync(fd, buf, read, length - read, offset + read);
      if (n === 0) break;
      read += n;
    }
    return read === length ? buf : buf.subarray(0, read);
  } finally { closeSync(fd); }
}

/** Hash of the first `length` bytes — the check that a file was not rewritten. */
function prefixSha(path, length) {
  return sha256(readRange(path, 0, length));
}

/**
 * Drop every JSONL operation stamped after `to`.
 *
 * The bytes are rebuilt from the lines that remain rather than the file being
 * sliced, so what lands on disk genuinely does not contain the later records —
 * a restore that merely stopped *reading* early would leave the data recoverable
 * by anyone who opened the file.
 */
function truncateTo(bytes, to) {
  const lines = bytes.toString('utf8').split('\n');
  const kept = [];
  let dropped = 0;
  for (const line of lines) {
    if (!line.trim()) continue;
    let t = null;
    try { t = JSON.parse(line).t ?? null; } catch { t = null; }
    // A line with no timestamp is structural (a header, a checkpoint) and is
    // kept: dropping it would corrupt the file, and it carries no record.
    if (t != null && t > to) { dropped++; continue; }
    kept.push(line);
  }
  return { bytes: Buffer.from(kept.length ? kept.join('\n') + '\n' : ''), kept: kept.length, dropped };
}

function countLines(bytes) {
  let n = 0;
  for (const line of bytes.toString('utf8').split('\n')) if (line.trim()) n++;
  return n;
}

/** The newest `t` in a chunk — what an RPO is honestly measured against. */
function lastRecordTimestamp(bytes) {
  let latest = 0;
  for (const line of bytes.toString('utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const t = JSON.parse(line).t;
      if (typeof t === 'number' && t > latest) latest = t;
    } catch { /* not every line is an operation */ }
  }
  return latest || null;
}
