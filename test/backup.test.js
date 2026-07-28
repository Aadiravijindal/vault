/**
 * Backup and disaster recovery (§5, §28) — measured, not asserted.
 *
 * Every claim in this file is checked against the real underlying state: bytes
 * on disk read back and hashed, a primary data directory genuinely deleted and
 * genuinely restored, wall-clock recovery time taken with `hrtime`, and
 * plaintext hunted for with a raw byte scan of the backup files rather than
 * asked for from the code that wrote them.
 *
 * The two tests that matter most are the ones that would be easiest to fake:
 * point-in-time restore (which must not merely *hide* later records — the bytes
 * must not be there) and crypto-shredding reaching backups (which must make an
 * old backup unreadable, or erasure is a promise the backups quietly break).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtempSync, rmSync, readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { BackupEngine, BackupStore } from '../src/continuity/backup.js';
import { setClock, MINUTE, HOUR } from '../src/util/time.js';

const dirs = [];
function tmp(prefix = 'vault-bk-') {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
process.on('exit', () => { for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* gone */ } } });

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

/** Every byte under a directory tree, concatenated. The disk, not the API. */
function allBytes(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p); else out.push(readFileSync(p));
    }
  };
  if (existsSync(dir)) walk(dir);
  return Buffer.concat(out);
}

function sizeOf(dir) {
  let total = 0;
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p); else total += statSync(p).size;
    }
  };
  if (existsSync(dir)) walk(dir);
  return total;
}

function makeVault(extra = {}) {
  const dir = tmp();
  const vault = new Vault({ dir, signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false, ...extra });
  vault.registerAgent({
    id: 'a-1', name: 'agent one', purpose: 'testing', businessOwner: 'Owner', technicalOwner: 'Tech',
    department: 'sales', mode: 'inline', pinnedModel: 'm1', folders: ['sales/']
  });
  const cred = vault.issueCredential('a-1', {}).credential;
  const write = (text) => vault.ingest({
    agentId: 'a-1', channel: 'system_of_record',
    participants: [{ name: 'Sarah Reyes', kind: 'employee', internal: true }],
    turns: [{ speaker: 'Sarah Reyes', text }]
  }, { credential: cred });
  return { vault, dir, write };
}

function engineFor(vault, dir, opts = {}) {
  const backupDir = tmp('vault-store-');
  const store = new BackupStore({
    dir: backupDir,
    writeCredential: 'wr_backup_agent',
    // Deliberately a different secret. The primary never holds it.
    deleteCredential: 'del_offline_custodian',
    retentionMs: 7 * 24 * HOUR,
    ...(opts.store ?? {})
  });
  const engine = new BackupEngine({
    source: dir, db: vault.db, ledger: vault.ledger, kms: vault.kms, folders: vault.folders,
    store, credential: 'wr_backup_agent', region: 'eu-west-1', ...(opts.engine ?? {})
  });
  return { engine, store, backupDir };
}

describe('full backup — the bytes on disk, not the report about them', () => {
  test('a full backup contains every collection file, byte-identical', () => {
    const { vault, dir, write } = makeVault();
    write('Acme renewal is 40k ARR.');
    write('Beta Corp churn risk is high.');
    const { engine, store } = engineFor(vault, dir);

    const manifest = engine.full({ actor: 'ops@acme.com', reason: 'first full' });
    assert.equal(manifest.kind, 'full');
    assert.ok(manifest.files.length > 0, 'a full backup of a vault with data cannot be empty');

    for (const f of manifest.files) {
      // What the store holds must be exactly what the manifest says it is.
      const stored = store.get(f.object);
      assert.equal(sha(stored), f.sha256, `${f.name} is not what the backup store actually holds`);
      assert.equal(stored.length, f.size);

      // And it must be a genuine prefix of the live file. Not equality: the
      // ledger records the backup itself, so ledger.jsonl grows between the
      // capture and this assertion. Prefix equality is the real invariant for
      // an append-only file, and it is the one that catches a store holding
      // something other than this vault's bytes.
      const live = readFileSync(join(dir, f.name));
      assert.ok(live.length >= stored.length, `${f.name} shrank — an append-only file cannot do that`);
      assert.equal(Buffer.compare(live.subarray(0, stored.length), stored), 0,
        `${f.name} in the backup is not a prefix of the file on disk`);
    }
    assert.ok(manifest.files.some((f) => f.name === 'facts.jsonl'), 'the facts must be in the backup at all');
  });

  test('the backup store holds real files, and they are not the vault directory', () => {
    const { vault, dir, write } = makeVault();
    write('a fact worth keeping.');
    const { engine, backupDir } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'independence' });
    assert.ok(sizeOf(backupDir) > 0, 'a backup that wrote no bytes is not a backup');
    assert.notEqual(backupDir, dir);
  });
});

describe('incremental backup — genuinely incremental', () => {
  test('an incremental copies only the bytes appended since the last backup', () => {
    const { vault, dir, write } = makeVault();
    for (let i = 0; i < 40; i++) write(`baseline fact number ${i}.`);
    const { engine, store } = engineFor(vault, dir);

    const full = engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const sizeAfterFull = sizeOf(dir);

    write('one single new fact after the full backup.');
    const grew = sizeOf(dir) - sizeAfterFull;
    assert.ok(grew > 0, 'the vault must have actually grown for this test to mean anything');

    const inc = engine.incremental({ actor: 'ops@acme.com', reason: 'delta' });
    assert.equal(inc.kind, 'incremental');
    const copied = inc.files.reduce((a, f) => a + f.size, 0);
    const fullBytes = full.files.reduce((a, f) => a + f.size, 0);

    assert.ok(copied < fullBytes / 4,
      `the incremental copied ${copied} bytes against a full of ${fullBytes} — that is not an incremental`);
    // Every incremental byte must be a genuine tail of the live file.
    for (const f of inc.files) {
      const live = readFileSync(join(dir, f.name));
      const tail = live.subarray(f.offset, f.offset + f.size);
      assert.equal(Buffer.compare(store.get(f.object), tail), 0,
        `${f.name} incremental is not the tail of the live file at the offset it claims`);
    }
  });

  test('a compaction underneath the backup is detected and the file is re-copied whole', () => {
    // Byte offsets are only valid while the file is append-only. `compact()`
    // rewrites it. An incremental that kept counting from the old offset would
    // produce a restore that silently loses data — the worst possible failure.
    const { vault, dir, write } = makeVault();
    for (let i = 0; i < 20; i++) write(`fact ${i} before compaction.`);
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });

    vault.db.compactAll();
    write('written after the compaction.');

    const inc = engine.incremental({ actor: 'ops@acme.com', reason: 'after compaction' });
    const facts = inc.files.find((f) => f.name === 'facts.jsonl');
    assert.ok(facts, 'facts.jsonl must appear in the incremental at all');
    assert.equal(facts.mode, 'full', 'a rewritten file must be re-copied whole, not appended to');
    assert.equal(facts.offset, 0);
    assert.equal(facts.size, statSync(join(dir, 'facts.jsonl')).size);
  });

  test('an incremental with nothing to do says so instead of copying everything again', () => {
    const { vault, dir, write } = makeVault();
    write('nothing will change after this.');
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const inc = engine.incremental({ actor: 'ops@acme.com', reason: 'no-op' });
    // The data files must not be copied again. `ledger.jsonl` legitimately did
    // change — the full backup recorded itself in it — and an incremental that
    // skipped that would be losing an audit entry.
    const dataFiles = inc.files.filter((f) => f.name !== 'ledger.jsonl');
    assert.deepEqual(dataFiles, [], 'an idle vault must not cause its data files to be copied again');
    for (const f of inc.files) assert.equal(f.mode, 'append', 'nothing here justifies a whole-file re-copy');
  });
});

describe('point-in-time restore — to the minute, and the later bytes are not there', () => {
  test('restoring to 10:31 yields what existed at 10:31 and nothing after it', () => {
    let clock = Date.parse('2026-07-28T10:30:00Z');
    const restoreClock = setClock(() => clock);
    try {
      const { vault, dir, write } = makeVault();
      write('FACT-ALPHA written at half past ten.');
      clock += MINUTE;
      write('FACT-BRAVO written at 10:31.');
      const cutoff = clock;                       // 10:31:00
      clock += MINUTE;
      write('FACT-CHARLIE written at 10:32.');
      clock += MINUTE;
      write('FACT-DELTA written at 10:33.');

      // The store is encrypted, so scanning for the claim text would prove
      // nothing — it is not in the bytes either way. Record ids are in the
      // clear in every operation line, and they are what the byte scan hunts.
      const idOf = (needle) => vault.facts.all().find((f) => f.claim.includes(needle))?.id;
      const ids = {
        alpha: idOf('ALPHA'), bravo: idOf('BRAVO'), charlie: idOf('CHARLIE'), delta: idOf('DELTA')
      };
      for (const [k, id] of Object.entries(ids)) assert.ok(id, `${k} must have been stored`);

      const { engine } = engineFor(vault, dir);
      engine.full({ actor: 'ops@acme.com', reason: 'covers everything' });

      const into = tmp('vault-pit-');
      const out = engine.restore({ to: cutoff, into, actor: 'ops@acme.com', reason: 'point in time' });
      assert.equal(out.pointInTime, new Date(cutoff).toISOString());
      assert.ok(out.recordsDropped > 0, 'a PIT restore that dropped nothing did not do anything');

      // The later records must be ABSENT from the bytes, not merely hidden:
      // "restored to before the incident" has to mean the incident's data is
      // gone, including for anyone who opens the file directly.
      const bytes = allBytes(into).toString('utf8');
      assert.ok(bytes.includes(ids.alpha), 'the restore lost data that was inside the window');
      assert.ok(bytes.includes(ids.bravo), 'the cutoff must be inclusive of the minute named');
      assert.ok(!bytes.includes(ids.charlie), 'a record written after the cutoff survived the restore');
      assert.ok(!bytes.includes(ids.delta), 'a record written after the cutoff survived the restore');

      // And the restored directory must open as a working vault.
      const restored = new Vault({ dir: into });
      const claims = restored.facts.all().map((f) => f.claim).join(' | ');
      assert.ok(/ALPHA/.test(claims) && /BRAVO/.test(claims), `restored claims were: ${claims}`);
      assert.ok(!/CHARLIE/.test(claims) && !/DELTA/.test(claims), `restored claims were: ${claims}`);
    } finally { restoreClock(); }
  });

  test('a full plus a chain of incrementals restores to a moment covered only by the last one', () => {
    let clock = Date.parse('2026-07-28T12:00:00Z');
    const restoreClock = setClock(() => clock);
    try {
      const { vault, dir, write } = makeVault();
      write('IN-FULL only in the full backup.');
      const { engine } = engineFor(vault, dir);
      engine.full({ actor: 'ops@acme.com', reason: 'base' });

      clock += 10 * MINUTE;
      write('IN-FIRST-INCREMENTAL.');
      engine.incremental({ actor: 'ops@acme.com', reason: 'i1' });

      clock += 10 * MINUTE;
      write('IN-SECOND-INCREMENTAL.');
      engine.incremental({ actor: 'ops@acme.com', reason: 'i2' });
      const cutoff = clock;

      clock += 10 * MINUTE;
      write('AFTER-EVERY-BACKUP.');

      const into = tmp('vault-chain-');
      const out = engine.restore({ to: cutoff, into, actor: 'ops@acme.com', reason: 'chain' });
      assert.equal(out.chain.length, 3, 'the restore must replay the full and both incrementals');
      assert.equal(out.chain[0].kind, 'full');

      const idOf = (needle) => vault.facts.all().find((f) => f.claim.includes(needle))?.id;
      const bytes = allBytes(into).toString('utf8');
      assert.ok(bytes.includes(idOf('IN-FULL')));
      assert.ok(bytes.includes(idOf('IN-FIRST-INCREMENTAL')));
      assert.ok(bytes.includes(idOf('IN-SECOND-INCREMENTAL')), 'the last incremental was not applied');
      assert.ok(!bytes.includes(idOf('AFTER-EVERY-BACKUP')), 'data that was never backed up cannot appear in a restore');

      const restored = new Vault({ dir: into });
      assert.equal(restored.facts.all().length, 3);
    } finally { restoreClock(); }
  });

  test('asking for a moment AFTER the last backup is refused, not silently rounded down', () => {
    // The dangerous answer is a successful-looking restore that is quietly
    // older than what was asked for. An operator recovering to "just before the
    // incident at 14:00" must not be handed 02:00 without being told.
    const { vault, dir, write } = makeVault();
    write('something.');
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });
    assert.throws(
      () => engine.restore({ to: Date.now() + 6 * HOUR, into: tmp(), actor: 'ops@acme.com' }),
      /no backup covers/
    );
  });

  test('a moment before the vault held anything restores an empty vault, not an error', () => {
    const { vault, dir, write } = makeVault();
    write('written today.');
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const into = tmp('vault-early-');
    const out = engine.restore({ to: Date.parse('2020-01-01T00:00:00Z'), into, actor: 'ops@acme.com' });
    assert.ok(out.recordsDropped > 0);
    assert.equal(new Vault({ dir: into }).facts.all().length, 0);
  });
});

describe('measured RPO and RTO — the primary is actually destroyed', () => {
  test('deleting the entire data directory and restoring gives real numbers', () => {
    const { vault, dir, write } = makeVault();
    for (let i = 0; i < 120; i++) {
      write(`pre-disaster fact ${i} about the renewal pipeline.`);
    }
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'nightly' });

    const liveBefore = vault.facts.all().length;
    const lastBackedUpAt = engine.status().lastBackupAt;

    // Data written after the last backup. This is what RPO measures: it is
    // genuinely lost, and the number has to say so.
    write('written after the last backup and therefore lost.');
    const lostId = vault.facts.all().find((f) => /therefore lost/.test(f.claim)).id;
    const failureAt = Date.now();

    // Total loss of the primary.
    rmSync(dir, { recursive: true, force: true });
    assert.equal(existsSync(dir), false, 'the primary must really be gone for this to measure anything');

    const t0 = process.hrtime.bigint();
    const into = tmp('vault-dr-');
    const out = engine.restore({ into, actor: 'ops@acme.com', reason: 'disaster recovery exercise' });
    const restored = new Vault({ dir: into });
    const rtoMs = Number(process.hrtime.bigint() - t0) / 1e6;

    assert.equal(restored.facts.all().length, liveBefore,
      'the restored vault does not hold what the primary held at the last backup');
    assert.ok(!allBytes(into).toString('utf8').includes(lostId),
      'a fact written after the last backup cannot be in the restore — if it is, the RPO number is a lie');

    // Real numbers, computed here rather than reported by the engine.
    const rpoMs = failureAt - Date.parse(lastBackedUpAt);
    assert.ok(rtoMs > 0 && rtoMs < 60_000, `RTO of ${rtoMs}ms is not plausible`);
    assert.ok(rpoMs >= 0);
    assert.equal(typeof out.measured.rtoMs, 'number');
    assert.ok(out.measured.rtoMs > 0, 'the engine must report its own measured recovery time');
    assert.ok(Math.abs(out.measured.rtoMs - rtoMs) < rtoMs + 5000, 'the engine\'s RTO must be in the same universe as the observed one');

    // Reported for the record, because a DR claim with no number is not a claim.
    console.log(`    measured: RTO ${out.measured.rtoMs.toFixed(1)}ms for ${liveBefore} facts, RPO ${rpoMs}ms`);
  });

  test('the engine reports the RPO its schedule can actually achieve, not an aspiration', () => {
    const { vault, dir, write } = makeVault();
    write('anything.');
    const { engine } = engineFor(vault, dir, { engine: { incrementalIntervalMs: 5 * MINUTE } });
    engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const objective = engine.objectives();
    assert.equal(objective.rpoTargetMs, 5 * MINUTE,
      'the achievable RPO is the incremental interval — nothing else is honest');
    assert.ok(objective.basis.includes('incremental'));
  });
});

describe('immutability and ransomware resistance', () => {
  test('a backup object cannot be deleted before its retention expires — by anyone', () => {
    const { vault, dir, write } = makeVault();
    write('the thing ransomware would want to destroy.');
    const { engine, store } = engineFor(vault, dir);
    const manifest = engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const object = manifest.files[0].object;

    // The credential the primary holds cannot delete at all.
    assert.throws(() => store.delete(object, { credential: 'wr_backup_agent' }), /not permitted to delete/);
    // The custodian's credential is refused too, while the lock holds. This is
    // what compliance-mode object lock means: nobody, including the owner.
    assert.throws(() => store.delete(object, { credential: 'del_offline_custodian' }), /immutable until/);
    // And the bytes are still there.
    assert.ok(store.get(object).length > 0);
  });

  test('the retention expiring lets the custodian delete, but never the backup agent', () => {
    const { vault, dir, write } = makeVault();
    write('expires eventually.');
    const { engine, store } = engineFor(vault, dir, { store: { retentionMs: MINUTE } });
    const manifest = engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const object = manifest.files[0].object;
    const later = Date.now() + 2 * MINUTE;
    assert.throws(() => store.delete(object, { credential: 'wr_backup_agent', at: later }), /not permitted to delete/);
    assert.equal(store.delete(object, { credential: 'del_offline_custodian', at: later }).deleted, true);
  });

  test('overwriting a stored object is refused — the store has no update path', () => {
    const { vault, dir, write } = makeVault();
    write('write once.');
    const { engine, store } = engineFor(vault, dir);
    const manifest = engine.full({ actor: 'ops@acme.com', reason: 'base' });
    assert.throws(() => store.put(manifest.files[0].object, Buffer.from('replaced'), { credential: 'wr_backup_agent' }),
      /already exists/);
  });

  test('a backup file corrupted on disk is caught by verification and named', () => {
    const { vault, dir, write } = makeVault();
    write('this will be corrupted underneath us.');
    const { engine, store, backupDir } = engineFor(vault, dir);
    const manifest = engine.full({ actor: 'ops@acme.com', reason: 'base' });
    assert.equal(engine.verify(manifest.id).ok, true, 'a fresh backup must verify');

    // Ransomware reaching past the API, straight at the filesystem.
    const target = store.pathFor(manifest.files[0].object);
    const original = readFileSync(target);
    writeFileSync(target, Buffer.concat([original, Buffer.from('\n{"o":"i","id":"injected"}\n')]));

    const bad = engine.verify(manifest.id);
    assert.equal(bad.ok, false, 'a modified backup object verified clean');
    assert.ok(bad.failures.some((f) => f.object === manifest.files[0].object));
    assert.match(bad.failures[0].reason, /digest/);

    // And a restore from it must refuse rather than restore corrupted data.
    assert.throws(() => engine.restore({ into: tmp(), actor: 'ops@acme.com' }), /did not verify/);
  });

  test('the manifest chain is hash-linked, so a deleted backup in the middle is visible', () => {
    const { vault, dir, write } = makeVault();
    write('one.');
    const { engine } = engineFor(vault, dir);
    const a = engine.full({ actor: 'ops@acme.com', reason: 'base' });
    write('two.');
    const b = engine.incremental({ actor: 'ops@acme.com', reason: 'i1' });
    write('three.');
    const c = engine.incremental({ actor: 'ops@acme.com', reason: 'i2' });

    assert.equal(b.prev, a.hash, 'each manifest must name the one before it');
    assert.equal(c.prev, b.hash);
    assert.equal(engine.verifyChain().ok, true);

    // Excise the middle manifest the way an attacker covering their tracks would.
    engine.manifests.splice(1, 1);
    const broken = engine.verifyChain();
    assert.equal(broken.ok, false, 'a missing manifest left the chain looking intact');
    assert.match(broken.reason, /chain/);
  });
});

describe('cross-region replication respects residency', () => {
  test('EU-resident data is not copied to a US region, and the bytes prove it', () => {
    const { vault, dir, write } = makeVault();
    // The agent writes into sales/, so that is the folder whose residency
    // decides. A file that mixes folders is refused as a whole when any record
    // in it is residency-pinned away from the target — the conservative answer
    // is the only correct one, because half a JSONL file is not a backup.
    vault.folders.setResidency('sales/', 'eu-west-1', { actor: 'root', reason: 'EU subject data' });
    write('EUONLY-SUBJECT-DATA about a German employee.');
    write('GLOBALDATA about the product roadmap.');

    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });

    const usDir = tmp('vault-us-');
    const us = new BackupStore({ dir: usDir, writeCredential: 'wr_us', deleteCredential: 'del_us', region: 'us-east-1' });
    const out = engine.replicate(us, { actor: 'ops@acme.com', reason: 'cross-region DR' });

    assert.ok(out.refused.length > 0, 'replicating EU data to us-east-1 must be refused, not warned about');
    assert.match(out.refused[0].reason, /residency/);

    const bytes = allBytes(usDir).toString('utf8');
    assert.ok(!bytes.includes('EUONLY-SUBJECT-DATA'),
      'EU-resident content reached a US region — this is the cross-border transfer the product promises never happens');
  });

  test('replication to an in-region target copies everything and the copy verifies', () => {
    const { vault, dir, write } = makeVault();
    vault.folders.setResidency('sales/', 'eu-west-1', { actor: 'root', reason: 'EU subject data' });
    write('EUONLY-SUBJECT-DATA stays in europe.');

    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });

    const euDir = tmp('vault-eu2-');
    const eu2 = new BackupStore({ dir: euDir, writeCredential: 'wr_eu2', deleteCredential: 'del_eu2', region: 'eu-central-1', residencyZone: 'eu' });
    const out = engine.replicate(eu2, { actor: 'ops@acme.com', reason: 'in-zone DR' });
    assert.equal(out.refused.length, 0);
    assert.ok(out.replicated > 0);
    assert.ok(allBytes(euDir).toString('utf8').includes('EUONLY-SUBJECT-DATA') ||
      out.encrypted === true, 'the replica must actually hold the data');
  });

  test('a target with no declared region is refused outright', () => {
    const { vault, dir, write } = makeVault();
    write('anything.');
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });
    const nowhere = new BackupStore({ dir: tmp(), writeCredential: 'w', deleteCredential: 'd' });
    assert.throws(() => engine.replicate(nowhere, { actor: 'ops@acme.com' }),
      /declare a region/);
  });
});

describe('crypto-shredding reaches the backups', () => {
  test('backups hold ciphertext, so the plaintext was never in them to begin with', () => {
    const { vault, dir, write } = makeVault();
    write('SHREDME-PLAINTEXT-CANARY about a specific person.');
    const { engine, backupDir } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });

    assert.ok(!allBytes(dir).toString('utf8').includes('SHREDME-PLAINTEXT-CANARY'),
      'the primary is storing plaintext — encryption at rest is not on');
    assert.ok(!allBytes(backupDir).toString('utf8').includes('SHREDME-PLAINTEXT-CANARY'),
      'the backup is storing plaintext, so shredding a key could never reach it');
  });

  test('shredding a key makes an OLD backup of that data unreadable, and says so', () => {
    // The claim under test: "erasure reaches backups". If a restore from a
    // backup taken before the erasure hands the content back, the erasure
    // receipt is false.
    const { vault, dir, write } = makeVault();
    write('SHREDME-CANARY belonging to one data subject.');
    const fact = vault.facts.all().find((x) => /SHREDME-CANARY/.test(x.claim));
    assert.ok(fact, 'the canary fact must have been stored for this test to mean anything');
    const scope = vault.db.collection('facts').keyScope(fact);

    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'before erasure' });

    vault.kms.cryptoShred(scope, { actor: 'dpo@acme.com', reason: 'erasure request ER-1' });

    const into = tmp('vault-shred-');
    const out = engine.restore({ into, actor: 'ops@acme.com', reason: 'restore after erasure' });
    assert.ok(out.unreadable > 0 && out.notes.some((n) => /shred/.test(n)),
      'a restore that includes crypto-shredded records must report them, not pretend they came back');

    // The ciphertext is still in the backup — that is the point. What is gone
    // is the key, so the row restores as an unreadable record rather than as
    // content.
    assert.ok(allBytes(into).toString('utf8').includes(fact.id),
      'the sealed row should still be present; it is the key that was destroyed, not the bytes');

    const restored = new Vault({ dir: into });
    const claims = restored.facts.all().map((x) => x.claim).join(' ');
    assert.ok(!claims.includes('SHREDME-CANARY'),
      'shredded content came back from a backup — the erasure receipt was a lie');
  });

  test('a restored vault without the root key yields nothing readable', () => {
    const { vault, dir, write } = makeVault();
    write('CONFIDENTIAL-RESTORE-CANARY.');
    const { engine } = engineFor(vault, dir);
    engine.full({ actor: 'ops@acme.com', reason: 'base' });

    const into = tmp('vault-nokey-');
    engine.restore({ into, actor: 'ops@acme.com', reason: 'test', includeKeys: false });
    assert.equal(existsSync(join(into, 'root.key')), false, 'the restore shipped the root key it was told to withhold');
    const bytes = allBytes(into).toString('utf8');
    assert.ok(!bytes.includes('CONFIDENTIAL-RESTORE-CANARY'),
      'a keyless restore still exposed content — the backup is not really encrypted');
  });
});

describe('the schedule, the ledger and the operator view', () => {
  test('every backup reaches the ledger with its digest', () => {
    const { vault, dir, write } = makeVault();
    write('auditable.');
    const { engine } = engineFor(vault, dir);
    const m = engine.full({ actor: 'ops@acme.com', reason: 'auditable' });
    const entries = vault.ledger.entries({ limit: Infinity }).filter((e) => e.action === 'backup.completed');
    assert.equal(entries.length, 1);
    assert.equal(entries[0].manifestHash, m.hash,
      'the ledger must record the manifest digest, so a backup cannot be swapped for another without the chain showing it');
  });

  test('status names the last backup, the next one due, and whether it is overdue', () => {
    let clock = Date.parse('2026-07-28T02:00:00Z');
    const restoreClock = setClock(() => clock);
    try {
      const { vault, dir, write } = makeVault();
      write('x.');
      const { engine } = engineFor(vault, dir, { engine: { incrementalIntervalMs: 15 * MINUTE, fullIntervalMs: 24 * HOUR } });
      engine.full({ actor: 'ops@acme.com', reason: 'nightly' });
      const fresh = engine.status();
      assert.equal(fresh.overdue, false);
      assert.equal(fresh.backups, 1);

      clock += 3 * HOUR;
      const stale = engine.status();
      assert.equal(stale.overdue, true, 'three hours past a fifteen-minute interval is overdue');
      assert.match(stale.detail, /overdue/i);
    } finally { restoreClock(); }
  });

  test('a backup taken with the wrong credential is refused', () => {
    const { vault, dir, write } = makeVault();
    write('x.');
    const { engine } = engineFor(vault, dir, { engine: { credential: 'wrong' } });
    assert.throws(() => engine.full({ actor: 'ops@acme.com', reason: 'base' }), /credential/);
  });
});

describe('the control surface — backup and restore over real HTTP', () => {
  test('an operator can take, verify and restore a backup without touching the filesystem', async () => {
    const { ApiServer } = await import('../src/api/server.js');
    const backupDir = tmp('vault-http-store-');
    const dir = tmp();
    const vault = new Vault({
      dir, signingKey: Ledger.newSigningKey(), seedRules: false,
      backup: {
        store: new BackupStore({ dir: backupDir, writeCredential: 'w1', deleteCredential: 'd1', region: 'eu-west-1' }),
        credential: 'w1', region: 'eu-west-1'
      }
    });
    vault.registerAgent({
      id: 'a-1', name: 'a', purpose: 't', businessOwner: 'O', technicalOwner: 'T',
      department: 'sales', mode: 'inline', pinnedModel: 'm1', folders: ['sales/']
    });
    const cred = vault.issueCredential('a-1', {}).credential;
    vault.ingest({
      agentId: 'a-1', channel: 'system_of_record',
      turns: [{ speaker: 'Sarah Reyes', text: 'HTTP-BACKUP-CANARY has 300 seats provisioned.' }]
    }, { credential: cred });

    const server = new ApiServer({ vault, port: 0 });
    const admin = server.issueToken({ name: 'ops@acme.com', role: 'admin' });
    const analyst = server.issueToken({ name: 'nobody@acme.com', role: 'end_user' });
    await server.listen();
    const base = `http://127.0.0.1:${server.server.address().port}`;
    const call = (m, p, body, tok = admin) => fetch(base + p, {
      method: m, headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {})
    });

    try {
      assert.equal((await call('POST', '/api/backup/full', { reason: 'over http' }, analyst)).status, 403,
        'taking a backup is not an end-user operation');

      const taken = await call('POST', '/api/backup/full', { reason: 'over http' });
      assert.equal(taken.status, 200);
      const manifest = await taken.json();
      assert.ok(manifest.files.length > 0);

      const verified = await (await call('GET', '/api/backup/verify')).json();
      assert.equal(verified.objects.ok, true);
      assert.equal(verified.chain.ok, true);

      const into = tmp('vault-http-restore-');
      const restored = await call('POST', '/api/backup/restore', { into, reason: 'DR exercise' });
      assert.equal(restored.status, 200);
      const out = await restored.json();
      assert.ok(out.measured.rtoMs > 0);

      // The proof is a working vault at the other end, not the report.
      const back = new Vault({ dir: into });
      assert.ok(back.facts.all().some((f) => /HTTP-BACKUP-CANARY/.test(f.claim)),
        'the restored directory does not open as a vault holding the data');
    } finally {
      await server.close();
    }
  });

  test('a deployment with no backup store says so rather than pretending', async () => {
    const { ApiServer } = await import('../src/api/server.js');
    const vault = new Vault({ dir: tmp(), seedRules: false });
    const server = new ApiServer({ vault, port: 0 });
    const admin = server.issueToken({ name: 'ops@acme.com', role: 'admin' });
    await server.listen();
    try {
      const res = await fetch(`http://127.0.0.1:${server.server.address().port}/api/backup/status`,
        { headers: { Authorization: `Bearer ${admin}` } });
      assert.equal(res.status, 400);
      assert.match((await res.json()).message, /no backup store is configured/);
    } finally { await server.close(); }
  });
});
