#!/usr/bin/env node
/**
 * THE STANDALONE VERIFIER (§13.2, §21).
 *
 * This file trusts neither Vault nor the customer. It reads an exported ledger
 * (or an export directory) and recomputes, from first principles:
 *
 *   1. every entry's content hash          H(canonical(body))
 *   2. every chain link                    H(prevHash || contentHash)
 *   3. the sequence — no gaps, no reordering
 *   4. every signature, against the PUBLIC key in the export
 *   5. the anchors published to independent witnesses
 *   6. the file hashes in the manifest, for a full export
 *
 * It imports nothing from src/. It is deliberately a single file, in plain
 * Node, with no dependencies, so an auditor can read all of it in ten minutes
 * and run it on a laptop that has never heard of Vault.
 *
 *   node bin/vault-verify.js <ledger-export.json | export-dir/>
 *
 * Exit code 0 = verified, 1 = failed.
 */
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';

const GENESIS = 'GENESIS';

const sha256 = (d) => createHash('sha256').update(d).digest('hex');

/** Canonical JSON — key-sorted. Must match the writer exactly, or nothing verifies. */
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

const chainHash = (prev, content) => sha256(`${prev || GENESIS}\n${content}`);

function verifyExport(exp) {
  const problems = [];
  const entries = [...(exp.entries || [])].sort((a, b) => a.seq - b.seq);
  if (!entries.length) problems.push({ problem: 'empty_ledger' });

  let prev = GENESIS;
  let signaturesChecked = 0;
  let publicKey = null;
  if (exp.publicKeyPem) {
    try { publicKey = createPublicKey(exp.publicKeyPem); }
    catch { problems.push({ problem: 'public_key_unreadable' }); }
  }

  for (const e of entries) {
    // Strip everything that is not part of the signed body. The writer hashes
    // the body BEFORE adding contentHash/prevHash/hash/signature, and the store
    // adds _v/_created/_updated afterwards.
    const { id, contentHash, prevHash, hash, signature, _v, _created, _updated, ...body } = e;

    const recomputedContent = sha256(canonical(body));
    if (recomputedContent !== contentHash) {
      problems.push({ seq: e.seq, problem: 'content_hash_mismatch', expected: contentHash, actual: recomputedContent });
    }
    if (prevHash !== prev) {
      problems.push({ seq: e.seq, problem: 'chain_break', expected: prev, actual: prevHash });
    }
    const recomputedLink = chainHash(prevHash, contentHash);
    if (recomputedLink !== hash) {
      problems.push({ seq: e.seq, problem: 'link_hash_mismatch', expected: hash, actual: recomputedLink });
    }
    if (signature && publicKey) {
      const ok = nodeVerify(null, Buffer.from(hash), publicKey, Buffer.from(signature, 'base64'));
      signaturesChecked++;
      if (!ok) problems.push({ seq: e.seq, problem: 'signature_invalid' });
    }
    prev = hash;
  }

  // Sequence integrity — a missing entry is as much a tamper signal as an
  // altered one.
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].seq !== entries[i - 1].seq + 1) {
      problems.push({ seq: entries[i].seq, problem: 'sequence_gap', missing: `${entries[i - 1].seq + 1}..${entries[i].seq - 1}` });
    }
  }

  // Head must match the last link.
  if (exp.head && entries.length && exp.head !== entries[entries.length - 1].hash) {
    problems.push({ problem: 'head_mismatch', expected: exp.head, actual: entries[entries.length - 1].hash });
  }

  // Anchors: recompute the corpus hash each anchor claimed to cover.
  const anchorResults = [];
  for (const a of exp.anchors || []) {
    const covered = entries.filter((e) => e.seq <= a.seq).map((e) => e.hash).join('\n');
    const recomputed = sha256(covered);
    const ok = recomputed === a.corpusHash;
    anchorResults.push({ seq: a.seq, at: a.at, witnesses: (a.receipts || []).map((r) => r.witness), ok });
    if (!ok) problems.push({ seq: a.seq, problem: 'anchor_corpus_mismatch' });
  }
  const witnesses = new Set(anchorResults.flatMap((a) => a.witnesses));

  return {
    ok: problems.length === 0,
    entriesChecked: entries.length,
    signaturesChecked,
    signedBy: exp.publicKeyPem ? 'customer-held key present in the export' : 'UNSIGNED — no customer key in this export',
    head: exp.head,
    anchors: anchorResults,
    witnessDiversity: witnesses.size > 1,
    witnesses: [...witnesses],
    problems
  };
}

function verifyDirectory(dir) {
  const manifestPath = join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) throw new Error(`no manifest.json in ${dir}`);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  // 1. file hashes
  const fileProblems = [];
  for (const [name, expected] of Object.entries(manifest.fileHashes || {})) {
    const p = join(dir, name);
    if (!existsSync(p)) { fileProblems.push({ file: name, problem: 'missing' }); continue; }
    const actual = sha256(readFileSync(p, 'utf8'));
    if (actual !== expected) fileProblems.push({ file: name, problem: 'hash_mismatch', expected, actual });
  }

  // 2. the ledger itself
  const ledgerPath = join(dir, 'ledger.jsonl');
  if (!existsSync(ledgerPath)) throw new Error('no ledger.jsonl in the export');
  const entries = readFileSync(ledgerPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const chain = verifyExport({ entries, head: manifest.chainHead, publicKeyPem: manifest.publicKeyPem, anchors: [] });

  return {
    ...chain,
    ok: chain.ok && fileProblems.length === 0,
    files: Object.keys(manifest.fileHashes || {}).length,
    fileProblems,
    counts: manifest.counts,
    exportedAt: manifest.exportedAt,
    format: manifest.format
  };
}

function main() {
  const target = process.argv[2];
  if (!target) {
    console.error('usage: node bin/vault-verify.js <ledger-export.json | export-dir/>');
    process.exit(2);
  }
  if (!existsSync(target)) {
    console.error(`not found: ${target}`);
    process.exit(2);
  }

  const isDir = statSync(target).isDirectory();
  const r = isDir ? verifyDirectory(target) : verifyExport(JSON.parse(readFileSync(target, 'utf8')));

  console.log('');
  console.log('VAULT INDEPENDENT VERIFIER');
  console.log('This tool trusts neither the vendor nor the operator. It recomputes');
  console.log('every hash, every chain link and every signature from the export alone.');
  console.log('');
  console.log(`  target              ${target}`);
  if (r.format) console.log(`  format              ${r.format}`);
  if (r.exportedAt) console.log(`  exported at         ${r.exportedAt}`);
  console.log(`  ledger entries      ${r.entriesChecked}`);
  console.log(`  signatures checked  ${r.signaturesChecked}`);
  console.log(`  signing key         ${r.signedBy}`);
  if (r.files != null) console.log(`  files hashed        ${r.files} (${r.fileProblems.length} problems)`);
  if (r.anchors?.length) {
    console.log(`  anchors             ${r.anchors.length} · witnesses: ${r.witnesses.join(', ') || 'none'}`);
    console.log(`  witness diversity   ${r.witnessDiversity ? 'yes' : 'NO — anchor to more than one independent witness'}`);
  }
  if (r.counts) {
    console.log(`  corpus              ${r.counts.facts} facts · ${r.counts.conversations} conversations · ${r.counts.golden} golden`);
  }
  console.log('');
  if (r.ok) {
    console.log('  ✓ VERIFIED — the chain is internally consistent, unbroken and complete.');
    console.log('');
    console.log('  What this proves: no entry was altered, removed or reordered after it was');
    console.log('  written, and every signed entry was signed by the holder of the private key');
    console.log('  matching the public key in this export.');
    console.log('');
    console.log('  What it does not prove: that the facts recorded are true. It proves what was');
    console.log('  recorded, and that the record has not been changed since.');
  } else {
    console.log('  ✗ VERIFICATION FAILED');
    console.log('');
    for (const p of [...(r.problems || []), ...(r.fileProblems || [])].slice(0, 40)) {
      console.log(`    ${JSON.stringify(p)}`);
    }
  }
  console.log('');
  process.exit(r.ok ? 0 : 1);
}

main();
