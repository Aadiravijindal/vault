#!/usr/bin/env node
/**
 * The audit record, on the command line.
 *
 *   node bin/vault-journal.js --dir ./data                         recent activity
 *   node bin/vault-journal.js --dir ./data --subject f-abc123      one record's whole life
 *   node bin/vault-journal.js --dir ./data --actor dana            everything one person did
 *   node bin/vault-journal.js --dir ./data --refusals              what people asked for and did not get
 *   node bin/vault-journal.js --dir ./data --verify                does the chain hold
 *   node bin/vault-journal.js --dir ./data --export out.json --by ciso --reason "FCA request"
 *
 * This exists because an audit record that can only be read through a web
 * console is one that cannot be handed to somebody's own tooling. The export
 * is a signed, self-describing bundle that states how much of the journal it
 * contains — a filtered extract presented as a complete one is the oldest way
 * to mislead an auditor using nothing but true statements.
 */
import { writeFileSync } from 'node:fs';
import { Vault } from '../src/index.js';

const args = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? (args[i + 1] ?? true) : fallback;
};
const has = (name) => args.includes(`--${name}`);

const dir = flag('dir');
const json = has('json');
const vault = new Vault({ dir, seedRules: false });
const j = vault.journal;

if (has('verify')) {
  const r = j.verify();
  if (json) { console.log(JSON.stringify(r, null, 2)); process.exit(r.ok ? 0 : 1); }
  console.log('');
  console.log(r.ok
    ? `  ✓ the journal chain holds over all ${r.checked} entries`
    : `  ✗ ${r.problems.length} integrity problem(s) across ${r.checked} entries`);
  for (const p of r.problems.slice(0, 20)) console.log(`      seq ${p.seq}: ${p.problem}${p.missing ? ` (missing ${p.missing})` : ''}`);
  console.log('');
  process.exit(r.ok ? 0 : 1);
}

const out = flag('export');
if (out) {
  const by = flag('by');
  const reason = flag('reason');
  if (!by || !reason) {
    console.error('an export must name who is taking it and why: --by <name> --reason "<why>"');
    console.error('an unattributed copy of the audit record is not evidence, it is a leak');
    process.exit(2);
  }
  const bundle = j.export({
    exportedBy: by, reason,
    subject: flag('subject'), actor: flag('actor'), folder: flag('folder'), action: flag('action')
  });
  writeFileSync(out, JSON.stringify(bundle, null, 2));
  console.log('');
  console.log(`  wrote ${out}`);
  console.log(`  ${bundle.completeness.entriesInBundle} entries${bundle.signature ? ', signed' : ' (UNSIGNED — no customer key configured)'}`);
  console.log('');
  console.log(wrap(bundle.completeness.statement, 74, '  '));
  console.log('');
  process.exit(0);
}

const subject = flag('subject');
if (subject) {
  const d = j.dossier(subject, { facts: vault.facts, ledger: vault.ledger });
  if (json) { console.log(JSON.stringify(d, null, 2)); process.exit(0); }
  console.log('');
  console.log(`  ${d.subject}   (${d.subjectKind})`);
  if (d.fact) {
    console.log(`  ${trunc(d.fact.claim, 72)}`);
    console.log(`  ${d.fact.folder}  ·  ${d.fact.sensitivity}  ·  v${d.fact.version}  ·  ${d.fact.status}`
      + `${d.fact.tags?.length ? `  ·  ${d.fact.tags.join(', ')}` : ''}`
      + `${d.fact.locked ? '  ·  🔒 locked' : ''}${d.fact.golden ? '  ·  ★ golden' : ''}`);
  }
  console.log('');
  console.log(wrap(d.narrative, 74, '  '));
  console.log('');
  console.log('  WHEN                      WHO           WHAT               WHERE');
  for (const t of d.timeline) {
    console.log(`  ${t.at.slice(0, 19).replace('T', ' ')}   ${pad(t.who, 12)}  ${pad(t.action, 18)} ${t.where ?? ''}`
      + `${t.allowed === false ? '   ✗ REFUSED' : ''}`);
    if (t.why) console.log(`                              ↳ ${trunc(t.why, 68)}`);
    for (const c of t.changed ?? []) console.log(`                              ↳ ${c.field}: ${fmt(c.from)} → ${fmt(c.to)}`);
  }
  console.log('');
  process.exit(0);
}

const entries = has('refusals')
  ? j.refusals({ limit: Number(flag('limit', 50)) })
  : j.entries({
    actor: flag('actor'), action: flag('action'), folder: flag('folder'),
    limit: Number(flag('limit', 50))
  });

if (json) { console.log(JSON.stringify({ entries, stats: j.stats() }, null, 2)); process.exit(0); }

const s = j.stats();
console.log('');
console.log(`  ${s.entries} recorded action(s) · ${s.actors} actor(s) · ${s.refusals} refusal(s) · ${s.subjects} subject(s)`);
console.log(`  chain ${s.integrity.ok ? 'intact' : `BROKEN (${s.integrity.problems.length} problems)`}`);
console.log('');
if (!entries.length) {
  console.log('  nothing recorded yet.\n');
  process.exit(0);
}
console.log('  WHEN                  WHO           WHAT                SUBJECT');
for (const e of entries) {
  console.log(`  ${e.atIso.slice(0, 19).replace('T', ' ')}  ${pad(e.actor?.id ?? '—', 12)}  ${pad(e.action, 19)} ${trunc(e.subject ?? '', 24)}`
    + `${e.refusal ? '  ✗' : ''}`);
}
console.log('');
if (!has('refusals') && s.refusals) {
  console.log(`  ${s.refusals} refusal(s) are recorded. Run with --refusals to see what people asked for`);
  console.log('  and did not get — those are the entries an investigation turns on.\n');
}

function pad(s, n) { return String(s ?? '').slice(0, n).padEnd(n); }
function trunc(s, n) { const t = String(s ?? ''); return t.length > n ? t.slice(0, n - 1) + '…' : t; }
function fmt(v) { return Array.isArray(v) ? `[${v.join(', ')}]` : v === null ? '—' : trunc(String(v), 30); }
function wrap(text, width, indent = '') {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) { lines.push(line.trim()); line = w; }
    else line += ' ' + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => indent + l).join('\n');
}
