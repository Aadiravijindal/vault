#!/usr/bin/env node
/**
 * Let the librarian organise the file room.
 *
 *   node bin/vault-organize.js --dir ./data                   one pass
 *   node bin/vault-organize.js --dir ./data --watch           keep organising
 *   node bin/vault-organize.js --dir ./data --proposals       what it wants a decision on
 *   node bin/vault-organize.js --dir ./data --approve <id> --by ciso --reason "..." [--read sales]
 *   node bin/vault-organize.js --dir ./data --reject  <id> --by ciso --reason "..."
 *   node bin/vault-organize.js --dir ./data --notices         what it thinks you should see
 *   node bin/vault-organize.js --dir ./data --memory          what it has learned
 *
 * This runs off the write path on purpose. The gate publishes a latency budget
 * and a model call would blow it, so facts are filed instantly by the rules and
 * refined afterwards — never unprotected in between.
 *
 * --watch is the mode most estates want: a fact arrives, gets filed by the
 * rules within its budget, and is tidied a few minutes later without anybody
 * pressing anything.
 */
import { Vault } from '../src/index.js';

const args = process.argv.slice(2);
const flag = (name, fallback = null) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? (args[i + 1] ?? true) : fallback;
};
const has = (name) => args.includes(`--${name}`);

const vault = new Vault({ dir: flag('dir'), administrators: String(flag('administrators', '') || '').split(',').filter(Boolean), seedRules: false });
const json = has('json');
const lib = vault.librarian;

// -- decisions on proposals -------------------------------------------------

const approve = flag('approve');
const reject = flag('reject');
if (approve || reject) {
  const by = flag('by');
  const reason = flag('reason');
  if (!by || !reason) {
    console.error('a decision on a folder needs a name and a reason: --by <name> --reason "<why>"');
    console.error('"who approved this category, and when" is the question an auditor asks');
    process.exit(2);
  }
  try {
    if (approve) {
      const read = flag('read');
      const r = lib.approveProposal(approve, {
        actor: by, reason,
        read: read ? String(read).split(',') : null,
        write: flag('write') ? String(flag('write')).split(',') : null,
        adminOnly: has('admin-only')
      });
      console.log(`\n  created ${r.folder.path}`);
      console.log(`  readable by ${r.folder.read.join(', ')}, writable by ${r.folder.write.join(', ')}`);
      console.log(`  approved by ${by} — ${reason}\n`);
    } else {
      lib.rejectProposal(reject, { actor: by, reason });
      console.log(`\n  rejected — ${reason}\n`);
    }
  } catch (e) {
    console.error(`\n  refused: ${e.message}\n`);
    process.exit(1);
  }
  process.exit(0);
}

// -- read-only views --------------------------------------------------------

if (has('proposals')) {
  const open = lib.openProposals();
  if (json) { console.log(JSON.stringify(open, null, 2)); process.exit(0); }
  console.log('');
  if (!open.length) { console.log('  no folders proposed.\n'); process.exit(0); }
  console.log(`  ${open.length} folder(s) proposed. Nothing has been created — a folder is a wall,`);
  console.log('  so a named administrator decides and that name is what an auditor is shown.\n');
  for (const p of open) {
    console.log(`  ${p.id}`);
    console.log(`    ${p.path}${p.parentExists ? '' : '   ⚠ parent does not exist'}`);
    console.log(`    wanted for ${p.count} fact(s) — ${p.because}`);
    if (p.suggestedWall) console.log(`    the model suggested: ${p.suggestedWall}  (you set the real one)`);
    console.log('');
  }
  console.log(`  approve:  node bin/vault-organize.js --approve ${open[0].id} --by <you> --reason "…" --read <dept>`);
  console.log(`  reject:   node bin/vault-organize.js --reject  ${open[0].id} --by <you> --reason "…"\n`);
  process.exit(0);
}

if (has('notices')) {
  // The wall applies to whoever is running this, exactly as it does in the UI —
  // there is no admin bypass anywhere else in this product and there is not one
  // here. Name yourself and your department to see your own inbox.
  const inbox = lib.inbox({
    actor: {
      id: flag('as', 'operator'),
      kind: 'human',
      department: flag('department'),
      administrator: true
    }
  });
  if (json) { console.log(JSON.stringify(inbox, null, 2)); process.exit(0); }
  console.log('');
  for (const n of inbox.notices) {
    console.log(`  ${n.level === 'urgent' ? '🔴' : '🟡'} ${n.createdAt.slice(0, 19).replace('T', ' ')}  ${n.folder ?? ''}`);
    console.log(`     ${n.why}`);
    if (n.excerpt) console.log(`     "${n.excerpt}"`);
    console.log('');
  }
  if (!inbox.notices.length) console.log('  nothing flagged that you can see.\n');
  // Printed whether or not anything was shown. "Nothing flagged" next to a
  // hidden count is the same failure as a silent drop: the reader concludes
  // there is nothing there, and there is.
  if (inbox.withheld) {
    console.log(`  ${inbox.note}\n`);
    for (const r of inbox.withheldSummary) {
      console.log(`    ${r.urgent ? '🔴' : '🟡'} ${String(r.folder).padEnd(24)} ${r.total} notice(s)`
        + `${r.urgent ? `, ${r.urgent} urgent` : ''}   latest ${r.latestAt.slice(0, 16).replace('T', ' ')}`);
    }
    console.log('');
    console.log('  Run with --as <your name> --department <dept> to read the ones addressed to you.\n');
  }
  process.exit(0);
}

if (has('memory')) {
  const s = vault.memory.status();
  if (json) { console.log(JSON.stringify(s, null, 2)); process.exit(0); }
  console.log('');
  console.log(`  ${s.format}   ${s.path ?? '(in memory only — nothing is being persisted)'}`);
  console.log(`  ${s.size.tokens} vocabulary entries · ${s.size.clients} named entities · ${s.revisions} revisions`
    + `${s.bytesOnDisk ? ` · ${s.bytesOnDisk} bytes on disk` : ''}`);
  console.log(`  integrity: ${s.integrity.ok ? 'intact' : `BROKEN — ${s.integrity.problems.map((p) => p.problem).join(', ')}`}`);
  console.log('');
  if (s.topClients.length) {
    console.log('  WHAT IT KNOWS ABOUT WHOM');
    for (const c of s.topClients) console.log(`    ${String(c.name).padEnd(28)} ${c.observations} observation(s) → ${c.usualFolder}`);
    console.log('');
  }
  if (s.recentCorrections.length) {
    console.log('  RECENT CORRECTIONS (a human correction is weighted above anything the model decided alone)');
    for (const c of s.recentCorrections) console.log(`    ${c.at.slice(0, 10)}  ${c.from} → ${c.to}  (${c.by})`);
    console.log('');
  }
  console.log(wrap(s.statement, 74, '  '));
  console.log('');
  process.exit(0);
}

// -- the pass itself --------------------------------------------------------

const limit = Number(flag('limit', 50));
const actor = flag('by', 'ai-librarian');

async function pass() {
  const r = await vault.organize({ limit, actor });
  if (json) { console.log(JSON.stringify(r, null, 2)); return r; }
  if (!r.ran) {
    console.log(`\n  did not run — ${r.reason}\n`);
    console.log(wrap(r.statement, 74, '  '));
    console.log('\n  node bin/vault-model.js  shows how to switch a model on.\n');
    return r;
  }
  console.log('');
  console.log(`  ${new Date().toISOString().slice(0, 19).replace('T', ' ')}  `
    + `${r.considered} considered · ${r.tagged.length} tagged · ${r.moved.length} moved · `
    + `${r.proposed.length} proposed · ${r.notices.length} flagged · ${r.durationMs}ms`);
  for (const t of r.tagged) console.log(`      tag   ${t.id}  ${t.tags.join(', ')}`);
  for (const m of r.moved) console.log(`      move  ${m.id}  ${m.from} → ${m.to}  (${m.by}${m.why ? `: ${m.why}` : ''})`);
  for (const p of r.proposed) console.log(`      NEW   ${p.path}  — ${p.because}   [needs an administrator]`);
  for (const n of r.notices) console.log(`      ${n.level === 'urgent' ? '🔴' : '🟡'}  ${n.factId}  ${n.why}`);
  if (r.considered) {
    console.log('');
    console.log(`      ${r.modelCalls} model call(s); ${r.considered - r.modelCalls} settled by the learned memory without one.`);
  }
  console.log('');
  return r;
}

const r = await pass();

if (has('watch')) {
  const intervalMs = Number(flag('interval-ms', 5 * 60 * 1000));
  console.log(`  watching — organising every ${Math.round(intervalMs / 1000)}s. Ctrl-C to stop.\n`);
  const timer = setInterval(() => { pass().catch((e) => console.error(`  pass failed: ${e.message}`)); }, intervalMs);
  process.on('SIGINT', () => { clearInterval(timer); vault.memory.save({ actor, reason: 'shutdown' }); process.exit(0); });
} else {
  if (r.ran) vault.memory.save({ actor, reason: 'organise pass' });
  process.exit(0);
}

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
