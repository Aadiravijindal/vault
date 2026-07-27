#!/usr/bin/env node
/**
 * Vault CLI.
 *
 *   vault serve [--port 8080] [--data ./data]
 *   vault status | doctor | map | coverage
 *   vault agent register --name N --owner O --tech-owner T [--folder sales/]
 *   vault agent [list|show|credential|revoke|suspend|retire|attest] <id>
 *   vault golden add "<claim>" --folder f --actor who --role CFO [--approver b]
 *   vault golden [list|due|verify|blast-radius|reattest] <id>
 *   vault ingest <file.json> [--credential vlt_…]
 *   vault ask "<query>" [--agent a-…]
 *   vault review [--folder sales/]
 *   vault rules [list|backtest "<plain>"|export yaml]
 *   vault ledger verify | export [file]
 *   vault privacy [status|preview <jur>|apply <jur>]
 *   vault killswitch [status|engage <level>|release|test]
 *   vault hygiene [--dry-run]
 *   vault insure | comply | value
 *   vault export <dir>
 */
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { ApiServer } from '../src/api/server.js';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flags = {};
const rest = [];
for (let i = 1; i < argv.length; i++) {
  if (argv[i].startsWith('--')) {
    const key = argv[i].slice(2);
    const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    flags[key] = val;
  } else rest.push(argv[i]);
}

const DATA = flags.data ? resolve(String(flags.data)) : resolve('./data');
const KEYFILE = join(DATA, 'signing-key.json');

/**
 * The signing key is generated and persisted BEFORE the Vault is constructed.
 * Construction itself appends ledger entries (bootstrap, seeded rules, folder
 * tree), so a key created afterwards would leave those first entries signed by
 * a key nobody can produce again — and `ledger verify` would call the whole
 * chain tampered on the very next run. Persist first, then build.
 */
function loadVault({ seedRules = true } = {}) {
  let signingKey = null;
  if (existsSync(KEYFILE)) {
    signingKey = JSON.parse(readFileSync(KEYFILE, 'utf8'));
  } else {
    signingKey = Ledger.newSigningKey();
    try {
      mkdirSync(DATA, { recursive: true });
      writeFileSync(KEYFILE, JSON.stringify(signingKey, null, 2), { mode: 0o600 });
    } catch (e) {
      console.error(`warning: could not persist the ledger signing key to ${KEYFILE} (${e.message}).`);
      console.error('         entries written in this run will not verify against a later run.');
    }
  }
  return new Vault({
    dir: DATA,
    signingKey,
    mirrorDir: join(DATA, 'mirror'),
    administrators: [process.env.VAULT_ADMIN || 'admin'],
    seedRules
  });
}

const out = (x) => console.log(typeof x === 'string' ? x : JSON.stringify(x, replacer, 2));
function replacer(k, v) {
  if (typeof v === 'function') return undefined;
  if (v instanceof Map) return Object.fromEntries(v);
  if (v instanceof Set) return [...v];
  return v;
}

const COMMANDS = {
  async serve() {
    const vault = loadVault();
    const server = new ApiServer({ vault, port: Number(flags.port) || 8080, host: flags.host || '0.0.0.0' });
    const tokens = {
      admin: server.issueToken({ name: process.env.VAULT_ADMIN || 'admin', role: 'admin', clearance: 'secret' }),
      security: server.issueToken({ name: 'ciso', role: 'security', clearance: 'secret', department: 'security' }),
      legal: server.issueToken({ name: 'gc', role: 'legal', clearance: 'secret', department: 'legal' })
    };
    await server.listen();
    console.log(`\n🔒 VAULT is running`);
    console.log(`   UI + API   http://localhost:${server.port}`);
    console.log(`   data       ${DATA}`);
    console.log(`   mirror     ${join(DATA, 'mirror')}`);
    console.log(`\n   tokens (this process only):`);
    for (const [role, t] of Object.entries(tokens)) console.log(`     ${role.padEnd(9)} ${t}`);
    console.log(`\n   ledger: ${vault.ledger.length} entries · facts: ${vault.facts.stats().total}`);
    console.log(`   ctrl-c to stop\n`);
    process.on('SIGINT', () => { console.log('\nstopping…'); server.close().then(() => process.exit(0)); });
  },

  async status() { out(loadVault().status()); },

  async doctor() {
    const d = loadVault().doctor();
    console.log(`\nVAULT DOCTOR — ${d.at}\n`);
    console.log(`  ledger chain      ${d.checks.ledger ? '✓' : '✗ FAILED'}`);
    console.log(`  fact integrity    ${d.checks.factIntegrity ? '✓' : '✗ FAILED'}`);
    console.log(`  three-way consistency ${d.checks.consistency ? '✓' : '✗ FAILED'}\n`);
    if (!d.problems.length) { console.log('  no problems found.\n'); return; }
    for (const p of d.problems) {
      console.log(`  [${p.severity.toUpperCase().padEnd(8)}] ${p.area}: ${p.detail}`);
      console.log(`             fix: ${p.fix}`);
    }
    console.log('');
    if (!d.ok) process.exitCode = 1;
  },

  async map() { out(loadVault().map()); },
  async coverage() {
    const c = loadVault().coverage();
    console.log(`\nCOVERAGE MAP — what Vault can and cannot see\n`);
    console.log('TOOL'.padEnd(34) + 'CONVOS  MEMORIES  BLOCK?  MODE'.padEnd(34) + 'NOTES');
    for (const r of c.rows) {
      console.log(
        String(r.tool).slice(0, 32).padEnd(34) +
        String(r.convos).padEnd(8) + String(r.memories).padEnd(10) +
        String(r.canBlock).padEnd(8) + String(r.mode).padEnd(14) +
        String(r.notes || '').slice(0, 70)
      );
    }
    console.log(`\n${c.honesty}\n${c.ruleOfThumb}\n`);
  },

  /**
   *   vault agent register --name … --owner … --tech-owner … [--folder sales/] [--mode inline]
   *   vault agent list | show <id> | credential <id> | suspend <id> | retire <id> | attest <id>
   */
  async agent() {
    const vault = loadVault();
    const sub = rest[0] || 'list';
    const actor = flags.actor || process.env.VAULT_ADMIN || 'admin';

    if (sub === 'list') {
      const inv = vault.registry.inventory();
      if (!inv.length) { console.log('\nno agents registered yet — vault agent register --name … --owner … --tech-owner …\n'); return; }
      console.log('\nID'.padEnd(26) + 'NAME'.padEnd(24) + 'MODE'.padEnd(9) + 'STATUS'.padEnd(11) + 'CREDENTIAL'.padEnd(12) + 'SCOPE');
      for (const a of inv) {
        const c = vault.registry.credentialState(a.id);
        console.log(
          String(a.id).padEnd(26) + String(a.name).slice(0, 22).padEnd(24) +
          String(a.mode).padEnd(9) + String(a.status).padEnd(11) +
          String(c.state).padEnd(12) + (a.folders.join(' ') || 'unrestricted')
        );
      }
      console.log('');
      return;
    }
    if (sub === 'register') {
      const agent = vault.registry.register({
        name: flags.name || rest[1],
        purpose: flags.purpose || '',
        businessOwner: flags.owner,
        technicalOwner: flags['tech-owner'] || flags.owner,
        department: flags.department || null,
        mode: flags.mode || 'inline',
        vendor: flags.vendor || null,
        tool: flags.tool || null,
        folders: flags.folder ? String(flags.folder).split(',') : [],
        sensitivityCeiling: flags.ceiling || 'internal',
        pinnedModel: flags.model || null,
        defaultFolder: flags.folder ? String(flags.folder).split(',')[0] : null,
        actor
      });
      const cred = vault.registry.issueCredential(agent.id, {
        origins: flags.origin ? String(flags.origin).split(',') : [],
        ttl: flags.ttl || '12h',
        actor
      });
      console.log(`\nregistered  ${agent.id}  ${agent.name}`);
      console.log(`owners      ${agent.businessOwner} (business) · ${agent.technicalOwner} (technical)`);
      console.log(`scope       ${agent.folders.join(', ') || 'unrestricted'} · up to ${agent.sensitivityCeiling}`);
      console.log(`\ncredential  ${cred.credential}`);
      console.log(`expires     ${cred.expiresAt}`);
      console.log(`\n${cred.note}`);

      // Folder walls are keyed on department, not on the agent's own scope list.
      // An agent registered without one is legal but mute, and finding that out
      // through a queue full of held writes is a bad first hour.
      const blocked = agent.folders.filter((f) => {
        try { return !vault.folders.check('write', { id: agent.id, kind: 'agent', department: agent.department }, f).allowed; }
        catch { return false; }
      });
      if (blocked.length) {
        console.log(`\nwarning: this agent may not write to ${blocked.join(', ')}.`);
        console.log(`         folder walls are keyed on department${agent.department ? ` and "${agent.department}" is not on the write list` : ', and this agent has none'}.`);
        console.log(`         re-register with --department <name>, or open the wall on the Walls screen.`);
      }
      console.log('');
      return;
    }

    const id = rest[1];
    if (!id) throw new Error(`usage: vault agent ${sub} <agent-id>`);
    if (sub === 'show') {
      out({ ...vault.registry.inventory().find((a) => a.id === id), credential: vault.registry.credentialState(id), baseline: vault.registry.baselineSummary(id) });
    } else if (sub === 'credential') {
      const cred = vault.registry.issueCredential(id, {
        origins: flags.origin ? String(flags.origin).split(',') : [],
        ttl: flags.ttl || '12h', actor
      });
      console.log(`\ncredential  ${cred.credential}\nexpires     ${cred.expiresAt}\n\n${cred.note}\n`);
    } else if (sub === 'revoke') {
      out(vault.registry.revokeCredential(id, { actor, reason: flags.reason || 'revoked via CLI' }));
    } else if (sub === 'suspend') {
      out(vault.registry.suspend(id, { actor, reason: flags.reason || 'suspended via CLI' }));
    } else if (sub === 'retire') {
      const r = vault.registry.retire(id, { actor, reason: flags.reason || 'retired via CLI', reassignTo: flags.reassign });
      console.log(`\nretired ${id}\n${r.note}\n`);
    } else if (sub === 'attest') {
      out(vault.registry.attest(id, { actor, notes: flags.notes || null }));
    } else {
      throw new Error('usage: vault agent [list|register|show|credential|revoke|suspend|retire|attest]');
    }
  },

  /**
   *   vault golden add "<claim>" --folder sales/pricing/ --actor cfo --role CFO [--approver ceo]
   *   vault golden list | due | verify <id> | blast-radius <id> | reattest <id>
   */
  async golden() {
    const vault = loadVault();
    const sub = rest[0] || 'list';
    const actor = flags.actor || process.env.VAULT_ADMIN || 'admin';

    if (sub === 'list' || sub === 'due') {
      // Golden facts live in their own more-restricted collection, not in the
      // general fact store — reading facts.all() finds none of them.
      const golden = sub === 'due' ? vault.facts.goldenDue() : vault.facts.goldenFacts();
      if (!golden.length) { console.log(`\nno golden facts ${sub === 'due' ? 'are due for re-attestation' : 'yet'}\n`); return; }
      for (const g of golden) {
        console.log(`\n★ ${g.id}  ${g.folder}  [${g.sensitivity}]`);
        console.log(`  ${g.claim}`);
        console.log(`  approved by ${g.approvedBy} (${g.approverRole})${g.secondApprover ? ` · four-eyes with ${g.secondApprover}` : ''}`);
        console.log(`  signed ${g.signature ? '✓' : '—'} · review due ${g.reviewDueAt ? new Date(g.reviewDueAt).toISOString().slice(0, 10) : 'n/a'}`);
      }
      console.log('');
      return;
    }

    if (sub === 'add') {
      const claim = rest.slice(1).join(' ');
      if (!claim) throw new Error('usage: vault golden add "<claim>" --folder <f> --actor <who> --role <authority> [--approver <who-else>]');
      if (!flags.role) throw new Error('a golden fact requires --role, the named authority of the person setting it (e.g. --role CFO)');
      const g = vault.createGoldenFact(
        {
          claim,
          folder: flags.folder || 'company/policies/',
          sensitivity: flags.sensitivity || 'internal',
          businessOwner: flags.owner || actor,
          reviewEvery: flags['review-every'] || '12mo'
        },
        { actor, actorKind: 'human', authorityRole: flags.role, secondApprover: flags.approver }
      );
      console.log(`\n★ golden ${g.id} created in ${g.folder}`);
      console.log(`  ${g.claim}`);
      console.log(`  approved by ${g.approvedBy} (${g.approverRole})${g.secondApprover ? ` · four-eyes with ${g.secondApprover}` : ''}`);
      console.log(`  signed ${g.signature ? '✓' : '— (no signing key configured)'} · review due ${new Date(g.reviewDueAt).toISOString().slice(0, 10)}\n`);
      return;
    }

    const id = rest[1];
    if (!id) throw new Error(`usage: vault golden ${sub} <golden-id>`);
    if (sub === 'verify') out(vault.facts.verifyGolden(id));
    else if (sub === 'blast-radius') out(vault.facts.goldenBlastRadius(id));
    else if (sub === 'reattest') {
      if (!flags.role) throw new Error('re-attestation requires --role');
      out(vault.facts.reattest(id, { actor, authorityRole: flags.role, secondApprover: flags.approver, newClaim: flags.claim || null }));
    } else throw new Error('usage: vault golden [list|due|add|verify|blast-radius|reattest]');
  },

  async ingest() {
    const file = rest[0];
    if (!file) throw new Error('usage: vault ingest <file.json>');
    const vault = loadVault();
    const payload = JSON.parse(readFileSync(file, 'utf8'));
    const items = Array.isArray(payload) ? payload : [payload];
    for (const raw of items) {
      const r = vault.ingest(raw, { credential: flags.credential });
      console.log(`${r.conversationId}  ${r.summary}`);
      for (const f of r.facts) {
        console.log(`   ${f.outcome.toUpperCase().padEnd(10)} ${f.claim}`);
        for (const why of f.reasons || []) console.log(`              ↳ ${why}`);
      }
    }
  },

  async ask() {
    const q = rest.join(' ');
    if (!q) throw new Error('usage: vault ask "<query>"');
    const vault = loadVault();
    console.log(vault.ask(q, {
      agentId: flags.agent, actor: flags.actor || 'cli',
      clearance: flags.clearance || 'confidential',
      purpose: flags.purpose || 'memory_governance'
    }));
  },

  async review() {
    const vault = loadVault();
    console.log('\n' + vault.review.render({ folder: flags.folder }) );
    const alarm = vault.review.volumeAlarm();
    if (alarm.alarm) console.log(`⚠️  ${alarm.message}\n`);
  },

  async rules() {
    const vault = loadVault();
    const sub = rest[0] || 'list';
    if (sub === 'list') {
      for (const r of vault.rules.all()) {
        console.log(`${r.id.padEnd(22)} ${r.state.padEnd(10)} ${r.action.padEnd(16)} ${r.name}`);
        console.log(`${' '.repeat(22)} ${r.expression}`);
      }
    } else if (sub === 'backtest') {
      const plain = rest.slice(1).join(' ');
      const r = vault.backtest({ plain });
      console.log(`\nPOLICY BACKTEST — "${plain}"`);
      console.log(`Run against: ${r.window} · ${r.evaluated} evaluated writes\n`);
      console.log(`  Would match:          ${r.wouldMatch}`);
      console.log(`     → legitimate:      ${r.legitimate}`);
      console.log(`     → look at NOW:     ${r.suspicious} ${r.suspicious ? '⚠️' : ''}`);
      console.log(`  False positive rate:  est. ${r.estimatedFalsePositiveRate}`);
      console.log(`  Reviewer load added:  ${r.reviewerLoadAdded}`);
      console.log(`  Agents affected:      ${r.agentsAffected.join(' · ') || 'none'}\n`);
      console.log(`  ${r.recommendation}\n`);
      console.log(`  [ ${r.actions.join(' ]  [ ')} ]\n`);
    } else if (sub === 'export') {
      console.log(vault.rules.exportAsCode(rest[1] || 'yaml'));
    } else if (sub === 'conflicts') {
      out(vault.rules.detectConflicts());
    }
  },

  async ledger() {
    const vault = loadVault();
    const sub = rest[0] || 'verify';
    if (sub === 'verify') {
      const v = vault.verifyLedger();
      const a = vault.ledger.verifyAnchors();
      console.log(`\nLEDGER VERIFICATION`);
      console.log(`  entries checked   ${v.checked}`);
      console.log(`  result            ${v.ok ? '✓ CLEAN' : '✗ TAMPERED'}`);
      console.log(`  head              ${v.head}`);
      console.log(`  duration          ${v.durationMs}ms`);
      console.log(`  anchors           ${a.results.length} (witness diversity: ${a.diverse ? 'yes' : 'no'})`);
      if (v.problems.length) { console.log('\n  PROBLEMS'); for (const p of v.problems) console.log(`    seq ${p.seq}: ${p.problem}`); }
      console.log(`\n  A chain we sign ourselves proves nothing to an adversary.`);
      console.log(`  Verify independently: node bin/vault-verify.js <export.json>\n`);
      if (!v.ok) process.exitCode = 1;
    } else if (sub === 'export') {
      const target = rest[1] || 'ledger-export.json';
      writeFileSync(target, JSON.stringify(vault.ledger.export(), null, 2));
      console.log(`wrote ${target} — run: node bin/vault-verify.js ${target}`);
    }
  },

  async privacy() {
    const vault = loadVault();
    const sub = rest[0] || 'status';
    if (sub === 'status') out(vault.privacy.status());
    else if (sub === 'preview') out(vault.privacyPreview(rest[1]));
    else if (sub === 'apply') {
      const r = vault.applyPrivacyMode(rest[1], { actor: flags.actor || 'cli', reason: flags.reason || 'set via CLI' });
      console.log(r.note);
    } else if (sub === 'pack') {
      const p = vault.privacy.compliancePack();
      for (const d of p.documents) console.log(`\n${'='.repeat(78)}\n${d.name}\n${'='.repeat(78)}\n${d.body}`);
    }
  },

  async killswitch() {
    const vault = loadVault();
    const sub = rest[0] || 'status';
    const actor = flags.actor || process.env.VAULT_ADMIN || 'admin';
    if (sub === 'status') out(vault.killswitch.specification());
    else if (sub === 'engage') out(vault.killswitch.engage(Number(rest[1]), { actor, reason: flags.reason || 'engaged via CLI', scope: flags.folder ? { folder: flags.folder } : null }));
    else if (sub === 'release') out(vault.killswitch.release({ actor, reason: flags.reason || 'released via CLI' }));
    else if (sub === 'test') {
      const r = vault.killswitch.test({ actor, level: Number(rest[1]) || 3 });
      console.log(`Kill switch test: ${r.passed ? '✓ PASSED' : '✗ FAILED'} in ${r.activationMs}ms (target ${r.target})`);
    }
  },

  async hygiene() {
    const vault = loadVault();
    const r = vault.runHygiene({ dryRun: Boolean(flags['dry-run']), actor: flags.actor || 'cli' });
    console.log(`\nHYGIENE ${flags['dry-run'] ? '(dry run)' : ''}`);
    console.log(`  deduplicated       ${r.deduplicated.merged}`);
    console.log(`  expired            ${r.expired.expired} (${r.expired.heldBack} held back by legal hold)`);
    console.log(`  contradictions     ${r.contradictions.length}`);
    console.log(`  decayed            ${r.decayed.decayed}`);
    console.log(`  summaries          ${r.summaries.length}`);
    console.log(`  drift              ${r.drift.length}`);
    console.log(`  orphans            ${r.orphans.length}`);
    console.log(`  stale              ${r.stale.length}`);
    console.log(`  single-source risk ${r.singleSource.length}`);
    console.log(`  golden due         ${r.goldenDue.length}`);
    console.log(`  consistency        ${r.consistency.ok ? '✓' : `✗ ${r.consistency.problems.length} problems`}\n`);
  },

  async insure() {
    const vault = loadVault();
    console.log(vault.insure.render(vault.insure.pack({ actor: flags.actor || 'cli', carrier: flags.carrier })));
  },

  async comply() {
    const vault = loadVault();
    const sub = rest[0] || 'controls';
    if (sub === 'controls') out(vault.comply.monitorControls());
    else if (sub === 'gaps') out(vault.comply.gapAnalysis(rest.slice(1).join(' ') || 'ISO 42001'));
    else if (sub === 'board') out(vault.comply.boardPack());
    else if (sub === 'crosswalk') out(vault.comply.crosswalk(rest.slice(1).join(' ') || null));
  },

  async value() {
    const vault = loadVault();
    console.log('\n' + vault.value.render());
    console.log('');
  },

  async export() {
    const vault = loadVault();
    const dir = rest[0] || './vault-export';
    const r = vault.exportAll({ actor: flags.actor || 'cli', dir, reason: flags.reason || 'CLI export' });
    console.log(`\nExported to ${r.written}`);
    console.log(`  files: ${r.files.join(', ')}`);
    console.log(`  facts ${r.manifest.counts.facts} · conversations ${r.manifest.counts.conversations} · ledger ${r.manifest.counts.ledgerEntries}`);
    console.log(`\n  Free, any time, any volume. Open documented format.`);
    console.log(`  Verify it without us: node bin/vault-verify.js ${dir}\n`);
  },

  async help() {
    console.log(readFileSync(new URL(import.meta.url), 'utf8').split('*/')[0].split('/**')[1].replace(/^\s*\*ap?/gm, '').replace(/^ \* ?/gm, ''));
  }
};

const fn = COMMANDS[cmd] || COMMANDS.help;
fn().catch((e) => {
  console.error(`\nerror: ${e.message}`);
  if (flags.debug) console.error(e.stack);
  process.exit(1);
});
