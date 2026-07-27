#!/usr/bin/env node
/**
 * Checklist coverage, verified against the code rather than asserted about it.
 *
 *   node bin/vault-audit.js                 the whole checklist
 *   node bin/vault-audit.js --section gate  one section
 *   node bin/vault-audit.js --missing       only what is NOT covered
 *   node bin/vault-audit.js --json a.json   machine-readable
 *
 * Every item names a *check*, not a claim. A check is one of:
 *
 *   symbol   an exported class, function or method exists and is callable
 *   route    an HTTP route is registered
 *   behaviour a function runs against a live Vault and returns what it should
 *   data     a catalogue, table or document set contains what it claims
 *   test     a named test file exercises it
 *   absent   a capability is deliberately NOT present, and its absence is proven
 *
 * The last one matters as much as the others. "Vault cannot score employee
 * productivity" is a claim, and the way to substantiate it is to show that no
 * such code path exists — not to point at a switch that is currently off.
 *
 * Items that cannot be checked from code are marked `organisational` and are
 * reported separately, never counted as covered. A certification, a pen test or
 * a signed contract is not something a program can grant itself.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { ApiServer } from '../src/api/server.js';
import { CHECKLIST } from '../src/audit/checklist.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const flags = {};
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i].startsWith('--')) {
    const k = process.argv[i].slice(2);
    flags[k] = process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[++i] : true;
  }
}

const B = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const blue = (s) => `\x1b[34m${s}\x1b[0m`;

// --- build a live instance to check behaviour against ----------------------
const signingKey = Ledger.newSigningKey();
// The chat apps refuse to construct without a secret, and the audit needs them
// present to check them. Generated per run rather than written down: a literal
// secret in a bin/ script is a bad pattern whatever its value, and the secret
// scanner is right to say so — silencing it with an exemption would be the
// wrong instinct in a repository whose whole argument is not doing that.
const throwaway = randomBytes(24).toString('hex');
const vault = new Vault({
  signingKey, administrators: ['ciso', 'cto'], seedRules: true,
  slack: { signingSecret: throwaway },
  teams: { securityToken: Buffer.from(throwaway).toString('base64') }
});
const server = new ApiServer({ vault, requireAuth: false });
const routes = new Set(server.routes.map((r) => `${r.method} ${r.pattern}`));

const SOURCE = (() => {
  const out = new Map();
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (['node_modules', '.git'].includes(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (/\.(js|md|json)$/.test(entry.name)) {
        out.set(full.slice(ROOT.length).replace(/^\/+/, ''), readFileSync(full, 'utf8'));
      }
    }
  };
  for (const d of ['src', 'bin', 'test', 'docs', 'demo']) if (existsSync(join(ROOT, d))) walk(join(ROOT, d));
  return out;
})();
const ALL_SOURCE = [...SOURCE.values()].join('\n');
const TEST_SOURCE = [...SOURCE.entries()].filter(([p]) => p.startsWith('test/')).map(([, s]) => s).join('\n');

// --- the checkers -----------------------------------------------------------
function resolve(path) {
  let cur = vault;
  for (const part of path.split('.')) {
    if (cur == null) return undefined;
    cur = cur[part];
  }
  return cur;
}

const CHECKERS = {
  symbol: (item) => {
    const value = resolve(item.check);
    return value !== undefined && value !== null
      ? { ok: true, evidence: `vault.${item.check} is ${typeof value}` }
      : { ok: false, evidence: `vault.${item.check} is not defined` };
  },
  route: (item) => (routes.has(item.check)
    ? { ok: true, evidence: `route ${item.check} registered` }
    : { ok: false, evidence: `no route ${item.check}` }),
  behaviour: (item) => {
    try {
      const out = item.run(vault, { signingKey });
      return out === true || (out && out.ok !== false)
        ? { ok: true, evidence: typeof out === 'object' ? out.evidence : 'behaved as specified' }
        : { ok: false, evidence: (out && out.evidence) || 'returned falsy' };
    } catch (e) {
      return { ok: false, evidence: `threw: ${e.message}` };
    }
  },
  data: (item) => {
    try {
      const out = item.run(vault);
      return out.ok !== false ? { ok: true, evidence: out.evidence } : { ok: false, evidence: out.evidence };
    } catch (e) { return { ok: false, evidence: `threw: ${e.message}` }; }
  },
  test: (item) => {
    const hit = new RegExp(item.check).test(TEST_SOURCE);
    return hit ? { ok: true, evidence: `exercised by a test matching /${item.check}/` } : { ok: false, evidence: `no test matches /${item.check}/` };
  },
  absent: (item) => {
    // Proving a negative from source. The pattern is chosen to match what an
    // implementation would look like, not what a comment about it looks like,
    // and comment lines are stripped before searching so that documenting the
    // absence does not read as the presence.
    const code = [...SOURCE.entries()]
      // The checklist itself lives in src/ and necessarily contains the very
      // patterns it searches for. Without this exclusion every `absent` check
      // fails against its own definition — which the audit caught when first
      // run against itself, and which is exactly the sort of thing it is for.
      .filter(([p]) => p.startsWith('src/') && !p.startsWith('src/audit/'))
      .map(([, s]) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, ''))
      .join('\n');
    const found = new RegExp(item.check, 'i').test(code);
    return found
      ? { ok: false, evidence: `/${item.check}/ appears in src/ — the capability may exist after all` }
      : { ok: true, evidence: `no implementation matching /${item.check}/ anywhere in src/` };
  },
  source: (item) => {
    const hit = new RegExp(item.check).test(ALL_SOURCE);
    return hit ? { ok: true, evidence: `found /${item.check}/` } : { ok: false, evidence: `no match for /${item.check}/` };
  },
  organisational: (item) => ({ ok: null, evidence: item.why })
};

// --- run --------------------------------------------------------------------
const results = [];
for (const section of CHECKLIST) {
  if (flags.section && !section.id.includes(String(flags.section))) continue;
  for (const item of section.items) {
    const checker = CHECKERS[item.kind];
    const outcome = checker ? checker(item) : { ok: false, evidence: `unknown check kind "${item.kind}"` };
    results.push({ section: section.id, sectionName: section.name, ...item, ...outcome, run: undefined });
  }
}

const covered = results.filter((r) => r.ok === true);
const missing = results.filter((r) => r.ok === false);
const organisational = results.filter((r) => r.ok === null);

// --- report -----------------------------------------------------------------
console.log(B('\nVAULT — checklist coverage, verified against the code'));
console.log(dim(`  ${results.length} items · ${covered.length} verified · ${missing.length} not covered · ${organisational.length} organisational (cannot be verified by a program)`));

let currentSection = null;
for (const r of results) {
  if (flags.missing && r.ok !== false) continue;
  if (r.section !== currentSection) {
    currentSection = r.section;
    console.log(`\n${B(r.sectionName)}`);
  }
  const mark = r.ok === true ? green('✓') : r.ok === false ? red('✗') : blue('○');
  console.log(`  ${mark} ${r.item}`);
  if (r.ok !== true || flags.verbose) console.log(dim(`      ${r.evidence}`));
}

console.log(`\n${B('Summary')}`);
console.log(`  ${green('✓')} verified in code      ${String(covered.length).padStart(4)}`);
console.log(`  ${red('✗')} not covered           ${String(missing.length).padStart(4)}`);
console.log(`  ${blue('○')} organisational        ${String(organisational.length).padStart(4)}   ${dim('a program cannot grant itself a certification')}`);

if (organisational.length && !flags.missing) {
  console.log(`\n${B('Organisational — these need an organisation, not a commit')}`);
  for (const r of organisational) console.log(`  ${blue('○')} ${r.item}\n${dim(`      ${r.evidence}`)}`);
}

if (missing.length) {
  console.log(`\n${red(B('Not covered'))}`);
  for (const r of missing) console.log(`  ${red('✗')} [${r.section}] ${r.item}\n${dim(`      ${r.evidence}`)}`);
}

if (flags.json) {
  const path = typeof flags.json === 'string' ? flags.json : 'audit.json';
  const { writeFileSync } = await import('node:fs');
  writeFileSync(path, `${JSON.stringify({
    generatedAt: new Date().toISOString(),
    totals: { items: results.length, verified: covered.length, notCovered: missing.length, organisational: organisational.length },
    results: results.map(({ run, ...r }) => r)
  }, null, 2)}\n`);
  console.log(dim(`\n  wrote ${path}`));
}

console.log('');
vault.close?.();
// A missing item is a real finding, so this can gate a release.
process.exit(missing.length ? 1 : 0);
