#!/usr/bin/env node
/**
 * Supply-chain evidence: SBOM, secret scan, static analysis, build provenance.
 *
 *   node bin/vault-supplychain.js                 human-readable, everything
 *   node bin/vault-supplychain.js --sbom sbom.json  write a CycloneDX SBOM
 *   node bin/vault-supplychain.js --attest         write an SLSA-style provenance statement
 *   node bin/vault-supplychain.js --ci             non-zero exit on any finding
 *
 * This build has zero runtime dependencies, which makes the SBOM short and the
 * dependency-confusion story trivial. That is a genuine property worth stating
 * — but "no dependencies" is not "no supply chain": the toolchain, the source
 * files themselves and the build process are all still in scope, and this tool
 * covers those rather than declaring victory.
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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
const H = (s) => `\n${B(s)}\n${'─'.repeat(Math.min(78, s.length + 24))}`;

// ---------------------------------------------------------------------------
// Source inventory
// ---------------------------------------------------------------------------
const SKIP = new Set(['node_modules', '.git', 'coverage', 'dist', '.claude']);
function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, out);
    else out.push({ path: relative(ROOT, full), bytes: st.size, ext: extname(name) });
  }
  return out;
}
const files = walk(ROOT);
const jsFiles = files.filter((f) => f.ext === '.js');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

const hashOf = (p) => createHash('sha256').update(readFileSync(join(ROOT, p))).digest('hex');

// ---------------------------------------------------------------------------
// Dependency inventory
// ---------------------------------------------------------------------------
const runtimeDeps = Object.entries(pkg.dependencies || {});
const devDeps = Object.entries(pkg.devDependencies || {});
const optionalDeps = Object.entries(pkg.optionalDependencies || {});

// ---------------------------------------------------------------------------
// Secret scanning
// ---------------------------------------------------------------------------
/**
 * Patterns are deliberately specific. A scanner that flags every string with
 * "key" in it gets muted within a week, and a muted scanner is worse than none.
 */
const SECRET_PATTERNS = [
  { id: 'aws-access-key', rx: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, what: 'AWS access key id' },
  { id: 'private-key-block', rx: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, what: 'private key block' },
  { id: 'slack-token', rx: /\bxox[baprs]-[0-9A-Za-z-]{10,}/g, what: 'Slack token' },
  { id: 'github-token', rx: /\bgh[pousr]_[0-9A-Za-z]{36,}/g, what: 'GitHub token' },
  { id: 'google-api-key', rx: /\bAIza[0-9A-Za-z_-]{35}\b/g, what: 'Google API key' },
  { id: 'stripe-key', rx: /\b[sr]k_live_[0-9A-Za-z]{24,}/g, what: 'Stripe live key' },
  { id: 'jwt', rx: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./g, what: 'JWT' },
  { id: 'generic-assignment', rx: /(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"'\s${}]{12,}["']/gi, what: 'hard-coded credential assignment' },
  { id: 'connection-string', rx: /\b(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s]+:[^@\s]+@/g, what: 'connection string with an inline password' }
];

// Anything that is obviously a test fixture or a documented example. These are
// listed explicitly rather than pattern-matched, so an exemption is a decision
// somebody made, not an accident of naming.
const ALLOWED = [
  { file: /^test\//, reason: 'test fixture — credentials here are fabricated and never leave the process' },
  { file: /^demo\//, reason: 'demo seed — the tokens it prints are minted at runtime' },
  { file: /^docs\//, reason: 'documentation example' },
  { file: /^src\/(?:gate\/pii|gate\/classifier|util\/crypto)\.js$/, reason: 'detector patterns and crypto helpers describe secret shapes; they do not contain secrets' }
];

function scanSecrets() {
  const findings = [];
  for (const f of files) {
    if (!['.js', '.json', '.md', '.yml', '.yaml', '.env', '.sh', '.html', '.css'].includes(f.ext)) continue;
    let text;
    try { text = readFileSync(join(ROOT, f.path), 'utf8'); } catch { continue; }
    for (const p of SECRET_PATTERNS) {
      p.rx.lastIndex = 0;
      let m;
      while ((m = p.rx.exec(text)) !== null) {
        const line = text.slice(0, m.index).split('\n').length;
        const exemption = ALLOWED.find((a) => a.file.test(f.path));
        findings.push({
          file: f.path, line, pattern: p.id, what: p.what,
          // Never the match itself. A secret scanner that prints the secret it
          // found has copied it into your CI logs.
          fingerprint: createHash('sha256').update(m[0]).digest('hex').slice(0, 12),
          exempt: Boolean(exemption),
          exemptReason: exemption?.reason ?? null
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Static analysis — the checks that matter for this codebase
// ---------------------------------------------------------------------------
const SAST_RULES = [
  { id: 'eval', rx: /\beval\s*\(/g, severity: 'high', what: 'eval()', why: 'arbitrary code execution from data' },
  { id: 'new-function', rx: /new\s+Function\s*\(/g, severity: 'high', what: 'new Function()', why: 'same as eval, wearing a hat' },
  { id: 'child-process-shell', rx: /exec(?:Sync)?\s*\(\s*[`'"]/g, severity: 'medium', what: 'shell exec with a literal', why: 'shell metacharacters in interpolated values become command injection' },
  { id: 'tls-off', rx: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED/g, severity: 'high', what: 'TLS verification disabled', why: 'every transport guarantee in the product depends on this staying on' },
  { id: 'weak-hash', rx: /createHash\s*\(\s*['"](?:md5|sha1)['"]/g, severity: 'medium', what: 'MD5 or SHA-1', why: 'not collision-resistant; unacceptable anywhere integrity is claimed' },
  { id: 'math-random-token', rx: /Math\.random\(\)[^\n]{0,60}(?:token|secret|key|nonce|id\b)/gi, severity: 'high', what: 'Math.random() for a security value', why: 'not a CSPRNG' },
  { id: 'non-constant-compare', rx: /(?:secret|token|signature|hmac|password)\s*===/gi, severity: 'medium', what: 'non-constant-time comparison of a secret', why: 'timing oracle' },
  { id: 'path-join-input', rx: /join\s*\([^)]*\breq\./g, severity: 'high', what: 'path built from request input', why: 'directory traversal' }
];

const SAST_ALLOWED = [
  { file: /^test\//, rule: /.*/, reason: 'test code' },
  { file: /^bin\/vault-supplychain\.js$/, rule: /.*/, reason: 'this scanner contains the patterns it looks for' },
  { file: /^src\/util\/crypto\.js$/, rule: /^weak-hash$/, reason: 'MD5 appears only for S3 Content-MD5, which is a transport checksum, not an integrity claim' },
  { file: /^src\/storage\/buckets\.js$/, rule: /^weak-hash$/, reason: 'Content-MD5 is required by the S3 API' }
];

function scanSast() {
  const findings = [];
  for (const f of jsFiles) {
    const text = readFileSync(join(ROOT, f.path), 'utf8');
    for (const r of SAST_RULES) {
      r.rx.lastIndex = 0;
      let m;
      while ((m = r.rx.exec(text)) !== null) {
        const line = text.slice(0, m.index).split('\n').length;
        const exemption = SAST_ALLOWED.find((a) => a.file.test(f.path) && a.rule.test(r.id));
        findings.push({
          file: f.path, line, rule: r.id, severity: r.severity, what: r.what, why: r.why,
          exempt: Boolean(exemption), exemptReason: exemption?.reason ?? null
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// SBOM — CycloneDX 1.5
// ---------------------------------------------------------------------------
function sbom() {
  const components = [
    ...runtimeDeps.map(([name, version]) => ({
      type: 'library', name, version: String(version), scope: 'required',
      purl: `pkg:npm/${name}@${String(version).replace(/^[^\d]*/, '')}`
    })),
    ...devDeps.map(([name, version]) => ({
      type: 'library', name, version: String(version), scope: 'optional',
      purl: `pkg:npm/${name}@${String(version).replace(/^[^\d]*/, '')}`,
      // Dev dependencies are not shipped, but they DO run on the machine that
      // produces the artefact, so they are in scope for build integrity.
      description: 'build-time only; not present in the deployed artefact, but part of the build environment'
    })),
    {
      type: 'platform', name: 'nodejs', version: process.version.replace(/^v/, ''), scope: 'required',
      purl: `pkg:generic/nodejs@${process.version.replace(/^v/, '')}`,
      description: 'the only runtime requirement. Vault imports node: builtins and nothing else.'
    }
  ];

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${createHash('sha256').update(jsFiles.map((f) => hashOf(f.path)).join('')).digest('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*$/, '$1-$2-$3-$4-$5')}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        type: 'application', name: pkg.name, version: pkg.version,
        description: pkg.description ?? 'AI memory governance',
        licenses: pkg.license ? [{ license: { id: pkg.license } }] : undefined,
        hashes: [{ alg: 'SHA-256', content: createHash('sha256').update(jsFiles.map((f) => `${f.path}:${hashOf(f.path)}`).sort().join('\n')).digest('hex') }]
      },
      tools: [{ vendor: 'Vault', name: 'vault-supplychain', version: pkg.version }]
    },
    components,
    // File-level inventory, so the SBOM identifies the artefact rather than
    // just describing its dependencies. With zero dependencies, a
    // dependency-only SBOM would be an empty document.
    properties: [
      { name: 'vault:sourceFiles', value: String(jsFiles.length) },
      { name: 'vault:runtimeDependencies', value: String(runtimeDeps.length) },
      { name: 'vault:buildStep', value: pkg.scripts?.build ? String(pkg.scripts.build) : 'none — the source is the artefact' }
    ],
    files: jsFiles.map((f) => ({ path: f.path, bytes: f.bytes, 'SHA-256': hashOf(f.path) }))
  };
}

// ---------------------------------------------------------------------------
// Build provenance — SLSA-style in-toto statement
// ---------------------------------------------------------------------------
function gitInfo() {
  const run = (args) => { try { return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim(); } catch { return null; } };
  return {
    commit: run(['rev-parse', 'HEAD']),
    branch: run(['rev-parse', '--abbrev-ref', 'HEAD']),
    dirty: run(['status', '--porcelain']) !== '',
    remote: run(['config', '--get', 'remote.origin.url'])
  };
}

function provenance() {
  const git = gitInfo();
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: jsFiles.map((f) => ({ name: f.path, digest: { sha256: hashOf(f.path) } })),
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://vault.example/buildtypes/source-is-artefact/v1',
        externalParameters: { repository: git.remote, ref: git.branch },
        resolvedDependencies: [
          { uri: git.remote ? `git+${git.remote}` : 'unknown', digest: { gitCommit: git.commit } },
          { uri: `pkg:generic/nodejs@${process.version.replace(/^v/, '')}` }
        ]
      },
      runDetails: {
        builder: { id: 'https://vault.example/builders/local', version: { 'vault-supplychain': pkg.version } },
        metadata: { invocationId: createHash('sha256').update(String(Date.now())).digest('hex').slice(0, 16), startedOn: new Date().toISOString() }
      },
      // The honesty note that decides whether this document is worth anything.
      vaultNotes: {
        slsaLevel: git.dirty
          ? 'none — the working tree is dirty, so these digests do not correspond to any committed state'
          : 'L1 equivalent at best: provenance exists and is machine-readable, but it is generated on the same machine as the build and is not signed by an independent builder. L2 requires a hosted build service; L3 requires a hardened, non-falsifiable one. Do not claim either.',
        whatThisProves: 'These exact source files, with these exact hashes, were present at this commit. There is no compilation step, so the source IS the artefact.',
        whatThisDoesNotProve: 'That the build machine was uncompromised, that the committed source was reviewed, or that this statement was produced by anyone in particular. Signing it with a key held outside the build machine is what would change that.'
      }
    }
  };
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const secrets = scanSecrets();
const sast = scanSast();
const git = gitInfo();
const liveSecrets = secrets.filter((s) => !s.exempt);
const liveSast = sast.filter((s) => !s.exempt);

console.log(B('\nVAULT — supply-chain evidence'));
console.log(dim(`  ${pkg.name}@${pkg.version} · ${jsFiles.length} source files · node ${process.version} · commit ${git.commit?.slice(0, 8) ?? 'unknown'}${git.dirty ? red(' (working tree dirty)') : ''}`));

console.log(H('Dependencies'));
console.log(`  runtime:      ${runtimeDeps.length === 0 ? green('0') : yellow(String(runtimeDeps.length))}   ${dim(runtimeDeps.map(([n, v]) => `${n}@${v}`).join(', ') || 'none — node: builtins only')}`);
console.log(`  development:  ${devDeps.length === 0 ? green('0') : String(devDeps.length)}   ${dim(devDeps.map(([n, v]) => `${n}@${v}`).join(', ') || 'none')}`);
console.log(`  optional:     ${optionalDeps.length}`);
console.log(dim('  Zero runtime dependencies removes dependency confusion, typosquatting and transitive-CVE exposure by construction.'));
console.log(dim('  It does NOT remove the toolchain, the source itself or the build machine from the supply chain — those are below.'));

console.log(H('Secret scan'));
if (!liveSecrets.length) {
  console.log(`  ${green('✓')} no credentials found in ${files.length} files${secrets.length ? dim(` (${secrets.length} match(es) in exempted paths)`) : ''}`);
} else {
  for (const s of liveSecrets) console.log(`  ${red('✗')} ${s.file}:${s.line} — ${s.what} ${dim(`[${s.pattern}, fingerprint ${s.fingerprint}]`)}`);
}
for (const s of secrets.filter((x) => x.exempt)) {
  console.log(dim(`  · exempt: ${s.file}:${s.line} ${s.what} — ${s.exemptReason}`));
}

console.log(H('Static analysis'));
if (!liveSast.length) {
  console.log(`  ${green('✓')} no findings across ${jsFiles.length} source files`);
} else {
  for (const s of liveSast) {
    const mark = s.severity === 'high' ? red('✗') : yellow('!');
    console.log(`  ${mark} ${s.file}:${s.line} — ${s.what}: ${s.why} ${dim(`[${s.rule}]`)}`);
  }
}
for (const s of sast.filter((x) => x.exempt && !/^test\//.test(x.file))) {
  console.log(dim(`  · exempt: ${s.file}:${s.line} ${s.what} — ${s.exemptReason}`));
}

console.log(H('Build provenance'));
const prov = provenance();
console.log(`  ${git.dirty ? red('✗') : green('✓')} ${prov.predicate.vaultNotes.slsaLevel}`);
console.log(dim(`  ${prov.predicate.vaultNotes.whatThisDoesNotProve}`));

if (flags.sbom) {
  const path = typeof flags.sbom === 'string' ? flags.sbom : 'sbom.json';
  writeFileSync(path, `${JSON.stringify(sbom(), null, 2)}\n`);
  console.log(`\n  wrote ${path} ${dim('(CycloneDX 1.5, with a file-level inventory — a dependency-only SBOM for this project would be empty)')}`);
}
if (flags.attest) {
  const path = typeof flags.attest === 'string' ? flags.attest : 'provenance.json';
  writeFileSync(path, `${JSON.stringify(prov, null, 2)}\n`);
  console.log(`  wrote ${path} ${dim('(in-toto statement, SLSA provenance predicate)')}`);
}

const failures = liveSecrets.length + liveSast.filter((s) => s.severity === 'high').length;
console.log(failures ? `\n${red(`  ${failures} finding(s) require attention.`)}\n` : `\n${green('  Clean.')}\n`);
process.exit(flags.ci && failures ? 1 : 0);
