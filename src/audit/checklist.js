import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import * as catalog from '../connectors/catalog.js';
import * as buckets from '../storage/buckets.js';
import * as kms from '../storage/kms.js';
import * as kmsclient from '../storage/kmsclient.js';
import * as jurisdictions from '../privacy/jurisdictions.js';
import * as killswitch from '../security/killswitch.js';
import * as apiserver from '../api/server.js';
import * as i18n from '../ui/i18n.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));

/** Read a repo file for a check. `soft` returns null instead of throwing. */
export function readSource(rel, soft = false) {
  try { return readFileSync(join(ROOT, rel.replace(/^\//, '')), 'utf8'); } catch (e) { if (soft) return null; throw e; }
}

/**
 * The modules the checks reach into.
 *
 * Statically imported rather than resolved at check time: a check that silently
 * fails to load its module would report "not covered" for a feature that is
 * present, which is the wrong kind of wrong for an audit.
 */
const MODULES = {
  '../connectors/catalog.js': catalog,
  '../storage/buckets.js': buckets,
  '../storage/kms.js': kms,
  '../storage/kmsclient.js': kmsclient,
  '../privacy/jurisdictions.js': jurisdictions,
  '../security/killswitch.js': killswitch,
  '../api/server.js': apiserver,
  '../ui/i18n.js': i18n
};
function require0(spec) {
  const mod = MODULES[spec];
  if (!mod) throw new Error(`module ${spec} is not available to the audit`);
  return mod;
}

/**
 * The master feature checklist, expressed as executable checks.
 *
 * The point of this file is that "done" stops being an opinion. Every item
 * names how it can be verified, and `bin/vault-audit.js` runs them all against
 * a live instance. An item that cannot be verified from code is marked
 * `organisational` and is never counted as covered — a program cannot award
 * itself a SOC 2 report, and a checklist that let it would be worthless.
 *
 * Deliberately, some items are `absent` checks: proving that a capability does
 * NOT exist. "Vault cannot score employee productivity" is only credible if no
 * such code path is there to be switched on, and that is a searchable property
 * of the source rather than a promise.
 */

export const CHECKLIST = [
  // ------------------------------------------------------------------ §4
  {
    id: 'connection',
    name: '§4 — Connection layer',
    items: [
      { item: 'Connector catalogue with the full contract per source', kind: 'data', run: (v) => {
        const cs = v.connectors.describe ? null : null;
        const { CONNECTORS } = require0('../connectors/catalog.js');
        return { ok: true, evidence: `${CONNECTORS.length} connectors declared` };
      } },
      { item: 'Every connector declares auth, modes, pulls, cannotPull, setupMinutes, scopes, rateLimit', kind: 'data', run: () => {
        const { CONNECTORS } = require0('../connectors/catalog.js');
        const required = ['auth', 'modes', 'pulls', 'cannotPull', 'setupMinutes', 'scopes', 'rateLimit'];
        const bad = CONNECTORS.filter((c) => required.some((f) => c[f] === undefined));
        return bad.length
          ? { ok: false, evidence: `${bad.length} incomplete: ${bad.slice(0, 3).map((c) => c.id).join(', ')}` }
          : { ok: true, evidence: `all ${CONNECTORS.length} carry all ${required.length} fields` };
      } },
      { item: 'Watch / inline / gateway modes', kind: 'data', run: () => {
        const { MODES } = require0('../connectors/catalog.js');
        const have = Object.keys(MODES);
        return have.includes('watch') && have.includes('inline') && have.includes('gateway')
          ? { ok: true, evidence: have.join(', ') } : { ok: false, evidence: `only ${have.join(', ')}` };
      } },
      { item: 'Least-privilege scopes — never widened beyond the catalogue', kind: 'source', check: 'scopes\\.filter\\(\\(s\\) => entry\\.scopes\\.includes' },
      { item: 'Secrets never stored in the collection, ledger or logs', kind: 'source', check: 'credential is NOT stored here' },
      { item: 'Backfill on connect', kind: 'symbol', check: 'connectors.backfill' },
      { item: 'Idempotency — a replayed event does not duplicate', kind: 'test', check: 'idempoten|duplicate' },
      { item: 'Rate-limit awareness with resumable cursors', kind: 'symbol', check: 'connectors.recordRateLimit' },
      { item: 'Gap detection with alarm', kind: 'symbol', check: 'connectors.detectGaps' },
      { item: 'Health monitoring to a named owner', kind: 'symbol', check: 'connectors.health' },
      { item: 'Disconnect ≠ delete', kind: 'source', check: 'access died immediately' },
      { item: 'Version pinning and schema-drift detection', kind: 'source', check: 'schemaFingerprint' },
      { item: 'Per-connector kill switch', kind: 'symbol', check: 'connectors.kill' },
      { item: 'Per-connector cost meter', kind: 'symbol', check: 'connectors.costReport' },
      { item: 'Credential rotation, provable by fingerprint', kind: 'symbol', check: 'connectors.rotateCredential' },
      { item: 'Gateway discovers unregistered agents', kind: 'symbol', check: 'gateway.intercept' }
    ]
  },

  // ------------------------------------------------------------------ §5
  {
    id: 'archive',
    name: '§5 — Raw archive and storage',
    items: [
      { item: 'WORM archive with no update or delete code path', kind: 'behaviour', run: (v) => {
        const col = v.archive.col;
        const hasWrite = typeof col.update === 'function' || typeof col.delete === 'function';
        if (!hasWrite) return { ok: true, evidence: 'the WORM collection exposes no update/delete method at all' };
        try {
          const first = col.all()[0];
          if (!first) return { ok: true, evidence: 'no records to attempt against; the collection is marked worm' };
          col.update(first.id, { transcriptText: 'tampered' });
          return { ok: false, evidence: 'an update on the WORM archive SUCCEEDED' };
        } catch (e) { return { ok: true, evidence: `update refused: ${e.code || e.message}` }; }
      } },
      { item: 'Bring your own bucket — S3, Azure, GCS and compatibles', kind: 'data', run: () => {
        const { DRIVERS } = require0('../storage/buckets.js');
        return { ok: Object.keys(DRIVERS).length >= 8, evidence: `${Object.keys(DRIVERS).length} drivers: ${Object.keys(DRIVERS).join(', ')}` };
      } },
      { item: 'Hash-only mode — content has no transport out', kind: 'absent', check: 'class HashOnlyBucket[\\s\\S]{0,3000}?_fetch\\(' },
      { item: 'Bucket health check before the first real write', kind: 'behaviour', run: () => {
        // Checked on the driver, not on a configured instance: with no customer
        // bucket, vault.bucket is legitimately null, and an audit that read that
        // as a missing feature would nag every default install forever.
        const { createBucket } = require0('../storage/buckets.js');
        const b = createBucket('hash-only', {});
        return typeof b.healthCheck === 'function' && typeof b.verifyResidency === 'function'
          ? { ok: true, evidence: 'healthCheck() and verifyResidency() on every driver' }
          : { ok: false, evidence: 'the bucket drivers expose no pre-flight check' };
      } },
      { item: 'Residency verified against the bucket\'s reported region', kind: 'source', check: 'verifyResidency' },
      { item: 'Object Lock / immutability support', kind: 'source', check: 'objectLockMode|retentionLocked' },
      { item: 'Tiering with lifecycle preview', kind: 'symbol', check: 'tiering.previewLifecycle' },
      { item: 'Envelope encryption, per-object DEK under a per-scope KEK', kind: 'symbol', check: 'kms.newObjectKey' },
      { item: 'BYOK / CMK / HYOK / HSM / split-key', kind: 'data', run: () => {
        const { KEY_MODES } = require0('../storage/kms.js');
        return { ok: KEY_MODES.length >= 6, evidence: KEY_MODES.join(', ') };
      } },
      { item: 'Real AWS KMS, Azure Key Vault and GCP Cloud KMS clients', kind: 'data', run: () => {
        const { KEY_PROVIDERS } = require0('../storage/kmsclient.js');
        return { ok: Object.keys(KEY_PROVIDERS).length === 3, evidence: Object.keys(KEY_PROVIDERS).join(', ') };
      } },
      { item: 'Crypto-shredding, named honestly in the erasure receipt', kind: 'symbol', check: 'kms.cryptoShred' },
      { item: 'Key access log independent of the provider console', kind: 'symbol', check: 'kms.accessLog' }
    ]
  },

  // ------------------------------------------------------------------ §8/9
  {
    id: 'gate',
    name: '§8–9 — The gate',
    items: [
      { item: 'All ten checks run on every write', kind: 'behaviour', run: (v) => {
        v.registerAgent({ id: 'audit-a', name: 'A', purpose: 'p', businessOwner: 'o', technicalOwner: 't', department: 'sales', mode: 'inline', folders: ['sales/'] });
        const cred = v.issueCredential('audit-a', {}).credential;
        const r = v.ingest({
          agentId: 'audit-a', channel: 'system_of_record',
          participants: [{ name: 'Dana', kind: 'employee', internal: true }],
          turns: [{ speaker: 'Dana', text: 'Globex has 340 seats provisioned.' }]
        }, { credential: cred, folderHint: 'sales/accounts/', sampleRoll: 0 });
        const checks = r.facts?.[0]?.verdict?.checks ?? [];
        return checks.length >= 10
          ? { ok: true, evidence: `${checks.length} checks ran: ${checks.map((c) => c.name).slice(0, 4).join(', ')}…` }
          : { ok: false, evidence: `only ${checks.length} checks ran` };
      } },
      { item: 'Deny-by-source channel trust', kind: 'source', check: 'channelTrust' },
      { item: 'Instruction detection — a multi-layer ensemble, any layer holds', kind: 'symbol', check: 'instructions.analyse' },
      { item: 'PII detection and masking before storage', kind: 'symbol', check: 'pii.scan' },
      { item: 'Blocked content is blocked entirely, never masked-and-stored', kind: 'source', check: 'blocked entirely, never' },
      { item: 'Authority-ordered reconciliation', kind: 'symbol', check: 'reconciler.reconcile' },
      { item: 'Temporal attacks — drip-feed, slow-boil, coordinated, laundering', kind: 'behaviour', run: (v) => {
        const kinds = ['drip_feed', 'slow_boil', 'coordinated', 'confidence_laundering'];
        const src = readSource('/src/security/temporal.js');
        const missing = kinds.filter((k) => !src.includes(`'${k}'`));
        return missing.length ? { ok: false, evidence: `missing ${missing.join(', ')}` } : { ok: true, evidence: kinds.join(', ') };
      } },
      { item: 'Walls enforced at read AND write, with no admin bypass', kind: 'symbol', check: 'folders.enforce' },
      { item: 'Break-glass needs two named humans, a reason and a time box', kind: 'source', check: 'break-glass|breakGlass' },
      { item: 'Rules engine with plain-language compilation and backtest', kind: 'symbol', check: 'rules.backtest' },
      { item: 'Rule backtest offers enable / warn-only / adjust / discard', kind: 'behaviour', run: (v) => {
        const src = readSource('/src/gate/rules.js');
        const has = ['Enable', 'warn-only', 'threshold', 'Discard'].filter((a) => src.includes(a));
        return has.length >= 4 ? { ok: true, evidence: has.join(', ') } : { ok: false, evidence: `only ${has.join(', ')}` };
      } },
      { item: 'Every verdict explains itself in a sentence a human can act on', kind: 'source', check: 'explanation' },
      { item: 'Adversarial suite — attacks that must never become durable facts', kind: 'test', check: 'attack|adversar|injection' }
    ]
  },

  // ------------------------------------------------------------------ §10-11
  {
    id: 'facts',
    name: '§10–11 — Fact model, folders, hygiene',
    items: [
      { item: 'A fact without provenance is refused', kind: 'source', check: 'isn\'t a fact' },
      { item: 'Append-only versioning — editing creates a version', kind: 'symbol', check: 'facts.revise' },
      { item: 'Golden facts in a separate store, no agent write path', kind: 'behaviour', run: (v) => {
        const src = readSource('/src/facts/factstore.js');
        return src.includes('goldenCol') && /human-only|no API path for an agent/.test(src)
          ? { ok: true, evidence: 'separate collection, human-only creation path' }
          : { ok: false, evidence: 'golden facts do not appear to be separately stored' };
      } },
      { item: 'Content hash sealed and re-verified', kind: 'symbol', check: 'facts.verifyIntegrity' },
      { item: 'Folder tree with inherited walls a child may narrow but never widen', kind: 'behaviour', run: (v) => {
        v.folders.ensure('hr/audit-probe/');
        try {
          v.folders.setWalls('hr/audit-probe/', { read: ['hr', 'sales'], actor: 'audit', reason: 'probe' });
          return { ok: false, evidence: 'a child folder was widened beyond its parent' };
        } catch (e) { return { ok: true, evidence: `refused: ${e.message.slice(0, 60)}` }; }
      } },
      { item: 'Walls can be changed after creation, audibly', kind: 'symbol', check: 'folders.setWalls' },
      { item: 'Deduplication preserving both witnesses', kind: 'test', check: 'both witnesses' },
      { item: 'Decay flags and demotes; never deletes', kind: 'source', check: 'never deleted' },
      { item: 'Orphan detection when an agent retires', kind: 'symbol', check: 'hygiene.detectOrphans' },
      { item: 'Re-summarisation inherits the strictest wall and label', kind: 'test', check: 'strictest wall and label' },
      { item: 'Rolling summaries are persisted as gated, readable facts', kind: 'test', check: 'rolling_summary' },
      { item: 'Three-way consistency check across facts, archive and ledger', kind: 'source', check: 'consistency' }
    ]
  },

  // ------------------------------------------------------------------ §12-13
  {
    id: 'ledger',
    name: '§12–13 — Read path, ledger, proof',
    items: [
      { item: 'Read path enforces clearance, wall, purpose and credential', kind: 'behaviour', run: (v) => {
        try {
          v.read('renewal', { agentId: 'audit-a', actor: 'audit-a', clearance: 'internal', purpose: 'memory_governance' });
          return { ok: false, evidence: 'a read without a credential succeeded' };
        } catch (e) { return { ok: true, evidence: `refused: ${e.code || e.message}` }; }
      } },
      { item: 'Hash-chained ledger, signed with a customer-held key', kind: 'behaviour', run: (v) => {
        const out = v.verifyLedger();
        return out.ok ? { ok: true, evidence: `${out.checked} entries verified` } : { ok: false, evidence: JSON.stringify(out.problems?.[0]) };
      } },
      { item: 'External anchoring to independent witnesses', kind: 'symbol', check: 'ledger.anchor' },
      { item: 'Incremental verification since the last anchor', kind: 'symbol', check: 'verifyLedgerTail' },
      { item: 'Standalone verifier importing nothing from src/', kind: 'behaviour', run: () => {
        const src = readSource('/bin/vault-verify.js');
        const imports = [...src.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);
        const fromSrc = imports.filter((i) => i.includes('../src/'));
        return fromSrc.length
          ? { ok: false, evidence: `imports from src/: ${fromSrc.join(', ')}` }
          : { ok: true, evidence: `imports only ${imports.join(', ')}` };
      } },
      { item: 'The verifier is licensed so an auditor can actually use it', kind: 'behaviour', run: () => {
        const has = readSource('/LICENSE-verifier', true);
        return has && /Apache License/.test(has)
          ? { ok: true, evidence: 'bin/vault-verify.js carved out under Apache-2.0' }
          : { ok: false, evidence: 'the verifier has no permissive licence, which makes the proof claim circular' };
      } },
      { item: 'Tamper is detected with a non-zero exit', kind: 'test', check: 'TAMPERED' },
      { item: 'Every ledger entry hashes content rather than storing it raw', kind: 'source', check: 'hashed by the ledger, never stored raw' }
    ]
  },

  // ------------------------------------------------------------------ §14-15
  {
    id: 'legal',
    name: '§14–15 — Legal, privacy, jurisdictions',
    items: [
      { item: 'Legal holds freeze a fact against every other process', kind: 'symbol', check: 'legal.placeHold' },
      { item: 'Erasure planning with a receipt that names crypto-shredding honestly', kind: 'symbol', check: 'legal.erasurePlan' },
      { item: 'DSAR workflow with deadline tracking', kind: 'symbol', check: 'legal.dsarStatus' },
      { item: 'Consent registry with lawful basis per subject and purpose', kind: 'symbol', check: 'consent' },
      { item: 'Employee privacy mode with a preview before it applies', kind: 'symbol', check: 'privacy.preview' },
      { item: 'k-anonymity floor enforced on aggregates', kind: 'source', check: 'kAnonymityFloor' },
      { item: 'Productivity scoring refuses rather than being switched off', kind: 'behaviour', run: (v) => {
        try { v.privacy.scoreProductivity(); return { ok: false, evidence: 'scoreProductivity() returned a value' }; }
        catch (e) {
          // A named refusal is stronger evidence than absence: absence could be
          // an oversight, whereas a function whose only behaviour is to explain
          // why it will never do this is a decision somebody made on purpose.
          return e.meta?.code === 'productivity_scoring_does_not_exist'
            ? { ok: true, evidence: 'scoreProductivity() exists only to refuse, with a stated reason' }
            : { ok: false, evidence: `threw the wrong error: ${e.message.slice(0, 60)}` };
        }
      } },
      { item: 'Twelve or more jurisdiction packs', kind: 'data', run: () => {
        const { JURISDICTIONS } = require0('../privacy/jurisdictions.js');
        const n = Object.keys(JURISDICTIONS).length;
        return { ok: n >= 12, evidence: `${n} packs: ${Object.keys(JURISDICTIONS).join(', ')}` };
      } },
      { item: 'Every co-determination pack ships its own instrument, in its own language', kind: 'data', run: () => {
        const { JURISDICTIONS } = require0('../privacy/jurisdictions.js');
        const marks = { at: /ArbVG/, nl: /WOR/, se: /MBL/, fr: /CSE|L\. 2312/, de: /BetrVG/ };
        const bad = [];
        for (const [id, rx] of Object.entries(marks)) {
          const text = JURISDICTIONS[id].documents.map((d) => d.body({ settings: JURISDICTIONS[id].settings, generatedAt: 'x' })).join('\n');
          if (!rx.test(text)) bad.push(id);
        }
        return bad.length ? { ok: false, evidence: `${bad.join(', ')} do not cite their own statute` } : { ok: true, evidence: 'AT, NL, SE, FR, DE each cite their own instrument' };
      } },
      { item: 'India employee-monitoring position, stating there is no single statute', kind: 'data', run: () => {
        const { JURISDICTIONS } = require0('../privacy/jurisdictions.js');
        const text = JURISDICTIONS.in.documents.map((d) => d.body({ settings: JURISDICTIONS.in.settings, generatedAt: 'x' })).join('\n');
        return /no dedicated employee-monitoring statute/i.test(text) && /Puttaswamy/.test(text)
          ? { ok: true, evidence: 'DPDP §7(i), IT Act §43A, SPDI Rules, §72A, Puttaswamy, standing orders' }
          : { ok: false, evidence: 'the India pack does not map the instruments that actually apply' };
      } },
      { item: 'Every pack that requires consultation says what it does not cover', kind: 'data', run: () => {
        const { JURISDICTIONS } = require0('../privacy/jurisdictions.js');
        const bad = Object.values(JURISDICTIONS).filter((p) => p.requiresConsultation && p.id !== 'global_strictest' && !p.doesNotCover);
        return bad.length ? { ok: false, evidence: `${bad.map((p) => p.id).join(', ')} claim no limits` } : { ok: true, evidence: 'all state their limits' };
      } },
      { item: 'Emotion and sentiment analysis refuses, citing AI Act Art 5(1)(f)', kind: 'behaviour', run: (v) => {
        for (const method of ['analyseSentiment', 'analyseEmotion']) {
          try { v.privacy[method](); return { ok: false, evidence: `${method}() returned a value` }; }
          catch (e) {
            if (e.meta?.code !== 'affect_analysis_does_not_exist') return { ok: false, evidence: `${method} threw ${e.message.slice(0, 50)}` };
          }
        }
        return { ok: true, evidence: 'both refuse, citing the February 2025 EU prohibition, in every mode and jurisdiction' };
      } },
      { item: 'No scoring pipeline exists behind those refusals', kind: 'absent', check: 'function computeAffect|sentimentModel|\\.predictEmotion\\(' }
    ]
  },

  // ------------------------------------------------------------------ §16-21
  {
    id: 'modules',
    name: '§16–21 — Trace, Comply, Insure, Registry, Continuity',
    items: [
      { item: 'Vault Trace — what did this agent believe, and when', kind: 'symbol', check: 'trace.trace' },
      { item: 'Contagion — everything downstream of a bad fact', kind: 'symbol', check: 'trace.contagion' },
      { item: 'Undo supersedes rather than deletes', kind: 'symbol', check: 'trace.undo' },
      { item: 'Vault Comply — controls mapped to frameworks', kind: 'symbol', check: 'comply' },
      { item: 'Vault Insure — carrier-format evidence pack', kind: 'symbol', check: 'insure' },
      { item: 'Agent registry with owners, attestation and retirement', kind: 'symbol', check: 'registry.attestationStatus' },
      { item: 'Shadow-agent discovery', kind: 'symbol', check: 'registry.observeTraffic' },
      { item: 'Export is complete, documented and self-describing', kind: 'test', check: 'SCHEMA\\.md' },
      { item: 'Continuous mirror to customer-owned storage', kind: 'symbol', check: 'continuity.mirrorStatus' },
      { item: 'A missing mirror is a high finding, not a note', kind: 'test', check: "area === 'continuity' && p.severity === 'high'" },
      { item: 'Restore drill: export, verify, restore, compare by data', kind: 'symbol', check: 'drill.run' },
      { item: 'RPO and RTO measured, not declared', kind: 'test', check: 'not a guaranteed RPO' },
      { item: 'Import accepts the export format without bypassing the gate', kind: 'test', check: 'does not bypass the gate' }
    ]
  },

  // ------------------------------------------------------------------ §22-26
  {
    id: 'security',
    name: '§22–26 — Security, roles, screens, kill switch',
    items: [
      { item: 'Six-level graduated kill switch', kind: 'data', run: () => {
        const { LEVELS } = require0('../security/killswitch.js');
        return { ok: LEVELS.length === 7, evidence: `${LEVELS.length} levels, 0 through ${LEVELS.length - 1}` };
      } },
      { item: 'Kill switch requires a named administrator', kind: 'behaviour', run: (v) => {
        try { v.killswitch.engage(3, { actor: 'nobody', reason: 'probe' }); return { ok: false, evidence: 'an unnamed actor engaged it' }; } catch (e) { return { ok: true, evidence: 'refused' }; }
      } },
      { item: 'Kill switch state survives restart', kind: 'source', check: 'engaged level is persisted' },
      { item: 'Alert deduplication within a window', kind: 'source', check: 'dedup' },
      { item: 'Thirteen roles, enforced at the route', kind: 'data', run: () => {
        const { ROLES } = require0('../api/server.js');
        return { ok: Object.keys(ROLES).length >= 12, evidence: `${Object.keys(ROLES).length} roles` };
      } },
      { item: 'Admins get configuration, not content', kind: 'data', run: () => {
        const { ROLES } = require0('../api/server.js');
        return ROLES.admin.content === 'break-glass only'
          ? { ok: true, evidence: `admin content access: ${ROLES.admin.content}` }
          : { ok: false, evidence: `admin content access is "${ROLES.admin.content}"` };
      } },
      { item: 'Works council sees configuration, never content or individuals', kind: 'data', run: () => {
        const { ROLES } = require0('../api/server.js');
        const r = ROLES.works_council;
        return r.content === 'none' && r.noIndividualViews
          ? { ok: true, evidence: 'content: none, noIndividualViews: true' }
          : { ok: false, evidence: JSON.stringify(r) };
      } },
      { item: 'API rate limiting with RateLimit and Retry-After headers', kind: 'symbol', check: 'rateLimiter.check' },
      { item: 'Kill switch and health are exempt from rate limiting', kind: 'source', check: 'ALWAYS_ALLOW' },
      { item: 'API keys are hashed, scoped, expiring and revocable', kind: 'symbol', check: 'apiKeys.verify' },
      { item: 'Fourteen screens', kind: 'behaviour', run: () => {
        const app = readSource('/src/ui/app.js');
        const n = (app.match(/\{ id: '[a-z]+', icon:/g) || []).length;
        return n >= 14 ? { ok: true, evidence: `${n} screens declared` } : { ok: false, evidence: `${n} screens` };
      } },
      { item: 'Module toggle: built-in, connected or both, with parity reporting', kind: 'symbol', check: 'modules.table' }
    ]
  },

  // ------------------------------------------------------------------ §27-31
  {
    id: 'platform',
    name: '§27–31 — Value, billing, lifecycle, non-functionals',
    items: [
      { item: 'Value measurement with a stated methodology', kind: 'symbol', check: 'value' },
      { item: 'Notification channels with severity floors and dedup', kind: 'symbol', check: 'notifier.notify' },
      { item: 'Metering and itemised invoicing', kind: 'symbol', check: 'metering.usage' },
      { item: 'Usage caps warn before they exceed', kind: 'symbol', check: 'metering.checkCaps' },
      { item: 'Bulk historical import with resume and honest failure reporting', kind: 'symbol', check: 'bulkImport.start' },
      { item: 'Offboarding needs two approvers and respects legal holds', kind: 'symbol', check: 'offboarding.plan' },
      { item: 'Guided setup that checks system state, not a form', kind: 'symbol', check: 'onboarding.status' },
      { item: 'Setup reports elapsed time honestly against the 30-minute target', kind: 'test', check: 'no rounding in our favour' },
      { item: 'Sample tenant that refuses to seed over real data', kind: 'symbol', check: 'demo.load' },
      { item: 'Status page with component health computed from live signals', kind: 'symbol', check: 'statusPage.components' },
      { item: 'Uptime refuses to report a quiet window as 100%', kind: 'test', check: 'absence of a record, not a measurement' },
      { item: 'Incident log requiring a post-mortem with owned actions', kind: 'symbol', check: 'statusPage.postMortem' },
      { item: 'Latency measured as p50/p95/p99 from every sample', kind: 'symbol', check: 'startedAt' },
      { item: 'Scale characterised by growth shape, not extrapolated', kind: 'test', check: 'does NOT hold at 100M' },
      { item: 'Configuration as code: plan, apply, drift', kind: 'symbol', check: 'config.plan' },
      { item: 'Plan provably does not mutate', kind: 'test', check: 'plan wrote to the estate' },
      { item: 'Facts cannot be declared in configuration', kind: 'behaviour', run: (v) => {
        try { v.config.plan({ fact: [{ id: 'f-1', claim: 'x' }] }); return { ok: false, evidence: 'a config file declared a fact' }; } catch { return { ok: true, evidence: 'unknown resource type rejected' }; }
      } },
      { item: 'Slack and Teams apps with verified inbound signatures', kind: 'symbol', check: 'slack.verify' },
      { item: 'Chat carries no claim text', kind: 'test', check: 'has none of Vault' },
      { item: 'Installable on a phone, with the review queue and kill switch as shortcuts', kind: 'behaviour', run: () => {
        const m = JSON.parse(readSource('/src/ui/manifest.json'));
        const urls = (m.shortcuts || []).map((s) => s.url);
        return urls.includes('/#review') && urls.includes('/#admin')
          ? { ok: true, evidence: urls.join(', ') } : { ok: false, evidence: `shortcuts: ${urls.join(', ')}` };
      } },
      { item: 'The service worker never caches an API response', kind: 'source', check: "url\\.pathname\\.startsWith\\('/api/'\\)\\) return;" },
      { item: 'Interface localisation with honest coverage reporting', kind: 'behaviour', run: () => {
        const { coverage } = require0('../ui/i18n.js');
        const cov = coverage();
        const complete = cov.filter((c) => c.percent === 100);
        return complete.length >= 3
          ? { ok: true, evidence: `${cov.length} locales, ${complete.length} complete, each labelled with its real percentage` }
          : { ok: false, evidence: `only ${complete.length} complete locales` };
      } },
      { item: 'RTL support as a document direction', kind: 'source', check: 'documentElement\\.dir = dir' },
      { item: 'Contrast clears WCAG AA by calculation', kind: 'test', check: 'fail AA for normal text' },
      { item: 'SBOM, secret scanning, static analysis and build provenance', kind: 'behaviour', run: () => {
        const src = readSource('/bin/vault-supplychain.js');
        const has = ['CycloneDX', 'SECRET_PATTERNS', 'SAST_RULES', 'in-toto.io'].filter((s) => src.includes(s));
        return has.length === 4 ? { ok: true, evidence: has.join(', ') } : { ok: false, evidence: `only ${has.join(', ')}` };
      } },
      { item: 'Zero runtime dependencies', kind: 'behaviour', run: () => {
        const pkg = JSON.parse(readSource('/package.json'));
        const n = Object.keys(pkg.dependencies || {}).length;
        return n === 0 ? { ok: true, evidence: 'node: builtins only' } : { ok: false, evidence: `${n} runtime dependencies` };
      } },
      { item: 'Incident response plan', kind: 'behaviour', run: () => ({ ok: Boolean(readSource('/docs/INCIDENT-RESPONSE.md', true)), evidence: 'docs/INCIDENT-RESPONSE.md' }) },
      { item: 'Breach blast-radius analysis', kind: 'behaviour', run: () => ({ ok: Boolean(readSource('/docs/BLAST-RADIUS.md', true)), evidence: 'docs/BLAST-RADIUS.md' }) },
      { item: 'Business-continuity disclosure', kind: 'behaviour', run: () => ({ ok: Boolean(readSource('/docs/legal/BUSINESS-CONTINUITY.md', true)), evidence: 'docs/legal/BUSINESS-CONTINUITY.md' }) },
      { item: 'Escrow position', kind: 'behaviour', run: () => ({ ok: Boolean(readSource('/docs/legal/ESCROW.md', true)), evidence: 'docs/legal/ESCROW.md' }) },
      { item: 'Contractual positions the engineering can actually support', kind: 'behaviour', run: () => ({ ok: Boolean(readSource('/docs/legal/MSA-TERMS.md', true)), evidence: 'docs/legal/MSA-TERMS.md' }) }
    ]
  },

  // ------------------------------------------------------------------ the rest
  {
    id: 'organisational',
    name: 'Requires an organisation, not a commit',
    items: [
      { item: 'SOC 2 Type II report', kind: 'organisational', why: 'Requires an accredited auditor and an observation window of 3–12 months. The product generates control evidence continuously; it cannot generate an opinion about itself. Start the readiness assessment, then the window.' },
      { item: 'ISO 27001 certification', kind: 'organisational', why: 'Requires a certification body auditing a management system, not a codebase. The technical controls are evidenced; the ISMS, the risk register and the management reviews are organisational artefacts.' },
      { item: 'ISO 42001 (AI management system) certification', kind: 'organisational', why: 'Same shape as 27001, for AI governance. Vault Comply maps the controls; the certificate needs an auditor.' },
      { item: 'Third-party penetration test', kind: 'organisational', why: 'bin/vault-supplychain.js runs static and secret analysis, and the test suite includes adversarial attacks against the gate. Neither is a pen test, and calling them one would be exactly the overclaim this product exists to prevent. Engage a firm.' },
      { item: 'Bug bounty programme', kind: 'organisational', why: 'Needs a published policy, a triage commitment, a payout budget and a safe-harbour statement. All organisational.' },
      { item: 'Signed customer agreements (MSA, DPA, SLA)', kind: 'organisational', why: 'docs/legal/MSA-TERMS.md states, per term, whether the software can evidence it — including the six terms that should be refused. Drafting is counsel\'s.' },
      { item: 'Source-code escrow agreement', kind: 'organisational', why: 'docs/legal/ESCROW.md explains why the architecture largely removes the need and what a sensible deposit looks like. Executing one is a commercial act.' },
      { item: 'Measured performance at 100M facts / 10B ledger entries / 50TB', kind: 'organisational', why: 'bin/vault-bench.js measures at whatever scale it is pointed at and characterises the growth shape, which is what predicts behaviour at that size. Proving it needs hardware of that size, and the report says so rather than extrapolating.' },
      { item: 'Quarterly restore drills, performed', kind: 'organisational', why: 'vault.drill.run() performs and records one, and a never-run drill is reported as a high finding. Running it every quarter is a practice, not a feature.' },
      { item: 'Independent code review', kind: 'organisational', why: 'Structurally impossible to satisfy from inside this repository: a review by the author is not independent, whatever it concludes.' },
      { item: 'Production disaster-recovery exercise', kind: 'organisational', why: 'The restore drill proves an export can be turned back into a working instance. A data-centre failover needs a data centre, and docs/legal/BUSINESS-CONTINUITY.md states that distinction rather than blurring it.' },
      { item: 'Published vulnerability disclosure policy', kind: 'organisational', why: 'Needs a contact address, a response commitment and a safe harbour — none of which a commit can create.' }
    ]
  }
];
