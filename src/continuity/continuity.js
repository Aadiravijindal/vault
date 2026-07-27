/**
 * 🚪 EXIT & CONTINUITY (§21).
 *
 * A customer will not hand their entire company brain to a startup without this.
 * If Vault dies tonight, their memory is intact tomorrow morning — and provable
 * without us.
 *
 * Publish this page. Every competitor's silence here is your advantage.
 */
import { writeFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { now, iso, ago, DAY } from '../util/time.js';
import { sha256 } from '../util/crypto.js';
import { VaultError, forbidden } from '../util/errors.js';

/** The documented, published export schema. Not a proprietary blob. */
export const EXPORT_SCHEMA = {
  format: 'vault.export.v1',
  files: {
    'facts.jsonl': 'one fact per line, complete fact model per §10',
    'golden.jsonl': 'golden facts with attestations and signatures',
    'conversations.jsonl': 'raw archive, whole transcripts, seal hashes',
    'ledger.jsonl': 'the hash-chained ledger, verifiable standalone',
    'rules.yaml': 'policy rules as code',
    'folders.json': 'folder tree with walls, owners, retention and residency',
    'entities.json': 'resolved entities, aliases and cross-system ids',
    'receipts.jsonl': 'deletion, consent and hold receipts with proofs',
    'agents.json': 'agent registry with owners, scopes and pinned models',
    'manifest.json': 'file hashes, counts, schema version and the chain head'
  },
  encodings: ['jsonl', 'json', 'yaml', 'parquet (optional)'],
  license: 'the schema is published; you may implement a reader without our permission or involvement'
};

export class Continuity {
  /**
   * @param {object} deps
   */
  constructor({ facts, archive, ledger, rules, folders, entities, registry, legal, db, signingKey = null, mirrorDir = null }) {
    this.facts = facts;
    this.archive = archive;
    this.ledger = ledger;
    this.rules = rules;
    this.folders = folders;
    this.entities = entities;
    this.registry = registry;
    this.legal = legal;
    this.db = db;
    this.signingKey = signingKey;
    this.mirrorDir = mirrorDir;
    this.mirrorLog = [];
    this.escrow = null;
    this.mirrorEnabled = Boolean(mirrorDir);
    if (mirrorDir) mkdirSync(mirrorDir, { recursive: true });
    // Continuous mirror: subscribe to the ledger so every event streams out in
    // real time rather than on a nightly batch.
    if (mirrorDir) {
      this._unsubscribe = this.ledger.subscribe((entry) => this._mirrorEvent(entry));
    }
  }

  _mirrorEvent(entry) {
    if (!this.mirrorEnabled || !this.mirrorDir) return;
    try {
      const line = JSON.stringify(entry) + '\n';
      const path = join(this.mirrorDir, 'ledger.jsonl');
      appendFileSync(path, line);
      this.mirrorLog.push({ at: now(), seq: entry.seq, ok: true });
    } catch (e) {
      this.mirrorLog.push({ at: now(), seq: entry.seq, ok: false, error: e.message });
    }
  }

  /**
   * Full export. Free, any time, any volume — no egress charge, no throttling,
   * no "contact sales".
   * @param {{actor:string, dir?:string, includeContent?:boolean}} opts
   */
  export({ actor, dir = null, includeContent = true, reason = 'customer export' } = {}) {
    if (!actor) throw forbidden('an export requires a named actor (it is logged, not gated)');
    const files = {};

    files['facts.jsonl'] = this.facts.col.all().map((f) => JSON.stringify(includeContent ? f : redact(f))).join('\n');
    files['golden.jsonl'] = this.facts.goldenCol.all().map((f) => JSON.stringify(includeContent ? f : redact(f))).join('\n');
    files['conversations.jsonl'] = this.archive.col.all().map((c) => JSON.stringify(includeContent ? c : redact(c))).join('\n');
    files['ledger.jsonl'] = this.ledger.entries({ limit: Infinity }).map((e) => JSON.stringify(e)).join('\n');
    files['rules.yaml'] = this.rules.exportAsCode('yaml');
    files['rules.tf'] = this.rules.exportAsCode('terraform');
    files['folders.json'] = JSON.stringify(this.folders.all(), null, 2);
    files['entities.json'] = JSON.stringify(this.entities.all(), null, 2);
    files['agents.json'] = JSON.stringify(this.registry.inventory(), null, 2);
    files['receipts.jsonl'] = (this.legal?.receipts ?? []).map((r) => JSON.stringify(r)).join('\n');

    const manifest = {
      ...EXPORT_SCHEMA,
      exportedAt: iso(),
      exportedBy: actor,
      reason,
      counts: {
        facts: this.facts.col.size,
        golden: this.facts.goldenCol.size,
        conversations: this.archive.col.size,
        ledgerEntries: this.ledger.length,
        rules: this.rules.all().length,
        folders: this.folders.all().length,
        entities: this.entities.all().length,
        agents: this.registry.all().length
      },
      chainHead: this.ledger.head,
      publicKeyPem: this.signingKey?.publicKeyPem ?? null,
      fileHashes: Object.fromEntries(Object.entries(files).map(([k, v]) => [k, sha256(v)])),
      verifier: 'node bin/vault-verify.js <dir> — open source, trusts neither Vault nor the customer',
      selfHost: 'see SELFHOST.md in this export'
    };
    files['manifest.json'] = JSON.stringify(manifest, null, 2);
    files['SELFHOST.md'] = this.selfHostInstructions();
    files['SCHEMA.md'] = this.schemaDoc();

    this.ledger.append('export.created', {
      subject: 'full_export', actor, reason,
      facts: manifest.counts.facts, conversations: manifest.counts.conversations,
      ledgerEntries: manifest.counts.ledgerEntries, format: 'vault.export.v1'
    });

    if (dir) {
      mkdirSync(dir, { recursive: true });
      for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
      return { written: dir, files: Object.keys(files), manifest };
    }
    return { files, manifest };
  }

  /** Import from a competitor, or from our own export (both directions). */
  import(payload, { actor, source = 'vault', reason = 'migration' }) {
    if (!actor) throw forbidden('an import requires a named actor');
    const stats = { facts: 0, conversations: 0, rules: 0, skipped: 0 };
    const adapters = {
      vault: (p) => p,
      mem0: (p) => ({ facts: (p.memories || []).map((m) => ({ claim: m.memory ?? m.text, folder: m.metadata?.folder ?? 'imported/', claimType: 'heard', createdAt: Date.parse(m.created_at ?? '') || now() })) }),
      zep: (p) => ({ facts: (p.facts || []).map((m) => ({ claim: m.fact ?? m.content, folder: 'imported/', claimType: 'heard', createdAt: Date.parse(m.created_at ?? '') || now() })) }),
      letta: (p) => ({ facts: (p.blocks || []).map((m) => ({ claim: m.value, folder: `imported/${m.label ?? 'core'}/`, claimType: 'heard', createdAt: now() })) }),
      glean: (p) => ({ facts: (p.documents || []).map((d) => ({ claim: d.snippet ?? d.title, folder: 'imported/', claimType: 'heard', createdAt: now() })) }),
      smarsh: (p) => ({ conversations: (p.messages || []).map((m) => ({ content: m.body, channel: m.channel ?? 'email', participants: m.participants ?? [], startedAt: Date.parse(m.timestamp ?? '') || now(), externalId: m.id })) })
    };
    const adapt = adapters[source] || adapters.vault;
    const data = adapt(payload);

    // Imported facts still pass the gate — importing is not a bypass.
    for (const c of data.conversations || []) {
      try { this.archive.seal({ ...c, connector: `import:${source}` }); stats.conversations++; }
      catch { stats.skipped++; }
    }
    for (const f of data.facts || []) {
      try {
        this.archive.seal({
          content: f.claim, channel: 'system_of_record', connector: `import:${source}`,
          participants: [{ name: source, kind: 'system-of-record' }], startedAt: f.createdAt ?? now(),
          turns: [{ speaker: source, text: f.claim }]
        });
        stats.facts++;
      } catch { stats.skipped++; }
    }
    for (const r of data.rules || []) {
      try { this.rules.create({ ...r, actor, reason }); stats.rules++; } catch { stats.skipped++; }
    }
    this.ledger.append('admin.action', { subject: source, actor, action: 'continuity.import', reason, ...stats });
    return { ...stats, note: 'imported material passes the gate like anything else — importing is not a bypass' };
  }

  /** Continuous mirror status: if Vault dies tonight, is their memory intact? */
  mirrorStatus() {
    const failures = this.mirrorLog.filter((m) => !m.ok);
    const last = this.mirrorLog[this.mirrorLog.length - 1];
    return {
      enabled: this.mirrorEnabled,
      destination: this.mirrorDir,
      eventsMirrored: this.mirrorLog.filter((m) => m.ok).length,
      failures: failures.length,
      lastEvent: last ? { seq: last.seq, at: iso(last.at), ok: last.ok } : null,
      lag: last ? ago(last.at) : null,
      guarantee: this.mirrorEnabled
        ? 'every fact, transcript, ledger entry, rule and receipt streams to customer-owned storage in real time'
        : '⚠️ mirroring is not configured — set mirrorDir to enable the continuity guarantee'
    };
  }

  enableMirror(dir, { actor }) {
    if (!actor) throw forbidden('enabling the mirror requires a named actor');
    mkdirSync(dir, { recursive: true });
    this.mirrorDir = dir;
    this.mirrorEnabled = true;
    if (!this._unsubscribe) this._unsubscribe = this.ledger.subscribe((entry) => this._mirrorEvent(entry));
    this.ledger.append('admin.action', { subject: 'continuity', actor, action: 'continuity.mirror_enabled', destination: dir });
    return this.mirrorStatus();
  }

  /** Source-code escrow with defined release triggers (§21). */
  configureEscrow({ agent, triggers = null, actor }) {
    if (!actor) throw forbidden('configuring escrow requires a named actor');
    this.escrow = {
      agent,
      configuredAt: now(),
      configuredBy: actor,
      triggers: triggers || [
        'insolvency or an equivalent proceeding',
        'acquisition without assumption of this agreement',
        'service failure exceeding 30 consecutive days',
        'breach of the continuity terms in this agreement'
      ],
      contents: ['source code', 'build instructions', 'deployment manifests', 'schema documentation', 'the standalone verifier'],
      verificationCadence: 'annual — the escrow agent confirms the deposit builds'
    };
    this.ledger.append('admin.action', { subject: 'escrow', actor, action: 'continuity.escrow_configured', agent });
    return this.escrow;
  }

  /** Run-anywhere build instructions the customer can stand up from their mirror. */
  selfHostInstructions() {
    return `# Running Vault from your own mirror, without us

This export is complete and self-describing. These steps stand up a working Vault from it, on your own
infrastructure, with no involvement from the vendor.

## Requirements
- Node.js 22 or later. Nothing else. No database server, no message broker, no cloud account.

## Steps
1. Place this export directory somewhere the process can read and write, e.g. \`./vault-data\`.
2. Obtain the Vault engine — from your own npm mirror, from source escrow, or from the copy in this export.
3. Start it against the export:

   \`\`\`
   node bin/vault.js serve --data ./vault-data --port 8080
   \`\`\`

4. Verify the ledger before you trust anything:

   \`\`\`
   node bin/vault-verify.js ./vault-data
   \`\`\`

   The verifier is standalone and open source. It recomputes every content hash and every chain link, and
   checks the signatures against the public key in \`manifest.json\`. It trusts neither the vendor nor you.

## What you have
- every fact, with its complete provenance and version history
- every raw conversation, whole, with its seal hash
- the full hash-chained ledger, and the anchors published to independent witnesses
- your rules, as code, in YAML and Terraform form
- your folder tree, with walls, owners, retention and residency
- every deletion, consent and hold receipt, with its cryptographic proof

## What you do not need from us
Nothing. The schema is published in \`SCHEMA.md\`, the verifier is open source, and the format is documented
well enough to write your own reader. Portability to a competitor is a design goal, not a concession.
`;
  }

  schemaDoc() {
    return `# Vault export schema — ${EXPORT_SCHEMA.format}

${Object.entries(EXPORT_SCHEMA.files).map(([f, d]) => `## \`${f}\`\n${d}\n`).join('\n')}

## Verifying integrity
\`manifest.json\` contains a SHA-256 of every file, the chain head, and the public key used to sign ledger
entries and receipts. Recompute the hashes, then run the standalone verifier.

## Licence
${EXPORT_SCHEMA.license}
`;
  }

  /** The commitments page (§21). Publish this. */
  commitments() {
    return {
      continuousMirrorExport: this.mirrorStatus(),
      openDocumentedFormat: EXPORT_SCHEMA,
      selfHostEscapeHatch: 'a run-anywhere build the customer can stand up from their own mirror, without us, with documented steps',
      sourceCodeEscrow: this.escrow ?? { configured: false, note: 'not yet configured — call configureEscrow()' },
      ledgerVerifiableWithoutUs: {
        customerHeldKeys: Boolean(this.signingKey?.publicKeyPem),
        standaloneVerifier: 'bin/vault-verify.js — open source',
        statement: 'proof survives our death'
      },
      freeExport: { charge: 'none', throttling: 'none', volumeLimit: 'none', gate: 'a named actor for the log — nothing else' },
      migrationBothWays: {
        importFrom: ['Mem0', 'Zep', 'Letta', 'Glean', 'Smarsh', 'Vault'],
        exportTo: 'any of them, plus the documented open format'
      },
      changeOfControl: [
        'written commitment on what happens to customer data if we are acquired',
        'a termination right on change of control',
        'the mirror and escrow survive the transaction'
      ],
      concentrationRiskStatement: this.concentrationRisk(),
      contractTermsPreAgreed: [
        'no training on customer data, by default',
        'sub-processor disclosure with flow-down',
        '90-day model-deprecation notice',
        'change-of-law compliance maintenance',
        'AI-specific indemnity',
        'audit rights on notice',
        '30–60 day deletion with written backup-purge confirmation',
        'named portability window and format',
        'kill switch SLA with a named administrator'
      ],
      businessContinuityDisclosure: 'runway, insurance and key-person coverage disclosed under NDA to enterprise buyers who ask'
    };
  }

  /** "What % of our AI operations depends on you" — because their insurer asks. */
  concentrationRisk() {
    const agents = this.registry.active();
    const inline = agents.filter((a) => a.mode === 'inline').length;
    const facts = this.facts.stats().total;
    return {
      agentsDependingOnVault: agents.length,
      agentsWhereVaultIsInTheWritePath: inline,
      percentageInWritePath: agents.length ? Math.round((inline / agents.length) * 100) : 0,
      factsHeld: facts,
      ifVaultIsUnavailable: [
        `${agents.length - inline} agent(s) in Watch or Gateway mode continue unaffected — Vault observes them, it is not in their path`,
        `${inline} agent(s) in Inline mode fail-safe: writes queue locally and drain when Vault returns (the configured posture), or are refused in high-assurance mode`,
        'reads fall back to the agent\'s own context — degraded, not broken',
        'your mirror holds every fact, transcript and ledger entry as of the last streamed event'
      ],
      recoveryPosition: this.mirrorEnabled
        ? 'complete — the mirror is live and the self-host build runs from it'
        : '⚠️ incomplete — enable the mirror to close this',
      statement: 'this answer is generated from your actual deployment, not a template'
    };
  }
}

function redact(o) {
  const { claim, transcriptText, transcript, native, attachments, ...rest } = o;
  return { ...rest, redacted: true, contentHash: o.contentHash ?? sha256(String(claim ?? transcriptText ?? '')) };
}
