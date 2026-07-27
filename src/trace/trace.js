/**
 * TRACE, UNDO, CONTAGION and the INCIDENT BUNDLE (§13.3–13.6).
 *
 * The question after an incident is never "was there a bad fact?". It is
 * "who believed the lie, and what did they do about it?"
 */
import { newId } from '../util/id.js';
import { sha256, signMessage } from '../util/crypto.js';
import { now, iso, ago, DAY } from '../util/time.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';
import { truncate } from '../util/text.js';

export class TraceEngine {
  constructor({ facts, archive, ledger, registry, folders, search, alerts = null, tiering = null, signingKey = null }) {
    this.facts = facts;
    this.archive = archive;
    this.ledger = ledger;
    this.registry = registry;
    this.folders = folders;
    this.search = search;
    this.alerts = alerts;
    this.tiering = tiering;
    this.signingKey = signingKey;
    /** Undo operations are themselves logged and reversible. */
    this.undoLog = [];
  }

  // ==== TRACE (§13.3) ====================================================

  /** Click any fact and see its whole life. */
  trace(factId) {
    const fact = this.facts.get(factId);
    if (!fact) throw notFound('fact', factId);
    const conversation = fact.source?.conversationId ? this.archive.get(fact.source.conversationId) : null;
    const agent = fact.capturedBy ? this.registry.get(fact.capturedBy) : null;
    const ledgerEntries = this.ledger.entries({ subject: factId, limit: 1000 });
    const versions = this.facts.history(factId);

    return {
      fact: {
        id: fact.id, claim: fact.claim, status: fact.status, version: fact.version,
        folder: fact.folder, sensitivity: fact.sensitivity, golden: Boolean(fact.golden)
      },
      // Who said it, verbatim, with a clickable jump to the exact moment.
      saidBy: {
        ...fact.saidBy,
        verbatim: fact.source?.excerpt ?? fact.claim,
        sourceRef: fact.source?.conversationId
          ? this.archive.sourceRef(fact.source.conversationId, fact.source.start ?? 0)
          : { label: 'human attestation', approvedBy: fact.approvedBy }
      },
      capturedBy: agent ? {
        id: agent.id, name: agent.name, mode: agent.mode,
        businessOwner: agent.businessOwner, technicalOwner: agent.technicalOwner
      } : { id: fact.capturedBy, note: 'agent no longer registered' },
      model: { model: fact.model, version: fact.modelVersion },
      channel: { channel: fact.channel, trustAtTheTime: fact.channelTrust },
      sourceVerification: fact.sourceVerification ?? null,
      // Every check that ran, and its verdict, with the gate's reasoning.
      gate: {
        outcome: fact.gateOutcome,
        verdict: fact.gateVerdict,
        checks: fact.gateVerdict?.checks ?? [],
        reasons: fact.gateVerdict?.reasons ?? [],
        latencyMs: fact.gateVerdict?.latencyMs
      },
      rulesEvaluated: fact.rulesEvaluated,
      humanReview: fact.reviewedBy
        ? { reviewer: fact.reviewedBy, at: iso(fact.reviewedAt), decision: 'approved' }
        : (fact.golden ? { approver: fact.approvedBy, role: fact.approverRole, attestations: fact.attestations } : null),
      versions: versions.map((v) => ({
        version: v.version, at: iso(v.at), change: v.change, actor: v.actor ?? null, reason: v.reason ?? null
      })),
      supersedes: fact.supersedes,
      supersededBy: fact.supersededBy,
      // Every agent that read it, when, and what for.
      reads: (fact.readBy || []).map((r) => ({ agentId: r.agentId, at: iso(r.at), purpose: r.purpose })),
      readCount: fact.readCount,
      derivedFacts: fact.derivedFacts,
      influencedActions: fact.influencedActions,
      integrity: {
        contentHash: fact.contentHash,
        ledgerPosition: fact.ledgerPosition,
        prevHash: fact.prevHash,
        signature: fact.signature ? `${fact.signature.slice(0, 24)}…` : null,
        verified: this.verifyFact(factId)
      },
      storageJourney: this.tiering?.get(fact.source?.conversationId ?? fact.id)?.journey?.map(
        (j) => ({ tier: j.tier, at: iso(j.at), reason: j.reason })) ?? [],
      ledger: ledgerEntries.map((e) => ({ seq: e.seq, type: e.type, at: iso(e.at), actor: e.actor })),
      conversation: conversation ? {
        id: conversation.id, at: iso(conversation.startedAt), channel: conversation.channel,
        participants: conversation.participants, sealHash: conversation.sealHash,
        excerpt: truncate(conversation.transcriptText, 400)
      } : null
    };
  }

  verifyFact(factId) {
    const fact = this.facts.get(factId);
    if (!fact) return { ok: false, reason: 'not found' };
    const integrity = this.facts.verifyIntegrity({ limit: Infinity });
    const problem = integrity.problems.find((p) => p.factId === factId);
    const chain = this.ledger.verify({ from: Math.max(1, (fact.ledgerPosition || 1) - 1), to: (fact.ledgerPosition || 1) + 1 });
    return { ok: !problem && chain.ok, contentHash: !problem, chain: chain.ok };
  }

  // ==== CONTAGION (§13.5) ================================================

  /**
   * Who believed the lie, and what did they do about it?
   */
  contagion(factId) {
    const fact = this.facts.get(factId);
    if (!fact) throw notFound('fact', factId);
    const liveFrom = fact.createdAt;
    const liveTo = fact.status === 'live' ? now() : (fact.updatedAt || now());
    const agent = fact.capturedBy ? this.registry.get(fact.capturedBy) : null;

    // Reads, grouped by agent.
    const byAgent = new Map();
    for (const r of fact.readBy || []) {
      const g = byAgent.get(r.agentId) || { agentId: r.agentId, count: 0, first: r.at, last: r.at, purposes: new Set() };
      g.count++;
      g.first = Math.min(g.first, r.at);
      g.last = Math.max(g.last, r.at);
      if (r.purpose) g.purposes.add(r.purpose);
      byAgent.set(r.agentId, g);
    }

    const derived = (fact.derivedFacts || []).map((id) => this.facts.get(id)).filter(Boolean);
    const summaries = this.facts.all().filter((f) => f.kind === 'rolling_summary' && (f.inputs || []).includes(factId));
    const actions = fact.influencedActions || [];

    const gateRan = !String(fact.gateOutcome || '').includes('not run') && agent?.mode !== 'watch';
    const folders = new Set([fact.folder, ...derived.map((d) => d.folder)].filter(Boolean));

    return {
      factId,
      claim: truncate(fact.claim, 140),
      liveFrom: iso(liveFrom),
      liveTo: fact.status === 'live' ? 'still live' : iso(liveTo),
      liveForDays: Math.round((liveTo - liveFrom) / DAY),
      origin: {
        channel: fact.channel,
        channelTrust: fact.channelTrust,
        saidBy: fact.saidBy?.name,
        saidByKind: fact.saidBy?.kind,
        conversationId: fact.source?.conversationId,
        sourceRef: fact.source?.conversationId ? this.archive.sourceRef(fact.source.conversationId, fact.source.start ?? 0) : null,
        gateRan,
        gateWarning: gateRan ? null : `⚠️ gate NOT run — ${agent ? `agent ${agent.id} was in ${agent.mode} mode` : 'this write predates registration'}`
      },
      readBy: [...byAgent.values()].map((g) => {
        const a = this.registry.get(g.agentId);
        return {
          agentId: g.agentId,
          agentName: a?.name ?? g.agentId,
          owner: a?.businessOwner ?? 'unknown',
          reads: g.count,
          window: `${iso(g.first).slice(0, 10)} – ${iso(g.last).slice(0, 10)}`,
          purposes: [...g.purposes],
          unattended: a?.purpose?.toLowerCase().includes('ci') || false
        };
      }),
      derivedFacts: derived.map((d) => ({ id: d.id, claim: truncate(d.claim, 80), status: d.status, flaggedForRollback: true })),
      summariesAffected: summaries.map((s) => ({ id: s.id, folder: s.folder })),
      actionsInfluenced: actions,
      blastRadius: {
        agents: byAgent.size,
        folders: folders.size,
        derivedFacts: derived.length,
        summaries: summaries.length,
        externalExposure: actions.filter((a) => a.external).length
      },
      remediation: [
        { action: 'Roll back all', call: `trace.undo({ scope:'fact', id:'${factId}', cascade:true, actor, reason })` },
        { action: 'Roll back fact only', call: `trace.undo({ scope:'fact', id:'${factId}', cascade:false, actor, reason })` },
        { action: 'Export incident bundle', call: `trace.incidentBundle('${factId}', { actor })` },
        ...(agent && agent.mode === 'watch'
          ? [{ action: `Move ${agent.id} to Inline mode`, call: `registry.changeScope('${agent.id}', { mode:'inline' }, { actor, reason, approvedBy })`, isTheFix: true }]
          : [])
      ]
    };
  }

  // ==== UNDO (§13.4) =====================================================

  /**
   * Undo never destroys — it moves to history. Undo is itself logged and
   * reversible. Preview before commit.
   *
   * @param {{scope:string, id?:string, agentId?:string, source?:string, channel?:string,
   *          folder?:string, entity?:string, from?:number, to?:number, version?:number,
   *          cascade?:boolean, actor:string, reason:string, preview?:boolean}} opts
   */
  undo(opts) {
    const { scope, actor, reason, cascade = false, preview = false } = opts;
    if (!actor || !reason) throw forbidden('undo requires a named actor and a reason');
    const targets = this._undoTargets(opts);

    const affected = {
      facts: targets.length,
      summaries: new Set(targets.flatMap((f) => this.facts.all().filter((s) => (s.inputs || []).includes(f.id)).map((s) => s.id))).size,
      derived: cascade ? new Set(targets.flatMap((f) => f.derivedFacts || [])).size : 0
    };

    if (preview) {
      return {
        preview: true,
        scope,
        affected,
        message: `this will affect ${affected.facts} fact${affected.facts === 1 ? '' : 's'}`
          + (affected.summaries ? ` and ${affected.summaries} summar${affected.summaries === 1 ? 'y' : 'ies'}` : '')
          + (affected.derived ? ` and cascade to ${affected.derived} derived fact${affected.derived === 1 ? '' : 's'}` : ''),
        sample: targets.slice(0, 20).map((f) => ({ id: f.id, claim: truncate(f.claim, 70), folder: f.folder }))
      };
    }

    const undone = [];
    const held = [];
    for (const f of targets) {
      if (f.legalHold) { held.push({ id: f.id, reason: 'under legal hold' }); continue; }
      if (opts.version != null) {
        const snapshot = this.facts.history(f.id).find((v) => v.version === opts.version);
        if (!snapshot) continue;
        this.facts.revise(f.id, { claim: snapshot.snapshot.claim, structured: snapshot.snapshot.structured, status: snapshot.snapshot.status },
          { actor, reason: `${reason} (rolled back to v${opts.version})`, kind: 'undo_version' });
      } else {
        this.facts.setStatus(f.id, 'superseded', { actor, reason: `undo: ${reason}` });
      }
      undone.push(f.id);
      if (cascade) {
        for (const d of f.derivedFacts || []) {
          const df = this.facts.get(d);
          if (!df || df.legalHold) continue;
          this.facts.setStatus(d, 'superseded', { actor, reason: `undo cascade from ${f.id}: ${reason}` });
          undone.push(d);
        }
      }
    }

    const record = {
      id: newId('incident'), at: now(), scope, opts: omitFns(opts), actor, reason,
      undone, held, cascade, reversible: true
    };
    this.undoLog.push(record);
    this.ledger.append('fact.restored', {
      subject: opts.id || scope, actor, reason, scope, undone: undone.length, held: held.length, cascade,
      undoId: record.id
    });
    this.search?.reindexAll?.();

    return {
      undoId: record.id,
      scope,
      undone: undone.length,
      heldBack: held,
      cascade,
      note: 'undo never destroys — the affected facts moved to history and can be restored',
      reverse: `trace.reverseUndo('${record.id}', { actor, reason })`
    };
  }

  _undoTargets(opts) {
    const all = this.facts.all();
    switch (opts.scope) {
      case 'fact': return all.filter((f) => f.id === opts.id);
      case 'version': return all.filter((f) => f.id === opts.id);
      case 'agent': return all.filter((f) => f.capturedBy === opts.agentId &&
        (!opts.from || f.createdAt >= opts.from) && (!opts.to || f.createdAt <= opts.to));
      case 'source': return all.filter((f) => f.source?.conversationId === opts.source ||
        f.saidBy?.id === opts.source || f.saidBy?.name === opts.source);
      case 'channel': return all.filter((f) => f.channel === opts.channel &&
        (!opts.from || f.createdAt >= opts.from) && (!opts.to || f.createdAt <= opts.to));
      case 'folder': return all.filter((f) => String(f.folder || '').startsWith(opts.folder) &&
        (!opts.to || f.createdAt > opts.to));
      case 'entity': return all.filter((f) => (f.entities || []).some((e) => e.name === opts.entity || e.id === opts.entity));
      case 'memory': return all.filter((f) => !opts.to || f.createdAt > opts.to);
      default: throw new VaultError('validation', `unknown undo scope "${opts.scope}"`);
    }
  }

  /** Undo is itself reversible (§13.4). */
  reverseUndo(undoId, { actor, reason }) {
    const record = this.undoLog.find((u) => u.id === undoId);
    if (!record) throw notFound('undo record', undoId);
    if (!actor || !reason) throw forbidden('reversing an undo requires a named actor and a reason');
    let restored = 0;
    for (const id of record.undone) {
      const f = this.facts.get(id);
      if (!f) continue;
      this.facts.setStatus(id, 'live', { actor, reason: `reverse undo ${undoId}: ${reason}` });
      restored++;
    }
    this.ledger.append('fact.restored', { subject: undoId, actor, reason, restored, reverseOf: undoId });
    this.search?.reindexAll?.();
    return { reversed: undoId, restored };
  }

  undoHistory({ limit = 100 } = {}) {
    return this.undoLog.slice(-limit).map((u) => ({
      id: u.id, at: iso(u.at), scope: u.scope, actor: u.actor, reason: u.reason,
      undone: u.undone.length, heldBack: u.held.length
    }));
  }

  // ==== INCIDENT BUNDLE (§13.6) ==========================================

  /**
   * One click. Formatted for a regulator, an auditor, an insurer or opposing
   * counsel. Optionally signed.
   */
  incidentBundle(factId, { actor, matter = null, sign = true }) {
    if (!actor) throw forbidden('exporting an incident bundle requires a named actor');
    const fact = this.facts.get(factId);
    if (!fact) throw notFound('fact', factId);
    const trace = this.trace(factId);
    const contagion = this.contagion(factId);
    const conversation = fact.source?.conversationId ? this.archive.get(fact.source.conversationId) : null;
    const chain = this.ledger.verify();
    const anchors = this.ledger.verifyAnchors();

    const timeline = [
      ...this.ledger.entries({ subject: factId, limit: 1000 }).map((e) => ({ at: iso(e.at), event: e.type, actor: e.actor, seq: e.seq })),
      ...(fact.readBy || []).map((r) => ({ at: iso(r.at), event: 'fact.read', actor: r.agentId, purpose: r.purpose }))
    ].sort((a, b) => a.at.localeCompare(b.at));

    const body = {
      format: 'vault.incident-bundle.v1',
      generatedAt: iso(),
      generatedBy: actor,
      matter,
      fact: trace.fact,
      narrative: this._narrative(fact, trace, contagion),
      trace,
      contagion,
      rawSource: conversation ? {
        id: conversation.id,
        sealHash: conversation.sealHash,
        prevHash: conversation.prevHash,
        startedAt: iso(conversation.startedAt),
        channel: conversation.channel,
        participants: conversation.participants,
        transcript: conversation.transcriptText,
        attachments: (conversation.attachments || []).map((a) => ({ name: a.name, sha256: a.sha256 })),
        toolCalls: conversation.toolCalls
      } : null,
      gateVerdicts: fact.gateVerdict,
      reviewerDecisions: trace.humanReview,
      derivedFacts: contagion.derivedFacts,
      summariesAffected: contagion.summariesAffected,
      everyRead: trace.reads,
      chainProof: {
        ok: chain.ok,
        head: chain.head,
        entriesChecked: chain.checked,
        problems: chain.problems,
        anchors: anchors.results,
        witnessDiversity: anchors.diverse,
        verifier: 'run `node bin/vault-verify.js <export.json>` — it trusts neither Vault nor the customer'
      },
      timeline
    };

    const proof = sha256(JSON.stringify(body));
    return {
      ...body,
      proof,
      signature: sign && this.signingKey?.privateKeyPem ? signMessage(this.signingKey.privateKeyPem, proof) : null,
      humanReadable: this._renderBundle(body, proof)
    };
  }

  _narrative(fact, trace, contagion) {
    const parts = [];
    parts.push(
      `On ${iso(fact.createdAt)}, a claim entered Vault via ${fact.channel} `
      + `(${fact.channelTrust} by architecture), attributed to ${fact.saidBy?.name ?? 'an unattributed speaker'}`
      + `${fact.saidBy?.org ? ` of ${fact.saidBy.org}` : ''}, captured by ${fact.capturedBy ?? 'a human attestation'}.`
    );
    parts.push(`The gate returned ${fact.gateOutcome}. ${(fact.gateVerdict?.reasons || []).join('; ') || 'All ten checks passed.'}`);
    if (contagion.origin.gateWarning) parts.push(contagion.origin.gateWarning);
    parts.push(
      `The fact was live for ${contagion.liveForDays} day${contagion.liveForDays === 1 ? '' : 's'} and was read `
      + `${fact.readCount} time${fact.readCount === 1 ? '' : 's'} by ${contagion.blastRadius.agents} agent${contagion.blastRadius.agents === 1 ? '' : 's'}.`
    );
    if (contagion.derivedFacts.length) {
      parts.push(`${contagion.derivedFacts.length} further fact${contagion.derivedFacts.length === 1 ? ' was' : 's were'} derived from it and ${contagion.derivedFacts.length === 1 ? 'is' : 'are'} flagged for rollback.`);
    }
    if (contagion.actionsInfluenced.length) {
      parts.push(`${contagion.actionsInfluenced.length} downstream action${contagion.actionsInfluenced.length === 1 ? '' : 's'} plausibly influenced by it: ${contagion.actionsInfluenced.map((a) => a.kind || a.description).join(', ')}.`);
    }
    parts.push(
      `Every event above is recorded in a hash-chained ledger, positions ${Math.min(...trace.ledger.map((l) => l.seq))}–${Math.max(...trace.ledger.map((l) => l.seq))}, `
      + `anchored to independent witnesses and verifiable with a standalone tool that trusts neither party.`
    );
    return parts.join(' ');
  }

  _renderBundle(body, proof) {
    return [
      `INCIDENT BUNDLE — ${body.fact.id}`,
      `Generated ${body.generatedAt} by ${body.generatedBy}${body.matter ? ` for matter ${body.matter}` : ''}`,
      '',
      'NARRATIVE',
      wrap(body.narrative, 96),
      '',
      'ORIGIN',
      `  channel        ${body.contagion.origin.channel} (${body.contagion.origin.channelTrust})`,
      `  said by        ${body.contagion.origin.saidBy ?? 'unattributed'} (${body.contagion.origin.saidByKind ?? 'unknown'})`,
      `  source         ${body.contagion.origin.sourceRef?.label ?? 'human attestation'}`,
      body.contagion.origin.gateWarning ? `  ${body.contagion.origin.gateWarning}` : '  gate           ran on this write',
      '',
      'READ BY',
      ...body.contagion.readBy.map((r) => `  ${r.agentName.padEnd(18)} ×${String(r.reads).padEnd(4)} ${r.window}  (${r.owner})`),
      '',
      `DERIVED FACTS      ${body.contagion.derivedFacts.length}`,
      `SUMMARIES AFFECTED ${body.contagion.summariesAffected.length}`,
      `ACTIONS INFLUENCED ${body.contagion.actionsInfluenced.length}`,
      `BLAST RADIUS       ${body.contagion.blastRadius.agents} agents · ${body.contagion.blastRadius.folders} folders · ${body.contagion.blastRadius.externalExposure} external exposures`,
      '',
      'CHAIN PROOF',
      `  ${body.chainProof.ok ? '✓ verified' : '✗ FAILED'} — ${body.chainProof.entriesChecked} entries, head ${String(body.chainProof.head).slice(0, 16)}…`,
      `  anchors: ${body.chainProof.anchors.length}, witness diversity: ${body.chainProof.witnessDiversity ? 'yes' : 'no'}`,
      '',
      `PROOF ${proof}`
    ].join('\n');
  }
}

function wrap(text, width) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) { lines.push(line.trim()); line = w; }
    else line += ' ' + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => `  ${l}`).join('\n');
}

function omitFns(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) if (typeof v !== 'function') out[k] = v;
  return out;
}
