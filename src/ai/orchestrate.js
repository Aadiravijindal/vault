/**
 * THE LIBRARIAN — the model as a filing clerk with a defined job.
 *
 * `refile.js` does one narrow thing: move a fact between folders that already
 * exist. That is safe and it is not what anyone means when they ask for the AI
 * to organise their memory. Organising means the shape of the file room changes
 * as the material arrives — new drawers get labelled, everything gets indexed
 * by who it is about, and somebody says "you should look at this one" when
 * something matters.
 *
 * So this does four jobs the refile pass does not, and the interesting part of
 * each is where the authority stops.
 *
 * ── 1. TAGS: the model creates these freely ─────────────────────────────────
 *
 * Client names, project names, risk markers, deadlines. Unbounded, invented on
 * the fly, no approval.
 *
 * That is a real difference in authority from folders, and it is not
 * inconsistency — it is the actual security property. A FOLDER IS A WALL: it
 * decides who can read what, so inventing one invents an access boundary
 * nobody approved. A TAG IS AN INDEX: it decides what is easy to find, and
 * every read through it is still checked against the folder wall underneath.
 * A wrongly tagged fact is findable by the wrong search term. A wrongly
 * foldered fact is readable by the wrong person. Only one of those is a breach,
 * and the model gets full freedom on exactly the side that isn't.
 *
 * ── 2. FOLDERS: proposed, never created ─────────────────────────────────────
 *
 * When the model believes a drawer is missing it says so, with evidence: the
 * facts that would go in it, the wall it would need, and why the existing
 * folders are wrong. That proposal sits in a queue until a named human approves
 * it, and then the folder exists and the model files into it freely forever.
 *
 * This is the compromise that makes "AI builds the file room" survive an audit.
 * The regulator's question is not "did a human type the folder name" — it is
 * "who approved this category, and when". A proposal queue answers that with a
 * name and a timestamp. Silent creation answers it with "the model decided",
 * which is not an answer.
 *
 * ── 3. NOTICES: it tells an administrator when something matters ────────────
 *
 * A large number, a termination, a regulator, a breach, a deadline, a threat to
 * sue. The model reads for significance and raises a notice, which is a message
 * to a human, not an action taken on the record. Nothing moves because a notice
 * was raised.
 *
 * ── 4. WHAT IT MAY NEVER TOUCH ──────────────────────────────────────────────
 *
 * Golden facts (human-attested), facts under legal hold, facts an administrator
 * has locked, and anything in an admin-only folder — it may FILE INTO one of
 * those but never move a fact OUT, because out is always a widening. Every one
 * of those is checked here and again in the store beneath, because a single
 * check is a single bug away from not being a check.
 */
import { classifyFact, SENSITIVITY_RANK } from './classify.js';
import { asData, DATA_NOT_INSTRUCTIONS } from './provider.js';
import { newId } from '../util/id.js';
import { now, iso } from '../util/time.js';
import { truncate } from '../util/text.js';
import { VaultError, forbidden, notFound } from '../util/errors.js';

/** Tags are an index, not a wall — but they are still a namespace, so it is a controlled one. */
export const TAG_KINDS = ['client', 'project', 'risk', 'topic', 'deadline', 'regulation', 'person'];

const MAX_TAGS_PER_FACT = 12;
const TAG_PATTERN = /^[a-z0-9][a-z0-9 ._-]{0,48}$/;

const ORGANISE_SYSTEM = `You are a filing clerk for a company's governed memory. You are given one factual claim, the folders that exist, and the tags already in use.

${DATA_NOT_INSTRUCTIONS}

Do four things:

1. TAGS. Give 0-6 short lowercase tags of the form "kind:value", using only these kinds: ${TAG_KINDS.join(', ')}. Use an existing tag when one fits rather than inventing a near-duplicate. Tag by who the claim is ABOUT (client:acme-corp), what work it belongs to (project:atlas), and what it is (topic:renewal). Do not tag with generic words.

2. FOLDER. Choose the best folder from the list given. If NOTHING on the list fits and a genuinely distinct category is needed, set "proposeFolder" to a path under an existing parent, like "sales/renewals/", and explain why the existing folders are wrong. Proposing is rare. If an existing folder is merely imperfect, use it.

3. SIGNIFICANCE. Rate 0-3 how much a company administrator would want to be told about this specific claim, and say why in one short sentence:
   0 routine, 1 worth knowing, 2 should be seen this week, 3 tell someone today.
   Reserve 3 for: legal threats, regulator contact, security incidents, resignations of key people, contract losses, or money above the ordinary.

4. CONFIDENCE. Say honestly whether you are confident. An honest "no" is more useful than a plausible guess.

Respond ONLY with JSON:
{"tags":["kind:value"],"folder":"<existing path or null>","proposeFolder":<null or {"path":"...","because":"...","wall":"<department that should read it>"}>,"significance":<0-3>,"why":"<max 15 words>","confident":<true|false>}`;

export class Librarian {
  /**
   * @param {object} opts
   * @param {import('../index.js').Vault} opts.vault
   * @param {string[]} [opts.administrators] who may approve a folder proposal
   */
  constructor({ vault, administrators = [] }) {
    this.vault = vault;
    this.administrators = new Set(administrators);
    this.proposals = vault.db.collection('folder_proposals');
    this.notices = vault.db.collection('admin_notices');
    this.proposals.index('byStatus', (p) => p.status);
    this.notices.index('byStatus', (n) => n.status);
    this.lastRun = null;
  }

  // == the pass ============================================================

  /**
   * Read recently-filed facts and organise them.
   *
   * Runs off the write path, like every other model pass in this codebase. See
   * refile.js for why: the gate publishes a latency budget and a model call
   * cannot be inside it. Facts are already filed and already walled before this
   * ever sees them, so the worst case of this never running is that filing is
   * exactly as good as the deterministic rules made it.
   *
   * @param {object} [o]
   * @param {number} [o.limit] facts to consider
   * @param {string} [o.actor]
   * @param {boolean} [o.useMemory] consult the .vmem file before calling the model
   */
  async organize({ limit = 50, actor = 'ai-librarian', useMemory = true } = {}) {
    const started = Date.now();
    const provider = this.vault.model;
    const memory = this.vault.memory;

    const folders = this.vault.folders.all().filter((f) => !f.archived);
    const allowedFolders = folders.map((f) => f.path);
    const adminOnly = new Set(folders.filter((f) => f.adminOnly).map((f) => f.path));

    const candidates = this.vault.facts.live()
      .filter((f) => this._mayTouch(f).ok)
      .filter((f) => !f.organisedAt)
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, limit);

    const out = {
      ran: true,
      considered: candidates.length,
      tagged: [], moved: [], raised: [], proposed: [], notices: [],
      fromMemory: 0, fromModel: 0, skipped: [], modelCalls: 0
    };

    if (!provider?.available && !memory) {
      return {
        ...out,
        ran: false,
        reason: provider?.unavailableReason ?? 'no model configured',
        statement: 'No model and no learned memory, so filing is exactly what the deterministic rules decided. '
          + 'That is a complete answer, not a degraded one — it is keyword routing rather than meaning.'
      };
    }

    for (const fact of candidates) {
      // The memory answers first. It is microseconds against hundreds of
      // milliseconds for a hosted model and seconds for a local one, and after
      // a few thousand facts it knows most of what the model would say —
      // because the model, and every human correction, is what taught it.
      let recall = null;
      if (useMemory && memory) {
        recall = memory.recall({ claim: fact.claim, entities: fact.entities ?? [], allowedFolders });
        if (recall) {
          this.vault.journal?.record('memory.recalled', {
            subject: fact.id, actor: { id: actor, kind: 'system' },
            where: { folder: fact.folder },
            detail: { proposed: recall.folder, confidence: recall.confidence, evidence: recall.evidence, acted: recall.confident }
          });
        }
      }

      const settledByMemory = recall?.confident && recall.folder === fact.folder;
      if (settledByMemory) {
        out.fromMemory++;
        this._markOrganised(fact.id, actor, 'memory agreed with the rules');
        out.skipped.push({ id: fact.id, reason: `the learned memory agreed with where the rules put it (confidence ${recall.confidence})` });
        continue;
      }

      if (!provider?.available) {
        // Memory alone can still move a fact, but only when it is confident AND
        // the move is not into or out of an admin-only folder. A prior is
        // evidence about vocabulary, and that is not enough to cross a wall
        // that exists because somebody decided who may read it.
        if (recall?.confident && recall.folder !== fact.folder && !adminOnly.has(recall.folder) && !adminOnly.has(fact.folder)) {
          this._move(fact, recall.folder, { actor, why: recall.why, source: 'memory' });
          out.moved.push({ id: fact.id, from: fact.folder, to: recall.folder, by: 'memory', confidence: recall.confidence });
          out.fromMemory++;
        } else {
          out.skipped.push({ id: fact.id, reason: 'no model configured and the learned memory had no confident opinion' });
        }
        continue;
      }

      let parsed;
      try {
        out.modelCalls++;
        parsed = await provider.completeJson({
          system: ORGANISE_SYSTEM,
          user: this._prompt(fact, allowedFolders),
          valid: (p) => p && typeof p === 'object'
            && (p.folder === null || p.folder === undefined || typeof p.folder === 'string')
            && (p.tags === undefined || Array.isArray(p.tags))
            && (p.significance === undefined || (typeof p.significance === 'number' && p.significance >= 0 && p.significance <= 3)),
          maxTokens: 500
        });
      } catch (err) {
        out.skipped.push({ id: fact.id, reason: err.message });
        continue;
      }

      if (!parsed) {
        out.skipped.push({ id: fact.id, reason: 'the model returned nothing usable — the fact is exactly where the rules put it' });
        continue;
      }
      out.fromModel++;

      // -- tags: free, but sanitised and capped ---------------------------
      const tags = this._acceptTags(parsed.tags);
      if (tags.length) {
        this.tag(fact.id, tags, { actor, reason: 'organised by the librarian', kind: 'model' });
        out.tagged.push({ id: fact.id, tags });
      }

      // -- folder: only one that exists, and never out of an admin-only one --
      const wantsFolder = typeof parsed.folder === 'string' && allowedFolders.includes(parsed.folder) ? parsed.folder : null;
      if (wantsFolder && wantsFolder !== fact.folder) {
        const guard = this._mayMove(fact, wantsFolder, adminOnly);
        if (!guard.ok) {
          this.vault.journal?.record('model.refused', {
            subject: fact.id, actor: { id: actor, kind: 'system' },
            where: { folder: fact.folder }, why: guard.reason, allowed: false,
            detail: { attempted: wantsFolder }
          });
          out.skipped.push({ id: fact.id, reason: guard.reason });
        } else if (parsed.confident === false) {
          this._toReview(fact, wantsFolder, parsed.why);
          out.skipped.push({ id: fact.id, reason: 'the model was not confident about a move, so a human decides' });
        } else {
          this._move(fact, wantsFolder, { actor, why: parsed.why, source: 'model' });
          out.moved.push({ id: fact.id, from: fact.folder, to: wantsFolder, by: 'model', why: parsed.why });
        }
      }

      // -- a missing drawer: proposed, never created ----------------------
      if (parsed.proposeFolder?.path) {
        const p = this.propose({
          path: parsed.proposeFolder.path,
          because: parsed.proposeFolder.because ?? parsed.why ?? 'the model found no fitting folder',
          wall: parsed.proposeFolder.wall ?? null,
          exampleFactId: fact.id,
          by: actor
        });
        if (p) out.proposed.push({ id: p.id, path: p.path, because: p.because });
      }

      // -- significance: a message to a human, never an action ------------
      if ((parsed.significance ?? 0) >= 2) {
        const n = this.notify({
          factId: fact.id,
          level: parsed.significance >= 3 ? 'urgent' : 'attention',
          why: parsed.why ?? 'the model judged this significant',
          folder: fact.folder,
          by: actor
        });
        out.notices.push({ id: n.id, factId: fact.id, level: n.level, why: n.why });
      }

      // -- teach the memory what the model decided ------------------------
      memory?.learn({
        factId: fact.id,
        folder: wantsFolder ?? fact.folder,
        claim: fact.claim,
        sensitivity: fact.sensitivity,
        by: 'model',
        entities: fact.entities ?? [],
        correctedFrom: wantsFolder && wantsFolder !== fact.folder ? fact.folder : null
      });
      if (parsed.confident === false) {
        memory?.flagUncertain({ factId: fact.id, folder: fact.folder, options: [wantsFolder].filter(Boolean), why: parsed.why });
      }

      this._markOrganised(fact.id, actor, parsed.why ?? null);
    }

    if (memory?.state?.dirty) {
      const saved = memory.save({ actor, reason: 'librarian pass' });
      this.vault.journal?.record('memory.saved', {
        subject: 'ai-memory', subjectKind: 'memory', actor: { id: actor, kind: 'system' },
        detail: { revision: saved.revision.seq, bytes: saved.bytes, signed: saved.signed, size: saved.revision.size }
      });
    }

    this.lastRun = {
      at: now(), durationMs: Date.now() - started, considered: out.considered,
      modelCalls: out.modelCalls, fromMemory: out.fromMemory
    };

    const avoided = out.considered - out.modelCalls;
    return {
      ...out,
      durationMs: Date.now() - started,
      provider: provider?.provider ?? null,
      model: provider?.model ?? null,
      local: Boolean(provider?.local),
      statement: `${out.considered} fact(s) organised in ${Date.now() - started}ms. ${out.tagged.length} tagged, `
        + `${out.moved.length} moved to a folder that already existed, ${out.proposed.length} new folder(s) PROPOSED for an `
        + `administrator to approve or reject, ${out.notices.length} raised to a human as significant. `
        + `${out.modelCalls} model call(s) were needed; ${avoided} fact(s) were settled by the learned memory without one. `
        + 'The librarian invents tags freely because a tag is an index and every read through it is still checked against the '
        + 'folder wall underneath. It cannot invent a folder, because a folder IS the wall.'
    };
  }

  _prompt(fact, allowedFolders) {
    const existingTags = this.tagVocabulary().slice(0, 60);
    return `Folders that exist:\n${allowedFolders.map((f) => `- ${f}`).join('\n')}\n\n`
      + `Tags already in use (prefer these over near-duplicates):\n${existingTags.length ? existingTags.join(', ') : '(none yet)'}\n\n`
      + `Currently filed in: ${fact.folder}\n`
      + `The claim:\n${asData(fact.claim, { label: 'CLAIM' })}`;
  }

  // == tags ================================================================

  /**
   * Add tags to a fact.
   *
   * A tag is a new fact version like any other change, so tagging is in the
   * ledger, in the journal, attributed and reversible. It would have been
   * cheaper to keep tags in a side table, and then nobody could answer "who
   * tagged this client:acme and when" — which for a tag that routes a whole
   * account's history into one search result is a question worth being able to
   * answer.
   */
  tag(factId, tags, { actor, reason = 'tagged', kind = 'human', as = null } = {}) {
    const fact = this.vault.facts.require(factId);
    // A tag is not a wall, but writing one is still a WRITE to a walled record.
    // Without this a caller who is refused the fact on read could still attach
    // a tag to it — a modification of something they cannot see, and a way to
    // confirm a fact exists in a folder that is closed to them. The librarian's
    // own pass runs as the system and has no `as`, so it is unaffected.
    if (as) this.vault.folders.enforce('write', as, fact.folder, { subject: factId });
    const guard = this._mayTouch(fact);
    if (!guard.ok) throw forbidden(guard.reason, { factId });
    const accepted = this._acceptTags(tags);
    if (!accepted.length) return fact;

    const before = fact.tags ?? [];
    const after = [...new Set([...before, ...accepted])].slice(0, MAX_TAGS_PER_FACT);
    if (after.length === before.length && after.every((t) => before.includes(t))) return fact;

    const updated = this.vault.facts.revise(factId, { tags: after }, { actor, reason, kind: 'tag' });
    this.vault.journal?.record('fact.tagged', {
      subject: factId, actor: { id: actor, kind: kind === 'model' ? 'system' : 'human' },
      where: { folder: fact.folder, namespace: fact.namespace },
      why: reason, how: { model: kind === 'model' ? this.vault.model?.model ?? null : null },
      before: { tags: before }, after: { tags: after },
      detail: { added: accepted.filter((t) => !before.includes(t)) }
    });
    return updated;
  }

  untag(factId, tags, { actor, reason = 'untagged', as = null } = {}) {
    const fact = this.vault.facts.require(factId);
    if (as) this.vault.folders.enforce('write', as, fact.folder, { subject: factId });
    const drop = new Set((Array.isArray(tags) ? tags : [tags]).map(normaliseTag).filter(Boolean));
    const before = fact.tags ?? [];
    const after = before.filter((t) => !drop.has(t));
    if (after.length === before.length) return fact;
    const updated = this.vault.facts.revise(factId, { tags: after }, { actor, reason, kind: 'tag' });
    this.vault.journal?.record('fact.untagged', {
      subject: factId, actor: { id: actor, kind: 'human' }, why: reason,
      where: { folder: fact.folder }, before: { tags: before }, after: { tags: after }
    });
    return updated;
  }

  _acceptTags(tags) {
    if (!Array.isArray(tags)) return [];
    const out = [];
    for (const raw of tags.slice(0, MAX_TAGS_PER_FACT)) {
      const t = normaliseTag(raw);
      if (t) out.push(t);
    }
    return [...new Set(out)];
  }

  /** Every tag in use, most-used first. The model is shown this so it reuses rather than invents. */
  tagVocabulary() {
    const counts = new Map();
    for (const f of this.vault.facts.all()) {
      for (const t of f.tags ?? []) counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t);
  }

  byTag(tag) {
    const t = normaliseTag(tag);
    return this.vault.facts.all().filter((f) => (f.tags ?? []).includes(t));
  }

  // == folder proposals ====================================================

  /**
   * Propose a folder. Nothing is created; a human decides.
   *
   * Duplicate proposals for the same path accumulate evidence on the existing
   * one instead of filling the queue with the same suggestion fifty times, so
   * an administrator reviewing it sees "the model has wanted this for 50 facts"
   * — which is exactly the signal that makes the decision easy.
   */
  propose({ path, because, wall = null, exampleFactId = null, by = 'ai-librarian' }) {
    const normalised = String(path || '').trim().toLowerCase().replace(/^\/+/, '');
    if (!normalised || !/^[a-z0-9][a-z0-9/_-]*\/?$/.test(normalised)) return null;
    const withSlash = normalised.endsWith('/') ? normalised : normalised + '/';
    if (this.vault.folders.get(withSlash)) return null; // it already exists

    const existing = this.proposals.first((p) => p.path === withSlash && p.status === 'open');
    if (existing) {
      const updated = this.proposals.update(existing.id, {
        seenFor: [...new Set([...(existing.seenFor ?? []), exampleFactId].filter(Boolean))].slice(0, 50),
        count: (existing.count ?? 1) + 1,
        lastSeenAt: now()
      });
      return updated;
    }

    const parent = withSlash.split('/').filter(Boolean).slice(0, -1).join('/');
    const proposal = this.proposals.insert({
      id: newId('prop'),
      path: withSlash,
      parent: parent ? parent + '/' : null,
      parentExists: parent ? Boolean(this.vault.folders.get(parent + '/')) : true,
      because: truncate(String(because ?? ''), 240),
      suggestedWall: wall,
      seenFor: exampleFactId ? [exampleFactId] : [],
      count: 1,
      proposedBy: by,
      status: 'open',
      createdAt: now(),
      lastSeenAt: now(),
      decidedBy: null, decidedAt: null, decision: null, decisionReason: null
    });
    this.vault.journal?.record('folder.proposed', {
      subject: withSlash, subjectKind: 'folder',
      actor: { id: by, kind: 'system' },
      why: proposal.because,
      how: { model: this.vault.model?.model ?? null, provider: this.vault.model?.provider ?? null },
      detail: { proposalId: proposal.id, suggestedWall: wall, exampleFactId }
    });
    this.vault.alerts?.raise({
      severity: 'low', kind: 'folder_proposed', subject: withSlash, actor: by,
      detail: `the librarian proposes a new folder ${withSlash} — ${proposal.because}. Nothing has been created; it needs an administrator.`
    });
    return proposal;
  }

  openProposals() {
    return this.proposals.by('byStatus', 'open').sort((a, b) => b.count - a.count);
  }

  /**
   * A named human approves a proposal, and only then does the folder exist.
   *
   * The wall is set by the approver, not by the proposal. The model may suggest
   * who should read a new folder and that suggestion is shown, but an access
   * boundary that a model chose is an access boundary nobody chose — so the
   * value that actually gets written is the one the human passed in.
   */
  approveProposal(id, { actor, reason, read = null, write = null, adminOnly = false, as = null }) {
    const p = this.proposals.get(id);
    if (!p) throw notFound('folder proposal', id);
    if (p.status !== 'open') throw new VaultError('conflict', `this proposal was already ${p.status}`, { id });
    this._requireAdmin(actor, 'approve a new folder', as);
    if (!reason) throw new VaultError('validation', 'approving a new folder requires a stated reason — "who approved this category and why" is the question an auditor asks');

    const spec = {};
    if (read) spec.read = read;
    if (write) spec.write = write;
    if (adminOnly) { spec.adminOnly = true; spec.hardWall = true; }
    const folder = this.vault.folders.ensure(p.path, spec);

    const updated = this.proposals.update(id, {
      status: 'approved', decision: 'approved', decidedBy: actor, decidedAt: now(), decisionReason: reason
    });
    this.vault.journal?.record('folder.approved', {
      subject: p.path, subjectKind: 'folder', actor: { id: actor, kind: 'human' }, why: reason,
      after: { read: folder.read, write: folder.write, adminOnly: Boolean(folder.adminOnly) },
      detail: { proposalId: id, proposedBy: p.proposedBy, wantedFor: p.count, modelSuggestedWall: p.suggestedWall }
    });
    this.vault.ledger.append('admin.action', {
      subject: p.path, actor, action: 'folder.proposal_approved', reason,
      proposedBy: p.proposedBy, adminOnly: Boolean(adminOnly)
    });
    return { proposal: updated, folder };
  }

  rejectProposal(id, { actor, reason, as = null }) {
    const p = this.proposals.get(id);
    if (!p) throw notFound('folder proposal', id);
    this._requireAdmin(actor, 'reject a folder proposal', as);
    if (!reason) throw new VaultError('validation', 'a rejection needs a reason — the model will propose this again otherwise, and nobody will know why it was refused last time');
    const updated = this.proposals.update(id, {
      status: 'rejected', decision: 'rejected', decidedBy: actor, decidedAt: now(), decisionReason: reason
    });
    this.vault.journal?.record('folder.rejected', {
      subject: p.path, subjectKind: 'folder', actor: { id: actor, kind: 'human' },
      why: reason, allowed: false, detail: { proposalId: id, proposedBy: p.proposedBy }
    });
    return updated;
  }

  // == notices to a human ==================================================

  /**
   * Tell an administrator something looks important.
   *
   * A notice is a message, not an action. Nothing about the fact changes
   * because one was raised — it is not moved, relabelled or held. That
   * separation is the point: the model gets to have an opinion about
   * significance, which is a thing it is genuinely good at, without that
   * opinion being able to do anything to the record on its own.
   */
  notify({ factId, level = 'attention', why, folder = null, by = 'ai-librarian' }) {
    const fact = factId ? this.vault.facts.get(factId) : null;
    const notice = this.notices.insert({
      id: newId('notice'),
      factId: factId ?? null,
      level,
      why: truncate(String(why ?? ''), 240),
      excerpt: fact ? truncate(fact.claim, 200) : null,
      folder: folder ?? fact?.folder ?? null,
      sensitivity: fact?.sensitivity ?? null,
      raisedBy: by,
      status: 'open',
      createdAt: now(),
      readBy: null, readAt: null, dismissedReason: null
    });
    this.vault.journal?.record('model.flagged', {
      subject: factId ?? 'librarian', actor: { id: by, kind: 'system' },
      where: { folder: notice.folder }, why: notice.why,
      how: { model: this.vault.model?.model ?? null, provider: this.vault.model?.provider ?? null },
      detail: { noticeId: notice.id, level }
    });
    if (level === 'urgent') {
      this.vault.alerts?.raise({
        severity: 'medium', kind: 'librarian_notice', subject: factId ?? 'memory', actor: by,
        detail: `the librarian flagged this as needing attention today: ${notice.why}`
      });
    }
    return notice;
  }

  /**
   * Open notices, most urgent first — and filtered to what this reader may see.
   *
   * A notice quotes the fact it is about, so an unfiltered inbox would be a way
   * to read the contents of a folder you have no access to by waiting for the
   * model to find it interesting. The wall applies to the notice exactly as it
   * applies to the fact.
   */
  inbox({ actor, limit = 50 } = {}) {
    const open = this.notices.by('byStatus', 'open');
    const visible = [];
    const hidden = [];
    for (const n of open) {
      if (!n.folder) { visible.push(n); continue; }
      let allowed = false;
      try { allowed = this.vault.folders.check('read', actor ?? { id: 'unknown', kind: 'human' }, n.folder).allowed; } catch { allowed = false; }
      (allowed ? visible : hidden).push(n);
    }

    // WHERE things are waiting, without WHAT they say.
    //
    // A count alone told an administrator "1 notice you cannot read", which is
    // true and useless — they cannot tell whether it is a routine tag on a
    // marketing note or a threat of litigation, so the honest count reads as
    // noise and gets ignored. The wall exists to protect the fact's CONTENT:
    // the `why` and the excerpt are model-written summaries of it and stay
    // hidden. Which folder, how many, how urgent and when are metadata about
    // where attention is needed, and withholding those protects nothing while
    // costing somebody the ability to route the message to the right person.
    const byFolder = new Map();
    for (const n of hidden) {
      const row = byFolder.get(n.folder) ?? { folder: n.folder, total: 0, urgent: 0, latestAt: 0 };
      row.total++;
      if (n.level === 'urgent') row.urgent++;
      row.latestAt = Math.max(row.latestAt, n.createdAt);
      byFolder.set(n.folder, row);
    }
    const withheldSummary = [...byFolder.values()]
      .sort((a, b) => b.urgent - a.urgent || b.total - a.total)
      .map((r) => ({ ...r, latestAt: iso(r.latestAt) }));
    const urgentWithheld = withheldSummary.reduce((a, r) => a + r.urgent, 0);

    return {
      notices: visible
        .sort((a, b) => (b.level === 'urgent') - (a.level === 'urgent') || b.createdAt - a.createdAt)
        .slice(0, limit)
        .map((n) => ({ ...n, createdAt: iso(n.createdAt) })),
      open: visible.length,
      withheld: hidden.length,
      withheldSummary,
      urgentWithheld,
      note: hidden.length
        ? `${hidden.length} further notice(s) concern folders you cannot read`
          + (urgentWithheld ? `, ${urgentWithheld} of them urgent` : '')
          + '. Where and how many is shown below; what they say is not, because a notice quotes the fact it is about.'
        : null
    };
  }

  dismissNotice(id, { actor, reason }) {
    const n = this.notices.get(id);
    if (!n) throw notFound('notice', id);
    const updated = this.notices.update(id, { status: 'dismissed', readBy: actor, readAt: now(), dismissedReason: reason ?? null });
    this.vault.journal?.record('admin.action', {
      subject: n.factId ?? id, subjectKind: 'notice', actor: { id: actor, kind: 'human' },
      why: reason ?? 'dismissed', detail: { noticeId: id, level: n.level }
    });
    return updated;
  }

  // == locking =============================================================

  /**
   * Mark a fact as untouchable by any automated pass.
   *
   * "Important stuff, keep it untouched" is a real requirement and the existing
   * mechanisms are the wrong shape for it: golden facts need a human authority
   * role and four eyes, and a legal hold is a legal instrument with disclosure
   * consequences. A lock is the ordinary version — an administrator saying this
   * one is right, leave it alone. Automated passes skip it; humans can still
   * revise it deliberately.
   */
  lock(factId, { actor, reason, as = null }) {
    this._requireAdmin(actor, 'lock a fact', as);
    if (!reason) throw new VaultError('validation', 'locking a fact requires a reason');
    const fact = this.vault.facts.require(factId);
    const updated = this.vault.facts.revise(factId, { locked: true, lockedBy: actor, lockedAt: now(), lockReason: reason },
      { actor, reason, kind: 'lock' });
    this.vault.journal?.record('fact.locked', {
      subject: factId, actor: { id: actor, kind: 'human' }, why: reason,
      where: { folder: fact.folder }, before: { locked: false }, after: { locked: true }
    });
    return updated;
  }

  unlock(factId, { actor, reason, as = null }) {
    this._requireAdmin(actor, 'unlock a fact', as);
    const fact = this.vault.facts.require(factId);
    const updated = this.vault.facts.revise(factId, { locked: false, unlockedBy: actor, unlockedAt: now() },
      { actor, reason: reason ?? 'unlocked', kind: 'lock' });
    this.vault.journal?.record('fact.unlocked', {
      subject: factId, actor: { id: actor, kind: 'human' }, why: reason ?? null,
      where: { folder: fact.folder }, before: { locked: true }, after: { locked: false }
    });
    return updated;
  }

  // == guards ==============================================================

  /** May an automated pass touch this fact at all? */
  _mayTouch(fact) {
    if (fact.golden) return { ok: false, reason: 'golden facts are human-attested — no automated pass touches one' };
    if (fact.legalHold) return { ok: false, reason: 'the fact is under a legal hold — it is frozen until the hold is lifted' };
    if (fact.locked) return { ok: false, reason: `the fact was locked by ${fact.lockedBy} — ${fact.lockReason ?? 'no reason recorded'}` };
    return { ok: true };
  }

  /** May it move from here to there? Out of an admin-only folder is always no. */
  _mayMove(fact, to, adminOnly) {
    const touch = this._mayTouch(fact);
    if (!touch.ok) return touch;
    if (adminOnly.has(fact.folder)) {
      return {
        ok: false,
        reason: `${fact.folder} is administrator-only — a fact may be filed INTO it automatically but only a named administrator moves one out, because out is always a widening`
      };
    }
    const target = this.vault.folders.get(to);
    if (!target) return { ok: false, reason: `${to} does not exist — the librarian may propose a folder, never create one` };
    return { ok: true };
  }

  /**
   * Only a named administrator.
   *
   * Delegates to the folder tree rather than checking its own list, so there is
   * ONE definition of "administrator" in the product. Keeping a second copy here
   * meant a deployment that mints administrators from its identity provider —
   * which is how the API grants the capability — had a role-admin the walls
   * accepted and the librarian refused. Two answers to the same question is a
   * bug whichever one is right.
   */
  _requireAdmin(actor, what, as = null) {
    if (!actor && !as?.id) throw forbidden(`a named administrator is required to ${what}`);
    const candidate = as ?? { id: actor };
    if (this.vault.folders.isAdministrator({ ...candidate, id: candidate.id ?? actor })) return;
    throw forbidden(`${as?.id ?? actor} is not an administrator — only a named administrator may ${what}`, {
      code: 'not_administrator', administrators: [...this.administrators]
    });
  }

  _move(fact, to, { actor, why, source }) {
    const before = { folder: fact.folder, namespace: fact.namespace };
    this.vault.facts.revise(fact.id, {
      folder: to,
      namespace: to.split('/')[0],
      organisedAt: now(),
      organisedBy: source
    }, {
      actor,
      reason: `librarian re-file: ${fact.folder} → ${to}${why ? ` (${why})` : ''}`,
      kind: 'model_refile'
    });
    this.vault.journal?.record('fact.moved', {
      subject: fact.id, actor: { id: actor, kind: 'system' },
      where: { folder: to, namespace: to.split('/')[0] },
      why: why ?? null,
      how: { model: source === 'model' ? this.vault.model?.model ?? null : null, provider: source },
      before, after: { folder: to, namespace: to.split('/')[0] },
      excerpt: fact.claim
    });
  }

  /**
   * Note that this fact has been considered, so the next pass skips it.
   *
   * Bookkeeping, not a change — see FactStore#markOrganised for why this must
   * not create a fact version. A pass that actually moves, tags or relabels
   * something goes through `revise()` and is a version like any other.
   */
  _markOrganised(factId, actor, why) {
    try {
      this.vault.facts.markOrganised(factId, { by: actor, why: why ?? null });
    } catch { /* a fact that vanished mid-pass is not an error worth raising */ }
  }

  _toReview(fact, proposed, why) {
    try {
      this.vault.review.enqueue({
        factId: fact.id,
        candidate: { claim: fact.claim, proposedFolder: fact.folder },
        verdict: {
          outcome: 'hold',
          folder: fact.folder,
          reasons: [`the librarian proposes moving this to ${proposed} (${why ?? 'no reason given'}) and is not confident — a human decides`]
        }
      });
    } catch { /* the queue is advisory here; the fact has not moved either way */ }
  }

  // == what an operator sees ===============================================

  status({ actor = null } = {}) {
    const open = this.openProposals();
    const inbox = this.inbox({ actor });
    // Surfaced here as well as on the Map, because this is the screen where a
    // fact gets routed into an administrator-only folder — the person looking
    // at it is the one who needs to know that nothing can come back out.
    const unreadable = this.vault.folders.findings().filter((f) => /no administrators are named/.test(f.finding));
    return {
      warnings: unreadable.map((f) => ({
        severity: 'high', path: f.path, detail: f.finding, fix: f.fix
      })),
      model: this.vault.model?.status() ?? null,
      memory: this.vault.memory?.status() ?? null,
      lastRun: this.lastRun ? { ...this.lastRun, at: iso(this.lastRun.at) } : null,
      proposals: {
        open: open.length,
        items: open.slice(0, 20).map((p) => ({
          id: p.id, path: p.path, because: p.because, wantedFor: p.count,
          parentExists: p.parentExists, suggestedWall: p.suggestedWall, proposedAt: iso(p.createdAt)
        })),
        note: 'Proposed, not created. A folder is a wall, so a named administrator approves it and that name is what an auditor is shown.'
      },
      // Forwarded whole rather than field-picked. Picking is how the summary
      // and the note went missing here while `inbox()` returned both correctly,
      // and the screen showed an empty table where the withheld work was.
      notices: {
        open: inbox.open,
        withheld: inbox.withheld,
        urgentWithheld: inbox.urgentWithheld,
        withheldSummary: inbox.withheldSummary,
        note: inbox.note,
        items: inbox.notices.slice(0, 20)
      },
      tags: { distinct: this.tagVocabulary().length, top: this.tagVocabulary().slice(0, 20) },
      administrators: [...this.administrators],
      statement: 'The librarian tags freely, files into folders that exist, proposes ones that do not, and tells a human when '
        + 'something looks significant. It never creates a folder, never lowers a sensitivity label, and never touches a golden '
        + 'fact, a fact under legal hold, or one an administrator has locked.'
    };
  }
}

// ---------------------------------------------------------------------------

/**
 * Normalise a tag to `kind:value`.
 *
 * Untyped tags are rejected rather than accepted with a default kind. A bare
 * "acme" is ambiguous forever — is it the client, the project, or a topic? —
 * and a tag vocabulary that mixes those is one nobody can search reliably.
 */
export function normaliseTag(raw) {
  const s = String(raw ?? '').trim().toLowerCase();
  if (!s.includes(':')) return null;
  const [kind, ...rest] = s.split(':');
  const value = rest.join(':').trim().replace(/\s+/g, ' ');
  if (!TAG_KINDS.includes(kind)) return null;
  if (!TAG_PATTERN.test(value)) return null;
  return `${kind}:${value}`;
}
