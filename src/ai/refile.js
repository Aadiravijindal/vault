/**
 * SEMANTIC RE-FILING — the model pass, deliberately off the write path.
 *
 * The gate publishes a latency budget (p50 80ms, p95 250ms) and `ingest()` is
 * synchronous by design. A model call is hundreds of milliseconds on a good
 * day and can time out entirely, so putting one inside the gate would trade a
 * hard guarantee for a soft one — and would mean a model outage became a write
 * outage. It does not go there.
 *
 * Instead the deterministic rules file every fact immediately, exactly as they
 * always have, and this runs afterwards over facts that have already landed.
 * That ordering has a useful property beyond speed: the fact is never
 * unprotected while it waits. It is already inside a folder, already behind
 * whatever wall that folder has, already labelled. The model can only move it
 * somewhere else that exists, or raise its label.
 *
 * What a re-file may do:
 *   · move a fact to a DIFFERENT EXISTING folder
 *   · RAISE its sensitivity label
 *
 * What it may never do:
 *   · create a folder, or move a fact to one that does not exist
 *   · lower a sensitivity label
 *   · touch a golden fact — those are human-attested and this is not that path
 *   · touch a fact under legal hold — revise() refuses, and so does this
 *   · silently move a confidential fact it disagrees with the rules about —
 *     that goes to the review queue for a human instead
 *
 * Every move is a new fact version with the model named as the actor, so the
 * ledger shows who moved what and a re-file is as auditable and as reversible
 * as any other revision.
 */
import { classifyFact, SENSITIVITY_RANK } from './classify.js';

/**
 * Run the model over recently-filed facts and refine where it is confident.
 *
 * @param {object} o
 * @param {import('../index.js').Vault} o.vault
 * @param {number} [o.limit] how many facts to consider in this pass
 * @param {string} [o.actor]
 * @returns {Promise<object>} what moved, what was raised, what went to review
 */
export async function refilePass({ vault, limit = 50, actor = 'model-refile' } = {}) {
  const provider = vault.model;
  if (!provider?.available) {
    return {
      ran: false,
      reason: provider?.unavailableReason ?? 'no model configured',
      considered: 0, moved: [], raised: [], toReview: [], skipped: [],
      statement: 'No model is configured, so filing is exactly what the deterministic rules decided. '
        + 'That is a complete and safe answer, not a degraded one — it is simply keyword routing rather than meaning.'
    };
  }

  const folders = vault.folders.all().filter((f) => !f.archived);
  const allowedFolders = folders.map((f) => f.path);
  // Administrator-only folders. A fact may be filed INTO one automatically —
  // that is how something sensitive lands somewhere safe without a human in the
  // loop — but moving one OUT is always a widening, and this pass must refuse it
  // exactly as the librarian does. Two model paths with one guard between them
  // is the same as no guard: whichever one an operator runs is the one that
  // matters, and `refileWithModel()` is still on the public surface.
  const adminOnly = new Set(folders.filter((f) => f.adminOnly).map((f) => f.path));

  const candidates = vault.facts.live()
    // `locked` joins golden and legalHold here rather than relying on revise()
    // to throw: a refusal that arrives as an exception counted under "skipped"
    // is indistinguishable from a model that said nothing, and an administrator
    // who locked a fact should see it was left alone on purpose.
    .filter((f) => !f.golden && !f.legalHold && !f.locked && !f.modelFiledAt)
    .filter((f) => !adminOnly.has(f.folder))
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);

  const moved = [];
  const raised = [];
  const toReview = [];
  const skipped = [];

  for (const fact of candidates) {
    let r;
    try {
      r = await classifyFact({
        claim: fact.claim,
        ruleFolder: fact.folder,
        ruleSensitivity: fact.sensitivity,
        allowedFolders,
        provider
      });
    } catch (err) {
      skipped.push({ id: fact.id, reason: err.message });
      continue;
    }

    // The rules already decided this one and the model added nothing.
    if (r.source !== 'model') { skipped.push({ id: fact.id, reason: 'model returned nothing usable' }); continue; }

    const wantsMove = r.folder && r.folder !== fact.folder;
    const wantsRaise = SENSITIVITY_RANK[r.sensitivity] > SENSITIVITY_RANK[fact.sensitivity];

    // Uncertain, or a disagreement about something sensitive: a human decides.
    // Moving a confidential fact across a wall on a model's say-so is exactly
    // the failure this product exists to prevent.
    if (r.uncertain && (wantsMove || wantsRaise)) {
      toReview.push({
        id: fact.id, claim: fact.claim, from: fact.folder, proposed: r.folder,
        reason: `the model proposes ${r.folder ?? fact.folder} (${r.why ?? 'no reason given'}) and is not confident — a human decides where a fact this sensitive lives`
      });
      try {
        vault.review.enqueue({
          factId: fact.id,
          candidate: { claim: fact.claim, proposedFolder: fact.folder },
          verdict: {
            outcome: 'hold',
            folder: fact.folder,
            reasons: [`the model proposes re-filing to ${r.folder ?? fact.folder} (${r.why ?? 'no reason given'}) and is not confident — a fact this sensitive does not move on a model's say-so`]
          }
        });
      } catch { /* the queue is advisory here; the fact has not moved either way */ }
      continue;
    }

    if (!wantsMove && !wantsRaise) { skipped.push({ id: fact.id, reason: 'the model agreed with the rules' }); continue; }

    // Checked again at the destination, not only at the source. Moving a fact
    // INTO an administrator-only folder narrows access and is fine; the guard
    // above covers moving out. This one exists so a model cannot quietly park
    // something where only administrators will ever see it either.
    if (wantsMove && adminOnly.has(r.folder)) {
      toReview.push({
        id: fact.id, claim: fact.claim, from: fact.folder, proposed: r.folder,
        reason: `the model proposes moving this into ${r.folder}, which only administrators can read — a human decides who loses sight of a fact`
      });
      continue;
    }

    const patch = { modelFiledAt: Date.now(), modelFiledWhy: r.why ?? null };
    if (wantsMove) patch.folder = r.folder;
    if (wantsRaise) patch.sensitivity = r.sensitivity;

    try {
      vault.facts.revise(fact.id, patch, {
        actor,
        reason: wantsMove
          ? `semantic re-file: ${fact.folder} → ${r.folder}${r.why ? ` (${r.why})` : ''}`
          : `sensitivity raised ${fact.sensitivity} → ${r.sensitivity}${r.why ? ` (${r.why})` : ''}`,
        kind: 'model_refile'
      });
      if (wantsMove) moved.push({ id: fact.id, from: fact.folder, to: r.folder, why: r.why });
      if (wantsRaise) raised.push({ id: fact.id, from: fact.sensitivity, to: r.sensitivity, why: r.why });
    } catch (err) {
      // A legal hold or a golden fact refusing revision is correct behaviour.
      skipped.push({ id: fact.id, reason: err.message });
    }
  }

  return {
    ran: true,
    provider: provider.provider,
    model: provider.model,
    considered: candidates.length,
    moved, raised, toReview, skipped,
    statement: `${candidates.length} fact(s) considered. ${moved.length} re-filed to a folder that already existed, `
      + `${raised.length} had their sensitivity raised, ${toReview.length} sent to a human because the model was not `
      + `confident about something sensitive, ${skipped.length} left exactly where the rules put them. A model may move `
      + `a fact between existing folders and raise a label; it may never create a folder, lower a label, or touch a `
      + `golden fact or one under legal hold. Every move is a new version in the ledger, attributed and reversible.`
  };
}
