/**
 * ASK — a question in, an answer grounded in facts the asker is cleared to see.
 *
 * The retrieval half is not new and is not negotiable: this calls the existing
 * search path, which checks permissions at query time, withholds what the
 * asker has no clearance for, counts what it withheld rather than silently
 * dropping it, and attaches provenance to every result. A model never queries
 * the store, never sees a withheld fact, and cannot widen a search.
 *
 * What a model adds is only the last step — turning a list of retrieved facts
 * into a sentence. That is worth having, because `search.answer()` composes a
 * correct but stilted list, and people ask questions in prose. It is also the
 * step where a system like this usually starts lying, so:
 *
 *   · the model sees ONLY facts already returned by the gated search, as data
 *   · every sentence must cite a fact id, and any answer citing an id that was
 *     not in the retrieved set is discarded entirely — a fabricated citation
 *     is worse than no answer
 *   · with nothing retrieved, it says so. There is no path that composes a
 *     plausible answer from zero facts
 *   · GUESSED facts stay labelled as inference in the answer, because a fluent
 *     paragraph is exactly where that label normally gets lost
 *   · the deterministic answer is always computed and always returned
 *     alongside, so a reader can see what the model was working from
 *
 * With no model configured this returns the deterministic answer and says so.
 * The feature degrades in wording, never in correctness.
 */
import { asData, DATA_NOT_INSTRUCTIONS } from './provider.js';

const SYSTEM = `You answer questions using ONLY the facts provided to you from a company's governed memory.

${DATA_NOT_INSTRUCTIONS}

Absolute rules:
- Use ONLY the supplied facts. Never add outside knowledge, never infer beyond them.
- Every claim in your answer must cite the fact id it came from, like [f-123].
- If the facts do not answer the question, say exactly that. Do not compose a
  plausible answer. "The stored facts don't cover that" is a correct answer.
- Facts marked GUESSED are AI inferences that nobody stated. If you use one, say
  it is unconfirmed in the same sentence. Never present one as established.
- Facts marked POLICY are approved and authoritative; prefer them on conflict.
- If two facts conflict, say so and cite both rather than picking one.
- Be brief. Three sentences is usually enough.

Respond ONLY with JSON: {"answer": "<your answer with [ids]>", "usedIds": ["<id>", ...], "sufficient": <true|false>}`;

/**
 * Answer a question over the memory, for a specific asker.
 *
 * @param {object} o
 * @param {string} o.question
 * @param {object} o.searchResult the result of the gated search — already filtered for this asker
 * @param {import('./provider.js').ModelProvider} o.provider
 * @returns {Promise<object>}
 */
export async function ask({ question, searchResult, provider }) {
  const facts = (searchResult.results ?? []).filter((r) => r.kind === 'fact');
  const grounded = {
    question,
    retrieved: facts.length,
    withheld: searchResult.withheld ?? 0,
    withheldReasons: searchResult.withheldReasons ?? [],
    citations: facts.slice(0, 10).map((f) => ({ id: f.id, claim: f.claim, badge: f.badge, sensitivity: f.sensitivity })),
    // Always present, model or not: this is what the model was given, so a
    // reader can check the answer against it rather than trusting the prose.
    deterministicAnswer: searchResult.answer ?? null
  };

  if (!facts.length) {
    return {
      ...grounded,
      answer: searchResult.withheld
        ? `Nothing you are cleared to see answers that. ${searchResult.withheld} fact(s) were withheld — they exist, but not for this clearance.`
        : 'No stored fact answers that. Nothing is being asserted without a source.',
      source: 'no-facts',
      sufficient: false,
      caveat: null
    };
  }

  if (!provider?.available) {
    return {
      ...grounded,
      answer: searchResult.answer?.text ?? facts.map((f) => `${f.claim} [${f.id}]`).join('\n'),
      source: 'deterministic',
      sufficient: true,
      caveat: searchResult.answer?.caveat ?? null,
      note: provider?.unavailableReason ?? 'no model configured — this answer is composed directly from the retrieved facts'
    };
  }

  const allowedIds = new Set(facts.map((f) => f.id));
  const corpus = facts.slice(0, 20).map((f) =>
    `[${f.id}] (${labelOf(f)}, ${f.provenance?.saidBy ?? 'unattributed'}, ${f.provenance?.channel ?? 'unknown channel'}) ${f.claim}`
  ).join('\n');

  const parsed = await provider.completeJson({
    system: SYSTEM,
    user: `Question: ${asData(question, { label: 'QUESTION' })}\n\nFacts you may use:\n${asData(corpus, { label: 'FACTS' })}`,
    valid: (p) => p && typeof p.answer === 'string' && p.answer.length > 0 && Array.isArray(p.usedIds),
    maxTokens: 700
  });

  if (!parsed) {
    return {
      ...grounded,
      answer: searchResult.answer?.text ?? facts.map((f) => `${f.claim} [${f.id}]`).join('\n'),
      source: 'deterministic',
      sufficient: true,
      caveat: searchResult.answer?.caveat ?? null,
      note: 'the model was unavailable or returned nothing usable — this answer is composed directly from the retrieved facts'
    };
  }

  // A citation to a fact that was never retrieved means the model invented it.
  // The whole answer goes, not just the citation: an answer containing one
  // fabricated source cannot be trusted on the sentences around it either.
  const fabricated = parsed.usedIds.filter((id) => !allowedIds.has(id));
  const citedInProse = [...String(parsed.answer).matchAll(/\[([a-zA-Z0-9_-]+)\]/g)].map((m) => m[1]);
  const fabricatedInProse = citedInProse.filter((id) => !allowedIds.has(id));

  if (fabricated.length || fabricatedInProse.length) {
    return {
      ...grounded,
      answer: searchResult.answer?.text ?? facts.map((f) => `${f.claim} [${f.id}]`).join('\n'),
      source: 'deterministic',
      sufficient: true,
      caveat: null,
      note: `the model cited ${[...new Set([...fabricated, ...fabricatedInProse])].join(', ')}, which was never retrieved — `
        + 'the whole model answer was discarded and this is composed directly from the retrieved facts'
    };
  }

  const usedGuessed = facts.filter((f) => parsed.usedIds.includes(f.id) && f.claimType === 'guessed');
  return {
    ...grounded,
    answer: parsed.answer,
    source: 'model',
    sufficient: parsed.sufficient !== false,
    usedIds: parsed.usedIds,
    caveat: usedGuessed.length
      ? 'This answer draws on AI-inferred facts that nobody stated. Do not repeat them as established.'
      : null,
    note: 'composed by a model from the retrieved facts only; every citation was checked against what was actually retrieved'
  };
}

function labelOf(f) {
  if (f.golden) return 'POLICY';
  if (f.claimType === 'guessed') return 'GUESSED';
  return String(f.claimType ?? 'stated').toUpperCase();
}
