/**
 * Check 7 — instruction detection (§8.7, §9.3).
 *
 * Principle: facts describe the world; instructions try to change behaviour.
 * Vault stores facts only.
 *
 * Seven layers. ANY layer firing holds the write — this is not a majority vote.
 * Recall over precision, with the review queue absorbing the false positives,
 * which is exactly why §12 spends so much effort on the queue not rotting.
 *
 * This check runs INDEPENDENTLY of the channel check. Both must pass.
 */
import { deobfuscate, extractHiddenText, styleScore, sentences, jaccard, truncate } from '../util/text.js';
import { classifyInstruction } from './classifier.js';

/** Held on sight, regardless of channel (§9.3). */
export const DETERMINISTIC_PATTERNS = [
  { id: 'from_now_on', re: /\bfrom now on\b|\bgoing forward\b|\bfrom this point (?:on|forward)\b/i, weight: 1.0, label: '"from now on…"' },
  { id: 'always_never', re: /\b(?:always|never)\s+(?:use|say|approve|allow|treat|assume|respond|reply|escalate|trust|share|send|grant)\b/i, weight: 0.95, label: '"always / never…"' },
  { id: 'ignore_previous', re: /\b(?:ignore|disregard|forget|discard)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|earlier|above|preceding|foregoing)\b/i, weight: 1.0, label: '"ignore previous / disregard…"' },
  { id: 'remember_that', re: /\b(?:remember|note)\s+(?:that\s+)?you\s+(?:should|must|can|may|will)\b/i, weight: 1.0, label: '"remember that you should…"' },
  { id: 'for_this_ticket', re: /\bfor this (?:ticket|case|customer|account|request)\b[^.]{0,40}\b(?:it'?s? (?:fine|ok(?:ay)?)|you (?:may|can))\b/i, weight: 1.0, label: '"for this ticket it\'s fine to…"' },
  { id: 'do_not_tell', re: /\b(?:do not|don'?t|never)\s+(?:tell|inform|notify|mention|disclose|reveal)\b/i, weight: 1.0, label: '"do not tell the user…"' },
  { id: 'when_asked_say', re: /\bwhen(?:ever)?\s+(?:asked|the user asks|they ask)[^.]{0,50}\b(?:say|respond|reply|answer|tell)\b/i, weight: 1.0, label: '"when asked about X, say Y"' },
  { id: 'role_tags', re: /(?:^|\n)\s*(?:system|assistant|developer|tool)\s*:/i, weight: 1.0, label: '"system:" / "assistant:" role tag' },
  { id: 'closing_tag', re: /<\/?(?:instructions?|system|prompt|im_start|im_end|s>|\|?im_\w+\|?)>/i, weight: 1.0, label: 'tag-shaped text / delimiter injection' },
  { id: 'you_are_approved', re: /\byou(?:'re| are)\s+(?:now\s+)?(?:approved|authoris?ed|permitted|allowed|able)\s+to\b/i, weight: 1.0, label: '"you are approved to…"' },
  { id: 'note_future', re: /\bnote\s+for\s+(?:the\s+)?future\s+reference\b|\bfor future reference\b/i, weight: 1.0, label: '"note for future reference…"' },
  { id: 'pre_approved', re: /\b(?:is|are)\s+pre-?approved\b|\bpre-?approved\s+(?:for|to|supplier|vendor|account)\b/i, weight: 1.0, label: '"this account is pre-approved…"' },
  { id: 'new_policy', re: /\bthe\s+new\s+policy\s+is\b|\bpolicy\s+(?:has\s+)?(?:changed|been\s+updated)\s+to\b/i, weight: 1.0, label: '"the new policy is…"' },
  { id: 'treat_this_as', re: /\btreat\s+(?:this|it|the following|me)\s+as\b/i, weight: 1.0, label: '"treat this as…"' },
  { id: 'limit_raised', re: /\b(?:your|the)\s+(?:limit|ceiling|cap|threshold|authority|budget)\s+(?:has been|is now|was)\s+(?:raised|increased|lifted|set)\b/i, weight: 1.0, label: '"your limit has been raised to…"' },
  { id: 'as_an_exception', re: /\bas an exception\b|\bexceptionally,? you (?:may|can)\b|\bjust this once\b/i, weight: 1.0, label: '"as an exception, you may…"' },
  { id: 'silently', re: /\b(?:silently|quietly|discreetly|without (?:logging|notifying|telling|informing|alerting))\b/i, weight: 1.0, label: '"silently…"' },
  { id: 'add_to_instructions', re: /\badd\s+(?:the\s+following\s+)?to\s+your\s+(?:instructions?|prompt|memory|rules|context)\b/i, weight: 1.0, label: '"add to your instructions…"' },
  { id: 'you_are_now', re: /\byou\s+are\s+now\b|\byour\s+role\s+(?:is\s+now|has changed)\b/i, weight: 1.0, label: '"you are now…"' },
  { id: 'override', re: /\boverrid(?:e|ing|es)\b|\bsupersedes?\b|\btakes? precedence over\b/i, weight: 0.95, label: '"override…" / "supersedes…"' },
  { id: 'bypass', re: /\bbypass(?:es|ing)?\b|\bskip\s+(?:the\s+)?(?:approval|verification|check|review|sign-?off)\b|\bwithout\s+(?:approval|sign-?off|verification)\b/i, weight: 1.0, label: '"bypass…"' },
  { id: 'the_following_supersedes', re: /\bthe\s+following\s+(?:supersedes|replaces|overrides)\b/i, weight: 1.0, label: '"the following supersedes…"' },
  { id: 'reveal_config', re: /\b(?:reveal|print|show|output|repeat|echo)\s+(?:your|the)\s+(?:system\s+prompt|instructions?|configuration|rules|context)\b/i, weight: 1.0, label: 'prompt/system-prompt extraction' },
  { id: 'end_of_document', re: /\b(?:end of (?:document|message|context|input))\b[\s\S]{0,40}\b(?:new|following)\s+(?:instructions?|directives?)\b/i, weight: 1.0, label: 'fake message boundary' }
];

/** Structural and semantic detectors (§9.3). */
export const SEMANTIC_DETECTORS = [
  { id: 'authority_claim', re: /\b(?:as\s+)?(?:approved|authoris?ed|signed off|mandated|instructed|requested)\s+by\s+(?:the\s+)?(?:cfo|ceo|cto|coo|finance|legal|compliance|security|management|board|head of \w+)\b/i, weight: 0.9, label: 'authority-claiming language' },
  { id: 'permission_grant', re: /\byou\s+(?:may|can|are able to|have permission to|are cleared to)\s+\w+/i, weight: 0.85, label: 'permission-granting shape' },
  { id: 'threshold_language', re: /\b(?:up to|no more than|not exceeding|limit(?:ed)? (?:of|to)|ceiling of|cap of|maximum of|threshold of)\s*[$£€]?\s?[\d,.]+\s?(?:k|m|bn|%|percent)?\b/i, weight: 0.7, label: 'threshold language' },
  { id: 'self_reference', re: /\byou(?:r|'re| are| must| should| will| shall| need)\b/i, weight: 0.55, label: 'text addressing the agent, not describing the world' },
  { id: 'future_conditional', re: /\b(?:when|if|whenever|next time|should)\s+(?:the\s+)?(?:user|customer|someone|anyone|they)\s+(?:asks?|requests?|mentions?|says?|contacts?)\b[^.]{0,60}\b(?:then\s+)?(?:say|do|reply|respond|approve|grant|escalate|send)\b/i, weight: 0.95, label: 'future-conditional trigger' },
  { id: 'secrecy', re: /\b(?:don'?t mention|do not mention|keep (?:this|it) (?:between us|confidential|quiet)|off the record|without telling|no need to (?:tell|inform|log))\b/i, weight: 0.95, label: 'secrecy language' },
  { id: 'roleplay', re: /\b(?:pretend|imagine|act as(?: if| though)?|role-?play|for (?:testing|debugging|demo) purposes|hypothetically|in a fictional)\b/i, weight: 0.9, label: 'role-play framing' },
  { id: 'urgency', re: /\b(?:immediately|right now|urgent(?:ly)?|asap|before the (?:audit|deadline|close|review)|the (?:ceo|cfo) needs this now|time[- ]sensitive)\b/i, weight: 0.6, label: 'urgency / pressure framing' },
  { id: 'delimiter_injection', re: /(?:```|---|===|\{\{|\[\[)\s*(?:system|instruction|prompt|tool_result|function_results?)\b/i, weight: 1.0, label: 'fake tool-result or JSON block' }
];

/** Imperative mood: grammatical commands vs statements. */
const IMPERATIVE_VERBS = new Set(('ignore disregard forget remember note treat assume add set update change override '
  + 'bypass skip approve grant allow deny reject send transfer pay issue reveal print show output '
  + 'respond reply say tell inform escalate route mark flag classify use apply enable disable stop start '
  + 'ensure make verify confirm check delete remove drop create write store save keep hold release').split(' '));

const STATE_VERBS = /\b(?:is|are|was|were|has|have|had|will be|would be|says?|said|reported|confirmed|prefers?|wants?|needs?|uses?|owns?|costs?|includes?)\b/i;

export class InstructionDetector {
  /**
   * @param {object} [opts]
   * @param {number} [opts.holdThreshold] ensemble score above which we hold
   * @param {()=>Array<{claim:string, id:string}>} [opts.goldenFacts] for cross-reference
   * @param {string[]} [opts.extraPatterns] company-specific regex sources
   */
  constructor({ holdThreshold = 0.5, goldenFacts = () => [], extraPatterns = [] } = {}) {
    this.holdThreshold = holdThreshold;
    this.goldenFacts = goldenFacts;
    this.extra = extraPatterns.map((p, i) => ({ id: `custom_${i}`, re: new RegExp(p, 'i'), weight: 1.0, label: `custom pattern ${i}` }));
  }

  /**
   * @param {string} text
   * @param {object} [ctx] { position, documentLength, channel, isToolDescription, surroundingText }
   * @returns {{score:number, verdict:'clean'|'hold', layers:object[], signals:string[], explanation:string}}
   */
  analyse(text, ctx = {}) {
    const original = String(text ?? '');
    const { normalised, signals: obfSignals, details } = deobfuscate(original);
    const hidden = extractHiddenText(original);
    const surfaces = [
      { name: 'original', text: original },
      { name: 'normalised', text: normalised },
      ...hidden.hidden.map((h, i) => ({ name: `hidden:${hidden.reasons[Math.min(i, hidden.reasons.length - 1)]}`, text: h }))
    ];

    /** @type {object[]} */
    const layers = [];

    // ---- Layer 1: deterministic -----------------------------------------
    const l1 = { layer: 1, name: 'deterministic', fired: false, hits: [] };
    for (const surface of surfaces) {
      for (const p of [...DETERMINISTIC_PATTERNS, ...this.extra]) {
        const m = p.re.exec(surface.text);
        if (m) {
          l1.fired = true;
          l1.hits.push({ id: p.id, label: p.label, weight: p.weight, surface: surface.name, match: truncate(m[0], 80) });
        }
      }
    }
    l1.score = l1.hits.length ? Math.max(...l1.hits.map((h) => h.weight)) : 0;
    layers.push(l1);

    // ---- Layer 2: structural --------------------------------------------
    const l2 = { layer: 2, name: 'structural', fired: false, hits: [] };
    if (hidden.hidden.length) {
      l2.fired = true;
      l2.hits.push({ id: 'hidden_text', label: `text hidden from humans (${hidden.reasons.join(', ')})`, weight: 1.0 });
    }
    if (obfSignals.length) {
      l2.fired = true;
      for (const s of obfSignals) l2.hits.push({ id: s, label: obfLabel(s), weight: s === 'encoded_payload' || s === 'invisible_characters' ? 1.0 : 0.8, details });
    }
    // Position: an instruction in a footer, signature block or trailing note is
    // not a fact about the world.
    if (ctx.position != null && ctx.documentLength) {
      const rel = ctx.position / ctx.documentLength;
      if (rel > 0.85 && /\b(?:you|your|please|note|important)\b/i.test(normalised)) {
        l2.fired = true;
        l2.hits.push({ id: 'footer_position', label: 'directive text in a document footer', weight: 0.7, relativePosition: Math.round(rel * 100) / 100 });
      }
    }
    if (ctx.isToolDescription) {
      // A tool *description* is untrusted content and gets the full scan (§9.4).
      l2.hits.push({ id: 'tool_description_surface', label: 'text originates from an MCP tool description', weight: 0.4 });
      l2.fired = true;
    }
    l2.score = l2.hits.length ? Math.max(...l2.hits.map((h) => h.weight)) : 0;
    layers.push(l2);

    // ---- Layer 3: statistical -------------------------------------------
    const l3 = { layer: 3, name: 'statistical', fired: false, hits: [] };
    const style = styleScore(normalised);
    if (style.score >= 0.5) {
      l3.fired = true;
      l3.hits.push({ id: 'style_outlier', label: 'style discontinuity — this text does not read like the rest', weight: style.score, features: style.features });
    }
    if (ctx.surroundingText) {
      const similarity = jaccard(normalised, ctx.surroundingText);
      if (similarity < 0.03 && normalised.length > 40 && ctx.surroundingText.length > 200) {
        l3.fired = true;
        l3.hits.push({ id: 'topic_discontinuity', label: 'paragraph is topically unrelated to its document', weight: 0.6, similarity: Math.round(similarity * 1000) / 1000 });
      }
    }
    l3.score = l3.hits.length ? Math.max(...l3.hits.map((h) => h.weight)) : 0;
    layers.push(l3);

    // ---- Layer 4: classifier --------------------------------------------
    const cls = classifyInstruction(normalised);
    const l4 = {
      layer: 4, name: 'classifier',
      // The classifier fires only when it is confident. It is one of seven
      // layers and the deterministic and semantic layers carry the real load;
      // a trigger-happy layer 4 would fill the queue with acknowledgements.
      fired: cls.label === 'instruction' && cls.instructionProbability >= 0.85,
      score: cls.instructionProbability,
      hits: cls.label === 'instruction'
        ? [{ id: 'nb_classifier', label: `classified as an instruction (p=${cls.instructionProbability})`, weight: cls.instructionProbability }]
        : []
    };
    layers.push(l4);

    // ---- Layer 5: semantic — does it try to change behaviour? ------------
    const l5 = { layer: 5, name: 'semantic', fired: false, hits: [] };
    for (const surface of surfaces) {
      for (const d of SEMANTIC_DETECTORS) {
        const m = d.re.exec(surface.text);
        if (m) l5.hits.push({ id: d.id, label: d.label, weight: d.weight, surface: surface.name, match: truncate(m[0], 80) });
      }
    }
    const mood = imperativeMood(normalised);
    if (mood.imperative) {
      l5.hits.push({ id: 'imperative_mood', label: `imperative mood — a command, not a statement (verb: "${mood.verb}")`, weight: 0.8 });
    }
    l5.fired = l5.hits.length > 0;
    l5.score = l5.hits.length ? Math.max(...l5.hits.map((h) => h.weight)) : 0;
    layers.push(l5);

    // ---- Layer 6: cross-reference against golden facts -------------------
    const l6 = { layer: 6, name: 'cross_reference', fired: false, hits: [] };
    for (const g of this.goldenFacts()) {
      const contradiction = contradicts(normalised, g.claim);
      if (contradiction) {
        l6.fired = true;
        l6.hits.push({ id: 'golden_contradiction', label: `contradicts golden fact ${g.id}`, weight: 1.0, goldenId: g.id, why: contradiction });
      }
    }
    l6.score = l6.fired ? 1 : 0;
    layers.push(l6);

    // ---- Layer 7: ensemble — ANY layer fires → hold ----------------------
    const firing = layers.filter((l) => l.fired);
    const score = Math.max(0, ...layers.map((l) => l.score || 0));
    const verdict = firing.length > 0 && score >= this.holdThreshold ? 'hold' : 'clean';

    const signals = [
      ...l1.hits.map((h) => h.id), ...l2.hits.map((h) => h.id), ...l3.hits.map((h) => h.id),
      ...(l4.fired ? ['classifier_instruction'] : []), ...l5.hits.map((h) => h.id), ...l6.hits.map((h) => h.id)
    ];

    return {
      score: Math.round(score * 100) / 100,
      verdict,
      layers,
      firingLayers: firing.map((l) => l.name),
      signals: [...new Set(signals)],
      obfuscation: obfSignals,
      hiddenText: hidden.hidden.map((h) => truncate(h, 120)),
      normalised,
      explanation: explain(firing, score, verdict)
    };
  }

  /**
   * Split a document and analyse each unit, so a clean 40-page contract with one
   * poisoned footer is caught at the footer rather than diluted to nothing.
   */
  analyseDocument(text, ctx = {}) {
    const units = sentences(text);
    const results = units.map((u) => ({
      unit: truncate(u.text, 120),
      start: u.start,
      ...this.analyse(u.text, { ...ctx, position: u.start, documentLength: text.length, surroundingText: text })
    }));
    const worst = results.reduce((a, b) => (b.score > (a?.score ?? -1) ? b : a), null);
    // Split payloads: instruction assembled across units.
    const joined = this.analyse(units.map((u) => u.text).join(' '), ctx);
    const split = joined.verdict === 'hold' && (!worst || worst.verdict === 'clean');
    return {
      verdict: split || worst?.verdict === 'hold' ? 'hold' : 'clean',
      score: Math.max(worst?.score ?? 0, split ? joined.score : 0),
      worstUnit: worst,
      splitPayload: split,
      units: results.filter((r) => r.verdict === 'hold'),
      wholeDocument: joined
    };
  }

  /**
   * Read-side detection: a query crafted to surface a specific poisoned fact
   * (§9.3, §11.4 step 11).
   */
  analyseQuery(query, { history = [] } = {}) {
    const q = String(query || '');
    const flags = [];
    if (/\b(?:pre-?approved|unlimited|no approval needed|exception|override|bypass)\b/i.test(q)) {
      flags.push('query_seeks_permission_language');
    }
    if (/\b(?:ignore|disregard)\b/i.test(q)) flags.push('query_contains_instruction_language');
    const repeats = history.filter((h) => jaccard(h, q) > 0.8).length;
    if (repeats >= 3) flags.push('repeated_identical_query');
    const direct = /\bf-[a-z0-9]{6,}\b/i.test(q);
    if (direct) flags.push('query_targets_a_specific_fact_id');
    return {
      suspicious: flags.length > 0,
      flags,
      repeats,
      note: flags.length ? 'retrieval-manipulation indicators present — logged, results still filtered normally' : null
    };
  }
}

// ---------------------------------------------------------------------------

function imperativeMood(text) {
  const s = String(text || '').trim();
  const first = s.toLowerCase().replace(/^(?:please|kindly|now|then|also|and)\s+/i, '').split(/\W+/)[0];
  if (!first) return { imperative: false };
  if (!IMPERATIVE_VERBS.has(first)) return { imperative: false };
  // "Note the invoice is wrong" is a statement wearing an imperative hat; a real
  // state verb right after the head disqualifies it.
  const rest = s.slice(s.toLowerCase().indexOf(first) + first.length, 80);
  if (STATE_VERBS.test(rest) && !/\byou\b/i.test(rest)) return { imperative: false };
  return { imperative: true, verb: first };
}

/**
 * Does `text` contradict a golden fact? Deliberately narrow: same subject and
 * attribute, different value. Broad semantic contradiction is a research
 * problem; a numeric ceiling moving is a Tuesday.
 */
export function contradicts(text, goldenClaim) {
  const a = String(text || '');
  const b = String(goldenClaim || '');
  const overlap = jaccard(a, b);
  const numsA = numbersIn(a);
  const numsB = numbersIn(b);
  if (overlap > 0.25 && numsA.length && numsB.length) {
    const differing = numsA.some((x) => numsB.every((y) => Math.abs(x - y) > Number.EPSILON));
    if (differing) return `same subject as the golden fact, different value (${numsB.join(', ')} → ${numsA.join(', ')})`;
  }
  const negA = /\b(not|no|never|without)\b/i.test(a);
  const negB = /\b(not|no|never|without)\b/i.test(b);
  if (overlap > 0.5 && negA !== negB) return 'same subject as the golden fact, opposite polarity';
  return null;
}

function numbersIn(s) {
  const out = [];
  for (const m of String(s).matchAll(/(?:[$£€]\s?)?(\d[\d,]*(?:\.\d+)?)\s?(k|m|bn|%|percent)?/gi)) {
    let n = parseFloat(m[1].replace(/,/g, ''));
    const suffix = (m[2] || '').toLowerCase();
    if (suffix === 'k') n *= 1e3;
    if (suffix === 'm') n *= 1e6;
    if (suffix === 'bn') n *= 1e9;
    if (!Number.isNaN(n)) out.push(n);
  }
  return out;
}

function obfLabel(signal) {
  return {
    invisible_characters: 'zero-width or bidi characters hiding text',
    homoglyphs: 'lookalike characters from another script',
    encoded_payload: 'encoded payload (base64/hex/percent/entity/rot13)',
    whitespace_steganography: 'whitespace steganography',
    unicode_normalisation_changed_text: 'unicode normalisation altered the text'
  }[signal] || signal;
}

function explain(firing, score, verdict) {
  if (verdict === 'clean') return 'No instruction indicators. This text describes the world rather than trying to change behaviour.';
  const parts = firing.map((l) => `${l.name} (${l.hits.map((h) => h.label).slice(0, 3).join('; ')})`);
  return `Held: ${firing.length} of 7 detection layers fired — ${parts.join(' · ')}. `
    + `Vault stores facts, not instructions. Any single layer firing is enough to hold; the ensemble does not vote.`;
}
