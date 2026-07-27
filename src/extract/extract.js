/**
 * L3 — EXTRACTION (§7). Conversation → candidate facts.
 *
 * Nothing here is a fact yet. Every candidate carries a byte range into the raw
 * archive, and an extractor that cannot point at bytes does not emit a
 * candidate. That is what "never invents" means operationally.
 *
 * Rules enforced in this file:
 *  - conservative: unsure → don't extract, or extract and hold
 *  - instructions are never extracted as facts (they are emitted as
 *    `instructionCandidate` so the gate can see and hold them, not silently drop)
 *  - never machine-translate before extracting — translation is a poisoning vector
 *  - negation and hedging preserved as separate, differently-confident claims
 *  - numbers/dates/currencies normalised AND the original string kept
 *  - unattributable claims are held, not guessed
 */
import { newId } from '../util/id.js';
import { sentences, contentTokens, truncate } from '../util/text.js';
import { now } from '../util/time.js';

/** §7.1 — the claim-type taxonomy. */
export const CLAIM_TYPES = {
  heard: { trust: 'needs review', authoritative: 'only after verification', rank: 2 },
  stated: { trust: 'trusted channel → pass', authoritative: 'yes', rank: 3 },
  guessed: { trust: 'flagged', authoritative: 'never', rank: 1 },
  verified: { trust: 'high', authoritative: 'yes', rank: 4 },
  approved: { trust: 'golden', authoritative: 'yes, and unoverwritable by any AI', rank: 5 }
};

export const TIME_SENSITIVITY = ['permanent', 'months', 'weeks', 'days', 'hours'];

const HEDGES = /\b(may|might|could|possibly|perhaps|maybe|seems?|appears?|likely|probably|i think|we think|apparently|reportedly|allegedly|not sure|unclear|potentially)\b/i;
const NEGATIONS = /\b(not|n't|never|no longer|declined|refused|denied|won't|cannot|can't|isn't|aren't|doesn't|didn't)\b/i;
const INFERENCE_MARKERS = /\b(i (?:infer|assume|guess|suspect|reckon)|it (?:looks|sounds) like|my (?:sense|read) is|reading between|presumably|implies that|suggests that)\b/i;

/** Sentences that command rather than describe are never facts. */
const IMPERATIVE_HEAD = /^(?:please\s+)?(ignore|disregard|forget|remember|note|treat|assume|add|set|update|change|override|bypass|always|never|from now on|do not|don't|make sure|ensure|you (?:are|must|should|may|will|can)|your\b|system:|assistant:)\b/i;

export class Extractor {
  /**
   * @param {object} [opts]
   * @param {number} [opts.minConfidence] below this, hold rather than emit clean
   * @param {(text:string)=>string} [opts.languageDetector]
   * @param {Array<{name:string, pattern:RegExp, attribute:string, unit?:string}>} [opts.customAttributes]
   */
  constructor({ minConfidence = 0.55, languageDetector = detectLanguage, customAttributes = [] } = {}) {
    this.minConfidence = minConfidence;
    this.detectLanguage = languageDetector;
    this.attributePatterns = [...ATTRIBUTE_PATTERNS, ...customAttributes];
  }

  /**
   * @param {object} conversation sealed archive record
   * @param {object} ctx { agent, channelTrust, knownEntities, folderHint }
   * @returns {{candidates:object[], skipped:object[], stats:object}}
   */
  extract(conversation, ctx = {}) {
    const candidates = [];
    const skipped = [];
    const text = conversation.transcriptText || '';
    const units = sentences(text);

    // Entities resolve at CONVERSATION level, not sentence level. "The contract
    // value is $84,000" in a call about Acme is a fact about Acme; requiring the
    // name in every sentence is how facts end up unfiled.
    const conversationEntities = detectEntities(text, ctx.knownEntities || []);
    const participantEntities = (conversation.participants || [])
      .filter((p) => p.org)
      .map((p) => ({ id: null, name: p.org, type: 'company', matched: p.org }));
    const contextEntities = dedupeEntities([...conversationEntities, ...participantEntities]);

    for (const unit of units) {
      const { speaker, body, speakerOffset } = splitSpeaker(unit.text);
      const start = unit.start + speakerOffset;
      const end = start + body.length;
      const trimmed = body.trim();

      if (trimmed.length < 8) { skipped.push({ reason: 'too_short', at: start }); continue; }

      const language = this.detectLanguage(trimmed);

      // Instruction-shaped text is emitted as a *candidate marked as an
      // instruction* — never silently dropped, because the gate needs to hold it
      // and the reviewer needs to see what was attempted (§7.2, §9.3).
      if (IMPERATIVE_HEAD.test(trimmed)) {
        candidates.push(this._candidate({
          conversation, ctx: { ...ctx, contextEntities }, claim: trimmed, start, end, speaker, language,
          claimType: 'heard',
          instructionShaped: true,
          confidence: 0.99,
          notes: ['instruction-shaped: describes desired behaviour, not the world']
        }));
        continue;
      }

      // Questions assert nothing.
      if (/\?\s*$/.test(trimmed) && !/\b(is|are|was|were)\b.*\b(confirmed|agreed)\b/i.test(trimmed)) {
        skipped.push({ reason: 'question', at: start }); continue;
      }

      // Pure pleasantries carry no claim.
      if (isPleasantry(trimmed)) { skipped.push({ reason: 'pleasantry', at: start }); continue; }

      // Speaker attribution is required. Unattributable claims are held (§7.2).
      const attributed = speaker && speaker !== 'unknown';
      const said = resolveSpeaker(speaker, conversation, ctx);

      const hedged = HEDGES.test(trimmed);
      const negated = NEGATIONS.test(trimmed);
      const inferred = INFERENCE_MARKERS.test(trimmed) || said?.kind === 'agent';

      let claimType = 'heard';
      if (inferred) claimType = 'guessed';
      else if (said?.kind === 'employee' && ctx.channelTrust === 'trusted') claimType = 'stated';
      else if (said?.kind === 'employee') claimType = 'heard';
      else if (said?.kind === 'system-of-record') claimType = 'verified';

      let confidence = 0.9;
      if (hedged) confidence -= 0.25;
      if (!attributed) confidence -= 0.3;
      if (inferred) confidence -= 0.2;
      if (trimmed.length > 320) confidence -= 0.1;
      if (contentTokens(trimmed).length < 3) confidence -= 0.2;
      confidence = Math.max(0.05, Math.min(0.99, Math.round(confidence * 100) / 100));

      const notes = [];
      if (hedged) notes.push('hedged — asserted as possible, not certain');
      if (negated) notes.push('negated — records what is NOT the case');
      if (inferred) notes.push('inferred by the AI; nobody said it');
      if (!attributed) notes.push('speaker could not be attributed — hold');

      const cand = this._candidate({
        conversation, ctx: { ...ctx, contextEntities }, claim: trimmed, start, end, speaker, language,
        claimType, confidence, hedged, negated, notes,
        requiresReview: !attributed || confidence < this.minConfidence
      });

      // Conservative: below threshold we still emit, but flagged for hold, so a
      // human sees it rather than the system quietly losing it.
      candidates.push(cand);
    }

    return {
      candidates,
      skipped,
      stats: {
        units: units.length,
        emitted: candidates.length,
        instructionShaped: candidates.filter((c) => c.instructionShaped).length,
        guessed: candidates.filter((c) => c.claimType === 'guessed').length,
        lowConfidence: candidates.filter((c) => c.confidence < this.minConfidence).length
      }
    };
  }

  _candidate({ conversation, ctx, claim, start, end, speaker, language, claimType, confidence = 0.8,
               hedged = false, negated = false, instructionShaped = false, notes = [], requiresReview = false }) {
    const said = resolveSpeaker(speaker, conversation, ctx);
    const own = detectEntities(claim, ctx.knownEntities || []);
    // A claim's own entities win. The conversation's entities fill the gap —
    // minus the speaker, who is who SAID it, not necessarily who it is ABOUT.
    // Subjects of the conversation (companies, projects) come first.
    const fallback = (ctx.contextEntities || [])
      .filter((e) => e.name !== said?.name && e.name !== speaker)
      .sort((a, b) => (a.type === 'person' ? 1 : 0) - (b.type === 'person' ? 1 : 0));
    const entities = own.length ? own : fallback.slice(0, 2);
    const structured = this._structure(claim, entities);
    const timeSensitivity = classifyTimeSensitivity(claim, structured);
    return {
      id: newId('candidate'),
      claim,
      claimType,
      instructionShaped,
      // provenance — a pointer at bytes, kept forever through every version
      source: {
        conversationId: conversation.id,
        start,
        end,
        excerpt: truncate(claim, 200),
        channel: conversation.channel,
        connector: conversation.connector,
        connectorMode: conversation.connectorMode,
        model: conversation.model,
        modelVersion: conversation.modelVersion
      },
      saidBy: said,
      capturedBy: conversation.agentId,
      entities,
      structured,
      proposedFolder: ctx.folderHint || proposeFolder(entities, claim, ctx),
      timeSensitivity,
      sensitivityGuess: guessSensitivity(claim, entities),
      confidence,
      language,
      hedged,
      negated,
      requiresReview,
      notes,
      extractedAt: now()
    };
  }

  /** entity / attribute / value / unit — plus the original string, always. */
  _structure(claim, entities) {
    for (const p of this.attributePatterns) {
      const m = p.pattern.exec(claim);
      p.pattern.lastIndex = 0;
      if (!m) continue;
      const rawValue = (m.groups?.value ?? m[2] ?? m[1] ?? '').trim();
      const normalised = normaliseValue(rawValue, p.unit);
      return {
        entity: entities[0]?.name ?? (m.groups?.entity ?? null),
        attribute: p.attribute,
        value: normalised.value,
        unit: normalised.unit ?? p.unit ?? null,
        originalString: rawValue,
        pattern: p.name
      };
    }
    return {
      entity: entities[0]?.name ?? null,
      attribute: null,
      value: null,
      unit: null,
      originalString: claim,
      pattern: null
    };
  }
}

// ---------------------------------------------------------------------------

const ATTRIBUTE_PATTERNS = [
  { name: 'start_date_preference', attribute: 'start_date_preference', pattern: /\b(?:wants?|prefers?|asked for|needs?|targeting)\b[^.]*?\b(?<value>Q[1-4](?:\s*\d{4})?|(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s+\d{4})?|\d{4}-\d{2}-\d{2}|next (?:quarter|month|year))\b/i },
  { name: 'contract_value', attribute: 'contract_value', pattern: /\b(?:contract (?:value|worth)|deal (?:size|value)|acv|arr|worth)\b[^.]*?(?<value>[$£€]\s?[\d,.]+\s?(?:k|m|bn|million|billion)?)/i },
  { name: 'currency_amount', attribute: 'amount', pattern: /(?<value>[$£€]\s?[\d,.]+\s?(?:k|m|bn|million|billion)?)/i },
  { name: 'billing_frequency', attribute: 'billing_frequency', pattern: /\b(?:billing|billed|invoiced|switch(?:ing)? to)\b[^.]*?\b(?<value>annual(?:ly)?|monthly|quarterly|weekly)\b/i },
  { name: 'discount_ceiling', attribute: 'discount_ceiling', pattern: /\b(?:discount|reduction)\b[^.]*?(?<value>\d{1,3}\s?%)/i },
  { name: 'percentage', attribute: 'percentage', pattern: /(?<value>\d{1,3}(?:\.\d+)?\s?%)/ },
  { name: 'headcount', attribute: 'headcount', pattern: /\b(?<value>\d{1,6})\s+(?:employees|staff|seats|users|agents)\b/i },
  { name: 'decision', attribute: 'decision', pattern: /\b(?:decided|agreed|signed off|chose|selected|approved)\b[^.]*?\b(?:to|on)\s+(?<value>[^.]{4,80})/i },
  { name: 'status', attribute: 'status', pattern: /\b(?:is|are|remains?)\s+(?<value>blocked|at risk|on track|delayed|live|churned|renewed|paused|cancelled|escalated)\b/i },
  { name: 'owner', attribute: 'owner', pattern: /\b(?:owned by|owner is|reports to|assigned to)\s+(?<value>[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/ },
  { name: 'deadline', attribute: 'deadline', pattern: /\b(?:by|before|due|deadline(?: is)?)\s+(?<value>\d{4}-\d{2}-\d{2}|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}(?:,?\s+\d{4})?|Q[1-4](?:\s*\d{4})?|end of (?:week|month|quarter|year))\b/i },
  { name: 'version', attribute: 'version', pattern: /\b(?:version|v)\s?(?<value>\d+(?:\.\d+){0,3})\b/i },
  { name: 'sla', attribute: 'sla', pattern: /\b(?:sla|uptime|response time)\b[^.]*?(?<value>\d{1,3}(?:\.\d+)?\s?%|\d+\s?(?:hours?|minutes?|days?|business days?))/i },
  { name: 'legal_name', attribute: 'legal_entity_name', pattern: /\blegal(?:ly)? (?:name|entity)(?: is)?\s+(?<value>[A-Z][\w&.,' -]{2,60})/ },
  { name: 'authority_limit', attribute: 'authority_limit', pattern: /\b(?:authority|limit|ceiling|cap|threshold)\b[^.]*?(?<value>[$£€]\s?[\d,.]+\s?(?:k|m|bn)?)/i }
];

function normaliseValue(raw, unitHint) {
  const s = String(raw || '').trim();
  const money = /^([$£€])\s?([\d,.]+)\s?(k|m|bn|million|billion)?$/i.exec(s);
  if (money) {
    const symbol = money[1];
    let n = parseFloat(money[2].replace(/,/g, ''));
    const mult = (money[3] || '').toLowerCase();
    if (mult === 'k') n *= 1e3;
    if (mult === 'm' || mult === 'million') n *= 1e6;
    if (mult === 'bn' || mult === 'billion') n *= 1e9;
    return { value: n, unit: { '$': 'USD', '£': 'GBP', '€': 'EUR' }[symbol] };
  }
  const pct = /^(\d{1,3}(?:\.\d+)?)\s?%$/.exec(s);
  if (pct) return { value: parseFloat(pct[1]), unit: 'percent' };
  const plain = /^-?\d+(?:\.\d+)?$/.exec(s.replace(/,/g, ''));
  if (plain) return { value: parseFloat(s.replace(/,/g, '')), unit: unitHint ?? null };
  const isoDate = /^\d{4}-\d{2}-\d{2}$/.exec(s);
  if (isoDate) return { value: s, unit: 'date' };
  const quarter = /^Q([1-4])(?:\s*(\d{4}))?$/i.exec(s);
  if (quarter) return { value: `Q${quarter[1]}${quarter[2] ? ` ${quarter[2]}` : ''}`, unit: 'quarter' };
  return { value: s, unit: unitHint ?? null };
}

function splitSpeaker(line) {
  const m = /^([A-Za-z0-9 ._@'-]{1,48}):\s*/.exec(line);
  if (!m) return { speaker: null, body: line, speakerOffset: 0 };
  return { speaker: m[1].trim(), body: line.slice(m[0].length), speakerOffset: m[0].length };
}

function resolveSpeaker(speaker, conversation, ctx) {
  if (!speaker) return null;
  const p = (conversation.participants || []).find(
    (x) => x.name === speaker || x.id === speaker || x.handle === speaker);
  if (p) {
    return {
      name: p.name || speaker,
      id: p.id || null,
      kind: p.kind || (p.internal ? 'employee' : 'external'),
      org: p.org || null,
      role: p.role || null,
      employeeId: p.employeeId || null,
      authority: p.authority || null
    };
  }
  if (speaker === 'agent' || speaker === conversation.agentId) {
    return { name: conversation.agentId || 'agent', kind: 'agent', id: conversation.agentId };
  }
  if (ctx.systemOfRecord) return { name: speaker, kind: 'system-of-record' };
  return { name: speaker, kind: 'unknown' };
}

const KNOWN_ORG_SUFFIX = /\b([A-Z][A-Za-z0-9&.-]+(?:\s+[A-Z][A-Za-z0-9&.-]+)*)\s+(Corp|Corporation|Inc|Ltd|LLC|GmbH|PLC|SA|AG|BV|Pty|Co)\b\.?/g;
const PERSON_NAME = /\b([A-Z][a-z]{1,15})\s+([A-Z][a-z]{1,20})\b/g;

function detectEntities(text, known = []) {
  const found = new Map();
  for (const k of known) {
    const names = [k.name, ...(k.aliases || [])];
    for (const n of names) {
      if (n && new RegExp(`\\b${escapeRe(n)}\\b`, 'i').test(text)) {
        found.set(k.id || k.name, { id: k.id || null, name: k.name, type: k.type || 'unknown', matched: n });
        break;
      }
    }
  }
  for (const m of text.matchAll(KNOWN_ORG_SUFFIX)) {
    const name = `${m[1]} ${m[2]}`.replace(/\.$/, '');
    if (![...found.values()].some((e) => e.name.toLowerCase().startsWith(m[1].toLowerCase()))) {
      found.set(name, { id: null, name, type: 'company', matched: name });
    }
  }
  for (const m of text.matchAll(PERSON_NAME)) {
    const name = `${m[1]} ${m[2]}`;
    if (STOP_NAMES.has(m[1]) || STOP_NAMES.has(m[2])) continue;
    if (!found.has(name)) found.set(name, { id: null, name, type: 'person', matched: name });
  }
  return [...found.values()].slice(0, 8);
}

const STOP_NAMES = new Set(['The', 'This', 'That', 'They', 'We', 'I', 'Our', 'Their', 'It', 'He', 'She',
  'Q1', 'Q2', 'Q3', 'Q4', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']);

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/** Routing: agent's project scope → entity match → classifier → department. */
function proposeFolder(entities, claim, ctx) {
  if (ctx.agent?.defaultFolder) return ctx.agent.defaultFolder;
  const company = entities.find((e) => e.type === 'company');
  const lower = claim.toLowerCase();
  if (/\b(refund|invoice|billing|payment|charge|credit note)\b/.test(lower)) return 'finance/';
  // Deliberately narrow: "contract value" in a sales call is a sales fact, not
  // a legal one. Mis-filing crosses a wall, so the legal test needs legal words.
  if (/\b(clause|liabilit|indemnit|nda\b|msa\b|terms of service|governing law|breach of contract|legal review|counsel|privileged)\b/.test(lower)) return 'legal/';
  if (/\b(salary|leave|performance review|onboarding|termination|payroll)\b/.test(lower)) return 'hr/';
  if (/\b(vulnerab|breach|phish|incident|cve|pen ?test)\b/.test(lower)) return 'security/';
  if (/\b(bug|deploy|architecture|api|schema|migration|repo|pull request)\b/.test(lower)) {
    return ctx.project ? `engineering/${ctx.project}/` : 'engineering/';
  }
  if (/\b(ticket|complaint|outage|not working|broken|error)\b/.test(lower)) {
    return company ? `support/customers/${slug(company.name)}/` : 'support/';
  }
  if (company) return `sales/accounts/${slug(company.name)}/`;
  if (/\b(campaign|brand|positioning|launch)\b/.test(lower)) return 'marketing/';
  // Routing order (§11.1): agent's project scope → entity match → classifier →
  // DEFAULT DEPARTMENT. Only when even the department is unknown do we refuse to
  // guess and send it to review.
  if (ctx.agent?.department) return `${ctx.agent.department}/`;
  return null; // uncertain → the gate routes to review, never a guess (§11.1)
}

function dedupeEntities(list) {
  const seen = new Map();
  for (const e of list) if (!seen.has(e.name.toLowerCase())) seen.set(e.name.toLowerCase(), e);
  return [...seen.values()].slice(0, 8);
}

export function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function classifyTimeSensitivity(claim, structured) {
  const l = claim.toLowerCase();
  if (/\b(legal name|registered|founded|headquarter|born|entity|domain)\b/.test(l)) return 'permanent';
  if (structured?.attribute === 'legal_entity_name') return 'permanent';
  if (/\b(today|right now|currently|at the moment|angry|frustrated|urgent)\b/.test(l)) return 'days';
  if (/\b(this week|next week|sprint)\b/.test(l)) return 'weeks';
  if (/\b(quarter|q[1-4]|renewal|contract|annual)\b/.test(l)) return 'months';
  if (/\b(policy|standard|convention|architecture|decision)\b/.test(l)) return 'permanent';
  return 'months';
}

function guessSensitivity(claim, entities) {
  const l = claim.toLowerCase();
  if (/\b(password|api key|secret|token|ssn|salary|diagnos|medical|termination|redundanc|acquisition|lawsuit)\b/.test(l)) return 'secret';
  if (/\b(contract value|pricing|discount|margin|roadmap|churn|pipeline|forecast)\b/.test(l)) return 'confidential';
  if (entities.some((e) => e.type === 'person')) return 'internal';
  return 'internal';
}

function isPleasantry(s) {
  const t = s.trim();
  if (/^(hi|hello|hey|thanks|thank you|ok(ay)?|sure|great|perfect|got it|no problem|bye|goodbye|good (morning|afternoon|evening)|you'?re welcome)\b[\s.!,]*$/i.test(t)) return true;
  // Agent acknowledgements assert nothing about the world. Extracting them
  // produces noise that looks like instruction-shaped text to the classifier,
  // which is how a review queue fills up with nothing.
  return /^(understood|noted|acknowledged|absolutely|certainly|of course|makes sense|sounds good|will do|happy to help|let me (?:check|look|see)|i'?(?:ll|ve) (?:note|make a note|record|check|look) )/i.test(t)
    && t.length < 90;
}

/**
 * Cheap script + stopword language identification. Extraction runs per-language
 * and never machine-translates first (§7.2).
 */
export function detectLanguage(text) {
  const s = String(text || '');
  if (/[ऀ-ॿ]/.test(s)) return 'hi';
  if (/[一-鿿]/.test(s)) return 'zh';
  if (/[぀-ヿ]/.test(s)) return 'ja';
  if (/[가-힯]/.test(s)) return 'ko';
  if (/[؀-ۿ]/.test(s)) return 'ar';
  if (/[Ѐ-ӿ]/.test(s)) return 'ru';
  const l = s.toLowerCase();
  const score = (words) => words.reduce((a, w) => a + (new RegExp(`\\b${w}\\b`).test(l) ? 1 : 0), 0);
  const scores = {
    de: score(['der', 'die', 'das', 'und', 'nicht', 'ist', 'wir', 'mit', 'für']),
    fr: score(['le', 'la', 'les', 'et', 'nous', 'pour', 'est', 'pas', 'avec']),
    es: score(['el', 'los', 'las', 'para', 'con', 'que', 'está', 'nosotros']),
    nl: score(['het', 'een', 'niet', 'wij', 'voor', 'met', 'is']),
    sv: score(['och', 'att', 'det', 'inte', 'för', 'med']),
    en: score(['the', 'and', 'is', 'we', 'for', 'with', 'not', 'that'])
  };
  const best = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
  return best[1] === 0 ? 'und' : best[0];
}
