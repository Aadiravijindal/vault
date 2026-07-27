/**
 * Check 8 — the policy rules engine (§8.8).
 *
 * Rules are written once by a human and checked on every write from every agent,
 * forever. Authored in plain language or a small expression DSL, compiled to
 * policy-as-code, version controlled, conflict-checked at authoring time, and —
 * the part that closes security reviews — backtestable against real history
 * before anyone turns them on.
 *
 * Rules evaluate against the RAW conversation as well as the tidy extracted
 * claim. That closes the obvious bypass where the poison lives in a part of the
 * message the extractor discarded.
 */
import { newId } from '../util/id.js';
import { now, iso, HOUR } from '../util/time.js';
import { VaultError } from '../util/errors.js';
import { truncate } from '../util/text.js';

export const RULE_ACTIONS = ['pass', 'hold', 'block', 'mask', 'escalate', 'alert', 'quarantine', 'require-4-eyes'];
export const RULE_STATES = ['draft', 'dry-run', 'warn-only', 'enforce', 'retired'];
export const RULE_TYPES = [
  'threshold', 'forbidden_claim', 'required_approver', 'content_ban', 'channel_ban',
  'cross_department', 'entity_scoped', 'jurisdiction', 'rate', 'claim_type',
  'golden_protection', 'regulatory_record', 'consent_basis', 'retention',
  'four_eyes', 'time_window', 'model_version', 'volume_anomaly', 'semantic'
];

// ---------------------------------------------------------------------------
// Expression language
// ---------------------------------------------------------------------------

const TOKEN = /\s*(?:(\d+(?:\.\d+)?)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(\/(?:[^/\\]|\\.)+\/[gimsuy]*)|(\btrue\b|\bfalse\b|\bnull\b)|([A-Za-z_][A-Za-z0-9_.]*)|(>=|<=|!=|==|=~|&&|\|\||[()<>!,[\]])|(\S))/y;

function lex(src) {
  const out = [];
  TOKEN.lastIndex = 0;
  let m;
  while (TOKEN.lastIndex < src.length && (m = TOKEN.exec(src))) {
    if (m[1] !== undefined) out.push({ t: 'num', v: parseFloat(m[1]) });
    else if (m[2] !== undefined) out.push({ t: 'str', v: m[2].slice(1, -1).replace(/\\(.)/g, '$1') });
    else if (m[3] !== undefined) {
      const lastSlash = m[3].lastIndexOf('/');
      out.push({ t: 'regex', v: new RegExp(m[3].slice(1, lastSlash), m[3].slice(lastSlash + 1)) });
    } else if (m[4] !== undefined) out.push({ t: 'lit', v: m[4] === 'true' ? true : m[4] === 'false' ? false : null });
    else if (m[5] !== undefined) {
      const w = m[5];
      const lower = w.toLowerCase();
      if (['and', 'or', 'not', 'in', 'matches', 'contains', 'startswith', 'endswith', 'is'].includes(lower)) {
        out.push({ t: 'op', v: lower });
      } else out.push({ t: 'ident', v: w });
    } else if (m[6] !== undefined) out.push({ t: 'op', v: m[6] });
    else throw new VaultError('rule_syntax', `unexpected character in rule expression at position ${m.index}`);
    if (TOKEN.lastIndex === m.index) break;
  }
  return out;
}

/** Recursive-descent parser producing an inspectable AST. */
export function parseExpression(src) {
  const toks = lex(src);
  let i = 0;
  const peek = () => toks[i];
  const eat = (t, v) => {
    const tok = toks[i];
    if (!tok || (t && tok.t !== t) || (v && tok.v !== v)) {
      throw new VaultError('rule_syntax', `expected ${v || t} in rule expression`, { position: i });
    }
    i++;
    return tok;
  };

  function parseOr() {
    let left = parseAnd();
    while (peek() && peek().t === 'op' && (peek().v === 'or' || peek().v === '||')) {
      i++;
      left = { op: 'or', left, right: parseAnd() };
    }
    return left;
  }
  function parseAnd() {
    let left = parseNot();
    while (peek() && peek().t === 'op' && (peek().v === 'and' || peek().v === '&&')) {
      i++;
      left = { op: 'and', left, right: parseNot() };
    }
    return left;
  }
  function parseNot() {
    if (peek() && peek().t === 'op' && (peek().v === 'not' || peek().v === '!')) {
      i++;
      return { op: 'not', expr: parseNot() };
    }
    return parseComparison();
  }
  function parseComparison() {
    const left = parsePrimary();
    const tok = peek();
    if (tok && tok.t === 'op' && ['>', '<', '>=', '<=', '==', '!=', '=~', 'in', 'matches', 'contains', 'startswith', 'endswith', 'is'].includes(tok.v)) {
      i++;
      const opName = tok.v === 'is' ? '==' : tok.v === '=~' ? 'matches' : tok.v;
      const right = parsePrimary();
      return { op: opName, left, right };
    }
    return left;
  }
  function parsePrimary() {
    const tok = peek();
    if (!tok) throw new VaultError('rule_syntax', 'unexpected end of rule expression');
    if (tok.t === 'op' && tok.v === '(') { i++; const e = parseOr(); eat('op', ')'); return e; }
    if (tok.t === 'op' && tok.v === '[') {
      i++;
      const items = [];
      while (peek() && !(peek().t === 'op' && peek().v === ']')) {
        items.push(parsePrimary());
        if (peek() && peek().t === 'op' && peek().v === ',') i++;
      }
      eat('op', ']');
      return { op: 'list', items };
    }
    i++;
    if (tok.t === 'num') return { op: 'const', value: tok.v };
    if (tok.t === 'str') return { op: 'const', value: tok.v };
    if (tok.t === 'lit') return { op: 'const', value: tok.v };
    if (tok.t === 'regex') return { op: 'const', value: tok.v };
    if (tok.t === 'ident') return { op: 'field', path: tok.v };
    throw new VaultError('rule_syntax', 'unexpected token in rule expression');
  }

  const ast = parseOr();
  if (i < toks.length) throw new VaultError('rule_syntax', 'trailing tokens in rule expression');
  return ast;
}

export function evaluateAst(ast, ctx) {
  switch (ast.op) {
    case 'const': return ast.value;
    case 'list': return ast.items.map((x) => evaluateAst(x, ctx));
    case 'field': return resolvePath(ctx, ast.path);
    case 'and': return Boolean(evaluateAst(ast.left, ctx)) && Boolean(evaluateAst(ast.right, ctx));
    case 'or': return Boolean(evaluateAst(ast.left, ctx)) || Boolean(evaluateAst(ast.right, ctx));
    case 'not': return !evaluateAst(ast.expr, ctx);
    default: {
      const l = evaluateAst(ast.left, ctx);
      const r = evaluateAst(ast.right, ctx);
      switch (ast.op) {
        case '>': return num(l) > num(r);
        case '<': return num(l) < num(r);
        case '>=': return num(l) >= num(r);
        case '<=': return num(l) <= num(r);
        case '==': return looseEq(l, r);
        case '!=': return !looseEq(l, r);
        case 'in': return Array.isArray(r) ? r.some((x) => looseEq(l, x)) : String(r ?? '').includes(String(l ?? ''));
        case 'matches': return toRegex(r).test(String(l ?? ''));
        case 'contains': return Array.isArray(l)
          ? l.some((x) => looseEq(x, r))
          : String(l ?? '').toLowerCase().includes(String(r ?? '').toLowerCase());
        case 'startswith': return String(l ?? '').toLowerCase().startsWith(String(r ?? '').toLowerCase());
        case 'endswith': return String(l ?? '').toLowerCase().endsWith(String(r ?? '').toLowerCase());
        default: throw new VaultError('rule_syntax', `unknown operator ${ast.op}`);
      }
    }
  }
}

function resolvePath(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
function num(v) { const n = typeof v === 'number' ? v : parseFloat(String(v ?? '').replace(/[^0-9.-]/g, '')); return Number.isNaN(n) ? -Infinity : n; }
function looseEq(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return a == null && b == null;
  return String(a).toLowerCase() === String(b).toLowerCase();
}
function toRegex(r) { return r instanceof RegExp ? r : new RegExp(String(r), 'i'); }

// ---------------------------------------------------------------------------
// Plain-language authoring
// ---------------------------------------------------------------------------

/**
 * Compile a plain-language rule into an expression. Non-engineers author, and
 * engineers review the compiled expression as code (§8.8).
 */
export function compilePlainLanguage(sentence) {
  const s = String(sentence).trim();
  const patterns = [
    {
      re: /^no\s+(.+?)\s+above\s+[$£€]?([\d,.]+)\s*(k|m|bn)?\s+(?:becomes a fact\s+)?without\s+(.+)$/i,
      build: (m) => ({
        type: 'threshold',
        // keyword() returns a regex alternation; escaping it would turn
        // /payment|authority/ into a search for a literal pipe character.
        expression: `claim matches /${keyword(m[1])}/ and amount > ${scale(m[2], m[3])}`,
        action: 'escalate',
        escalateTo: m[4].replace(/^(a|an|the)\s+/i, '').trim(),
        explanation: `${m[1]} over ${m[2]}${m[3] || ''} requires ${m[4]}`
      })
    },
    {
      // The same rule with the approver clause left off. People type the short
      // form far more often than the long one, and a threshold with no named
      // approver is a hold, not an escalation to nobody.
      re: /^no\s+(.+?)\s+(?:above|over|exceeding)\s+[$£€]?([\d,.]+)\s*(k|m|bn)?\s*\.?$/i,
      build: (m) => ({
        type: 'threshold',
        expression: `claim matches /${keyword(m[1])}/ and amount > ${scale(m[2], m[3])}`,
        action: 'hold',
        explanation: `${m[1]} over ${m[2]}${m[3] || ''} is held for a human`
      })
    },
    {
      re: /^nothing\s+containing\s+(?:a\s+)?(.+?)\s+(?:ever\s+)?becomes a fact$/i,
      build: (m) => ({
        type: 'content_ban',
        expression: `pii.categories contains "${categoryFor(m[1])}"`,
        action: 'block',
        explanation: `content containing ${m[1]} is never stored as a fact`
      })
    },
    {
      re: /^nothing\s+from\s+(.+?)\s+may write to\s+(.+)$/i,
      build: (m) => ({
        type: 'channel_ban',
        expression: `channel == "${m[1].trim()}" and folder startswith "${m[2].trim().replace(/\.$/, '')}"`,
        action: 'block',
        explanation: `${m[1]} may not write to ${m[2]}`
      })
    },
    {
      re: /^(.+?)\s+may never write into\s+(.+)$/i,
      build: (m) => ({
        type: 'cross_department',
        expression: `agent.department == "${m[1].trim().toLowerCase()}" and folder startswith "${m[2].trim().replace(/\.$/, '')}"`,
        action: 'block',
        explanation: `${m[1]} may never write into ${m[2]}`
      })
    },
    {
      re: /^facts about\s+(.+?)\s+only in\s+(.+)$/i,
      build: (m) => ({
        type: 'entity_scoped',
        expression: `entityTypes contains "${m[1].trim().replace(/s$/, '')}" and not (folder startswith "${m[2].trim().replace(/\.$/, '')}")`,
        action: 'block',
        explanation: `facts about ${m[1]} belong only in ${m[2]}`
      })
    },
    {
      re: /^no agent writes more than\s+(\d+)\s+facts?\s*\/\s*(hour|minute|day)$/i,
      build: (m) => ({
        type: 'rate',
        expression: `rate.${m[2].toLowerCase()} > ${m[1]}`,
        action: 'hold',
        explanation: `rate ceiling of ${m[1]} facts per ${m[2]}`
      })
    },
    {
      re: /^a\s+guessed\s+fact\s+may never be marked authoritative$/i,
      build: () => ({
        type: 'claim_type',
        expression: 'claimType == "guessed" and authoritative == true',
        action: 'block',
        explanation: 'guessed facts can never be authoritative'
      })
    },
    {
      re: /^no writes to\s+(.+?)\s+during\s+(.+)$/i,
      build: (m) => ({
        type: 'time_window',
        expression: `folder startswith "${m[1].trim()}" and freezeWindow == "${m[2].trim()}"`,
        action: 'block',
        explanation: `${m[1]} is frozen during ${m[2]}`
      })
    },
    {
      re: /^facts above sensitivity\s+(\w+)\s+need two approvers$/i,
      build: (m) => ({
        type: 'four_eyes',
        expression: `sensitivityRank >= ${sensitivityRank(m[1])}`,
        action: 'require-4-eyes',
        explanation: `two approvers required above ${m[1]}`
      })
    },
    {
      re: /^no fact may assert a legal obligation of the company$/i,
      build: () => ({
        type: 'semantic',
        expression: 'claim matches /\\b(we (?:are )?(?:will|shall|must|are obliged|undertake|commit|guarantee)|the company (?:will|shall|must|guarantees))\\b/',
        action: 'escalate',
        escalateTo: 'Legal',
        explanation: 'no fact may assert a legal obligation of the company'
      })
    },
    {
      re: /^no fact about a person without a recorded lawful basis$/i,
      build: () => ({
        type: 'consent_basis',
        expression: 'entityTypes contains "person" and consentBasis == null',
        action: 'hold',
        explanation: 'personal data requires a recorded lawful basis'
      })
    },
    {
      re: /^(?:eu|EU)[- ]subject data never leaves EU storage$/i,
      build: () => ({
        type: 'jurisdiction',
        expression: 'dataSubjectRegion == "eu" and not (storageRegion startswith "eu")',
        action: 'block',
        explanation: 'EU-subject data never leaves EU storage'
      })
    },
    {
      // Deliberately last: this is the loosest shape in the list, and placed
      // any earlier it swallows the specific sentences above it — "no fact
      // about a person without a recorded lawful basis" would compile to a
      // keyword match instead of the consent check it actually names.
      re: /^no\s+(.+?)\s+(?:promise|commitment)?\s*without\s+(?:a\s+)?(.+)$/i,
      build: (m) => ({
        type: 'forbidden_claim',
        expression: `claim matches /${keyword(m[1])}/`,
        action: 'escalate',
        escalateTo: m[2].trim(),
        explanation: `${m[1]} requires ${m[2]}`
      })
    }
  ];

  for (const p of patterns) {
    const m = p.re.exec(s);
    if (m) return { source: s, ...p.build(m) };
  }
  // An error that only says "no" teaches nobody. Show the shapes that work.
  throw new VaultError('rule_syntax',
    'could not compile that sentence — write it as an expression, or use one of the shapes below',
    { understood: PLAIN_LANGUAGE_SHAPES });
}

/** The plain-language shapes the compiler understands, shown on failure. */
export const PLAIN_LANGUAGE_SHAPES = [
  'No payment authority above $50,000 becomes a fact without sign-off',
  'No payment authority above $50k',
  'No refund without a supervisor',
  'Nothing containing a credential ever becomes a fact',
  'Nothing from email may write to finance/',
  'Support may never write into engineering/',
  'Facts about employees only in hr/',
  'No agent writes more than 200 facts/hour',
  'A guessed fact may never be marked authoritative',
  'No writes to finance/ during quarter-close',
  'Facts above sensitivity confidential need two approvers',
  'No fact may assert a legal obligation of the company',
  'No fact about a person without a recorded lawful basis',
  'EU-subject data never leaves EU storage'
];

const KEYWORDS = {
  'payment authority': 'payment|authority|authorise|authorize|pay|transfer|remit',
  refund: 'refund',
  discount: 'discount',
  credit: 'credit',
  priority: 'priority',
  sla: 'sla|uptime|service level',
  pricing: 'pric(?:e|ing)|rate card|quote'
};
function keyword(phrase) {
  const p = phrase.toLowerCase().trim();
  for (const [k, v] of Object.entries(KEYWORDS)) if (p.includes(k)) return v;
  return p.split(/\s+/).filter((w) => w.length > 3).join('|') || p;
}
function scale(n, suffix) {
  let v = parseFloat(String(n).replace(/,/g, ''));
  const s = (suffix || '').toLowerCase();
  if (s === 'k') v *= 1e3;
  if (s === 'm') v *= 1e6;
  if (s === 'bn') v *= 1e9;
  return v;
}
function categoryFor(what) {
  const w = what.toLowerCase();
  if (/credential|api key|password|token|secret/.test(w)) return 'credential';
  if (/card|payment|iban/.test(w)) return 'payment';
  if (/health|medical/.test(w)) return 'health';
  if (/ssn|aadhaar|passport|national/.test(w)) return 'national_id';
  return 'custom';
}
function sensitivityRank(label) {
  return { public: 0, internal: 1, confidential: 2, secret: 3 }[String(label).toLowerCase()] ?? 2;
}
function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

export class RulesEngine {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   */
  constructor({ collection, ledger }) {
    this.col = collection;
    this.ledger = ledger;
    this.col.index('byState', (r) => r.state);
    this._compiled = new Map();
  }

  /**
   * @param {object} spec
   * @returns {object} the stored rule
   */
  create(spec) {
    const {
      name, description = '', plain = null, expression = null, action, type = 'semantic',
      scope = { kind: 'global' }, state = 'draft', order = 100, actor = 'system',
      escalateTo = null, tests = [], reason = 'rule created'
    } = spec;

    if (!name) throw new VaultError('validation', 'a rule needs a name');
    let compiled = { expression, action, type, escalateTo, explanation: description };
    if (plain) {
      const c = compilePlainLanguage(plain);
      compiled = { ...c, ...(expression ? { expression } : {}), ...(action ? { action } : {}), escalateTo: escalateTo ?? c.escalateTo };
    }
    if (!compiled.expression) throw new VaultError('validation', 'a rule needs an expression or a compilable plain-language sentence');
    if (!RULE_ACTIONS.includes(compiled.action)) throw new VaultError('validation', `action must be one of ${RULE_ACTIONS.join(', ')}`);
    if (!RULE_STATES.includes(state)) throw new VaultError('validation', `state must be one of ${RULE_STATES.join(', ')}`);

    // Parse now, so a syntax error is an authoring-time failure, not a runtime one.
    const ast = parseExpression(compiled.expression);

    const rule = this.col.insert({
      id: spec.id || newId('rule'),
      name,
      description: description || compiled.explanation || '',
      plain,
      expression: compiled.expression,
      ast,
      type: compiled.type || type,
      action: compiled.action,
      escalateTo: compiled.escalateTo,
      scope,
      state,
      order,
      tests,
      version: 1,
      createdBy: actor,
      createdAt: now(),
      history: [{ version: 1, at: now(), actor, reason, change: 'created', expression: compiled.expression, action: compiled.action, state }]
    });
    this._compiled.set(rule.id, ast);
    this.ledger.append('rule.created', {
      subject: rule.id, actor, name, ruleType: rule.type, action: rule.action, state, expression: rule.expression
    });
    return rule;
  }

  /** Version-controlled change: who, when, why, full diff (§8.8). */
  update(id, patch, { actor, reason }) {
    const prev = this.col.get(id);
    if (!prev) throw new VaultError('not_found', 'rule not found', { id });
    if (!actor || !reason) throw new VaultError('forbidden', 'rule changes require a named actor and a reason');
    const next = { ...prev, ...patch };
    if (patch.expression) next.ast = parseExpression(patch.expression);
    const diff = {};
    for (const k of ['expression', 'action', 'state', 'order', 'scope', 'escalateTo', 'name', 'description']) {
      if (JSON.stringify(prev[k]) !== JSON.stringify(next[k])) diff[k] = { from: prev[k], to: next[k] };
    }
    const rule = this.col.update(id, {
      ...next,
      version: prev.version + 1,
      history: [...prev.history, { version: prev.version + 1, at: now(), actor, reason, change: 'updated', diff }]
    });
    this._compiled.set(id, rule.ast);
    this.ledger.append(patch.state === 'enforce' ? 'rule.enabled' : patch.state === 'retired' ? 'rule.disabled' : 'rule.changed', {
      subject: id, actor, reason, version: rule.version, diff: Object.keys(diff)
    });
    return rule;
  }

  get(id) { return this.col.get(id); }
  all() { return this.col.all().sort((a, b) => a.order - b.order || a.createdAt - b.createdAt); }
  active() { return this.all().filter((r) => r.state === 'enforce' || r.state === 'warn-only' || r.state === 'dry-run'); }

  _ast(rule) {
    let ast = this._compiled.get(rule.id);
    if (!ast) {
      ast = rule.ast || parseExpression(rule.expression);
      this._compiled.set(rule.id, ast);
    }
    return ast;
  }

  inScope(rule, ctx) {
    const s = rule.scope || { kind: 'global' };
    switch (s.kind) {
      case 'global': return true;
      case 'department': return (ctx.folder || '').startsWith(`${s.value}/`) || ctx.agent?.department === s.value;
      case 'folder': return (ctx.folder || '').startsWith(s.value);
      case 'project': return ctx.project === s.value || (ctx.folder || '').includes(`/${s.value}/`);
      case 'entity': return (ctx.entityNames || []).includes(s.value);
      case 'agent': return ctx.agentId === s.value;
      default: return true;
    }
  }

  /**
   * Evaluate every applicable rule, in order, with explicit precedence.
   * @param {object} ctx the evaluation context (claim, channel, agent, amounts…)
   * @returns {{evaluated:object[], action:string, matched:object[], escalateTo:string|null}}
   */
  evaluate(ctx) {
    const evaluated = [];
    const matched = [];
    let action = 'pass';
    let escalateTo = null;

    for (const rule of this.all()) {
      if (rule.state === 'draft' || rule.state === 'retired') continue;
      if (!this.inScope(rule, ctx)) {
        evaluated.push({ id: rule.id, name: rule.name, result: 'n/a', reason: 'out of scope', version: rule.version });
        continue;
      }
      let hit = false;
      let error = null;
      try {
        hit = Boolean(evaluateAst(this._ast(rule), ctx));
      } catch (e) {
        error = e.message;
      }
      const record = {
        id: rule.id, name: rule.name, version: rule.version, state: rule.state,
        result: error ? 'error' : hit ? 'match' : 'pass',
        action: hit ? rule.action : null, error, explanation: hit ? rule.description : null
      };
      evaluated.push(record);
      if (!hit || error) continue;
      matched.push({ ...record, escalateTo: rule.escalateTo, ruleAction: rule.action });
      // dry-run and warn-only observe without changing the outcome.
      if (rule.state === 'dry-run' || rule.state === 'warn-only') continue;
      if (severity(rule.action) > severity(action)) {
        action = rule.action;
        escalateTo = rule.escalateTo || escalateTo;
      }
    }
    return { evaluated, matched, action, escalateTo };
  }

  /**
   * Conflict detection at authoring time (§8.8): two enforced rules whose
   * expressions overlap but whose actions disagree.
   */
  detectConflicts() {
    const rules = this.all().filter((r) => r.state === 'enforce');
    const conflicts = [];
    for (let i = 0; i < rules.length; i++) {
      for (let j = i + 1; j < rules.length; j++) {
        const a = rules[i];
        const b = rules[j];
        if (a.action === b.action) continue;
        const overlap = expressionOverlap(a.expression, b.expression);
        if (overlap > 0.5) {
          conflicts.push({
            a: { id: a.id, name: a.name, action: a.action, order: a.order },
            b: { id: b.id, name: b.name, action: b.action, order: b.order },
            overlap: Math.round(overlap * 100) / 100,
            resolution: severity(a.action) === severity(b.action)
              ? `same severity — order decides: ${a.order <= b.order ? a.name : b.name} evaluates first`
              : `strictest wins: ${severity(a.action) > severity(b.action) ? a.action : b.action}`,
            warning: 'these rules can both match the same write and disagree'
          });
        }
      }
    }
    return conflicts;
  }

  /**
   * Rule test suite: assertions run in CI before a rule is enabled (§8.8).
   * @param {string} id
   */
  runTests(id) {
    const rule = this.col.get(id);
    if (!rule) throw new VaultError('not_found', 'rule not found', { id });
    const results = (rule.tests || []).map((t) => {
      let actual;
      let error = null;
      try { actual = Boolean(evaluateAst(this._ast(rule), t.ctx)); } catch (e) { error = e.message; }
      return { name: t.name, expected: t.expectMatch, actual, pass: !error && actual === t.expectMatch, error };
    });
    return { ruleId: id, total: results.length, passed: results.filter((r) => r.pass).length, results };
  }

  /**
   * DRY-RUN / BACKTEST — the procurement closer (§8.8).
   * Run a candidate rule against real history and report exactly what it would
   * have done, including the reviewer load it adds.
   *
   * @param {object} spec candidate rule ({expression|plain, action, ...})
   * @param {object[]} history array of past evaluation contexts
   * @param {{secondsPerReview?:number, windowDays?:number}} [opts]
   */
  backtest(spec, history, { secondsPerReview = 40, windowDays = 90 } = {}) {
    let compiled = spec;
    if (spec.plain) compiled = { ...compilePlainLanguage(spec.plain), ...spec };
    const ast = parseExpression(compiled.expression);
    const action = compiled.action || 'hold';

    const hits = [];
    for (const ctx of history) {
      let hit = false;
      try { hit = Boolean(evaluateAst(ast, ctx)); } catch { hit = false; }
      if (hit) hits.push(ctx);
    }

    // Heuristic triage: a hit that ALSO tripped another signal is the one you
    // want to look at right now.
    const suspicious = hits.filter((h) =>
      (h.instructionScore ?? 0) >= 0.5 || h.channelTrust === 'untrusted' ||
      (h.contradictsGolden ?? false) || (h.pii?.categories || []).includes('credential'));
    const legitimate = hits.length - suspicious.length;

    const byOutcome = { held: 0, blocked: 0, escalated: 0, masked: 0, quarantined: 0, fourEyes: 0 };
    if (action === 'hold') byOutcome.held = hits.length;
    else if (action === 'block') byOutcome.blocked = hits.length;
    else if (action === 'escalate') byOutcome.escalated = hits.length;
    else if (action === 'mask') byOutcome.masked = hits.length;
    else if (action === 'quarantine') byOutcome.quarantined = hits.length;
    else if (action === 'require-4-eyes') byOutcome.fourEyes = hits.length;

    const byAgent = {};
    for (const h of hits) byAgent[h.agentId || 'unknown'] = (byAgent[h.agentId || 'unknown'] || 0) + 1;

    const falsePositiveRate = hits.length ? Math.round((legitimate / hits.length) * 100) : 0;
    const weeklyReviewSeconds = (hits.length / Math.max(windowDays / 7, 1)) * secondsPerReview;

    return {
      rule: { name: spec.name || '(unnamed)', expression: compiled.expression, action, plain: spec.plain || null },
      window: `last ${windowDays} days`,
      evaluated: history.length,
      wouldMatch: hits.length,
      byOutcome,
      legitimate,
      suspicious: suspicious.length,
      suspiciousSamples: suspicious.slice(0, 5).map((h) => ({
        claim: truncate(h.claim, 100), agentId: h.agentId, channel: h.channel,
        why: [
          (h.instructionScore ?? 0) >= 0.5 ? 'instruction-shaped' : null,
          h.channelTrust === 'untrusted' ? 'untrusted channel' : null,
          h.contradictsGolden ? 'contradicts a golden fact' : null,
          (h.pii?.categories || []).includes('credential') ? 'contains a credential' : null
        ].filter(Boolean)
      })),
      estimatedFalsePositiveRate: `${falsePositiveRate}%`,
      reviewerLoadAdded: `~${Math.round(weeklyReviewSeconds / 60)} min/week`,
      agentsAffected: Object.entries(byAgent).sort((a, b) => b[1] - a[1]).map(([id, n]) => `${id} (${n})`),
      recommendation: hits.length === 0
        ? 'no historical matches — safe to enable, but it is also unproven; consider warn-only first'
        : suspicious.length > 0
          ? `${suspicious.length} historical write${suspicious.length === 1 ? '' : 's'} you should look at right now`
          : 'all matches look legitimate — enable in warn-only first and watch the queue',
      actions: ['Enable', 'Enable warn-only', 'Adjust threshold', 'Discard']
    };
  }

  /** Export as reviewable code, for git / Terraform (§8.8). */
  exportAsCode(format = 'yaml') {
    const rules = this.all();
    if (format === 'json') return JSON.stringify(rules.map(stripRuntime), null, 2);
    if (format === 'terraform') {
      return rules.map((r) => `resource "vault_rule" "${r.id.replace(/-/g, '_')}" {
  name        = ${JSON.stringify(r.name)}
  description = ${JSON.stringify(r.description || '')}
  type        = ${JSON.stringify(r.type)}
  expression  = ${JSON.stringify(r.expression)}
  action      = ${JSON.stringify(r.action)}
  state       = ${JSON.stringify(r.state)}
  order       = ${r.order}
  scope {
    kind  = ${JSON.stringify(r.scope?.kind || 'global')}
    value = ${JSON.stringify(r.scope?.value || '')}
  }
}`).join('\n\n');
    }
    // default: yaml
    return rules.map((r) => [
      `- id: ${r.id}`,
      `  name: ${JSON.stringify(r.name)}`,
      `  type: ${r.type}`,
      `  state: ${r.state}`,
      `  order: ${r.order}`,
      `  action: ${r.action}`,
      r.escalateTo ? `  escalateTo: ${JSON.stringify(r.escalateTo)}` : null,
      `  scope: { kind: ${r.scope?.kind || 'global'}${r.scope?.value ? `, value: ${JSON.stringify(r.scope.value)}` : ''} }`,
      `  expression: ${JSON.stringify(r.expression)}`,
      r.plain ? `  plain: ${JSON.stringify(r.plain)}` : null,
      `  version: ${r.version}`
    ].filter(Boolean).join('\n')).join('\n');
  }

  /** Import rules from the exported format (one-click migration, §1). */
  importRules(rules, { actor = 'import', reason = 'imported' } = {}) {
    const created = [];
    for (const r of rules) {
      try { created.push(this.create({ ...r, actor, reason })); } catch { /* skip invalid */ }
    }
    return { imported: created.length, skipped: rules.length - created.length, ids: created.map((r) => r.id) };
  }
}

const SEVERITY = { pass: 0, alert: 1, mask: 2, 'require-4-eyes': 3, escalate: 4, hold: 5, quarantine: 6, block: 7 };
export function severity(action) { return SEVERITY[action] ?? 0; }

function expressionOverlap(a, b) {
  const ta = new Set(String(a).toLowerCase().match(/[a-z_.]+/g) || []);
  const tb = new Set(String(b).toLowerCase().match(/[a-z_.]+/g) || []);
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  return inter / Math.max(1, Math.min(ta.size, tb.size));
}

function stripRuntime(r) {
  const { ast, history, ...rest } = r;
  return rest;
}

/** Rule templates library, per industry and per jurisdiction (§8.8). */
export const RULE_TEMPLATES = [
  { id: 'payment-authority', industry: 'all', name: 'Payment authority ceiling', plain: 'No payment authority above $50,000 becomes a fact without sign-off', action: 'escalate', type: 'threshold' },
  { id: 'no-refund-promise', industry: 'all', name: 'No unapproved refund promises', plain: 'No refund promise without a supervisor', action: 'escalate' },
  { id: 'no-credentials', industry: 'all', name: 'Credentials are never facts', plain: 'Nothing containing a credential ever becomes a fact', action: 'block' },
  { id: 'email-not-finance', industry: 'all', name: 'Email may not write to finance', plain: 'Nothing from email may write to finance/', action: 'block' },
  { id: 'support-not-eng', industry: 'all', name: 'Support may not write to engineering', plain: 'support may never write into engineering/', action: 'block' },
  { id: 'employee-facts-hr', industry: 'all', name: 'Employee facts belong in HR', plain: 'Facts about employees only in hr/', action: 'block' },
  { id: 'rate-ceiling', industry: 'all', name: 'Runaway-loop rate ceiling', plain: 'No agent writes more than 500 facts/hour', action: 'hold' },
  { id: 'guessed-never-authoritative', industry: 'all', name: 'Guessed facts are never authoritative', plain: 'A guessed fact may never be marked authoritative', action: 'block' },
  { id: 'four-eyes-secret', industry: 'all', name: 'Four eyes above confidential', plain: 'Facts above sensitivity confidential need two approvers', action: 'require-4-eyes' },
  { id: 'no-legal-obligation', industry: 'all', name: 'No fact may bind the company', plain: 'No fact may assert a legal obligation of the company', action: 'escalate' },
  { id: 'lawful-basis', industry: 'eu', name: 'Lawful basis required', plain: 'No fact about a person without a recorded lawful basis', action: 'hold' },
  { id: 'eu-residency', industry: 'eu', name: 'EU data stays in the EU', plain: 'EU-subject data never leaves EU storage', action: 'block' },
  { id: 'quarter-close-freeze', industry: 'finserv', name: 'Quarter-close freeze', plain: 'No writes to finance/ during quarter-close freeze', action: 'block' },
  {
    id: 'model-version-pin', industry: 'all', name: 'Approved model versions only', type: 'model_version',
    expression: 'modelApproved == false', action: 'hold',
    description: 'facts written by an unapproved model version are held'
  },
  {
    id: 'volume-anomaly', industry: 'all', name: 'Volume anomaly', type: 'volume_anomaly',
    expression: 'rate.baselineMultiple > 50', action: 'hold',
    description: 'an agent writing 50x its baseline has everything held pending review'
  },
  {
    id: 'golden-protection', industry: 'all', name: 'Golden facts are unoverwritable', type: 'golden_protection',
    expression: 'contradictsGolden == true and claimType != "approved"', action: 'block',
    description: 'an approved fact cannot be overwritten by any agent, ever'
  },
  {
    id: 'regulatory-record', industry: 'finserv', name: 'Business records go to WORM', type: 'regulatory_record',
    expression: 'channel in ["email","chat","phone_call","sms"] and businessRecord == true', action: 'alert',
    description: 'anything matching a defined business-record pattern must go to WORM'
  }
];
