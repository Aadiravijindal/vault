/**
 * Check 4 — private information scan (§8.4).
 * 🟢 Built-in: Vault PII Scanner. 🔵 Or consume a connected DLP's verdicts.
 *
 * Detect and act BEFORE storage. Credentials get special treatment: blocked
 * entirely, never masked-and-stored, alerted immediately, source flagged. A
 * masked credential is still a credential in your archive.
 */
import { shannonEntropy, sha256, randomToken } from '../util/crypto.js';
import { now, iso } from '../util/time.js';
import { VaultError } from '../util/errors.js';

/** @typedef {'mask'|'tokenise'|'redact'|'block'|'quarantine'|'allow'} PiiAction */

export const CATEGORIES = {
  payment: { severity: 'high', defaultAction: 'tokenise' },
  national_id: { severity: 'high', defaultAction: 'tokenise' },
  health: { severity: 'high', defaultAction: 'mask', specialCategory: true },
  credential: { severity: 'critical', defaultAction: 'block' },
  contact: { severity: 'medium', defaultAction: 'mask' },
  special_category: { severity: 'high', defaultAction: 'mask', specialCategory: true },
  children: { severity: 'high', defaultAction: 'quarantine' },
  secret_entropy: { severity: 'critical', defaultAction: 'block' },
  custom: { severity: 'medium', defaultAction: 'mask' }
};

/**
 * Every detector. `validate` weeds out false positives that plain regex can't —
 * a 16-digit order number is not a card number, and pretending otherwise is how
 * DLP tools earn their reputation.
 */
export const DETECTORS = [
  // ---- payment -----------------------------------------------------------
  { id: 'card', category: 'payment', label: 'payment card number', pattern: /\b(?:\d[ -]?){13,19}\b/g, validate: luhn, action: 'tokenise' },
  { id: 'cvv', category: 'payment', label: 'card security code', pattern: /\b(?:cvv|cvc|cid|security code)\b\D{0,12}(\d{3,4})\b/gi, action: 'redact' },
  { id: 'iban', category: 'payment', label: 'IBAN', pattern: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g, validate: ibanValid, action: 'tokenise' },
  { id: 'swift', category: 'payment', label: 'SWIFT/BIC', pattern: /\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g, validate: (m, ctx) => /\b(swift|bic)\b/i.test(ctx), action: 'mask' },
  { id: 'routing_aba', category: 'payment', label: 'US ABA routing number', pattern: /\b\d{9}\b/g, validate: (m, ctx) => /\b(routing|aba|rtn)\b/i.test(ctx) && abaChecksum(m), action: 'tokenise' },
  { id: 'bank_account', category: 'payment', label: 'bank account number', pattern: /\b(?:account|acct|a\/c)(?:\s*(?:number|no|#))?\s*[:#]?\s*(\d{6,17})\b/gi, action: 'tokenise' },
  { id: 'upi', category: 'payment', label: 'UPI ID', pattern: /\b[a-zA-Z0-9._-]{3,}@(?:ok(?:hdfcbank|icici|axis|sbi)|paytm|ybl|upi|apl|ibl)\b/g, action: 'tokenise' },

  // ---- national identifiers ---------------------------------------------
  { id: 'ssn', category: 'national_id', label: 'US SSN', pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, action: 'tokenise' },
  { id: 'aadhaar', category: 'national_id', label: 'Aadhaar', pattern: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g, validate: verhoeff, action: 'tokenise' },
  { id: 'pan_in', category: 'national_id', label: 'India PAN', pattern: /\b[A-Z]{5}\d{4}[A-Z]\b/g, action: 'tokenise' },
  { id: 'nino', category: 'national_id', label: 'UK National Insurance number', pattern: /\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi, action: 'tokenise' },
  { id: 'passport', category: 'national_id', label: 'passport number', pattern: /\b(?:passport)\b\D{0,16}([A-Z0-9]{6,9})\b/gi, action: 'tokenise' },
  { id: 'driving_licence', category: 'national_id', label: 'driving licence', pattern: /\b(?:driv(?:er'?s|ing)\s+licen[cs]e)\b\D{0,16}([A-Z0-9]{5,20})\b/gi, action: 'tokenise' },
  { id: 'tax_id', category: 'national_id', label: 'tax identifier', pattern: /\b(?:vat|tin|ein|utr|steuernummer)\b\D{0,10}([A-Z]{0,2}[\d ]{7,15})\b/gi, action: 'mask' },

  // ---- health (HIPAA / GDPR Art 9) --------------------------------------
  { id: 'mrn', category: 'health', label: 'medical record number', pattern: /\b(?:mrn|medical record(?: number)?|patient id)\b\D{0,10}([A-Z0-9-]{5,20})\b/gi, action: 'mask' },
  { id: 'insurance_id', category: 'health', label: 'health insurance id', pattern: /\b(?:member id|policy(?: number)?|insurance id|nhs number)\b\D{0,10}([A-Z0-9- ]{6,20})\b/gi, action: 'mask' },
  { id: 'icd', category: 'health', label: 'ICD/SNOMED code', pattern: /\b(?:ICD-?10:?\s*)?[A-TV-Z]\d{2}(?:\.\d{1,4})?\b|\bSNOMED:?\s*\d{6,18}\b/g, validate: (m, ctx) => /\b(icd|snomed|diagnos|code)\b/i.test(ctx), action: 'mask' },
  { id: 'clinical', category: 'health', label: 'clinical language', pattern: /\b(diagnos(?:ed|is) with|prescribed|dosage|mg (?:daily|bd|tds)|treatment plan|admitted to hospital|oncolog|psychiatr|hiv[- ]positive)\b/gi, action: 'mask' },

  // ---- credentials — critical, always blocked ---------------------------
  { id: 'aws_key', category: 'credential', label: 'AWS access key id', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, action: 'block' },
  { id: 'aws_secret', category: 'credential', label: 'AWS secret access key', pattern: /\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)\b\W{0,4}([A-Za-z0-9/+=]{40})\b/gi, action: 'block' },
  { id: 'gcp_key', category: 'credential', label: 'GCP API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, action: 'block' },
  { id: 'azure_conn', category: 'credential', label: 'Azure connection string', pattern: /\bDefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/gi, action: 'block' },
  { id: 'openai_key', category: 'credential', label: 'OpenAI API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, action: 'block' },
  { id: 'anthropic_key', category: 'credential', label: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, action: 'block' },
  { id: 'github_token', category: 'credential', label: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, action: 'block' },
  { id: 'slack_token', category: 'credential', label: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, action: 'block' },
  { id: 'stripe_key', category: 'credential', label: 'Stripe secret key', pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g, action: 'block' },
  { id: 'jwt', category: 'credential', label: 'JWT', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, action: 'block' },
  { id: 'private_key', category: 'credential', label: 'private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g, action: 'block' },
  { id: 'ssh_key', category: 'credential', label: 'SSH key', pattern: /\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{40,}={0,3}/g, action: 'block' },
  { id: 'password_assignment', category: 'credential', label: 'password in text', pattern: /\b(?:password|passwd|pwd|passphrase)\b\s*(?:is|=|:)\s*(\S{6,})/gi, action: 'block' },
  { id: 'db_conn', category: 'credential', label: 'database connection string', pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@]+:[^\s@]+@\S+/gi, action: 'block' },
  { id: 'bearer', category: 'credential', label: 'bearer token', pattern: /\b(?:authorization|bearer)\b\s*:?\s*(?:bearer\s+)?([A-Za-z0-9._~+/-]{24,}={0,2})\b/gi, action: 'block' },

  // ---- personal contact --------------------------------------------------
  { id: 'email', category: 'contact', label: 'email address', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, action: 'mask' },
  { id: 'phone', category: 'contact', label: 'phone number', pattern: /(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{3,4}[ -]?\d{3,4}[ -]?\d{0,4}/g, validate: (m) => m.replace(/\D/g, '').length >= 10 && m.replace(/\D/g, '').length <= 15, action: 'mask' },
  { id: 'address', category: 'contact', label: 'postal address', pattern: /\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct)\b\.?/g, action: 'mask' },
  { id: 'dob', category: 'contact', label: 'date of birth', pattern: /\b(?:dob|date of birth|born(?: on)?)\b\D{0,10}(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})\b/gi, action: 'mask' },
  { id: 'biometric', category: 'contact', label: 'biometric reference', pattern: /\b(?:fingerprint|faceprint|face id|iris scan|voiceprint|retina scan|gait analysis)\b/gi, action: 'mask' },

  // ---- GDPR Art 9 special category --------------------------------------
  { id: 'special_health', category: 'special_category', label: 'health (Art 9)', pattern: /\b(?:is (?:diabetic|epileptic|autistic|bipolar)|has (?:cancer|depression|anxiety|adhd)|mental health|disabilit(?:y|ies)|pregnan(?:t|cy))\b/gi, action: 'mask' },
  { id: 'special_race', category: 'special_category', label: 'racial or ethnic origin (Art 9)', pattern: /\b(?:racial|ethnic(?:ity)?|caste)\b/gi, action: 'mask' },
  { id: 'special_religion', category: 'special_category', label: 'religious belief (Art 9)', pattern: /\b(?:muslim|christian|jewish|hindu|sikh|buddhist|atheist|religio(?:n|us) belief)\b/gi, action: 'mask' },
  { id: 'special_politics', category: 'special_category', label: 'political opinion (Art 9)', pattern: /\b(?:voted for|political (?:party|opinion|affiliation)|member of the (?:labour|conservative|republican|democrat)\w* party)\b/gi, action: 'mask' },
  { id: 'special_union', category: 'special_category', label: 'trade union membership (Art 9)', pattern: /\b(?:trade union|union member(?:ship)?|works council|betriebsrat|shop steward)\b/gi, action: 'mask' },
  { id: 'special_sexlife', category: 'special_category', label: 'sexual orientation (Art 9)', pattern: /\b(?:sexual orientation|gay|lesbian|bisexual|transgender)\b/gi, action: 'mask' },

  // ---- children's data (DPDP §9, COPPA) ---------------------------------
  { id: 'children', category: 'children', label: "child's data indicator", pattern: /\b(?:my (?:son|daughter|child) is \d{1,2}|(?:aged?|age:?)\s*(?:[1-9]|1[0-7])\b(?!\s*(?:%|percent|months))|minor(?:'s)? (?:account|data)|under (?:13|16|18)|school (?:year|report)|kindergarten|parental consent)\b/gi, action: 'quarantine' }
];

export class PiiScanner {
  /**
   * @param {object} [opts]
   * @param {Array<{id:string,label:string,pattern:RegExp,category?:string,action?:PiiAction}>} [opts.customDetectors]
   *        Per-company: employee ID formats, contract numbers, project codenames…
   * @param {Record<string, PiiAction>} [opts.overrides] detectorId → action
   * @param {number} [opts.entropyThreshold]
   * @param {(e:object)=>void} [opts.onCredential]
   */
  constructor({ customDetectors = [], overrides = {}, entropyThreshold = 4.2, onCredential } = {}) {
    this.detectors = [...DETECTORS, ...customDetectors.map((d) => ({ category: 'custom', action: 'mask', ...d }))];
    this.overrides = overrides;
    this.entropyThreshold = entropyThreshold;
    this.onCredential = onCredential || (() => {});
    /** Token vault, separate from the fact store (§9.11). */
    this.tokenVault = new Map();
    this.reverseVault = new Map();
  }

  addCustomDetector(d) {
    this.detectors.push({ category: 'custom', action: 'mask', ...d, pattern: toGlobal(d.pattern) });
    return this;
  }

  /**
   * @param {string} text
   * @param {{subject?:string, purpose?:string}} [ctx]
   * @returns {{findings:object[], action:PiiAction, masked:string, credentials:object[], specialCategory:boolean, childrensData:boolean}}
   */
  scan(text, ctx = {}) {
    const input = String(text ?? '');
    /** @type {object[]} */
    const findings = [];
    const seen = new Set();

    for (const det of this.detectors) {
      const re = toGlobal(det.pattern);
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(input)) !== null) {
        const value = m[1] !== undefined && det.pattern.source.includes('(') && !det.pattern.source.startsWith('(?:')
          ? m[1] : m[0];
        const around = input.slice(Math.max(0, m.index - 60), m.index + m[0].length + 30);
        if (det.validate && !det.validate(value, around)) continue;
        const key = `${det.id}:${m.index}:${value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          detector: det.id,
          label: det.label,
          category: det.category,
          start: m.index,
          end: m.index + m[0].length,
          match: m[0],
          value,
          action: this.overrides[det.id] || det.action || CATEGORIES[det.category]?.defaultAction || 'mask',
          severity: CATEGORIES[det.category]?.severity || 'medium'
        });
        if (re.lastIndex === m.index) re.lastIndex++;
      }
    }

    // Free-text secrets by entropy — catches keys we have no pattern for.
    for (const m of input.matchAll(/\b[A-Za-z0-9+/_=-]{24,}\b/g)) {
      const s = m[0];
      if (findings.some((f) => f.start <= m.index && f.end >= m.index + s.length)) continue;
      if (/^\d+$/.test(s)) continue;
      if (shannonEntropy(s) >= this.entropyThreshold && /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s)) {
        findings.push({
          detector: 'entropy', label: 'high-entropy secret', category: 'secret_entropy',
          start: m.index, end: m.index + s.length, match: s, value: s,
          action: 'block', severity: 'critical', entropy: Math.round(shannonEntropy(s) * 100) / 100
        });
      }
    }

    findings.sort((a, b) => a.start - b.start || b.end - a.end);
    const credentials = findings.filter((f) => f.category === 'credential' || f.category === 'secret_entropy');

    // Credentials are blocked outright — never masked-and-stored — and the
    // source is flagged immediately (§8.4).
    if (credentials.length) {
      this.onCredential({
        at: iso(), count: credentials.length,
        detectors: [...new Set(credentials.map((c) => c.detector))],
        // fingerprint only; the secret itself never leaves this function
        fingerprints: credentials.map((c) => sha256(c.value).slice(0, 16)),
        subject: ctx.subject ?? null
      });
    }

    const action = credentials.length ? 'block'
      : findings.some((f) => f.action === 'quarantine') ? 'quarantine'
      : findings.length ? strictest(findings.map((f) => f.action))
      : 'allow';

    return {
      findings: findings.map((f) => ({ ...f, value: undefined, match: undefined, preview: preview(f) })),
      rawFindings: findings,
      action,
      masked: this.apply(input, findings),
      credentials: credentials.map((c) => ({ detector: c.detector, label: c.label, severity: c.severity })),
      specialCategory: findings.some((f) => CATEGORIES[f.category]?.specialCategory),
      childrensData: findings.some((f) => f.category === 'children'),
      categories: [...new Set(findings.map((f) => f.category))]
    };
  }

  /** Apply per-finding actions to produce the storable string. */
  apply(input, findings) {
    if (!findings.length) return input;
    let out = '';
    let cursor = 0;
    for (const f of findings) {
      if (f.start < cursor) continue; // overlapping — outermost wins
      out += input.slice(cursor, f.start);
      const original = input.slice(f.start, f.end);
      if (f.action === 'redact') out += `[REDACTED:${f.detector}]`;
      else if (f.action === 'tokenise') out += this.tokenise(original, f.detector);
      else if (f.action === 'block') out += `[BLOCKED:${f.detector}]`;
      else out += mask(original);
      cursor = f.end;
    }
    return out + input.slice(cursor);
  }

  /** Reversible only via break-glass with two approvers (§8.4). */
  tokenise(value, detector = 'pii') {
    const fp = sha256(value);
    let token = this.reverseVault.get(fp);
    if (!token) {
      token = `tok_${detector}_${randomToken(9)}`;
      this.tokenVault.set(token, { value, detector, created: now(), fingerprint: fp });
      this.reverseVault.set(fp, token);
    }
    return token;
  }

  /**
   * @param {string} token
   * @param {{approvers:string[], reason:string, caseId?:string}} auth
   */
  detokenise(token, auth) {
    if (!auth || !Array.isArray(auth.approvers) || new Set(auth.approvers).size < 2 || !auth.reason) {
      throw new VaultError('forbidden', 'detokenisation requires two distinct named approvers and a stated reason');
    }
    const entry = this.tokenVault.get(token);
    if (!entry) throw new VaultError('not_found', 'token not found in the token vault', { token });
    return { value: entry.value, detector: entry.detector, approvers: auth.approvers, reason: auth.reason, at: iso() };
  }

  /** Data minimisation at extraction time, not cleanup time (§9.11). */
  minimise(text, { keepCategories = [] } = {}) {
    const res = this.scan(text);
    const drop = res.rawFindings.filter((f) => !keepCategories.includes(f.category));
    return this.apply(text, drop.map((f) => ({ ...f, action: f.category === 'credential' ? 'block' : 'redact' })));
  }

  stats() {
    return { detectors: this.detectors.length, tokensIssued: this.tokenVault.size };
  }
}

// ---------------------------------------------------------------------------

const ORDER = { allow: 0, mask: 1, tokenise: 2, redact: 3, quarantine: 4, block: 5 };
function strictest(actions) {
  return actions.reduce((a, b) => (ORDER[b] > ORDER[a] ? b : a), 'allow');
}

/** Take the stricter of ours and a connected DLP's verdict (🟣 both mode). */
export function combineVerdicts(a, b) {
  return { ...a, action: strictest([a.action, b.action]), findings: [...(a.findings || []), ...(b.findings || [])] };
}

function mask(s) {
  const str = String(s);
  if (str.length <= 4) return '*'.repeat(str.length);
  const keep = Math.min(2, Math.floor(str.length / 6));
  return str.slice(0, keep) + '*'.repeat(Math.max(3, str.length - keep * 2)) + str.slice(str.length - keep);
}

function preview(f) {
  return f.category === 'credential' || f.category === 'secret_entropy'
    ? `[${f.label} — value never retained]`
    : mask(f.match);
}

function toGlobal(re) {
  return re.global ? re : new RegExp(re.source, re.flags + 'g');
}

// -- validators -------------------------------------------------------------

export function luhn(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

export function ibanValid(value) {
  const s = String(value).replace(/\s/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rem = 0;
  for (const ch of numeric) rem = (rem * 10 + Number(ch)) % 97;
  return rem === 1;
}

export function abaChecksum(value) {
  const d = String(value).replace(/\D/g, '');
  if (d.length !== 9) return false;
  const n = [...d].map(Number);
  return (3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + (n[2] + n[5] + n[8])) % 10 === 0;
}

/** Verhoeff checksum — Aadhaar. Without it every 12-digit number is a false positive. */
const D_TABLE = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
];
const P_TABLE = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
];
export function verhoeff(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length !== 12) return false;
  let c = 0;
  const reversed = [...digits].reverse().map(Number);
  for (let i = 0; i < reversed.length; i++) c = D_TABLE[c][P_TABLE[i % 8][reversed[i]]];
  return c === 0;
}
