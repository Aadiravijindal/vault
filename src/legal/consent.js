/**
 * Consent & lawful basis (§8.10, §14.5).
 *
 * Which basis applies to each fact, who consented to what and when, the notice
 * text version they saw, purpose limitation enforced AT READ TIME, withdrawal
 * that triggers an actual purge rather than a flag, children's data, and India's
 * DPDP Consent Manager interface.
 */
import { newId } from '../util/id.js';
import { now, iso, ago, duration, YEAR } from '../util/time.js';
import { sha256 } from '../util/crypto.js';
import { VaultError, notFound, forbidden } from '../util/errors.js';

export const LAWFUL_BASES = {
  consent: { article: 'GDPR Art 6(1)(a)', withdrawable: true },
  contract: { article: 'GDPR Art 6(1)(b)', withdrawable: false },
  legal_obligation: { article: 'GDPR Art 6(1)(c)', withdrawable: false },
  vital_interests: { article: 'GDPR Art 6(1)(d)', withdrawable: false },
  public_task: { article: 'GDPR Art 6(1)(e)', withdrawable: false },
  legitimate_interest: { article: 'GDPR Art 6(1)(f)', withdrawable: false, requiresLia: true }
};

export const ARTICLE_9_CONDITIONS = {
  explicit_consent: 'Art 9(2)(a) explicit consent',
  employment_law: 'Art 9(2)(b) employment, social security and social protection law',
  vital_interests: 'Art 9(2)(c) vital interests',
  legal_claims: 'Art 9(2)(f) establishment, exercise or defence of legal claims',
  substantial_public_interest: 'Art 9(2)(g) substantial public interest',
  health_care: 'Art 9(2)(h) preventive or occupational medicine'
};

/** Purposes are declared, and reads are checked against them. */
export const PURPOSES = [
  'memory_governance', 'support', 'sales', 'billing', 'security', 'compliance',
  'product_improvement', 'marketing', 'hr_administration', 'legal_defence'
];

/** Which purposes are compatible with which collection purpose (purpose limitation). */
const COMPATIBLE = {
  support: ['support', 'memory_governance', 'security', 'compliance', 'legal_defence'],
  sales: ['sales', 'memory_governance', 'compliance', 'legal_defence'],
  billing: ['billing', 'compliance', 'legal_defence', 'memory_governance'],
  hr_administration: ['hr_administration', 'compliance', 'legal_defence'],
  security: ['security', 'compliance', 'legal_defence', 'memory_governance'],
  marketing: ['marketing'],
  compliance: ['compliance', 'legal_defence'],
  memory_governance: ['memory_governance', 'security', 'compliance', 'legal_defence']
};

export class ConsentRegistry {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {{register:(r:object)=>any, verify:(s:string)=>any}} [opts.consentManager] DPDP Consent Manager
   */
  constructor({ collection, ledger, consentManager = null, retention = '7y' }) {
    this.col = collection;
    this.ledger = ledger;
    this.consentManager = consentManager;
    this.recordRetention = duration(retention);   // DPDP: 7-year consent record retention
    this.col.index('bySubject', (c) => c.subject);
    this.erasureRequests = new Set();
    this.onWithdrawal = null;
  }

  /**
   * Record a lawful basis for processing a subject's data.
   * @param {object} spec
   */
  record(spec) {
    const {
      subject, basis, purpose = 'memory_governance', actor = 'system',
      noticeVersion = null, noticeText = null, mechanism = 'unspecified',
      specialCategory = false, article9Condition = null,
      minor = false, parentalConsent = false, parentIdentity = null,
      lia = null, expiresIn = null, jurisdiction = 'eu'
    } = spec;

    if (!subject) throw new VaultError('validation', 'a consent record needs a subject');
    if (!LAWFUL_BASES[basis]) throw new VaultError('validation', `basis must be one of ${Object.keys(LAWFUL_BASES).join(', ')}`);
    if (basis === 'legitimate_interest' && !lia) {
      throw new VaultError('validation', 'legitimate interest requires a Legitimate Interests Assessment (LIA) reference');
    }
    if (specialCategory && !article9Condition) {
      throw new VaultError('validation', 'special-category data requires a recorded Art 9 condition');
    }
    if (minor && !parentalConsent) {
      throw new VaultError('validation', "a minor's data requires verifiable parental consent (DPDP §9 / COPPA)");
    }

    const record = this.col.insert({
      id: newId('consent'),
      subject, basis, purpose, jurisdiction,
      article: LAWFUL_BASES[basis].article,
      specialCategory, article9Condition,
      article9Text: article9Condition ? ARTICLE_9_CONDITIONS[article9Condition] ?? article9Condition : null,
      minor, parentalConsent, parentIdentity,
      lia,
      noticeVersion,
      noticeHash: noticeText ? sha256(noticeText) : null,
      mechanism,
      recordedBy: actor,
      recordedAt: now(),
      expiresAt: expiresIn ? now() + duration(expiresIn) : null,
      withdrawn: false,
      withdrawnAt: null,
      // DPDP: consent records retained 7 years even after withdrawal
      retainUntil: now() + this.recordRetention,
      consentManagerRef: null
    });

    // India DPDP Consent Manager integration — API-level, registered-manager
    // compatible (§14.5).
    if (this.consentManager && jurisdiction === 'in') {
      try {
        const ref = this.consentManager.register({
          subject, purpose, basis, noticeVersion, at: iso(record.recordedAt)
        });
        this.col.update(record.id, { consentManagerRef: ref?.id ?? ref ?? null });
      } catch { /* registry unavailable — the local record still stands */ }
    }

    this.ledger.append('privacy.consent_recorded', {
      subject, actor, basis, purpose, specialCategory, minor,
      noticeVersion, consentId: record.id
    });
    return this.col.get(record.id);
  }

  /**
   * Withdrawal triggers an ACTUAL PURGE, not a flag (§14.5).
   * @param {string} subject
   */
  withdraw(subject, { actor, reason, purpose = null }) {
    if (!actor) throw forbidden('recording a withdrawal requires a named actor');
    const records = this.col.by('bySubject', subject).filter((r) => !r.withdrawn && (!purpose || r.purpose === purpose));
    if (!records.length) throw notFound('consent record', subject);
    const withdrawn = [];
    for (const r of records) {
      if (!LAWFUL_BASES[r.basis].withdrawable) continue;   // contract/legal obligation survive
      withdrawn.push(this.col.update(r.id, { withdrawn: true, withdrawnAt: now(), withdrawnReason: reason }));
    }
    this.ledger.append('privacy.consent_withdrawn', {
      subject, actor, reason, records: withdrawn.length,
      remainingBases: records.filter((r) => !LAWFUL_BASES[r.basis].withdrawable).map((r) => r.basis)
    });
    const purge = this.onWithdrawal ? this.onWithdrawal({ subject, actor, reason, purpose }) : null;
    return {
      subject,
      withdrawnRecords: withdrawn.length,
      survivingBases: records.filter((r) => !LAWFUL_BASES[r.basis].withdrawable).map((r) => ({ basis: r.basis, why: LAWFUL_BASES[r.basis].article })),
      purge,
      note: 'withdrawal triggers an actual purge of consent-based data, not a flag'
    };
  }

  /**
   * @param {string} subject
   * @param {{purpose?:string}} [opts]
   */
  status(subject, { purpose = 'memory_governance' } = {}) {
    const records = this.col.by('bySubject', subject);
    if (!records.length) {
      return { subject, basis: null, erasureActive: this.erasureRequests.has(subject), reason: 'no lawful basis on record' };
    }
    const live = records.filter((r) => !r.withdrawn && (!r.expiresAt || r.expiresAt > now()));
    const chosen = live.find((r) => r.purpose === purpose) || live[0] || records[0];
    const collectedPurpose = chosen.purpose;
    const compatible = (COMPATIBLE[collectedPurpose] || [collectedPurpose]).includes(purpose);
    return {
      subject,
      basis: live.length ? chosen.basis : null,
      article: chosen.article,
      collectedPurpose,
      requestedPurpose: purpose,
      purposeCompatible: compatible,
      withdrawn: !live.length && records.some((r) => r.withdrawn),
      expired: Boolean(chosen.expiresAt && chosen.expiresAt <= now()),
      specialCategory: chosen.specialCategory,
      article9Condition: chosen.article9Condition,
      minor: chosen.minor,
      parentalConsent: chosen.parentalConsent,
      erasureActive: this.erasureRequests.has(subject),
      recordId: chosen.id,
      recordedAt: iso(chosen.recordedAt)
    };
  }

  /** Purpose limitation enforced at READ time (§14.5). */
  checkReadPurpose(subject, purpose) {
    const s = this.status(subject, { purpose });
    if (!s.basis) return { allowed: false, reason: `no lawful basis on record for ${subject}` };
    if (!s.purposeCompatible) {
      return {
        allowed: false,
        reason: `purpose limitation: collected for "${s.collectedPurpose}", this read serves "${purpose}"`
      };
    }
    if (s.erasureActive) return { allowed: false, reason: `${subject} has an active erasure request` };
    return { allowed: true, basis: s.basis };
  }

  markErasureRequest(subject, active = true) {
    if (active) this.erasureRequests.add(subject);
    else this.erasureRequests.delete(subject);
    return { subject, erasureActive: active };
  }

  /** Consent receipts, exportable (§14.5). */
  receipt(subject) {
    const records = this.col.by('bySubject', subject);
    if (!records.length) throw notFound('consent record', subject);
    const body = {
      format: 'vault.consent-receipt.v1',
      subject,
      generatedAt: iso(),
      records: records.map((r) => ({
        id: r.id, basis: r.basis, article: r.article, purpose: r.purpose,
        mechanism: r.mechanism, noticeVersion: r.noticeVersion, noticeHash: r.noticeHash,
        recordedAt: iso(r.recordedAt), withdrawn: r.withdrawn,
        withdrawnAt: r.withdrawnAt ? iso(r.withdrawnAt) : null,
        specialCategory: r.specialCategory, article9: r.article9Text,
        minor: r.minor, parentalConsent: r.parentalConsent,
        consentManagerRef: r.consentManagerRef,
        retainUntil: iso(r.retainUntil)
      }))
    };
    return { ...body, proof: sha256(JSON.stringify(body)) };
  }

  bySubject(subject) { return this.col.by('bySubject', subject); }

  /** Records due for deletion under their own retention. */
  expiredRecords() {
    return this.col.find((r) => r.retainUntil && r.retainUntil <= now());
  }

  stats() {
    const all = this.col.all();
    return {
      records: all.length,
      subjects: new Set(all.map((r) => r.subject)).size,
      withdrawn: all.filter((r) => r.withdrawn).length,
      specialCategory: all.filter((r) => r.specialCategory).length,
      minors: all.filter((r) => r.minor).length,
      byBasis: Object.keys(LAWFUL_BASES).reduce((acc, b) => ({ ...acc, [b]: all.filter((r) => r.basis === b).length }), {})
    };
  }
}

/**
 * A registered DPDP Consent Manager, modelled at the API boundary so a real one
 * drops in without touching the engine.
 */
export class ConsentManagerStub {
  constructor(name = 'dpdp-consent-manager') {
    this.name = name;
    this.records = new Map();
  }
  register(record) {
    const id = `cm-${sha256(JSON.stringify(record)).slice(0, 12)}`;
    this.records.set(id, { ...record, id, registeredAt: iso() });
    return { id, manager: this.name };
  }
  verify(id) {
    const r = this.records.get(id);
    return { valid: Boolean(r), record: r ?? null, manager: this.name };
  }
}
