/**
 * 🔒 EMPLOYEE PRIVACY MODE — the one-click button (§15).
 *
 * Click it, pick your country, and Vault reconfigures itself to be lawful there.
 *
 * Two things in this file are structural rather than configurable, on purpose:
 *
 *  - There is no per-employee view. Not permission-gated — ABSENT. The query
 *    does not exist; `individualActivity()` throws when the mode is on.
 *  - There is no affect analysis. No sentiment, mood, stress, engagement,
 *    motivation, honesty or emotion scoring, in any mode. The code does not
 *    exist. Emotion recognition at work has been prohibited in the EU since
 *    February 2025, and building it "for other markets" is how it leaks.
 */
import { pseudonym, randomToken, sha256 } from '../util/crypto.js';
import { now, iso, ago, duration, DAY, MONTH } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { JURISDICTIONS, jurisdictionPack } from './jurisdictions.js';

export class PrivacyMode {
  /**
   * @param {object} opts
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {string} [opts.jurisdiction]
   * @param {boolean} [opts.enabled]
   */
  constructor({ ledger, jurisdiction = null, enabled = false, kAnonymityFloor = 5, saltRotation = '30d' }) {
    this.ledger = ledger;
    this.enabled = enabled;
    this.jurisdiction = jurisdiction;
    this.kFloor = kAnonymityFloor;
    this.saltRotationMs = duration(saltRotation);
    this.salt = randomToken(24);
    this.saltRotatedAt = now();
    this.settings = enabled && jurisdiction ? jurisdictionPack(jurisdiction).settings : DEFAULT_OFF;
    this.reidentifications = [];
    this.objections = [];
    this.worksCouncil = { members: [], notifications: [] };
    this.changeLog = [];
  }

  isOn() { return this.enabled; }

  /** Preview before apply — exactly what changes, and who gets notified (§15.1). */
  preview(jurisdictionId) {
    const pack = jurisdictionPack(jurisdictionId);
    const before = this.settings;
    const after = pack.settings;
    const changes = [];
    for (const k of new Set([...Object.keys(before), ...Object.keys(after)])) {
      if (JSON.stringify(before[k]) !== JSON.stringify(after[k])) {
        changes.push({ setting: k, from: before[k], to: after[k], meaning: SETTING_MEANING[k] || k });
      }
    }
    return {
      jurisdiction: pack.id,
      name: pack.name,
      changes,
      screensRemoved: after.noIndividualDashboards ? ['any per-employee activity view', 'per-person productivity or output counts'] : [],
      fieldsPseudonymised: after.pseudonymiseByDefault ? ['employee identity on every fact, read log and trace'] : [],
      retentionShortened: after.employeeRetention ? `employee-linked data expires after ${after.employeeRetention}` : null,
      notifies: [
        ...(after.worksCouncilRole ? ['works council / employee representatives'] : []),
        ...(after.changeNotification ? ['all employees, via the transparency portal'] : [])
      ],
      documentsGenerated: pack.documents.map((d) => d.name),
      requiresConsultation: pack.requiresConsultation,
      apply: `privacy.apply('${pack.id}', { actor })`
    };
  }

  /** @param {string} jurisdictionId */
  apply(jurisdictionId, { actor, reason = 'employee privacy mode configured' }) {
    if (!actor) throw forbidden('changing Employee Privacy Mode requires a named actor');
    const pack = jurisdictionPack(jurisdictionId);
    const from = { enabled: this.enabled, jurisdiction: this.jurisdiction };
    this.enabled = pack.id !== 'off';
    this.jurisdiction = pack.id === 'off' ? null : pack.id;
    this.settings = pack.settings;
    this.kFloor = pack.settings.kAnonymityFloor ?? this.kFloor;

    const record = { at: now(), actor, reason, from, to: { enabled: this.enabled, jurisdiction: this.jurisdiction } };
    this.changeLog.push(record);
    this.ledger.append('privacy.mode_changed', {
      subject: 'employee_privacy_mode', actor, reason,
      from: from.jurisdiction ?? 'off', to: this.jurisdiction ?? 'off', enabled: this.enabled
    });

    // Any change to monitoring-relevant settings notifies employee reps
    // automatically (§15.2).
    if (this.settings.changeNotification) this._notifyWorksCouncil({ actor, reason, change: record });

    return {
      enabled: this.enabled,
      jurisdiction: this.jurisdiction,
      name: pack.name,
      settings: this.settings,
      compliancePack: pack.id === 'off' ? null : this.compliancePack(),
      note: pack.id === 'off'
        ? 'Employee Privacy Mode is OFF — full visibility (US at-will default). Individual views are available.'
        : `Employee Privacy Mode is ON for ${pack.name}. Individual employee views no longer exist as a query.`
    };
  }

  /**
   * ARCHITECTURALLY ABSENT (§15.2). This is the whole point: when the mode is
   * on, there is no code path that returns one named employee's AI activity.
   */
  individualActivity() {
    if (this.enabled && this.settings.noIndividualDashboards) {
      throw forbidden(
        'no screen anywhere shows one named employee\'s AI activity in Employee Privacy Mode — '
        + 'this query does not exist, it is not permission-gated',
        { code: 'architecturally_absent', jurisdiction: this.jurisdiction }
      );
    }
    return { available: true, note: 'Employee Privacy Mode is off — individual views are available under the US at-will default' };
  }

  /**
   * Aggregate-only analytics with a k-anonymity floor. Below the floor, NO
   * NUMBER RENDERS AT ALL (§15.2).
   * @param {Array<{group:string, subject:string, value?:number}>} rows
   */
  aggregate(rows, { by = 'group', metric = 'count' } = {}) {
    const groups = new Map();
    for (const r of rows) {
      const key = r[by] ?? 'unknown';
      const g = groups.get(key) || { group: key, subjects: new Set(), total: 0 };
      g.subjects.add(r.subject);
      g.total += r.value ?? 1;
      groups.set(key, g);
    }
    const out = [];
    let suppressed = 0;
    for (const g of groups.values()) {
      if (this.enabled && g.subjects.size < this.kFloor) {
        suppressed++;
        out.push({ group: g.group, value: null, suppressed: true, reason: `fewer than k=${this.kFloor} distinct people in this group` });
        continue;
      }
      out.push({ group: g.group, value: metric === 'count' ? g.total : g.total / g.subjects.size, people: this.enabled ? undefined : g.subjects.size });
    }
    return {
      rows: out,
      kFloor: this.enabled ? this.kFloor : null,
      suppressedGroups: suppressed,
      note: this.enabled
        ? `aggregate-only, department-level minimum, k=${this.kFloor}. Groups below the floor render no number at all.`
        : 'Employee Privacy Mode is off — full detail'
    };
  }

  /** Rotating pseudonym. Re-identification is a separate, receipted act. */
  pseudonymise(subject) {
    if (!this.enabled || !this.settings.pseudonymiseByDefault) return subject;
    this._maybeRotate();
    return pseudonym(this.salt, subject);
  }

  _maybeRotate() {
    if (now() - this.saltRotatedAt > this.saltRotationMs) {
      this.salt = randomToken(24);
      this.saltRotatedAt = now();
    }
  }

  /**
   * Re-identification needs TWO named approvers, a stated legal reason and a
   * time box — and is itself receipted and reported (§15.2).
   */
  reidentify(token, realSubjectLookup, { approvers, legalReason, timeboxMinutes = 60, actor }) {
    if (!this.enabled) return { subject: token, note: 'Employee Privacy Mode is off — no pseudonymisation in effect' };
    if (!Array.isArray(approvers) || new Set(approvers).size < 2) {
      throw forbidden('re-identification requires two distinct named approvers');
    }
    if (!legalReason) throw forbidden('re-identification requires a stated legal reason');
    const subject = typeof realSubjectLookup === 'function' ? realSubjectLookup(token) : realSubjectLookup;
    const record = {
      id: `reid-${sha256(token + now()).slice(0, 10)}`,
      token, approvers, legalReason, actor, at: now(),
      expiresAt: now() + timeboxMinutes * 60_000,
      jurisdiction: this.jurisdiction
    };
    this.reidentifications.push(record);
    this.ledger.append('privacy.reidentification', {
      subject: token, actor, approvers, legalReason,
      expiresAt: iso(record.expiresAt), jurisdiction: this.jurisdiction
    });
    this._notifyWorksCouncil({ actor, reason: `re-identification performed: ${legalReason}`, change: record });
    return { subject, record: { ...record, at: iso(record.at), expiresAt: iso(record.expiresAt) }, reportedTo: 'works council / employee representatives' };
  }

  /**
   * Purpose lock: memory governance ONLY. Enforced in the query layer AND
   * warranted in the MSA (§15.2).
   */
  assertPurpose(purpose) {
    if (!this.enabled) return true;
    const prohibited = ['performance', 'productivity', 'discipline', 'promotion', 'hr_decision', 'ranking', 'appraisal', 'termination'];
    if (prohibited.some((p) => String(purpose).toLowerCase().includes(p))) {
      throw forbidden(
        `Employee Privacy Mode purpose lock: Vault's employee-linked data may be used for memory governance only. `
        + `"${purpose}" is a prohibited use, enforced here and warranted in the MSA.`,
        { code: 'purpose_locked', prohibited }
      );
    }
    return true;
  }

  /**
   * NO AFFECT ANALYSIS, EVER. Not a config option (§15.2). Calling this is
   * always an error, in every jurisdiction, including with the mode off.
   */
  analyseSentiment() {
    throw forbidden(
      'Vault does not score people. No sentiment, mood, stress, engagement, motivation, honesty or emotion analysis exists in this system, '
      + 'in any mode or jurisdiction. Emotion recognition in the workplace has been prohibited in the EU since February 2025, and this is a design commitment, not a setting.',
      { code: 'affect_analysis_does_not_exist' }
    );
  }
  analyseEmotion() { return this.analyseSentiment(); }
  scoreProductivity() {
    throw forbidden(
      'No productivity scoring exists: no output counts per person, no speed rankings, no activity scores.',
      { code: 'productivity_scoring_does_not_exist' }
    );
  }

  /** Excluded contexts — never captured (§15.2). */
  isExcludedContext(ctx = {}) {
    if (!this.enabled) return { excluded: false };
    const excluded = this.settings.excludedContexts || [];
    const checks = [
      ['personal_account', ctx.accountType === 'personal'],
      ['personal_email', ctx.channel === 'email' && ctx.accountType === 'personal'],
      ['union_communications', Boolean(ctx.unionCommunication)],
      ['works_council_communications', Boolean(ctx.worksCouncilCommunication)],
      ['health_portal', ctx.category === 'health'],
      ['banking_portal', ctx.category === 'banking'],
      ['legal_advice', ctx.category === 'legal_advice'],
      ['break_periods', Boolean(ctx.onBreak)],
      ['outside_working_hours', this.settings.workingHoursOnly && ctx.outsideWorkingHours],
      ['personal_devices', ctx.deviceOwnership === 'personal']
    ];
    for (const [name, hit] of checks) {
      if (hit && excluded.includes(name)) {
        return { excluded: true, context: name, reason: `${name.replace(/_/g, ' ')} is an excluded context under the ${this.jurisdiction} pack — not captured` };
      }
    }
    return { excluded: false };
  }

  /** Sample, don't stream: event-triggered capture, minimisation by default. */
  shouldCapture(ctx = {}) {
    const ex = this.isExcludedContext(ctx);
    if (ex.excluded) return { capture: false, ...ex };
    if (!this.enabled || !this.settings.sampleDontStream) return { capture: true };
    // Capture on event triggers only.
    const triggered = Boolean(ctx.gateOutcome && ctx.gateOutcome !== 'pass') || Boolean(ctx.securityEvent) ||
      Boolean(ctx.regulatoryRecord) || (ctx.sampleRoll ?? Math.random()) < (this.settings.sampleRate ?? 0.05);
    return {
      capture: triggered,
      reason: triggered ? 'event-triggered capture' : 'sampled out — minimisation is the default posture, Vault does not stream employee activity'
    };
  }

  // -- employee-facing (§15.2) --------------------------------------------

  /** The 👤 My Data portal: what Vault holds about me, and an export. */
  transparencyPortal(employee, { facts = [], conversations = [], reads = 0 }) {
    return {
      employee,
      generatedAt: iso(),
      jurisdiction: this.jurisdiction,
      whatWeHold: {
        facts: facts.length,
        conversations: conversations.length,
        readsOfYourFacts: reads
      },
      whatWeDoNotHold: [
        'no sentiment, mood, stress or emotion scores — that code does not exist',
        'no productivity, speed or output scores',
        'no individual activity dashboard visible to your manager',
        ...(this.settings.excludedContexts || []).map((c) => `nothing from ${c.replace(/_/g, ' ')}`)
      ],
      yourRights: [
        'see everything we hold about you (this page)',
        'export it in a machine-readable format',
        'object formally to any fact about you, with a tracked response',
        'ask for a correction — we version rather than overwrite'
      ],
      export: { format: 'vault.employee-export.v1', facts, conversations },
      purposeLock: 'this data may be used for memory governance only, enforced in the query layer and warranted in our contract'
    };
  }

  /** Formal route to challenge a fact about yourself, with a tracked response. */
  objection({ employee, factId, objection, actor = null }) {
    const record = {
      id: `obj-${sha256(`${employee}${factId}${now()}`).slice(0, 10)}`,
      employee, factId, objection, raisedAt: now(),
      status: 'open', dueAt: now() + 30 * DAY, response: null, respondedBy: null
    };
    this.objections.push(record);
    this.ledger.append('admin.action', { subject: factId, actor: actor || employee, action: 'privacy.objection_raised' });
    return { ...record, raisedAt: iso(record.raisedAt), dueAt: iso(record.dueAt) };
  }

  respondToObjection(id, { actor, outcome, response }) {
    const o = this.objections.find((x) => x.id === id);
    if (!o) throw new VaultError('not_found', 'objection not found', { id });
    if (!actor || !response) throw forbidden('responding to an objection requires a named actor and a written response');
    o.status = 'closed';
    o.outcome = outcome;
    o.response = response;
    o.respondedBy = actor;
    o.respondedAt = now();
    this.ledger.append('admin.action', { subject: o.factId, actor, action: 'privacy.objection_answered', outcome });
    return o;
  }

  objectionQueue() {
    return this.objections.map((o) => ({
      ...o, raisedAt: iso(o.raisedAt), dueAt: iso(o.dueAt),
      overdue: o.status === 'open' && now() > o.dueAt
    }));
  }

  // -- works council (§15.2, §15.4) ---------------------------------------

  /** A named non-management role with visibility into policy, retention, access. */
  addWorksCouncilMember(name, { actor }) {
    if (!actor) throw forbidden('adding a works council member requires a named actor');
    this.worksCouncil.members.push({ name, addedAt: now(), addedBy: actor });
    this.ledger.append('admin.action', { subject: name, actor, action: 'privacy.works_council_member_added' });
    return this.worksCouncil.members;
  }

  _notifyWorksCouncil({ actor, reason, change }) {
    const notice = {
      at: now(), actor, reason,
      change: { from: change.from ?? null, to: change.to ?? null },
      recipients: this.worksCouncil.members.map((m) => m.name)
    };
    this.worksCouncil.notifications.push(notice);
    return notice;
  }

  /** What the works council role can see. No content, no individual data. */
  worksCouncilView() {
    return {
      role: 'works council / employee representatives — read-only',
      canSee: {
        privacyModeSettings: this.settings,
        jurisdiction: this.jurisdiction,
        retentionSettings: { employeeLinkedData: this.settings.employeeRetention ?? 'not shortened' },
        accessMatrix: 'which roles can see which categories of employee-linked data',
        changeNotifications: this.worksCouncil.notifications.map((n) => ({ ...n, at: iso(n.at) })),
        reidentifications: this.reidentifications.map((r) => ({
          at: iso(r.at), approvers: r.approvers, legalReason: r.legalReason, token: r.token
        })),
        objections: this.objectionQueue()
      },
      cannotSee: ['any content', 'any individual employee data', 'any per-person metric'],
      objectionChannel: 'formal objection to any policy change, tracked with a required response'
    };
  }

  // -- compliance pack ----------------------------------------------------

  /** Generate the downloadable pack the customer's DPO hands to the regulator. */
  compliancePack() {
    if (!this.jurisdiction) {
      return { jurisdiction: 'off', documents: [], note: 'Employee Privacy Mode is off — no jurisdiction pack generated' };
    }
    const pack = jurisdictionPack(this.jurisdiction);
    return {
      jurisdiction: pack.id,
      name: pack.name,
      generatedAt: iso(),
      settings: this.settings,
      controls: pack.controls,
      documents: pack.documents.map((d) => ({
        name: d.name,
        format: d.format,
        body: typeof d.body === 'function' ? d.body({ settings: this.settings, jurisdiction: pack, generatedAt: iso() }) : d.body
      })),
      frameworkCrosswalk: pack.crosswalk,
      coverage: pack.coverage,
      note: pack.plainLanguage
    };
  }

  status() {
    return {
      enabled: this.enabled,
      jurisdiction: this.jurisdiction,
      jurisdictionName: this.jurisdiction ? jurisdictionPack(this.jurisdiction).name : 'OFF — full visibility (US at-will default)',
      settings: this.settings,
      kAnonymityFloor: this.enabled ? this.kFloor : null,
      worksCouncilMembers: this.worksCouncil.members.length,
      openObjections: this.objections.filter((o) => o.status === 'open').length,
      reidentifications: this.reidentifications.length,
      available: Object.keys(JURISDICTIONS),
      guarantees: [
        'no individual dashboards — architecturally absent, not permission-gated',
        'no affect analysis, ever — the code does not exist',
        'no productivity scoring',
        'no covert monitoring — covert mode does not exist',
        'purpose lock enforced in the query layer and warranted in the MSA'
      ]
    };
  }
}

const DEFAULT_OFF = {
  noIndividualDashboards: false,
  aggregateOnly: false,
  kAnonymityFloor: null,
  pseudonymiseByDefault: false,
  purposeLock: false,
  affectAnalysis: 'never — not a setting',
  productivityScoring: false,
  excludedContexts: [],
  sampleDontStream: false,
  workingHoursOnly: false,
  covertMonitoring: 'does not exist',
  employeeRetention: null,
  transparencyPortal: true,
  objectionChannel: true,
  worksCouncilRole: false,
  changeNotification: false
};

const SETTING_MEANING = {
  noIndividualDashboards: 'no screen shows one named employee\'s AI activity',
  aggregateOnly: 'department-level minimum with a k-anonymity floor',
  kAnonymityFloor: 'below this many distinct people, no number renders at all',
  pseudonymiseByDefault: 'employee identity replaced with a rotating token',
  purposeLock: 'memory governance only — cannot be queried for HR decisions',
  excludedContexts: 'contexts never captured at all',
  sampleDontStream: 'event-triggered capture rather than continuous',
  workingHoursOnly: 'capture limited to contracted working hours',
  employeeRetention: 'employee-linked data expires faster than customer data',
  worksCouncilRole: 'a named non-management role with read-only oversight',
  changeNotification: 'monitoring-relevant changes notify employee representatives automatically'
};
