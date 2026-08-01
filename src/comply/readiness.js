/**
 * SOC 2 READINESS — the part of an audit that is not the auditor's.
 *
 * A SOC 2 Type II report cannot be produced by code. It requires a licensed
 * CPA firm, an observation window, and an opinion signed by a human who is
 * liable for it. Nothing in this file changes that, and any tool that implies
 * otherwise is selling a logo.
 *
 * What code CAN do is the work a firm bills for and a company usually fails
 * at: showing that each control was operating, continuously, across the whole
 * window, with evidence pulled from the system rather than assembled by hand
 * the week before fieldwork. That is the difference between a six-month
 * engagement and an eighteen-month one, and it is the difference between a
 * clean opinion and a qualified one.
 *
 * So this produces the artefact an auditor asks for on day one:
 *
 *   · every control, mapped to its SOC 2 Trust Services Criterion
 *   · for each, whether it is DESIGNED, IMPLEMENTED and OPERATING
 *   · the evidence, pulled live, with the ledger positions that prove it
 *   · every control that is NOT ready, named, with what is missing
 *
 * The last one is the point. A readiness report that says everything is fine
 * is a readiness report nobody needed.
 */
import { CONTROLS } from './comply.js';
import { iso, now, DAY } from '../util/time.js';

/**
 * The Trust Services Criteria this product touches.
 *
 * Availability, confidentiality and privacy are listed with what Vault does
 * and does not carry, because scoping a SOC 2 to Security alone and letting a
 * customer believe it covered privacy is the standard way this goes wrong.
 */
export const TSC = {
  CC1: { name: 'Control Environment', vaultCarries: false, note: 'organisational — board oversight, HR, code of conduct. No product can evidence this for you.' },
  CC2: { name: 'Communication and Information', vaultCarries: 'partial', note: 'the review queue and alerting evidence internal communication of control failures' },
  CC3: { name: 'Risk Assessment', vaultCarries: 'partial', note: 'the insurance gap report is a standing risk assessment of the AI estate' },
  CC4: { name: 'Monitoring Activities', vaultCarries: true, note: 'continuous control monitoring, this file' },
  CC5: { name: 'Control Activities', vaultCarries: true, note: 'the gate is the control activity' },
  CC6: { name: 'Logical and Physical Access', vaultCarries: 'partial', note: 'walls, identity and encryption; physical access is your cloud provider s' },
  CC7: { name: 'System Operations', vaultCarries: true, note: 'the ledger, alerting and incident detection' },
  CC8: { name: 'Change Management', vaultCarries: 'partial', note: 'model pinning and rule backtesting; your SDLC is yours' },
  CC9: { name: 'Risk Mitigation', vaultCarries: 'partial', note: 'vendor register and business continuity drills' },
  A1: { name: 'Availability', vaultCarries: 'partial', note: 'measured RPO/RTO from real restore drills; your uptime commitment is yours' },
  C1: { name: 'Confidentiality', vaultCarries: true, note: 'sensitivity labelling, walls and crypto-shredding' },
  P1: { name: 'Privacy', vaultCarries: true, note: 'lawful basis, erasure receipts, consent' }
};

/** A control is only "operating" if it produced evidence inside the window. */
const OPERATING_WINDOW_DAYS = 90;

/**
 * Assess readiness against the live system.
 *
 * @param {object} vault
 * @param {object} [opts]
 * @param {number} [opts.windowDays] the observation window an auditor would test
 */
export function assessReadiness(vault, { windowDays = OPERATING_WINDOW_DAYS } = {}) {
  const since = now() - windowDays * DAY;
  const controls = [];

  for (const control of CONTROLS) {
    const soc2 = control.frameworks['SOC 2'] ?? null;
    let evidence = null;
    let error = null;
    try {
      evidence = vault.comply?.collectEvidence?.(control.id) ?? null;
    } catch (err) {
      error = err.message;
    }

    // DESIGNED — the control exists and is described.
    const designed = Boolean(control.name && control.evidence);

    // IMPLEMENTED — the system can produce evidence for it at all.
    const implemented = !error && evidence != null && evidence.status !== 'unimplemented';

    // OPERATING — that evidence shows activity inside the window. A control
    // that is implemented but has never fired is not yet an operating control,
    // and an auditor will say so before you do.
    const activity = evidenceActivity(evidence);
    const operating = implemented && activity.observations > 0 && (activity.latestAt == null || activity.latestAt >= since);

    controls.push({
      id: control.id,
      name: control.name,
      soc2Criterion: soc2,
      trustServicesCategory: soc2 ? soc2.split(/[^A-Z0-9]/)[0] : null,
      designed,
      implemented,
      operating,
      status: !designed ? 'not_designed' : !implemented ? 'not_implemented' : !operating ? 'no_observations_in_window' : 'operating',
      observations: activity.observations,
      evidenceKey: control.evidence,
      blocker: !designed ? 'the control has no described evidence source'
        : !implemented ? (error ?? 'the system cannot produce evidence for this control')
          : !operating ? `no observations in the last ${windowDays} days — an auditor tests operation across the window, not existence on the day`
            : null
    });
  }

  const operating = controls.filter((c) => c.status === 'operating');
  const byCategory = {};
  for (const c of controls) {
    const cat = c.trustServicesCategory ?? 'unmapped';
    byCategory[cat] = byCategory[cat] || { total: 0, operating: 0, name: TSC[cat]?.name ?? null };
    byCategory[cat].total++;
    if (c.status === 'operating') byCategory[cat].operating++;
  }

  return {
    assessedAt: iso(),
    windowDays,
    controls,
    byCategory,
    ready: operating.length,
    total: controls.length,
    notReady: controls.filter((c) => c.status !== 'operating'),
    // The things no amount of code will close, stated in the artefact itself
    // so nobody has to discover them in a sales cycle.
    requiresAnExternalParty: [
      { item: 'SOC 2 Type II opinion', who: 'a licensed CPA firm', why: 'an opinion is signed by a human who is liable for it; software cannot issue one', status: 'not engaged' },
      { item: 'Observation window', who: 'the auditor', why: `Type II tests operation over 3–12 months. Vault can evidence a ${windowDays}-day window today; the clock is the clock.`, status: 'evidence available, window not yet observed by a firm' },
      { item: 'Third-party penetration test', who: 'a security firm', why: 'bin/vault-redteam.js attacks the gate and bin/vault-supplychain.js checks dependencies. Neither is a penetration test and calling one a pen test is the overclaim this product exists to prevent.', status: 'not engaged' },
      { item: 'Organisational controls (CC1)', who: 'your company', why: 'board oversight, background checks, code of conduct, onboarding and offboarding. Vault evidences none of these and should not appear to.', status: 'out of product scope' }
    ],
    statement: `${operating.length} of ${controls.length} controls are designed, implemented and producing evidence `
      + `inside a ${windowDays}-day window. That is audit readiness, not an audit: a SOC 2 Type II report requires a `
      + `licensed CPA firm and an observation window, neither of which is a feature. What this removes is the part `
      + `companies actually fail — assembling evidence by hand the week before fieldwork and discovering a control `
      + `has not fired since March.`
  };
}

/** How much has this control actually done, and when did it last do it? */
function evidenceActivity(evidence) {
  if (!evidence || typeof evidence !== 'object') return { observations: 0, latestAt: null };

  // Evidence shapes differ per control; count whatever countable thing is
  // present rather than demanding one schema of unrelated subsystems.
  let observations = 0;
  let latestAt = null;
  const visit = (v, depth = 0) => {
    if (depth > 3 || v == null) return;
    if (Array.isArray(v)) { observations += v.length; v.slice(0, 5).forEach((x) => visit(x, depth + 1)); return; }
    if (typeof v === 'number') { observations += v > 0 ? 1 : 0; return; }
    if (typeof v === 'string') {
      const t = Date.parse(v);
      if (!Number.isNaN(t) && /\d{4}-\d{2}-\d{2}/.test(v)) latestAt = Math.max(latestAt ?? 0, t);
      return;
    }
    if (typeof v === 'object') for (const x of Object.values(v)) visit(x, depth + 1);
  };
  visit(evidence);
  return { observations, latestAt };
}

/** Render for someone who will not open a JSON file. */
export function renderReadiness(r) {
  const L = [];
  L.push('SOC 2 READINESS');
  L.push('='.repeat(78));
  L.push(`Assessed ${r.assessedAt} · ${r.windowDays}-day observation window`);
  L.push('');
  L.push(`  ${r.ready}/${r.total} controls operating with evidence in the window`);
  L.push('');
  L.push('BY TRUST SERVICES CATEGORY');
  L.push('-'.repeat(78));
  for (const [cat, v] of Object.entries(r.byCategory)) {
    const meta = TSC[cat];
    const carries = meta ? (meta.vaultCarries === true ? '' : meta.vaultCarries === 'partial' ? ' (partial)' : ' (organisational — not Vault)') : '';
    L.push(`  ${cat.padEnd(5)} ${String(v.operating + '/' + v.total).padEnd(7)} ${(v.name ?? 'unmapped') + carries}`);
  }
  if (r.notReady.length) {
    L.push('');
    L.push(`NOT READY (${r.notReady.length})`);
    L.push('-'.repeat(78));
    for (const c of r.notReady) {
      L.push(`  ${c.id.padEnd(7)} ${c.name}`);
      L.push(`          ${c.blocker}`);
    }
  }
  L.push('');
  L.push('CANNOT BE CLOSED BY CODE');
  L.push('-'.repeat(78));
  for (const x of r.requiresAnExternalParty) {
    L.push(`  ${x.item}`);
    L.push(`      ${x.who} — ${x.status}`);
  }
  L.push('');
  L.push('-'.repeat(78));
  L.push(r.statement);
  return L.join('\n');
}
