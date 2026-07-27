/**
 * Configuration as code — plan, then apply.
 *
 * I had listed "Terraform provider" as not built, and a native one still is:
 * that is a Go binary speaking the plugin protocol, and this repository has no
 * Go and no build step by design. What a provider actually *gives* you,
 * though, is not the language it is written in. It is: a declarative
 * description of what the estate should look like, a plan that shows the diff
 * before anything changes, idempotent apply, and drift detection afterwards.
 * All four are implementable here, against the same REST API a provider would
 * call — and the Terraform files in iac/terraform/ drive exactly this endpoint
 * through the standard `restapi` provider, so `terraform plan` works today
 * without waiting for a bespoke binary.
 *
 * Three rules:
 *
 * 1. **Plan never mutates.** Not "mostly doesn't" — the planner is given a
 *    read-only view and the apply path is the only writer.
 * 2. **Apply is idempotent.** Running the same config twice produces no second
 *    change, which is what makes it safe to put in CI.
 * 3. **Destructive changes are opt-in and named.** Retiring an agent or
 *    narrowing a wall is not something a config drift should do silently at
 *    2am, so those appear in the plan as `destroy`/`shrink` and require
 *    `allowDestructive`.
 */
import { now, iso } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

/**
 * The resource types this manages.
 *
 * Deliberately not everything: facts and conversations are *data*, not
 * configuration, and a system that lets an HCL file declare what is true would
 * be the memory-poisoning vector this product exists to close.
 */
export const RESOURCES = {
  agent: {
    key: 'id',
    fields: ['id', 'name', 'purpose', 'businessOwner', 'technicalOwner', 'department', 'mode', 'folders', 'sensitivityCeiling', 'regions', 'pinnedModel'],
    read: (v) => v.registry.inventory().filter((a) => a.status !== 'retired'),
    create: (v, spec, ctx) => v.registerAgent({ ...spec, actor: ctx.actor }),
    update: (v, spec, current, ctx) => v.registry.changeScope(spec.id, diffFields(spec, current, RESOURCES.agent.fields), {
      actor: ctx.actor, reason: ctx.reason, approvedBy: ctx.approvedBy
    }),
    destroy: (v, current, ctx) => v.registry.retire(current.id, { actor: ctx.actor, reason: ctx.reason }),
    destructive: 'retiring an agent stops it writing; its facts remain'
  },
  folder: {
    key: 'path',
    fields: ['path', 'read', 'write', 'sensitivity', 'businessOwner', 'technicalOwner', 'hardWall', 'goldenPreferred'],
    read: (v) => v.folders.all().filter((f) => !f.archived),
    create: (v, spec) => v.folders.ensure(spec.path, spec),
    update: (v, spec, current, ctx) => {
      v.folders.ensure(spec.path, spec);
      // `ensure` returns an existing folder untouched, so walls go through
      // setWalls — which enforces the parent invariant and alerts on widening.
      if (spec.read || spec.write) {
        v.folders.setWalls(spec.path, { read: spec.read, write: spec.write, actor: ctx.actor, reason: ctx.reason });
      }
      if (spec.businessOwner || spec.technicalOwner) {
        v.folders.setOwners(spec.path, {
          businessOwner: spec.businessOwner ?? current.businessOwner,
          technicalOwner: spec.technicalOwner ?? current.technicalOwner,
          actor: ctx.actor
        });
      }
      return v.folders.get(spec.path);
    },
    // Folders are never destroyed by config: the facts inside them would be
    // orphaned, and an HCL edit is not a considered deletion decision.
    destroy: null,
    destructive: 'narrowing read or write access can cut off a working agent'
  },
  rule: {
    // Rules are keyed by name rather than id: an id is minted on creation, so
    // a config file that referenced one could only ever describe rules that
    // already existed.
    key: 'name',
    fields: ['name', 'description', 'plain', 'expression', 'action', 'type', 'scope', 'state', 'order', 'escalateTo'],
    read: (v) => v.rules.all(),
    create: (v, spec, ctx) => v.rules.create({ ...spec, actor: ctx.actor, reason: ctx.reason }),
    update: (v, spec, current, ctx) => v.rules.update(current.id, diffFields(spec, current, RESOURCES.rule.fields), { actor: ctx.actor, reason: ctx.reason }),
    destroy: (v, current, ctx) => v.rules.update(current.id, { state: 'retired' }, { actor: ctx.actor, reason: ctx.reason }),
    destructive: 'retiring a rule removes a control'
  },
  connector: {
    key: 'catalogId',
    fields: ['catalogId', 'mode', 'owner', 'technicalOwner', 'region', 'expectedRatePerHour', 'scopes', 'versionPin'],
    read: (v) => v.connectors.active(),
    create: (v, spec, ctx) => v.connectors.connect({ ...spec, actor: ctx.actor, credential: ctx.credentials?.[spec.catalogId] }),
    update: null,
    destroy: (v, current, ctx) => v.connectors.disconnect(current.id, { actor: ctx.actor, reason: ctx.reason }),
    destructive: 'disconnecting stops ingestion; nothing already captured is deleted'
  }
};

function diffFields(spec, current, fields) {
  const patch = {};
  for (const f of fields) {
    if (spec[f] === undefined) continue;
    if (JSON.stringify(spec[f]) !== JSON.stringify(current[f])) patch[f] = spec[f];
  }
  return patch;
}

/** Would applying `spec` over `current` reduce access? */
function shrinks(type, spec, current) {
  if (type === 'folder') {
    for (const list of ['read', 'write']) {
      const before = new Set(current[list] || []);
      const after = new Set(spec[list] || []);
      if ((current[list] || []).length && [...before].some((x) => !after.has(x))) return true;
    }
  }
  if (type === 'agent') {
    const before = new Set(current.folders || []);
    const after = new Set(spec.folders || []);
    if ([...before].some((x) => !after.has(x))) return true;
  }
  return false;
}

export class ConfigEngine {
  constructor({ vault, ledger = null }) {
    this.vault = vault;
    this.ledger = ledger ?? vault?.ledger ?? null;
    /** @type {Array<object>} */
    this.applies = [];
  }

  /**
   * Compute the diff between a declared configuration and reality.
   *
   * Never writes. The vault reference here is only ever read from, and the
   * tests assert that by taking a full snapshot before and after.
   */
  plan(config, { prune = false } = {}) {
    const changes = [];
    const unknown = Object.keys(config).filter((k) => !RESOURCES[k] && k !== 'version');
    if (unknown.length) {
      throw new VaultError('invalid', `unknown resource type(s): ${unknown.join(', ')}`, { available: Object.keys(RESOURCES) });
    }

    for (const [type, res] of Object.entries(RESOURCES)) {
      const declared = config[type] || [];
      if (!Array.isArray(declared)) throw new VaultError('invalid', `${type} must be a list`, { got: typeof declared });
      const existing = res.read(this.vault);
      const byKey = new Map(existing.map((e) => [e[res.key], e]));
      const declaredKeys = new Set();

      for (const spec of declared) {
        const key = spec[res.key];
        if (!key) throw new VaultError('invalid', `every ${type} needs "${res.key}"`, { spec });
        declaredKeys.add(key);
        const current = byKey.get(key);
        if (!current) {
          changes.push({ action: 'create', type, key, after: pick(spec, res.fields) });
          continue;
        }
        const patch = diffFields(spec, current, res.fields);
        if (!Object.keys(patch).length) {
          changes.push({ action: 'noop', type, key });
          continue;
        }
        changes.push({
          action: shrinks(type, spec, current) ? 'shrink' : 'update',
          type, key, patch,
          before: pick(current, Object.keys(patch)),
          after: patch,
          ...(shrinks(type, spec, current) ? { warning: res.destructive } : {})
        });
      }

      if (prune) {
        for (const [key, current] of byKey) {
          if (declaredKeys.has(key)) continue;
          changes.push(res.destroy
            ? { action: 'destroy', type, key, before: pick(current, res.fields), warning: res.destructive }
            : { action: 'orphan', type, key, note: `${type} "${key}" exists but is not declared, and this type is never destroyed by configuration — ${res.destructive}` });
        }
      }
    }

    const byAction = changes.reduce((a, c) => { a[c.action] = (a[c.action] ?? 0) + 1; return a; }, {});
    const destructive = changes.filter((c) => c.action === 'destroy' || c.action === 'shrink');
    return {
      changes: changes.filter((c) => c.action !== 'noop'),
      unchanged: changes.filter((c) => c.action === 'noop').length,
      summary: byAction,
      destructive,
      requiresApproval: destructive.length > 0,
      // The sentence a reviewer actually reads before typing yes.
      verdict: !changes.some((c) => c.action !== 'noop')
        ? 'No changes. Configuration matches the running estate.'
        : `${byAction.create ?? 0} to create, ${byAction.update ?? 0} to update, ${byAction.shrink ?? 0} that reduce access, ${byAction.destroy ?? 0} to destroy.${destructive.length ? ' Destructive changes need allowDestructive:true.' : ''}`,
      plannedAt: iso()
    };
  }

  /**
   * Apply a plan.
   *
   * Re-plans first rather than trusting the plan it was handed: between plan
   * and apply someone may have changed the estate, and applying a stale diff is
   * how configuration management overwrites an emergency fix.
   */
  apply(config, { actor, reason = 'configuration applied', approvedBy = null, prune = false, allowDestructive = false, credentials = {}, dryRun = false } = {}) {
    if (!actor) throw forbidden('applying configuration requires a named actor');
    const plan = this.plan(config, { prune });

    if (plan.requiresApproval && !allowDestructive) {
      throw new VaultError('forbidden',
        `this plan reduces access or destroys ${plan.destructive.length} resource(s) — pass allowDestructive:true if that is intended`,
        { destructive: plan.destructive.map((d) => ({ action: d.action, type: d.type, key: d.key, warning: d.warning })) });
    }
    if (dryRun) return { ...plan, applied: false, dryRun: true };

    const ctx = { actor, reason, approvedBy, credentials };
    const results = [];
    for (const change of plan.changes) {
      const res = RESOURCES[change.type];
      const spec = (config[change.type] || []).find((s) => s[res.key] === change.key);
      try {
        let out;
        if (change.action === 'create') out = res.create(this.vault, spec, ctx);
        else if (change.action === 'update' || change.action === 'shrink') {
          if (!res.update) throw new VaultError('unsupported', `${change.type} cannot be updated in place — destroy and recreate it deliberately`);
          out = res.update(this.vault, spec, res.read(this.vault).find((e) => e[res.key] === change.key), ctx);
        } else if (change.action === 'destroy') out = res.destroy(this.vault, res.read(this.vault).find((e) => e[res.key] === change.key), ctx);
        else continue;
        results.push({ ...change, ok: true, id: out?.id ?? change.key });
      } catch (e) {
        // One failure does not roll back the others: there is no transaction
        // across a registry, a folder tree and a rules engine, and pretending
        // otherwise would leave the operator with a false picture. Report
        // exactly what landed and what did not.
        results.push({ ...change, ok: false, error: e.message, code: e.code || 'error' });
      }
    }

    const failed = results.filter((r) => !r.ok);
    const record = {
      at: now(), actor, reason, approvedBy,
      applied: results.filter((r) => r.ok).length,
      failed: failed.length,
      results
    };
    this.applies.push(record);
    this.ledger?.append('admin.action', {
      subject: 'configuration', actor, reason,
      action: 'config.applied', applied: record.applied, failed: record.failed
    });

    return {
      ...plan,
      applied: true,
      results,
      succeeded: record.applied,
      failed: failed.length,
      // No partial-success theatre: if anything failed, say so first.
      note: failed.length
        ? `${failed.length} of ${results.length} change(s) FAILED and were not rolled back — there is no transaction across these subsystems. Re-run plan to see the current state.`
        : `${record.applied} change(s) applied. Re-running this configuration will produce no further changes.`,
      appliedAt: iso()
    };
  }

  /**
   * Drift: what the estate has that the configuration does not describe, or
   * describes differently.
   *
   * This is the check that belongs on a schedule. Configuration that was
   * correct at apply time and has been hand-edited since is the normal way an
   * estate stops matching its own documentation.
   */
  drift(config) {
    const plan = this.plan(config, { prune: true });
    // Drift is a declared resource that no longer matches. A resource that
    // simply is not declared is a different finding: on any real install the
    // default folder tree is undeclared, and reporting that as drift would mean
    // every estate is permanently out of sync and nobody looks at the report.
    const drifted = plan.changes.filter((c) => c.action === 'update' || c.action === 'shrink');
    return {
      inSync: drifted.length === 0,
      drifted,
      undeclared: plan.changes.filter((c) => c.action === 'destroy' || c.action === 'orphan')
        .map((c) => ({ type: c.type, key: c.key, note: c.note ?? 'exists but is not declared' })),
      missing: plan.changes.filter((c) => c.action === 'create').map((c) => ({ type: c.type, key: c.key })),
      checkedAt: iso(),
      verdict: drifted.length
        ? `${drifted.length} resource(s) differ from the declared configuration.`
        : 'Every declared resource matches. Resources that exist but are not declared are listed separately under "undeclared" — that is coverage, not drift.'
    };
  }

  /** Export the running estate AS configuration, for adopting an existing install. */
  export() {
    const out = { version: 1 };
    for (const [type, res] of Object.entries(RESOURCES)) {
      out[type] = res.read(this.vault).map((e) => pick(e, res.fields));
    }
    return out;
  }

  history() { return this.applies.map((a) => ({ ...a, at: iso(a.at) })); }
}

function pick(obj, fields) {
  const out = {};
  for (const f of fields) if (obj?.[f] !== undefined) out[f] = obj[f];
  return out;
}

/**
 * Render a plan the way a person reads one.
 *
 * Deliberately the same shape as `terraform plan` output, because that is the
 * format the audience already knows how to scan for the line that worries them.
 */
export function renderPlan(plan) {
  const sign = { create: '+', update: '~', shrink: '!', destroy: '-', orphan: '?' };
  const lines = plan.changes.map((c) => {
    const head = `  ${sign[c.action] ?? ' '} ${c.type}.${c.key}`;
    if (c.action === 'create') return `${head}\n${Object.entries(c.after).map(([k, val]) => `      ${k} = ${JSON.stringify(val)}`).join('\n')}`;
    if (c.action === 'update' || c.action === 'shrink') {
      return `${head}${c.warning ? `   ← ${c.warning}` : ''}\n${Object.entries(c.patch).map(([k, val]) => `      ${k}: ${JSON.stringify(c.before?.[k])} → ${JSON.stringify(val)}`).join('\n')}`;
    }
    if (c.action === 'destroy') return `${head}   ← ${c.warning}`;
    return `${head}   ${c.note ?? ''}`;
  });
  return [
    'Plan:',
    ...(lines.length ? lines : ['  (no changes)']),
    '',
    plan.verdict,
    ...(plan.requiresApproval ? ['', '⚠  This plan reduces access. Apply with allowDestructive:true only if that is intended.'] : [])
  ].join('\n');
}
