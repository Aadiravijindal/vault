/**
 * Folders and WALLS (§8.6, §11.1).
 *
 * Walls are hard boundaries, not preferences. They are enforced at read AND
 * write, they survive reorganisation, they apply to derived facts and summaries
 * as well as originals, and a cross-wall attempt is blocked, logged and alerted
 * — never silently dropped, because silent failure hides attacks.
 *
 * There is no admin bypass. Break-glass requires two named humans, a stated
 * reason, a time box and a loud log entry.
 */
import { now, iso, DAY, duration } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

/** The default tree. Created automatically as facts arrive. */
export const DEFAULT_TREE = {
  'company/': { read: ['*'], write: ['approved-humans'], description: 'org-wide truths' },
  'company/policies/': { read: ['*'], write: ['approved-humans'], goldenPreferred: true },
  'company/products/': { read: ['*'], write: ['product', 'marketing', 'approved-humans'] },
  'company/people/': { read: ['*'], write: ['hr', 'approved-humans'], sensitivity: 'internal' },
  'sales/': { read: ['sales', 'support', 'marketing'], write: ['sales'] },
  'sales/accounts/': { read: ['sales', 'support'], write: ['sales'] },
  'sales/pricing/': { read: ['sales', 'finance', 'marketing'], write: ['sales', 'finance'], goldenPreferred: true },
  'sales/objections/': { read: ['sales', 'marketing'], write: ['sales'] },
  'sales/competitors/': { read: ['sales', 'marketing', 'product'], write: ['sales', 'marketing'] },
  'engineering/': { read: ['engineering'], write: ['engineering'] },
  'engineering/infrastructure/': { read: ['engineering', 'security'], write: ['engineering'] },
  'support/': { read: ['support', 'sales'], write: ['support'] },
  'support/customers/': { read: ['support', 'sales'], write: ['support'] },
  'support/known-issues/': { read: ['support', 'engineering', 'sales'], write: ['support', 'engineering'] },
  'support/resolutions/': { read: ['support', 'engineering'], write: ['support'] },
  'marketing/': { read: ['marketing', 'sales'], write: ['marketing'] },
  'finance/': { read: ['finance'], write: ['finance'], hardWall: true },
  'legal/': { read: ['legal'], write: ['legal'], hardWall: true, privileged: true },
  'hr/': { read: ['hr'], write: ['hr'], hardWall: true, noBreakGlassWithoutSeparateChain: true },
  'security/': { read: ['security'], write: ['security'], hardWall: true },
  // The "only a few people see this" drawer. Agents and the librarian may FILE
  // into it — that is how something sensitive ends up somewhere safe without a
  // human in the loop — but only a named administrator reads it back out, and
  // nothing automated ever moves a fact out of it.
  'admin/': {
    read: ['admin'], write: ['approved-humans', 'system', 'admin'],
    hardWall: true, adminOnly: true, sensitivity: 'secret',
    description: 'administrator-only: readable by named administrators, or by break-glass with two humans'
  },
  '_quarantine/': { read: [], write: ['system'], hardWall: true, noAgentRead: true, description: 'no agent may read' }
};

export class FolderTree {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {(e:object)=>void} [opts.onAlert]
   * @param {string[]} [opts.administrators] who may read an administrator-only folder
   */
  constructor({ collection, ledger, onAlert = () => {}, administrators = [] }) {
    this.col = collection;
    this.ledger = ledger;
    this.onAlert = onAlert;
    this.administrators = new Set(administrators);
    this.col.index('byParent', (f) => f.parent);
    if (!this.col.size) this._seed();
  }

  /**
   * Is this actor a named administrator?
   *
   * A list of names, not a role claimed in the request. `actor.administrator`
   * is honoured only because the identity layer sets it from the provider —
   * anything a caller can assert about itself is not an authorisation.
   */
  isAdministrator(actor) {
    if (!actor) return false;
    if (actor.administrator === true) return true;
    return this.administrators.has(actor.id);
  }

  _seed() {
    for (const [path, spec] of Object.entries(DEFAULT_TREE)) this.ensure(path, { ...spec, seeded: true });
  }

  /** Normalise to a trailing-slash path. */
  static normalise(path) {
    let p = String(path || '').trim().replace(/^\/+/, '');
    if (!p) return null;
    if (!p.endsWith('/')) p += '/';
    return p.toLowerCase();
  }

  /**
   * Create a folder (and its ancestors) if missing. Children inherit the
   * parent's wall unless overridden — a new subfolder can never be *more* open
   * than its parent.
   */
  ensure(path, spec = {}) {
    const p = FolderTree.normalise(path);
    if (!p) throw new VaultError('validation', 'folder path required');
    const existing = this.col.get(p);
    if (existing) return existing;

    const parentPath = parentOf(p);
    const parent = parentPath ? this.ensure(parentPath) : null;

    const inheritedRead = parent ? parent.read : ['*'];
    const inheritedWrite = parent ? parent.write : ['approved-humans'];
    const read = spec.read ?? inheritedRead;
    const write = spec.write ?? inheritedWrite;

    // A child may narrow its parent's wall but never widen it.
    const effectiveRead = parent && !parent.read.includes('*')
      ? read.filter((r) => r === '*' ? false : parent.read.includes(r) || parent.read.includes('*'))
      : read;

    const folder = this.col.insert({
      id: p,
      path: p,
      parent: parentPath,
      read: effectiveRead.length ? effectiveRead : (parent ? parent.read : ['*']),
      write,
      hardWall: spec.hardWall ?? parent?.hardWall ?? false,
      // Inherited downwards and never cleared by a child: a subfolder of an
      // administrator-only folder cannot opt itself out of the restriction.
      adminOnly: spec.adminOnly || parent?.adminOnly || false,
      privileged: spec.privileged ?? parent?.privileged ?? false,
      noAgentRead: spec.noAgentRead ?? parent?.noAgentRead ?? false,
      noBreakGlassWithoutSeparateChain: spec.noBreakGlassWithoutSeparateChain ?? parent?.noBreakGlassWithoutSeparateChain ?? false,
      description: spec.description ?? '',
      businessOwner: spec.businessOwner ?? null,
      technicalOwner: spec.technicalOwner ?? null,
      retention: spec.retention ?? parent?.retention ?? null,
      residency: spec.residency ?? parent?.residency ?? null,
      keyScope: spec.keyScope ?? `ns:${p.split('/')[0]}`,
      reviewSlaMs: spec.reviewSlaMs ?? parent?.reviewSlaMs ?? DAY,
      defaultSensitivity: spec.sensitivity ?? parent?.defaultSensitivity ?? 'internal',
      goldenPreferred: spec.goldenPreferred ?? false,
      createdAt: now(),
      archived: false
    });
    return folder;
  }

  get(path) { return this.col.get(FolderTree.normalise(path)); }
  all() { return this.col.all().sort((a, b) => a.path.localeCompare(b.path)); }
  children(path) { return this.col.by('byParent', FolderTree.normalise(path)); }

  /** Nearest existing ancestor, used when a fact is filed deep. */
  resolve(path) {
    let p = FolderTree.normalise(path);
    while (p) {
      const f = this.col.get(p);
      if (f) return f;
      p = parentOf(p);
    }
    return null;
  }

  setOwners(path, { businessOwner, technicalOwner, actor }) {
    const f = this.get(path);
    if (!f) throw new VaultError('not_found', 'folder not found', { path });
    const updated = this.col.update(f.id, { businessOwner, technicalOwner });
    this.ledger.append('admin.action', { subject: f.id, actor, action: 'folder.owners_set', businessOwner, technicalOwner });
    return updated;
  }

  /** An unowned folder is a finding, reported on the Map (§11.1). */
  findings() {
    return this.all()
      .filter((f) => !f.archived && (!f.businessOwner || !f.technicalOwner))
      .map((f) => ({
        path: f.path,
        finding: !f.businessOwner && !f.technicalOwner ? 'no business or technical owner'
          : !f.businessOwner ? 'no business owner' : 'no technical owner',
        severity: f.hardWall ? 'high' : 'medium'
      }));
  }

  // -- the wall ------------------------------------------------------------

  /**
   * @param {'read'|'write'} mode
   * @param {object} actor { id, kind:'agent'|'human', department, clearance, breakGlass }
   * @param {string} path
   * @returns {{allowed:boolean, reason:string, folder:object|null, requiresBreakGlass?:boolean}}
   */
  check(mode, actor, path) {
    const folder = this.resolve(path);
    if (!folder) return { allowed: false, reason: 'folder does not exist', folder: null };

    if (folder.noAgentRead && actor.kind === 'agent' && mode === 'read') {
      return { allowed: false, reason: `${folder.path} is a quarantine namespace — no agent may read it`, folder };
    }

    // Administrator-only namespaces (§8.6, the "only a few people see this"
    // case). This REPLACES the read list rather than adding to it: a folder
    // that is administrator-only is not also readable by whoever happens to be
    // in the right department, or the restriction would be decorative. Writes
    // are unaffected — filing INTO one of these is ordinary, and it is getting
    // things out again that is controlled.
    if (folder.adminOnly && mode === 'read' && !this.isAdministrator(actor)) {
      if (actor.kind === 'agent') {
        return { allowed: false, reason: `${folder.path} is administrator-only — no agent reads one, with or without break-glass`, folder };
      }
      if (actor.breakGlass?.active) {
        if (folder.noBreakGlassWithoutSeparateChain && !actor.breakGlass.separateChain) {
          return { allowed: false, reason: `${folder.path} requires a separate break-glass approval chain`, folder };
        }
        return { allowed: true, reason: 'break-glass into an administrator-only folder', folder, breakGlass: true };
      }
      return {
        allowed: false,
        reason: `${folder.path} is administrator-only — ${actor.id ?? 'this actor'} is not a named administrator`,
        folder,
        requiresBreakGlass: true
      };
    }

    const allowedList = mode === 'read' ? folder.read : folder.write;
    const dept = String(actor.department || '').toLowerCase();

    if (allowedList.includes('*')) return { allowed: true, reason: 'open to all', folder };
    if (allowedList.includes(dept)) return { allowed: true, reason: `${dept} is on the ${mode} list for ${folder.path}`, folder };
    if (mode === 'write' && allowedList.includes('approved-humans') && actor.kind === 'human' && actor.approved) {
      return { allowed: true, reason: 'approved human writer', folder };
    }
    if (mode === 'write' && allowedList.includes('system') && actor.kind === 'system') {
      return { allowed: true, reason: 'system writer', folder };
    }
    // Project-level isolation inside a department (Atlas can't see Beacon).
    if (folder.projectScope && actor.projects && !actor.projects.includes(folder.projectScope)) {
      return { allowed: false, reason: `project isolation: ${folder.path} is scoped to ${folder.projectScope}`, folder };
    }

    // Break-glass: never a silent bypass.
    if (actor.breakGlass?.active && !folder.noAgentRead) {
      if (folder.noBreakGlassWithoutSeparateChain && !actor.breakGlass.separateChain) {
        return { allowed: false, reason: `${folder.path} requires a separate break-glass approval chain`, folder };
      }
      return { allowed: true, reason: 'break-glass session', folder, breakGlass: true };
    }

    return {
      allowed: false,
      reason: `wall: ${folder.path} is ${mode === 'read' ? 'readable' : 'writable'} by ${allowedList.join(', ') || 'nobody'}${dept ? ` — ${dept} is not on that list` : ''}`,
      folder,
      requiresBreakGlass: folder.hardWall
    };
  }

  /**
   * Enforce, and make the refusal loud. Cross-wall attempts are blocked, logged
   * and alerted (§8.6).
   */
  enforce(mode, actor, path, { subject = null } = {}) {
    const result = this.check(mode, actor, path);
    if (!result.allowed) {
      this.ledger.append('security.detection', {
        subject: subject || path, actor: actor.id, detection: 'cross_wall_attempt',
        mode, folder: result.folder?.path ?? path, reason: result.reason
      });
      this.onAlert({
        severity: 'high', kind: 'cross_wall_attempt', actor: actor.id,
        folder: result.folder?.path ?? path, mode, reason: result.reason, at: iso()
      });
      throw forbidden(result.reason, { code: 'wall_violation', folder: result.folder?.path ?? path, mode });
    }
    if (result.breakGlass) {
      this.ledger.append('admin.breakglass', {
        subject: result.folder.path, actor: actor.id, mode,
        approvers: actor.breakGlass.approvers, reason: actor.breakGlass.reason,
        expiresAt: iso(actor.breakGlass.expiresAt)
      });
    }
    return result;
  }

  /**
   * Inference protection: a summary that would leak across a wall is itself
   * walled. Derived content inherits the STRICTEST wall of its inputs (§8.6).
   */
  strictestOf(paths) {
    const folders = paths.map((p) => this.resolve(p)).filter(Boolean);
    if (!folders.length) return null;
    let read = null;
    let write = null;
    let hardWall = false;
    let privileged = false;
    for (const f of folders) {
      read = read === null ? [...f.read] : intersect(read, f.read);
      write = write === null ? [...f.write] : intersect(write, f.write);
      hardWall = hardWall || f.hardWall;
      privileged = privileged || f.privileged;
    }
    return { read, write, hardWall, privileged, derivedFrom: folders.map((f) => f.path) };
  }

  /**
   * Change a folder's wall.
   *
   * `ensure` deliberately returns an existing folder untouched, which meant
   * there was no path at all to change a wall after creation — an estate could
   * only be walled correctly on the first day. This is that path, and it is
   * deliberately not a generic update: a wall is the boundary everything else
   * in the product enforces, so changing one is its own operation with its own
   * rules.
   *
   * The invariant `ensure` applies at creation applies here too: a child may
   * narrow its parent's wall, never widen it. Otherwise the way to read `hr/`
   * would be to widen `hr/reviews/`, and the wall would be advisory.
   */
  setWalls(path, { read = null, write = null, actor, reason }) {
    const f = this.get(path);
    if (!f) throw new VaultError('not_found', 'folder not found', { path });
    if (!actor || !reason) throw forbidden('changing a wall requires a named actor and a reason');
    if (read === null && write === null) return f;

    const parent = f.parent ? this.get(f.parent) : null;
    const nextRead = read ?? f.read;
    const nextWrite = write ?? f.write;

    if (parent && !parent.read.includes('*')) {
      const widened = nextRead.filter((r) => r === '*' || !parent.read.includes(r));
      if (widened.length) {
        throw forbidden(
          `a folder cannot be more readable than its parent — ${widened.join(', ')} may not read ${parent.path}`,
          { path: f.path, parent: parent.path, parentRead: parent.read, attempted: nextRead }
        );
      }
    }

    // Widening is not forbidden, but it is never quiet: someone gained access
    // to something, and that is exactly the change an auditor asks about.
    const added = {
      read: nextRead.filter((r) => !f.read.includes(r)),
      write: nextWrite.filter((w) => !f.write.includes(w))
    };
    const removed = {
      read: f.read.filter((r) => !nextRead.includes(r)),
      write: f.write.filter((w) => !nextWrite.includes(w))
    };

    const updated = this.col.update(f.id, { read: nextRead, write: nextWrite });
    this.ledger.append('folder.wall_changed', {
      subject: f.path, actor, reason,
      before: { read: f.read, write: f.write },
      after: { read: nextRead, write: nextWrite },
      widened: added.read.length + added.write.length,
      narrowed: removed.read.length + removed.write.length
    });
    if (added.read.length || added.write.length) {
      this.onAlert({
        severity: 'medium', kind: 'wall_widened', subject: f.path, actor,
        detail: `${f.path} is now readable by ${added.read.join(', ') || '—'} and writable by ${added.write.join(', ') || '—'} — ${reason}`
      });
    }
    return { ...updated, added, removed };
  }

  /**
   * Pin where this folder's data may live.
   *
   * Treated like a wall change rather than a setting, because it is one:
   * everything already filed here becomes subject to it, and replication and
   * cross-border reads are decided by it. Children inherit unless they pin
   * their own, and re-pinning a folder that already has a region is called out
   * loudly — data written under the old pin does not move itself.
   */
  setResidency(path, region, { actor, reason }) {
    const f = this.get(path);
    if (!f) throw new VaultError('not_found', 'folder not found', { path });
    if (!actor || !reason) throw forbidden('pinning residency requires a named actor and a reason');
    const before = f.residency ?? null;
    const after = region ?? null;
    if (before === after) return f;

    const updated = this.col.update(f.id, { residency: after });
    for (const child of this.col.by('byParent', f.id)) {
      if ((child.residency ?? null) === before) this.setResidency(child.path, after, { actor, reason: `inherited from ${f.path}` });
    }
    this.ledger.append('folder.wall_changed', {
      subject: f.path, actor, reason, before: { residency: before }, after: { residency: after }
    });
    if (before && before !== after) {
      this.onAlert({
        severity: 'high', kind: 'residency_changed', subject: f.path, actor,
        detail: `${f.path} was pinned to ${before} and is now pinned to ${after} — data written under the old pin is still physically where it was; moving it is a separate, deliberate act — ${reason}`
      });
    }
    return updated;
  }

  /** Moving a folder moves its wall, its retention and its history (§8.6). */
  move(fromPath, toPath, { actor, reason }) {
    const from = this.get(fromPath);
    if (!from) throw new VaultError('not_found', 'folder not found', { path: fromPath });
    if (!actor || !reason) throw forbidden('folder moves require a named actor and a reason');
    const to = FolderTree.normalise(toPath);
    const descendants = this.all().filter((f) => f.path.startsWith(from.path));
    const moved = [];
    for (const d of descendants) {
      const newPath = to + d.path.slice(from.path.length);
      const clone = { ...d, id: newPath, path: newPath, parent: parentOf(newPath), movedFrom: d.path };
      this.col.insert(clone);
      this.col.update(d.id, { archived: true, movedTo: newPath });
      moved.push({ from: d.path, to: newPath });
    }
    this.ledger.append('admin.action', { subject: from.path, actor, action: 'folder.moved', reason, to, moved: moved.length });
    return { moved, wallPreserved: true, retentionPreserved: true, historyPreserved: true };
  }

  merge(sourcePath, targetPath, { actor, reason }) {
    const src = this.get(sourcePath);
    const tgt = this.get(targetPath);
    if (!src || !tgt) throw new VaultError('not_found', 'folder not found');
    if (!actor || !reason) throw forbidden('folder merges require a named actor and a reason');
    // The merged folder takes the STRICTER wall — merging must never widen access.
    const stricter = this.strictestOf([src.path, tgt.path]);
    this.col.update(tgt.id, { read: stricter.read, write: stricter.write, hardWall: stricter.hardWall, privileged: stricter.privileged });
    this.col.update(src.id, { archived: true, mergedInto: tgt.path });
    this.ledger.append('admin.action', { subject: src.path, actor, action: 'folder.merged', reason, into: tgt.path });
    return { merged: src.path, into: tgt.path, resultingWall: stricter };
  }

  /** Human-readable tree for the UI and the CLI. */
  render() {
    const lines = [];
    for (const f of this.all().filter((x) => !x.archived)) {
      const depth = f.path.split('/').filter(Boolean).length - 1;
      const mark = (f.adminOnly ? ' 🔒' : '') + (f.hardWall ? ' 🧱' : '');
      const owner = f.businessOwner ? ` — ${f.businessOwner}` : ' — ⚠️ unowned';
      lines.push(`${'  '.repeat(depth)}${f.path.split('/').filter(Boolean).pop()}/${mark}${owner}`);
    }
    return lines.join('\n');
  }
}

function parentOf(path) {
  const parts = String(path).split('/').filter(Boolean);
  if (parts.length <= 1) return null;
  return parts.slice(0, -1).join('/') + '/';
}

function intersect(a, b) {
  if (a.includes('*')) return [...b];
  if (b.includes('*')) return [...a];
  return a.filter((x) => b.includes(x));
}
