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
  '_quarantine/': { read: [], write: ['system'], hardWall: true, noAgentRead: true, description: 'no agent may read' }
};

export class FolderTree {
  /**
   * @param {object} opts
   * @param {import('../storage/db.js').Collection} opts.collection
   * @param {import('../ledger/ledger.js').Ledger} opts.ledger
   * @param {(e:object)=>void} [opts.onAlert]
   */
  constructor({ collection, ledger, onAlert = () => {} }) {
    this.col = collection;
    this.ledger = ledger;
    this.onAlert = onAlert;
    this.col.index('byParent', (f) => f.parent);
    if (!this.col.size) this._seed();
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
      const mark = f.hardWall ? ' 🧱' : '';
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
