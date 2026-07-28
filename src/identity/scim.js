/**
 * SCIM 2.0 — provisioning and, more importantly, deprovisioning.
 *
 * The whole reason this exists is the second half. Provisioning is a
 * convenience: someone joins, and their account appears without a ticket.
 * Deprovisioning is a control: someone is dismissed at 14:05, HR deactivates
 * them in Okta at 14:06, and the question a regulator asks is what they could
 * still read at 14:07.
 *
 * With self-describing tokens the honest answer is "until their token expires".
 * That is why sessions in this product are server-side state: `PATCH
 * active:false` calls `revokeAllFor`, and the next request — not the next
 * refresh — is refused. The test for this asserts on exactly that boundary,
 * because "eventually revoked" is the failure being prevented.
 *
 * Implements the parts of RFC 7643/7644 that IdPs actually send: Users and
 * Groups, POST/GET/PUT/PATCH/DELETE, `filter` on userName and externalId,
 * pagination, and the ListResponse envelope. It does not implement the full
 * filter grammar, and says so with a 501 rather than silently returning
 * everything — a filter that is ignored is an access-control failure wearing a
 * feature's clothes.
 */
import { randomUUID } from 'node:crypto';
import { now, iso } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';
import { constantTimeEqual } from '../util/crypto.js';

export const SCIM_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const SCIM_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
export const SCIM_ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
export const SCIM_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
export const SCIM_PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
export const SCIM_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';

/** Group name → Vault role. Anything unmapped gets nothing, deliberately. */
export const DEFAULT_GROUP_ROLES = {
  'vault-admins': 'admin',
  'vault-security': 'security',
  'vault-legal': 'legal',
  'vault-compliance': 'compliance',
  'vault-platform': 'platform',
  'vault-risk': 'risk',
  'vault-finance': 'finance',
  'vault-auditors': 'auditor',
  'vault-works-council': 'works_council',
  'vault-users': 'end_user'
};

export class ScimService {
  /**
   * @param {object} o
   * @param {import('./identity.js').SessionStore} o.sessions
   * @param {Record<string,string>} [o.groupRoles]
   * @param {string} [o.defaultRole] role for a provisioned user in no mapped group
   */
  constructor({ sessions, collection = null, groupCollection = null, ledger = null, groupRoles = DEFAULT_GROUP_ROLES,
    defaultRole = 'end_user', onDeprovision = null, bearerToken = null } = {}) {
    if (!sessions) throw new VaultError('config', 'SCIM needs the session store — deprovisioning that cannot revoke a session is decorative');
    this.sessions = sessions;
    /**
     * The IdP's provisioning credential.
     *
     * Deliberately NOT a Vault API token. The caller is Okta or Entra, not a
     * person, and it needs exactly one power: to create and deactivate
     * accounts. Reusing an admin token here would mean a leaked SCIM secret
     * also read memory.
     */
    this.bearerToken = bearerToken;
    this.col = collection;
    this.groupCol = groupCollection;
    this.ledger = ledger;
    this.groupRoles = groupRoles;
    this.defaultRole = defaultRole;
    this.onDeprovision = onDeprovision;
    /** @type {Map<string, object>} */
    this.users = new Map();
    /**
     * @type {Map<string, object>}
     *
     * Groups were in-memory only while users were persisted, so a restart left
     * every user carrying group names that no longer resolved to a group. The
     * Groups endpoint then reported an empty directory to the IdP, and the next
     * sync could re-create groups Vault had silently forgotten.
     */
    this.groups = new Map();
    if (collection) for (const u of collection.all()) this.users.set(u.id, u);
    if (groupCollection) for (const g of groupCollection.all()) this.groups.set(g.id, g);
    this.stats = { created: 0, updated: 0, deactivated: 0, deleted: 0, sessionsRevoked: 0 };
  }

  /**
   * Is this the IdP? Constant-time, and closed when no token is configured:
   * an unset credential must mean "SCIM is off", never "SCIM is open".
   */
  verifyBearer(token) {
    if (!this.bearerToken) return false;
    return constantTimeEqual(String(this.bearerToken), String(token ?? ''));
  }

  /** RFC 7643 §5 — what this server truthfully supports. */
  serviceProviderConfig() {
    return {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      documentationUri: 'https://vault.local/docs/scim',
      patch: { supported: true },
      // Advertising a capability that is not implemented is worse than not
      // having it: the IdP uses it and the sync fails halfway through.
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 200 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [{
        type: 'oauthbearertoken', name: 'OAuth Bearer Token',
        description: 'Authentication scheme using the OAuth Bearer Token Standard',
        specUri: 'https://www.rfc-editor.org/info/rfc6750', primary: true
      }],
      meta: { resourceType: 'ServiceProviderConfig', location: '/scim/v2/ServiceProviderConfig' }
    };
  }

  /** RFC 7643 §6. */
  resourceTypes() {
    const type = (id, name, schema, endpoint) => ({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
      id, name, endpoint, schema,
      meta: { resourceType: 'ResourceType', location: `/scim/v2/ResourceTypes/${id}` }
    });
    return {
      schemas: [SCIM_LIST], totalResults: 2, startIndex: 1, itemsPerPage: 2,
      Resources: [
        type('User', 'User', 'urn:ietf:params:scim:schemas:core:2.0:User', '/Users'),
        type('Group', 'Group', 'urn:ietf:params:scim:schemas:core:2.0:Group', '/Groups')
      ]
    };
  }

  // -- users ---------------------------------------------------------------

  createUser(resource, { actor = 'scim', at = now() } = {}) {
    const userName = resource.userName;
    if (!userName) throw new VaultError('invalid', 'a SCIM user needs a userName', { scimType: 'invalidValue' });
    const existing = this.byUserName(userName);
    if (existing) {
      // 409 is what an IdP expects; returning 200 here makes Okta think it
      // created a second account and the two drift apart forever.
      throw new VaultError('conflict', `a user with userName "${userName}" already exists`, { scimType: 'uniqueness', id: existing.id });
    }

    const user = this._toUser({ id: randomUUID(), ...resource }, at);
    this.users.set(user.id, user);
    this.col?.insert({ ...user });
    this.stats.created++;
    this.ledger?.append('admin.action', {
      subject: user.userName, actor, action: 'scim.user_created', role: user.role, active: user.active
    });
    return this._present(user);
  }

  /** PUT — a full replace, which is how Entra sends most updates. */
  replaceUser(id, resource, { actor = 'scim', at = now() } = {}) {
    const existing = this.require(id);
    const wasActive = existing.active;
    const user = this._toUser({ ...resource, id, meta: existing.meta }, at, existing);
    this.users.set(id, user);
    this.col?.update?.(id, { ...user });
    this.stats.updated++;
    if (wasActive && !user.active) this._deprovision(user, { actor, reason: 'SCIM replace set active:false', at });
    else if (existing.role !== user.role) this._roleChanged(user, existing.role, { actor, at });
    return this._present(user);
  }

  /**
   * PATCH — how Okta deactivates. The operation that matters most is
   * `{op:"replace", path:"active", value:false}`.
   */
  patchUser(id, patchOp, { actor = 'scim', at = now() } = {}) {
    const user = this.require(id);
    const ops = patchOp?.Operations ?? patchOp?.operations ?? [];
    if (!Array.isArray(ops) || !ops.length) {
      throw new VaultError('invalid', 'PatchOp needs an Operations array', { scimType: 'invalidSyntax' });
    }
    const wasActive = user.active;
    const wasRole = user.role;

    for (const op of ops) {
      const kind = String(op.op ?? '').toLowerCase();
      // A path-less replace carries an object of attributes — Entra's style.
      if (!op.path && kind === 'replace' && op.value && typeof op.value === 'object') {
        for (const [k, v] of Object.entries(op.value)) this._applyPath(user, k, v, kind);
        continue;
      }
      if (!op.path) throw new VaultError('invalid', `operation "${kind}" needs a path`, { scimType: 'noTarget' });
      this._applyPath(user, op.path, op.value, kind);
    }

    user.meta.lastModified = iso(at);
    this.users.set(id, user);
    this.col?.update?.(id, { ...user });
    this.stats.updated++;

    if (wasActive && !user.active) this._deprovision(user, { actor, reason: 'SCIM patch set active:false', at });
    else if (!wasActive && user.active) {
      this.ledger?.append('admin.action', { subject: user.userName, actor, action: 'scim.user_reactivated' });
    } else if (wasRole !== user.role) this._roleChanged(user, wasRole, { actor, at });

    return this._present(user);
  }

  /**
   * DELETE. Same immediacy requirement as deactivation.
   *
   * The record is kept as a tombstone rather than dropped: the audit trail
   * needs to show that this identity existed and what it did, and a deleted
   * row cannot answer that.
   */
  deleteUser(id, { actor = 'scim', at = now() } = {}) {
    const user = this.require(id);
    user.active = false;
    user.deleted = true;
    user.meta.lastModified = iso(at);
    this.users.set(id, user);
    this.col?.update?.(id, { ...user });
    this.stats.deleted++;
    this._deprovision(user, { actor, reason: 'SCIM delete', at });
    return { deleted: true, id, userName: user.userName, sessionsRevoked: user.lastRevocation?.revoked ?? 0 };
  }

  /**
   * The point of the whole module: access stops now.
   */
  _deprovision(user, { actor, reason, at }) {
    const result = this.sessions.revokeAllFor(user.userName, { actor, reason, at });
    this.stats.deactivated++;
    this.stats.sessionsRevoked += result.revoked;
    // `revokeAllFor` echoes the principal back, and persisting that would write
    // the userName to disk in the clear on the deprovision path — undoing the
    // field-level seal on `userName` for exactly the records that most need it.
    // The record IS that user, so the name here is redundant as well as unsafe.
    const { principal, ...safe } = result;
    user.lastRevocation = { ...safe, at: iso(at) };
    this.col?.update?.(user.id, { lastRevocation: user.lastRevocation });
    this.ledger?.append('admin.action', {
      subject: user.userName, actor, action: 'scim.user_deprovisioned', reason,
      sessionsRevoked: result.revoked
    });
    this.onDeprovision?.({ userName: user.userName, reason, sessionsRevoked: result.revoked, at });
    return result;
  }

  _roleChanged(user, from, { actor, at }) {
    // A role change is a privilege change. Existing sessions carry the old
    // role in their principal, so they are revoked rather than silently
    // upgraded or left stale.
    const result = this.sessions.revokeAllFor(user.userName, {
      actor, reason: `role changed from ${from ?? 'none'} to ${user.role ?? 'none'}`, at
    });
    this.stats.sessionsRevoked += result.revoked;
    this.ledger?.append('admin.action', {
      subject: user.userName, actor, action: 'scim.role_changed', from, to: user.role, sessionsRevoked: result.revoked
    });
  }

  _applyPath(user, path, value, kind) {
    const p = String(path).replace(/^urn:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:/, '').toLowerCase();
    const remove = kind === 'remove';
    switch (p) {
      case 'active':
        user.active = remove ? false : (value === true || value === 'True' || value === 'true');
        break;
      case 'username': user.userName = String(value); break;
      case 'name.givenname': user.name.givenName = String(value ?? ''); break;
      case 'name.familyname': user.name.familyName = String(value ?? ''); break;
      case 'displayname': user.displayName = String(value ?? ''); break;
      case 'emails': case 'emails[type eq "work"].value':
        user.emails = normaliseEmails(value);
        break;
      case 'department': case 'enterprise:department': user.department = value == null ? null : String(value); break;
      case 'groups': {
        const names = (Array.isArray(value) ? value : [value]).map((g) => (typeof g === 'string' ? g : g?.display ?? g?.value)).filter(Boolean);
        // RFC 7644 §3.5.2: `add` appends to a multi-valued attribute, `replace`
        // without a value filter substitutes the whole attribute. Treating a
        // replace as an append is how a demotion — "your groups are now
        // [vault-users]" — leaves the old privileged group attached.
        if (remove) user.groups = user.groups.filter((g) => !names.includes(g));
        else if (kind === 'replace') user.groups = [...new Set(names)];
        else user.groups = [...new Set([...user.groups, ...names])];
        user.role = this._roleFor(user.groups);
        break;
      }
      case 'externalid': user.externalId = value == null ? null : String(value); break;
      default:
        // Unknown attributes are recorded rather than dropped, so a customer
        // can see what their IdP is sending that Vault does not yet map.
        user.unmapped = { ...(user.unmapped ?? {}), [path]: value };
    }
  }

  _toUser(resource, at, previous = null) {
    const groups = (resource.groups ?? previous?.groups ?? [])
      .map((g) => (typeof g === 'string' ? g : g?.display ?? g?.value)).filter(Boolean);
    const enterprise = resource[SCIM_ENTERPRISE] ?? {};
    return {
      id: resource.id,
      externalId: resource.externalId ?? previous?.externalId ?? null,
      userName: resource.userName ?? previous?.userName,
      name: { givenName: resource.name?.givenName ?? '', familyName: resource.name?.familyName ?? '' },
      displayName: resource.displayName ?? previous?.displayName ?? resource.userName,
      emails: normaliseEmails(resource.emails ?? previous?.emails ?? []),
      department: enterprise.department ?? resource.department ?? previous?.department ?? null,
      groups,
      role: this._roleFor(groups),
      // SCIM's default when the IdP omits it is true, and getting this backwards
      // would silently provision everyone as deactivated.
      active: resource.active === undefined ? (previous?.active ?? true) : Boolean(resource.active),
      deleted: previous?.deleted ?? false,
      unmapped: previous?.unmapped,
      lastRevocation: previous?.lastRevocation,
      meta: resource.meta ?? { resourceType: 'User', created: iso(at), lastModified: iso(at), location: null }
    };
  }

  /**
   * Group → role. Unmapped groups grant nothing.
   *
   * The alternative — defaulting an unrecognised group to some role — is how a
   * new group in the IdP silently becomes an entitlement in Vault.
   */
  _roleFor(groups) {
    const roles = groups.map((g) => this.groupRoles[g] ?? this.groupRoles[String(g).toLowerCase()]).filter(Boolean);
    if (!roles.length) return this.defaultRole;
    const precedence = ['admin', 'security', 'legal', 'compliance', 'platform', 'risk', 'auditor', 'finance', 'works_council', 'department_head', 'folder_owner', 'end_user'];
    // A role this list has never heard of ranks last, not first. `groupRoles`
    // is a customer-supplied map, so any name they choose that is not on this
    // list scored -1 from indexOf and sorted ahead of `admin` — one custom
    // group in the IdP silently deciding the role of everyone who also holds a
    // known one. Ranking unknowns last means a custom mapping can only ever be
    // overridden by a role Vault understands, never the other way round.
    const rank = (r) => { const i = precedence.indexOf(r); return i === -1 ? Number.MAX_SAFE_INTEGER : i; };
    return roles.sort((a, b) => rank(a) - rank(b))[0];
  }

  // -- reads ---------------------------------------------------------------

  require(id) {
    const u = this.users.get(id);
    if (!u) throw new VaultError('not_found', `no user ${id}`, { scimType: null, status: 404 });
    return u;
  }
  byUserName(userName) {
    return [...this.users.values()].find((u) => u.userName?.toLowerCase() === String(userName).toLowerCase() && !u.deleted);
  }

  /**
   * ListResponse with the filters IdPs actually send.
   *
   * An unsupported filter returns 501, never an unfiltered list. Okta probes
   * with `userName eq "x"` before every create; answering that with everybody
   * would make it believe every user already exists.
   */
  listUsers({ filter = null, startIndex = 1, count = 100 } = {}) {
    let items = [...this.users.values()].filter((u) => !u.deleted);
    if (filter) {
      const m = /^\s*(\w+)\s+eq\s+"([^"]*)"\s*$/i.exec(String(filter));
      if (!m) {
        throw new VaultError('unsupported',
          `this SCIM implementation supports only simple "attribute eq \\"value\\"" filters, and refuses to answer "${filter}" with an unfiltered list`,
          { status: 501, scimType: 'invalidFilter' });
      }
      const [, attr, value] = m;
      const key = attr.toLowerCase();
      items = items.filter((u) => {
        if (key === 'username') return u.userName?.toLowerCase() === value.toLowerCase();
        if (key === 'externalid') return u.externalId === value;
        if (key === 'active') return String(u.active) === value.toLowerCase();
        throw new VaultError('unsupported', `filtering on "${attr}" is not supported`, { status: 501, scimType: 'invalidFilter' });
      });
    }
    const start = Math.max(1, Number(startIndex) || 1);
    const page = items.slice(start - 1, start - 1 + (Number(count) || 100));
    return {
      schemas: [SCIM_LIST],
      totalResults: items.length,
      startIndex: start,
      itemsPerPage: page.length,
      Resources: page.map((u) => this._present(u))
    };
  }

  /** A deleted user is a tombstone internally and a 404 over the wire. */
  getUser(id) {
    const u = this.require(id);
    if (u.deleted) throw new VaultError('not_found', `no user ${id}`, { status: 404 });
    return this._present(u);
  }

  // -- groups --------------------------------------------------------------

  /**
   * RFC 7643 §4.2: `members` is a multi-valued attribute of complex values.
   * Members are held internally as plain ids and presented as `{value}` — and
   * that has to be the ONLY way they are presented. GET wrapped them while
   * POST and PATCH returned bare strings, so an IdP reading the response to its
   * own create call got a body that does not conform to the schema it asked for.
   */
  _presentGroup(g) {
    return { schemas: [SCIM_GROUP], ...g, members: g.members.map((m) => ({ value: m })) };
  }

  getGroup(id) {
    const g = this.groups.get(id);
    if (!g) throw new VaultError('not_found', `no group ${id}`, { status: 404 });
    return this._presentGroup(g);
  }

  listGroups({ filter = null, startIndex = 1, count = 100 } = {}) {
    let items = [...this.groups.values()];
    if (filter) {
      const m = /^\s*(\w+)\s+eq\s+"([^"]*)"\s*$/i.exec(String(filter));
      if (!m || m[1].toLowerCase() !== 'displayname') {
        throw new VaultError('unsupported',
          `this SCIM implementation filters groups only on displayName, and refuses to answer "${filter}" with an unfiltered list`,
          { status: 501, scimType: 'invalidFilter' });
      }
      items = items.filter((g) => g.displayName?.toLowerCase() === m[2].toLowerCase());
    }
    const start = Math.max(1, Number(startIndex) || 1);
    const page = items.slice(start - 1, start - 1 + (Number(count) || 100));
    return {
      schemas: [SCIM_LIST], totalResults: items.length, startIndex: start, itemsPerPage: page.length,
      Resources: page.map((g) => ({ schemas: [SCIM_GROUP], ...g, members: g.members.map((m) => ({ value: m })) }))
    };
  }

  /**
   * Deleting a group is a mass privilege change: everyone in it loses whatever
   * it granted, so every one of their sessions goes with it.
   */
  deleteGroup(id, { actor = 'scim', at = now() } = {}) {
    const group = this.groups.get(id);
    if (!group) throw new VaultError('not_found', `no group ${id}`, { status: 404 });
    this.groups.delete(id);
    this.groupCol?.erase?.(id, { actor, reason: 'SCIM group deleted by the identity provider' });
    for (const uid of group.members) {
      const user = this.users.get(uid);
      if (!user) continue;
      const before = user.role;
      user.groups = user.groups.filter((g) => g !== group.displayName);
      user.role = this._roleFor(user.groups);
      this.col?.update?.(user.id, { groups: user.groups, role: user.role });
      if (before !== user.role) this._roleChanged(user, before, { actor, at });
    }
    this.ledger?.append('admin.action', { subject: group.displayName, actor, action: 'scim.group_deleted', members: group.members.length });
    return { deleted: true, id };
  }

  createGroup(resource, { actor = 'scim', at = now() } = {}) {
    if (!resource.displayName) throw new VaultError('invalid', 'a SCIM group needs a displayName');
    const group = {
      id: resource.id ?? randomUUID(),
      displayName: resource.displayName,
      externalId: resource.externalId ?? null,
      members: (resource.members ?? []).map((m) => m.value ?? m),
      meta: { resourceType: 'Group', created: iso(at), lastModified: iso(at) }
    };
    this.groups.set(group.id, group);
    this.groupCol?.put({ ...group });
    this._syncGroup(group, { actor, at });
    this.ledger?.append('admin.action', { subject: group.displayName, actor, action: 'scim.group_created', members: group.members.length });
    return this._presentGroup(group);
  }

  patchGroup(id, patchOp, { actor = 'scim', at = now() } = {}) {
    const group = this.groups.get(id);
    if (!group) throw new VaultError('not_found', `no group ${id}`, { status: 404 });
    for (const op of patchOp?.Operations ?? []) {
      const kind = String(op.op ?? '').toLowerCase();
      if (!/members/i.test(String(op.path ?? 'members'))) continue;
      const values = (Array.isArray(op.value) ? op.value : [op.value]).map((m) => m?.value ?? m).filter(Boolean);
      if (kind === 'add') group.members = [...new Set([...group.members, ...values])];
      else if (kind === 'remove') group.members = group.members.filter((m) => !values.includes(m));
      else if (kind === 'replace') group.members = values;
    }
    group.meta.lastModified = iso(at);
    this.groupCol?.put({ ...group });
    this._syncGroup(group, { actor, at });
    return this._presentGroup(group);
  }

  /**
   * Reflect group membership onto users.
   *
   * Losing a group is a privilege *reduction*, and it must take effect on the
   * live session for the same reason deactivation must — otherwise removing
   * someone from vault-admins leaves them an admin until they log out.
   */
  _syncGroup(group, { actor, at }) {
    for (const user of this.users.values()) {
      const shouldHave = group.members.includes(user.id) || group.members.includes(user.userName);
      const has = user.groups.includes(group.displayName);
      if (shouldHave === has) continue;
      const before = user.role;
      user.groups = shouldHave
        ? [...new Set([...user.groups, group.displayName])]
        : user.groups.filter((g) => g !== group.displayName);
      user.role = this._roleFor(user.groups);
      user.meta.lastModified = iso(at);
      this.col?.update?.(user.id, { groups: user.groups, role: user.role });
      if (before !== user.role) this._roleChanged(user, before, { actor, at });
    }
  }

  _present(u) {
    return {
      schemas: [SCIM_USER, ...(u.department ? [SCIM_ENTERPRISE] : [])],
      id: u.id,
      externalId: u.externalId ?? undefined,
      userName: u.userName,
      name: u.name,
      displayName: u.displayName,
      emails: u.emails,
      active: u.active,
      groups: u.groups.map((g) => ({ display: g })),
      ...(u.department ? { [SCIM_ENTERPRISE]: { department: u.department } } : {}),
      // Not part of SCIM, but the field an administrator most wants when
      // answering "what could they still see?"
      'urn:vault:params:scim:extension:2.0': {
        role: u.role,
        lastRevocation: u.lastRevocation ?? null,
        unmappedAttributes: u.unmapped ? Object.keys(u.unmapped) : []
      },
      meta: u.meta
    };
  }

  /** The SCIM error envelope IdPs expect. */
  static error(e) {
    const status = e?.meta?.status ?? ({ conflict: 409, not_found: 404, invalid: 400, unsupported: 501, forbidden: 403 }[e?.code] ?? 500);
    return {
      body: { schemas: [SCIM_ERROR], status: String(status), scimType: e?.meta?.scimType ?? undefined, detail: e?.message ?? 'error' },
      status
    };
  }

  /** What an administrator needs to see about the IdP connection's health. */
  status() {
    const users = [...this.users.values()];
    return {
      users: users.length,
      active: users.filter((u) => u.active && !u.deleted).length,
      deactivated: users.filter((u) => !u.active && !u.deleted).length,
      deleted: users.filter((u) => u.deleted).length,
      groups: this.groups.size,
      byRole: users.filter((u) => u.active).reduce((a, u) => { a[u.role] = (a[u.role] ?? 0) + 1; return a; }, {}),
      unmappedGroups: [...new Set(users.flatMap((u) => u.groups))].filter((g) => !this.groupRoles[g] && !this.groupRoles[String(g).toLowerCase()]),
      stats: this.stats
    };
  }
}

function normaliseEmails(value) {
  const list = Array.isArray(value) ? value : (value == null ? [] : [value]);
  return list.map((e) => (typeof e === 'string'
    ? { value: e, primary: true, type: 'work' }
    : { value: e.value, primary: e.primary ?? false, type: e.type ?? 'work' })).filter((e) => e.value);
}
