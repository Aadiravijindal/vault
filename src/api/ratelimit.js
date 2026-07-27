/**
 * Rate limiting and API key management for Vault's own surface.
 *
 * Distinct from per-connector rate limits and per-agent write budgets: this
 * protects Vault itself. An unauthenticated flood, or one customer integration
 * in a retry loop, must not be able to starve the review queue or the kill
 * switch of capacity.
 *
 * Two deliberate choices:
 *  - The limiter fails CLOSED for writes and OPEN for the kill switch. Losing
 *    the ability to stop the system because you were rate-limited is worse
 *    than any flood.
 *  - Keys are stored as hashes with a shown-once secret, the same contract as
 *    agent credentials, so a database dump does not yield working keys.
 */
import { newId } from '../util/id.js';
import { randomToken, sha256, constantTimeEqual } from '../util/crypto.js';
import { now, iso, ago, duration, MINUTE } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

/** Paths that must never be throttled — the ones you need on the bad day. */
const ALWAYS_ALLOW = [/^\/api\/killswitch/, /^\/api\/health$/];

export class RateLimiter {
  /**
   * @param {object} opts
   * @param {number} [opts.perMinute] default budget per principal
   * @param {number} [opts.burst] tokens available instantaneously
   */
  constructor({ perMinute = 600, burst = 120, windowMs = MINUTE, onLimit = null } = {}) {
    this.perMinute = perMinute;
    this.burst = burst;
    this.windowMs = windowMs;
    this.onLimit = onLimit;
    /** @type {Map<string, {tokens:number, updatedAt:number, rejected:number}>} */
    this.buckets = new Map();
  }

  /**
   * Token bucket. Returns the decision plus the headers a well-behaved client
   * needs to back off without guessing.
   */
  check(key, { at = now(), cost = 1, limit = null, path = '' } = {}) {
    if (ALWAYS_ALLOW.some((rx) => rx.test(path))) {
      return { allowed: true, exempt: true, reason: 'emergency and health paths are never throttled' };
    }
    const capacity = limit ?? this.perMinute;
    const refillPerMs = capacity / this.windowMs;
    let b = this.buckets.get(key);
    if (!b) this.buckets.set(key, (b = { tokens: Math.min(this.burst, capacity), updatedAt: at, rejected: 0 }));

    b.tokens = Math.min(capacity, b.tokens + (at - b.updatedAt) * refillPerMs);
    b.updatedAt = at;

    if (b.tokens < cost) {
      b.rejected++;
      const waitMs = Math.ceil((cost - b.tokens) / refillPerMs);
      this.onLimit?.({ key, path, waitMs, rejected: b.rejected });
      return {
        allowed: false,
        retryAfterMs: waitMs,
        headers: {
          'RateLimit-Limit': String(capacity),
          'RateLimit-Remaining': '0',
          'RateLimit-Reset': String(Math.ceil(waitMs / 1000)),
          'Retry-After': String(Math.ceil(waitMs / 1000))
        },
        reason: `rate limit: ${capacity} requests per minute for this principal`
      };
    }
    b.tokens -= cost;
    return {
      allowed: true,
      headers: {
        'RateLimit-Limit': String(capacity),
        'RateLimit-Remaining': String(Math.floor(b.tokens)),
        'RateLimit-Reset': String(Math.ceil((capacity - b.tokens) / refillPerMs / 1000))
      }
    };
  }

  stats() {
    const rows = [...this.buckets.entries()].map(([key, b]) => ({ key, remaining: Math.floor(b.tokens), rejected: b.rejected }));
    return {
      principals: rows.length,
      totalRejected: rows.reduce((n, r) => n + r.rejected, 0),
      perMinute: this.perMinute,
      burst: this.burst,
      exemptPaths: ALWAYS_ALLOW.map(String),
      top: rows.sort((a, b) => b.rejected - a.rejected).slice(0, 10)
    };
  }
}

/**
 * Customer-side API keys, for their own integrations calling Vault.
 * Same contract as agent credentials: shown once, stored hashed, scoped,
 * expiring, revocable in one click.
 */
export class ApiKeyStore {
  constructor({ collection = null, ledger = null } = {}) {
    this.col = collection;
    this.ledger = ledger;
    const saved = this.col?.get('state') ?? null;
    /** @type {Map<string, object>} */
    this.keys = new Map(Object.entries(saved?.keys ?? {}));
  }

  _persist() { this.col?.put({ id: 'state', keys: Object.fromEntries(this.keys) }); }

  /**
   * @param {{name:string, role:string, scopes?:string[], expiresIn?:string, rateLimitPerMinute?:number, actor:string}} spec
   */
  issue({ name, role, scopes = [], expiresIn = '90d', rateLimitPerMinute = null, actor, department = null, clearance = 'internal' }) {
    if (!name || !role) throw new VaultError('validation', 'an API key needs a name and a role');
    if (!actor) throw forbidden('issuing an API key requires a named actor');
    const secret = `vk_${randomToken(32)}`;
    const id = newId('apikey');
    const record = {
      id, name, role, scopes, department, clearance,
      hash: sha256(secret),
      // A prefix so a leaked key can be identified in a log without holding it.
      prefix: secret.slice(0, 11),
      rateLimitPerMinute,
      issuedBy: actor, issuedAt: now(),
      expiresAt: expiresIn ? now() + duration(expiresIn) : null,
      revoked: false, lastUsedAt: null, uses: 0
    };
    this.keys.set(id, record);
    this._persist();
    this.ledger?.append('admin.action', {
      subject: id, actor, action: 'apikey.issued', role, scopes: scopes.length,
      expiresAt: record.expiresAt ? iso(record.expiresAt) : null
    });
    return { id, name, key: secret, prefix: record.prefix, expiresAt: record.expiresAt ? iso(record.expiresAt) : null, note: 'store this now — Vault keeps only its hash' };
  }

  /** @returns {{valid:boolean, principal?:object, reason?:string}} */
  verify(presented) {
    if (!presented || !String(presented).startsWith('vk_')) return { valid: false, reason: 'not an API key' };
    const hash = sha256(presented);
    for (const k of this.keys.values()) {
      if (!constantTimeEqual(hash, k.hash)) continue;
      if (k.revoked) return { valid: false, reason: 'revoked' };
      if (k.expiresAt && now() > k.expiresAt) return { valid: false, reason: 'expired' };
      this.keys.set(k.id, { ...k, lastUsedAt: now(), uses: k.uses + 1 });
      this._persist();
      return {
        valid: true,
        principal: { name: k.name, role: k.role, department: k.department, clearance: k.clearance, apiKeyId: k.id, scopes: k.scopes },
        rateLimitPerMinute: k.rateLimitPerMinute
      };
    }
    return { valid: false, reason: 'unknown key' };
  }

  revoke(id, { actor, reason }) {
    const k = this.keys.get(id);
    if (!k) throw new VaultError('not_found', 'API key not found', { id });
    if (!actor) throw forbidden('revoking an API key requires a named actor');
    this.keys.set(id, { ...k, revoked: true, revokedBy: actor, revokedAt: now(), revokeReason: reason });
    this._persist();
    this.ledger?.append('admin.action', { subject: id, actor, action: 'apikey.revoked', reason });
    return { id, revoked: true };
  }

  /** Never returns the hash — a listing is not a key escrow. */
  list() {
    return [...this.keys.values()].map((k) => ({
      id: k.id, name: k.name, role: k.role, scopes: k.scopes, prefix: k.prefix,
      issuedBy: k.issuedBy, issuedAt: iso(k.issuedAt),
      expiresAt: k.expiresAt ? iso(k.expiresAt) : null,
      state: k.revoked ? 'revoked' : (k.expiresAt && now() > k.expiresAt ? 'expired' : 'active'),
      lastUsed: k.lastUsedAt ? ago(k.lastUsedAt) : 'never',
      uses: k.uses
    }));
  }
}
