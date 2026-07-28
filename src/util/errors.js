/**
 * Typed errors.
 *
 * Two rules enforced here, both from the spec:
 *  - no content in error messages (§9.11), so an error can never become a leak;
 *  - every refusal carries a machine-readable code, because "blocked" without a
 *    reason is indistinguishable from a bug to the agent on the other end.
 */

export class VaultError extends Error {
  /**
   * @param {string} code
   * @param {string} message safe, content-free
   * @param {Record<string,any>} [meta] ids and counts only — never content
   */
  constructor(code, message, meta = {}) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
    // A caller may pin the HTTP status where the code alone is ambiguous —
    // SCIM answers an unsupported filter with 501, not the 400 that
    // "unsupported" maps to. It is lifted out of the meta so it never lands in
    // the response body twice.
    const { status, ...rest } = meta;
    this.meta = rest;
    this.status = status ?? STATUS[code] ?? 400;
  }
  toJSON() {
    return { error: this.code, message: this.message, ...this.meta };
  }
}

const STATUS = {
  unauthenticated: 401,
  forbidden: 403,
  wall_violation: 403,
  clearance_denied: 403,
  region_denied: 403,
  not_found: 404,
  conflict: 409,
  immutable: 409,
  legal_hold: 409,
  rate_limited: 429,
  frozen: 503,
  killswitch: 503,
  internal: 500
};

export const err = (code, message, meta) => new VaultError(code, message, meta);

export function notFound(kind, id) {
  // Never widen this beyond an identifier. A caller that passes a whole record
  // by mistake would otherwise put its content — transcripts included — into an
  // error body that goes back over the API. Content in an error message is the
  // classic accidental exfiltration channel (§9.11).
  return new VaultError('not_found', `${kind} not found`, { id: identifierOf(id) });
}

/** Reduce anything to a safe, content-free identifier. */
export function identifierOf(x) {
  if (x == null) return null;
  if (typeof x === 'string' || typeof x === 'number') return String(x).slice(0, 128);
  if (typeof x === 'object' && typeof x.id === 'string') return x.id;
  return `<${typeof x}>`;
}

export function forbidden(message, meta) {
  return new VaultError('forbidden', message, meta);
}

export function immutable(message, meta) {
  return new VaultError('immutable', message, meta);
}

/** Assert without ever interpolating caller-supplied content into the message. */
export function assert(cond, code, message, meta) {
  if (!cond) throw new VaultError(code, message, meta);
}
