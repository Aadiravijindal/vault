/**
 * Enterprise identity: SAML 2.0, OIDC, SCIM 2.0, sessions, MFA and access
 * conditions.
 *
 * Before this existed, Vault authenticated with bearer tokens and API keys. No
 * CISO buys a governance product you log into with a bearer token, so this is
 * the gap that blocked the sale on its own.
 *
 * The design rule that shapes everything here: **sessions are server-side
 * state, not self-describing tokens.** A JWT that carries its own claims cannot
 * be revoked before it expires — you can only add a denylist, which is a
 * server-side session store with extra steps and a worse failure mode. When HR
 * deactivates someone in Okta, SCIM must make their access stop *now*, not at
 * the next refresh. That requirement decides the architecture, so the session
 * store is the architecture.
 *
 * What is genuinely verified here, and what is not:
 *
 *   - The SAML and OIDC verification paths are real protocol implementations
 *     over real cryptography, tested against assertions and tokens signed with
 *     real RSA keys and real X.509 certificates, including the signature
 *     wrapping and algorithm confusion attacks that break naive verifiers.
 *   - They have NOT been run against a live Okta, Entra or Google tenant,
 *     because this environment has no outbound network. The bytes on the wire
 *     are what those IdPs send; the tenant round trip is untested.
 */
import { createHash, createHmac, createVerify, randomBytes, timingSafeEqual, createPublicKey } from 'node:crypto';
import { parseXml, find, findAll, verifySignature, local } from './xmldsig.js';
import { now, iso, duration, MINUTE, HOUR, DAY } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

const sha256 = (v) => createHash('sha256').update(String(v)).digest('hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => Buffer.from(String(s), 'base64url');
const safeEq = (a, b) => {
  const A = Buffer.from(String(a)); const B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
};

// ---------------------------------------------------------------------------
// SAML 2.0 Service Provider
// ---------------------------------------------------------------------------

/** IdP presets. The differences that actually matter per vendor, not branding. */
export const IDP_PRESETS = {
  okta: {
    name: 'Okta',
    // Okta signs the assertion by default and can also sign the response.
    expectsSignedAssertion: true,
    attributeMap: { email: 'email', name: 'displayName', groups: 'groups', department: 'department' },
    note: 'In Okta, set the SAML app\'s Audience URI to the entityId below and Single Sign On URL to the ACS URL.'
  },
  entra: {
    name: 'Microsoft Entra ID (Azure AD)',
    expectsSignedAssertion: true,
    // Entra emits the long claim URIs rather than short names.
    attributeMap: {
      email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
      name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
      groups: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
      department: 'http://schemas.microsoft.com/identity/claims/department'
    },
    note: 'Entra sends group OBJECT IDs, not names, unless the app is configured to emit group names. Map them in groupMap.'
  },
  google: {
    name: 'Google Workspace',
    expectsSignedAssertion: true,
    attributeMap: { email: 'email', name: 'name', groups: 'groups', department: 'department' },
    note: 'Google Workspace SAML sends no groups by default; add them as custom attributes in the app profile.'
  },
  generic: { name: 'Generic SAML 2.0 IdP', expectsSignedAssertion: true, attributeMap: { email: 'email', name: 'name', groups: 'groups' }, note: null }
};

export class SamlProvider {
  /**
   * @param {object} o
   * @param {string} o.entityId our SP entity id (the audience the IdP must assert)
   * @param {string} o.acsUrl our assertion consumer service URL
   * @param {string} o.idpEntityId
   * @param {string} o.idpSsoUrl
   * @param {string[]} o.certificates IdP signing certificates (PEM or base64 DER)
   * @param {keyof IDP_PRESETS} [o.preset]
   */
  constructor({ entityId, acsUrl, idpEntityId, idpSsoUrl, certificates = [], preset = 'generic',
    attributeMap = null, groupMap = {}, clockSkewMs = 2 * MINUTE, ledger = null } = {}) {
    for (const [k, val] of Object.entries({ entityId, acsUrl, idpEntityId, idpSsoUrl })) {
      if (!val) throw new VaultError('config', `SAML needs ${k}`);
    }
    if (!certificates.length) {
      throw new VaultError('config',
        'SAML needs at least one IdP signing certificate — without one, any assertion would be accepted from anyone');
    }
    this.entityId = entityId;
    this.acsUrl = acsUrl;
    this.idpEntityId = idpEntityId;
    this.idpSsoUrl = idpSsoUrl;
    this.certificates = certificates;
    this.preset = IDP_PRESETS[preset] ?? IDP_PRESETS.generic;
    this.attributeMap = attributeMap ?? this.preset.attributeMap;
    this.groupMap = groupMap;
    this.clockSkewMs = clockSkewMs;
    this.ledger = ledger;
    /** In-flight AuthnRequests, so InResponseTo can be checked. */
    this.pending = new Map();
    /** Assertion IDs already consumed — a bearer assertion is single use. */
    this.consumed = new Map();
    this.stats = { requests: 0, accepted: 0, rejected: 0 };
  }

  /** SP metadata XML, for pasting into the IdP. */
  metadata() {
    return `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${this.entityId}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${this.acsUrl}" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`;
  }

  /** Begin login. Returns the redirect URL and the request id to correlate. */
  authnRequest({ relayState = null, at = now() } = {}) {
    const id = `_${randomBytes(16).toString('hex')}`;
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${iso(at)}" Destination="${this.idpSsoUrl}" AssertionConsumerServiceURL="${this.acsUrl}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>${this.entityId}</saml:Issuer></samlp:AuthnRequest>`;
    this.pending.set(id, { at, relayState });
    // Expire stale requests so `pending` cannot grow without bound.
    for (const [k, v] of this.pending) if (at - v.at > 10 * MINUTE) this.pending.delete(k);
    this.stats.requests++;
    const params = new URLSearchParams({ SAMLRequest: Buffer.from(xml).toString('base64') });
    if (relayState) params.set('RelayState', relayState);
    return { id, url: `${this.idpSsoUrl}?${params}`, xml };
  }

  /**
   * Consume a SAML Response at the ACS endpoint.
   *
   * Every check here exists because skipping it is a documented bypass:
   * unsigned assertions, signature wrapping, replayed bearer assertions,
   * audience confusion (an assertion minted for another SP), and expiry.
   */
  consume(base64Response, { at = now(), requireInResponseTo = true } = {}) {
    let xml;
    try {
      xml = Buffer.from(String(base64Response), 'base64').toString('utf8');
      if (!xml.includes('<')) xml = String(base64Response);
    } catch { xml = String(base64Response); }

    const doc = parseXml(xml);
    const status = find(doc, 'StatusCode')?.attrs.Value;
    if (status && !String(status).endsWith(':Success')) {
      this.stats.rejected++;
      throw forbidden(`the identity provider refused the login: ${status}`);
    }

    const assertions = findAll(doc, 'Assertion');
    if (!assertions.length) { this.stats.rejected++; throw forbidden('the response contains no assertion'); }
    if (assertions.length > 1) {
      // Multiple assertions is the shape of a wrapping attack: one signed and
      // harmless, one unsigned and attacker-controlled.
      this.stats.rejected++;
      throw forbidden('the response contains more than one assertion — refusing rather than guessing which one is authoritative');
    }
    const assertion = assertions[0];

    // The signature must cover THIS assertion. verifySignature refuses a
    // signature that lives anywhere else in the document.
    const sigResult = verifySignature({ doc, signedNode: assertion, certificates: this.certificates });

    const issuer = find(assertion, 'Issuer')?.text?.trim();
    if (issuer !== this.idpEntityId) {
      this.stats.rejected++;
      throw forbidden(`assertion issued by "${issuer}", not the configured IdP "${this.idpEntityId}"`);
    }

    const conditions = find(assertion, 'Conditions');
    const notBefore = conditions?.attrs.NotBefore ? Date.parse(conditions.attrs.NotBefore) : null;
    const notOnOrAfter = conditions?.attrs.NotOnOrAfter ? Date.parse(conditions.attrs.NotOnOrAfter) : null;
    if (notBefore !== null && at + this.clockSkewMs < notBefore) {
      this.stats.rejected++;
      throw forbidden('the assertion is not valid yet', { notBefore: iso(notBefore) });
    }
    if (notOnOrAfter !== null && at - this.clockSkewMs >= notOnOrAfter) {
      this.stats.rejected++;
      throw forbidden('the assertion has expired', { notOnOrAfter: iso(notOnOrAfter) });
    }

    // Audience: an assertion minted for a different SP must not work here, even
    // though it is perfectly validly signed by the same IdP.
    const audiences = findAll(assertion, 'Audience').map((a) => a.text.trim());
    if (audiences.length && !audiences.includes(this.entityId)) {
      this.stats.rejected++;
      throw forbidden(`the assertion is addressed to ${audiences.join(', ')}, not to ${this.entityId}`);
    }

    const confirmation = find(assertion, 'SubjectConfirmationData');
    const inResponseTo = confirmation?.attrs.InResponseTo ?? doc.attrs.InResponseTo;
    if (requireInResponseTo) {
      if (!inResponseTo || !this.pending.has(inResponseTo)) {
        this.stats.rejected++;
        throw forbidden('this response does not answer a login this service started — unsolicited assertions are refused');
      }
      this.pending.delete(inResponseTo);
    }
    const recipient = confirmation?.attrs.Recipient;
    if (recipient && recipient !== this.acsUrl) {
      this.stats.rejected++;
      throw forbidden(`the assertion names a different recipient (${recipient})`);
    }

    // Single use. A bearer assertion replayed is a stolen session.
    const assertionId = assertion.attrs.ID;
    for (const [k, t] of this.consumed) if (at - t > 12 * HOUR) this.consumed.delete(k);
    if (this.consumed.has(assertionId)) {
      this.stats.rejected++;
      throw forbidden('this assertion has already been used', { assertionId });
    }
    this.consumed.set(assertionId, at);

    const attrs = {};
    for (const a of findAll(assertion, 'Attribute')) {
      const key = a.attrs.Name ?? a.attrs.FriendlyName;
      const values = a.children.filter((c) => local(c.name) === 'AttributeValue').map((c) => c.text.trim());
      if (key) attrs[key] = values;
    }
    const pick = (field) => {
      const source = this.attributeMap[field];
      const v = source ? attrs[source] : undefined;
      return Array.isArray(v) ? v : (v == null ? [] : [v]);
    };

    const nameId = find(assertion, 'NameID')?.text?.trim();
    const email = pick('email')[0] ?? nameId;
    const groups = pick('groups').map((g) => this.groupMap[g] ?? g);

    this.stats.accepted++;
    this.ledger?.append('admin.action', {
      subject: email, actor: email, action: 'auth.saml_accepted', issuer, assertionId
    });

    return {
      subject: nameId ?? email,
      email,
      name: pick('name')[0] ?? null,
      department: pick('department')[0] ?? null,
      groups,
      attributes: attrs,
      issuer,
      assertionId,
      signedBy: sigResult.certificate,
      algorithm: sigResult.algorithm,
      notOnOrAfter: notOnOrAfter ? iso(notOnOrAfter) : null
    };
  }
}

// ---------------------------------------------------------------------------
// OIDC Relying Party
// ---------------------------------------------------------------------------

export class OidcProvider {
  /**
   * @param {object} o
   * @param {string} o.issuer expected `iss`
   * @param {string} o.clientId expected `aud`
   * @param {string} o.authorizationEndpoint
   * @param {string} o.tokenEndpoint
   * @param {Array<object>} o.jwks the IdP's public keys (JWKS `keys` array)
   */
  constructor({ issuer, clientId, clientSecret = null, authorizationEndpoint, tokenEndpoint,
    jwks = [], redirectUri, clockSkewMs = 2 * MINUTE, ledger = null } = {}) {
    for (const [k, val] of Object.entries({ issuer, clientId, authorizationEndpoint, tokenEndpoint, redirectUri })) {
      if (!val) throw new VaultError('config', `OIDC needs ${k}`);
    }
    if (!jwks.length) throw new VaultError('config', 'OIDC needs the IdP\'s JWKS — without it any token would be accepted');
    this.issuer = issuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.authorizationEndpoint = authorizationEndpoint;
    this.tokenEndpoint = tokenEndpoint;
    this.jwks = jwks;
    this.redirectUri = redirectUri;
    this.clockSkewMs = clockSkewMs;
    this.ledger = ledger;
    this.pending = new Map();
    this.consumed = new Map();
  }

  /**
   * Start the authorization-code flow with PKCE.
   *
   * PKCE is not optional here even though this is a confidential client: it
   * costs nothing and removes the entire class of authorization-code
   * interception.
   */
  authorizationUrl({ scope = 'openid email profile', at = now() } = {}) {
    const state = randomBytes(24).toString('base64url');
    const nonce = randomBytes(24).toString('base64url');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    this.pending.set(state, { nonce, verifier, at });
    for (const [k, v] of this.pending) if (at - v.at > 10 * MINUTE) this.pending.delete(k);
    const params = new URLSearchParams({
      response_type: 'code', client_id: this.clientId, redirect_uri: this.redirectUri,
      scope, state, nonce, code_challenge: challenge, code_challenge_method: 'S256'
    });
    return { url: `${this.authorizationEndpoint}?${params}`, state, nonce, codeVerifier: verifier };
  }

  /**
   * Verify an ID token.
   *
   * The two attacks this must survive are algorithm confusion (`alg: none`, or
   * an RS256 key fed to HS256 so the public certificate becomes the HMAC
   * secret) and kid confusion. Both are handled by never taking the algorithm
   * from the token alone.
   */
  verifyIdToken(idToken, { nonce = null, at = now() } = {}) {
    const parts = String(idToken).split('.');
    if (parts.length !== 3) throw forbidden('malformed ID token');
    const [h, p, s] = parts;

    let header; let payload;
    try {
      header = JSON.parse(unb64u(h).toString('utf8'));
      payload = JSON.parse(unb64u(p).toString('utf8'));
    } catch { throw forbidden('ID token header or payload is not JSON'); }

    if (!header.alg || header.alg === 'none') {
      throw forbidden('ID token declares alg "none" — refused');
    }
    if (header.alg.startsWith('HS')) {
      // An RS256 IdP that suddenly sends HS256 is the classic confusion attack:
      // the attacker signs with the public key, which the verifier has.
      throw forbidden(`ID token uses symmetric ${header.alg}; this relying party only accepts asymmetric signatures from the JWKS`);
    }

    const candidates = this.jwks.filter((k) => (!header.kid || k.kid === header.kid) && (!k.alg || k.alg === header.alg));
    if (!candidates.length) throw forbidden('no key in the configured JWKS matches this token', { kid: header.kid });

    const algMap = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512', ES256: 'sha256', PS256: 'RSA-SHA256' };
    const nodeAlg = algMap[header.alg];
    if (!nodeAlg) throw forbidden(`unsupported ID token algorithm ${header.alg}`);

    let verified = false;
    for (const jwk of candidates) {
      try {
        const key = createPublicKey({ key: jwk, format: 'jwk' });
        const v = createVerify(nodeAlg);
        v.update(`${h}.${p}`);
        v.end();
        const opts = header.alg.startsWith('PS') ? { key, padding: 1, saltLength: 32 } : key;
        if (v.verify(opts, unb64u(s))) { verified = true; break; }
      } catch { /* next key */ }
    }
    if (!verified) throw forbidden('the ID token signature does not verify against the IdP\'s keys');

    if (payload.iss !== this.issuer) throw forbidden(`ID token issued by ${payload.iss}, expected ${this.issuer}`);
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(this.clientId)) throw forbidden(`ID token is for ${aud.join(', ')}, not ${this.clientId}`);
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== this.clientId) {
      throw forbidden('multi-audience token without a matching azp');
    }
    if (payload.exp != null && at - this.clockSkewMs >= payload.exp * 1000) throw forbidden('the ID token has expired');
    if (payload.nbf != null && at + this.clockSkewMs < payload.nbf * 1000) throw forbidden('the ID token is not valid yet');
    if (nonce != null && payload.nonce !== nonce) throw forbidden('ID token nonce does not match the login that started this');

    // Replay: a token is consumed once.
    const jti = payload.jti ?? `${payload.sub}|${payload.iat}|${payload.nonce ?? ''}`;
    for (const [k, t] of this.consumed) if (at - t > 12 * HOUR) this.consumed.delete(k);
    if (this.consumed.has(jti)) throw forbidden('this ID token has already been used');
    this.consumed.set(jti, at);

    this.ledger?.append('admin.action', { subject: payload.email ?? payload.sub, actor: payload.email ?? payload.sub, action: 'auth.oidc_accepted', issuer: payload.iss });

    return {
      subject: payload.sub,
      email: payload.email ?? null,
      emailVerified: payload.email_verified ?? null,
      name: payload.name ?? null,
      groups: payload.groups ?? payload.roles ?? [],
      amr: payload.amr ?? [],
      acr: payload.acr ?? null,
      claims: payload,
      algorithm: header.alg
    };
  }

  /**
   * The raw token request.
   *
   * Split out as its own method because it is the single point where this class
   * touches the network. Replacing it in a test leaves everything that matters
   * — state lookup, PKCE verifier, nonce binding, JWKS signature verification —
   * running for real, so what is stubbed is the socket and nothing else.
   */
  async exchange(params, { fetchImpl = globalThis.fetch } = {}) {
    const res = await fetchImpl(this.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(params).toString()
    });
    if (!res.ok) throw forbidden(`token endpoint returned ${res.status}`);
    return res.json();
  }

  /** Exchange a code for tokens, then verify the ID token that comes back. */
  async exchangeCode(code, { state, fetchImpl = globalThis.fetch, at = now() } = {}) {
    const pending = this.pending.get(state);
    if (!pending) throw forbidden('unknown or expired state — this callback does not answer a login this service started');
    // Consumed before the network call, so a replayed callback cannot race a
    // slow token endpoint into a second session.
    this.pending.delete(state);
    const tokens = await this.exchange({
      grant_type: 'authorization_code', code, redirect_uri: this.redirectUri,
      client_id: this.clientId, code_verifier: pending.verifier,
      ...(this.clientSecret ? { client_secret: this.clientSecret } : {})
    }, { fetchImpl });
    if (!tokens?.id_token) throw forbidden('token response carried no id_token');
    return { tokens, identity: this.verifyIdToken(tokens.id_token, { nonce: pending.nonce, at }) };
  }
}

// ---------------------------------------------------------------------------
// Sessions — server-side, so revocation is immediate
// ---------------------------------------------------------------------------

export const AMR_STRONG = ['hwk', 'fido', 'webauthn', 'pkey', 'swk', 'mfa', 'otp', 'sms', 'tel'];
/** Phishing-resistant factors. TOTP and SMS are MFA but are not this. */
export const AMR_PHISHING_RESISTANT = ['hwk', 'fido', 'webauthn', 'pkey'];

export class SessionStore {
  /**
   * @param {object} o
   * @param {number} [o.idleTimeoutMs]
   * @param {number} [o.absoluteTimeoutMs]
   * @param {number} [o.maxConcurrent] per principal; 0 = unlimited
   */
  constructor({ collection = null, ledger = null, idleTimeoutMs = 30 * MINUTE,
    absoluteTimeoutMs = 12 * HOUR, maxConcurrent = 5, bindToDevice = true, bindToIp = false } = {}) {
    this.col = collection;
    this.ledger = ledger;
    this.idleTimeoutMs = idleTimeoutMs;
    this.absoluteTimeoutMs = absoluteTimeoutMs;
    this.maxConcurrent = maxConcurrent;
    this.bindToDevice = bindToDevice;
    this.bindToIp = bindToIp;
    /** token hash → session. The token itself is never stored. */
    this.sessions = new Map();
    if (collection) for (const s of collection.all()) this.sessions.set(s.id, s);
  }

  static hash(token) { return createHash('sha256').update(String(token)).digest('hex'); }

  /**
   * @returns {{token:string, session:object}} the token is returned once
   */
  create({ principal, amr = [], ip = null, deviceId = null, userAgent = null, at = now(), idp = null }) {
    if (!principal?.name) throw new VaultError('invalid', 'a session needs a named principal');
    const token = `vsx_${randomBytes(32).toString('base64url')}`;
    const id = SessionStore.hash(token);
    const session = {
      id,
      principal: { ...principal },
      createdAt: at,
      lastSeenAt: at,
      expiresAt: at + this.absoluteTimeoutMs,
      amr,
      // Recorded at creation and checked on every use: a session minted from a
      // phishing-resistant factor should not silently become a weak one.
      phishingResistant: amr.some((a) => AMR_PHISHING_RESISTANT.includes(String(a).toLowerCase())),
      mfa: amr.some((a) => AMR_STRONG.includes(String(a).toLowerCase())),
      ip, deviceId, userAgent, idp,
      revoked: null
    };

    // Concurrency: oldest goes, and it is logged. Silently dropping the newest
    // would leave someone locked out with no explanation.
    if (this.maxConcurrent > 0) {
      const live = this.forPrincipal(principal.name, { at });
      if (live.length >= this.maxConcurrent) {
        const oldest = live.sort((a, b) => a.lastSeenAt - b.lastSeenAt)[0];
        this.revoke(oldest.id, { actor: 'system', reason: `concurrent session limit (${this.maxConcurrent}) reached`, at });
      }
    }

    this.sessions.set(id, session);
    this.col?.insert({ ...session });
    this.ledger?.append('admin.action', {
      subject: principal.name, actor: principal.name, action: 'session.created',
      idp, mfa: session.mfa, phishingResistant: session.phishingResistant
    });
    return { token, session: this._present(session) };
  }

  /**
   * Resolve a token to a principal, or explain precisely why not.
   *
   * Every rejection reason is distinct, because "session expired" and "your
   * account was deactivated" need different responses from the person reading
   * them, and collapsing them into "unauthorized" is how support tickets are
   * born.
   */
  verify(token, { ip = null, deviceId = null, at = now() } = {}) {
    const session = this.sessions.get(SessionStore.hash(token ?? ''));
    if (!session) return { valid: false, reason: 'unknown session' };
    if (session.revoked) return { valid: false, reason: session.revoked.reason, revokedAt: iso(session.revoked.at) };
    if (at >= session.expiresAt) return { valid: false, reason: 'session reached its maximum lifetime' };
    if (at - session.lastSeenAt > this.idleTimeoutMs) {
      return { valid: false, reason: `idle for longer than ${Math.round(this.idleTimeoutMs / MINUTE)} minutes` };
    }
    if (this.bindToDevice && session.deviceId && deviceId && session.deviceId !== deviceId) {
      // A session token presented from a different device is a stolen token
      // until proven otherwise, so it is killed rather than merely refused.
      this.revoke(session.id, { actor: 'system', reason: 'presented from a different device', at });
      return { valid: false, reason: 'this session was bound to another device and has been revoked' };
    }
    if (this.bindToIp && session.ip && ip && session.ip !== ip) {
      return { valid: false, reason: 'this session is bound to a different address' };
    }
    session.lastSeenAt = at;
    this.col?.update?.(session.id, { lastSeenAt: at });
    return { valid: true, principal: session.principal, session: this._present(session) };
  }

  forPrincipal(name, { at = now() } = {}) {
    return [...this.sessions.values()].filter((s) => s.principal.name === name && !s.revoked && at < s.expiresAt);
  }

  revoke(id, { actor, reason, at = now() }) {
    const session = this.sessions.get(id);
    if (!session || session.revoked) return null;
    session.revoked = { at, actor, reason };
    this.col?.update?.(id, { revoked: session.revoked });
    this.ledger?.append('admin.action', { subject: session.principal.name, actor, action: 'session.revoked', reason });
    return this._present(session);
  }

  /**
   * Kill every session for a principal, now.
   *
   * This is the method SCIM deprovisioning calls, and the reason sessions are
   * server-side at all. With self-describing tokens the honest answer to "is
   * their access revoked?" would be "within fifteen minutes".
   */
  revokeAllFor(name, { actor, reason, at = now() }) {
    const killed = [];
    for (const s of this.sessions.values()) {
      if (s.principal.name !== name || s.revoked) continue;
      s.revoked = { at, actor, reason };
      this.col?.update?.(s.id, { revoked: s.revoked });
      killed.push(s.id);
    }
    if (killed.length) {
      this.ledger?.append('admin.action', { subject: name, actor, action: 'session.revoked_all', reason, count: killed.length });
    }
    return { principal: name, revoked: killed.length, at: iso(at) };
  }

  active({ at = now() } = {}) {
    return [...this.sessions.values()].filter((s) => !s.revoked && at < s.expiresAt).map((s) => this._present(s));
  }

  _present(s) {
    return {
      id: s.id, principal: s.principal, createdAt: iso(s.createdAt), lastSeenAt: iso(s.lastSeenAt),
      expiresAt: iso(s.expiresAt), amr: s.amr, mfa: s.mfa, phishingResistant: s.phishingResistant,
      ip: s.ip, deviceId: s.deviceId, idp: s.idp,
      revoked: s.revoked ? { at: iso(s.revoked.at), reason: s.revoked.reason, actor: s.revoked.actor } : null
    };
  }
}

// ---------------------------------------------------------------------------
// Access conditions: MFA, IP, geo, device
// ---------------------------------------------------------------------------

export class AccessPolicy {
  /**
   * @param {object} o
   * @param {boolean} [o.requireMfa]
   * @param {string[]} [o.phishingResistantRoles] roles that need FIDO2/passkey, not TOTP
   * @param {string[]} [o.ipAllowlist] CIDRs
   * @param {string[]} [o.allowedCountries] ISO-3166 alpha-2
   * @param {string[]} [o.blockedCountries]
   */
  constructor({ requireMfa = false, phishingResistantRoles = ['admin', 'security', 'legal'],
    ipAllowlist = [], allowedCountries = [], blockedCountries = [], requireKnownDevice = false,
    geoLookup = null, ledger = null, collection = null } = {}) {
    this.requireMfa = requireMfa;
    this.phishingResistantRoles = phishingResistantRoles;
    this.ipAllowlist = ipAllowlist.map(parseCidr);
    this.allowedCountries = allowedCountries.map((c) => c.toUpperCase());
    this.blockedCountries = blockedCountries.map((c) => c.toUpperCase());
    this.requireKnownDevice = requireKnownDevice;
    this.geoLookup = geoLookup;
    this.ledger = ledger;
    this.col = collection;
    this.knownDevices = new Map();
    /**
     * Device bindings were in-memory only, so a restart forgot every device.
     * With `requireKnownDevice` on that locks the whole estate out until each
     * person re-registers; the failure is loud but total, and it happens on
     * an ordinary deploy rather than an incident.
     */
    for (const rec of this.col?.all() ?? []) {
      this.knownDevices.set(`${rec.principal}|${rec.deviceId}`, rec);
    }
  }

  registerDevice(principal, deviceId, { actor, at = now() } = {}) {
    const key = `${principal}|${deviceId}`;
    const record = { principal, deviceId, registeredAt: at, actor: actor ?? principal };
    this.knownDevices.set(key, record);
    this.col?.put({ id: `dev-${sha256(key).slice(0, 24)}`, ...record });
    this.ledger?.append('admin.action', { subject: principal, actor: actor ?? principal, action: 'device.registered', deviceId });
    return { principal, deviceId, registeredAt: iso(at) };
  }

  /**
   * @returns {{allowed:boolean, reasons:string[], checks:object[]}}
   */
  evaluate({ principal, session, ip = null, deviceId = null, country = null }) {
    const checks = [];
    const reasons = [];
    const fail = (name, why) => { checks.push({ check: name, result: 'fail', why }); reasons.push(why); };
    const pass = (name, detail) => checks.push({ check: name, result: 'pass', detail });

    if (this.requireMfa) {
      if (session?.mfa) pass('mfa', `authenticated with ${session.amr.join(', ')}`);
      else fail('mfa', 'multi-factor authentication is required and this session used a single factor');
    }
    const role = principal?.role;
    if (role && this.phishingResistantRoles.includes(role)) {
      if (session?.phishingResistant) pass('phishing_resistant', `${role} authenticated with a phishing-resistant factor`);
      else {
        fail('phishing_resistant',
          `the ${role} role requires a phishing-resistant factor (FIDO2 or passkey); TOTP and SMS do not qualify`);
      }
    }

    if (this.ipAllowlist.length) {
      if (!ip) fail('ip_allowlist', 'an address allowlist is configured and this request presented no address');
      else if (this.ipAllowlist.some((c) => inCidr(ip, c))) pass('ip_allowlist', ip);
      else fail('ip_allowlist', `${ip} is not in the allowlist`);
    }

    const resolved = country ?? (this.geoLookup ? this.geoLookup(ip) : null);
    if (this.blockedCountries.length || this.allowedCountries.length) {
      if (!resolved) {
        // Geo-fencing that fails open is decoration. An address that cannot be
        // located, when a fence is configured, is refused.
        fail('geo_fence', 'a geographic restriction is configured and this address could not be located');
      } else if (this.blockedCountries.includes(resolved)) {
        fail('geo_fence', `access from ${resolved} is blocked`);
      } else if (this.allowedCountries.length && !this.allowedCountries.includes(resolved)) {
        fail('geo_fence', `access is restricted to ${this.allowedCountries.join(', ')}; this request came from ${resolved}`);
      } else pass('geo_fence', resolved);
    }

    if (this.requireKnownDevice) {
      if (!deviceId) fail('known_device', 'device registration is required and no device was identified');
      else if (this.knownDevices.has(`${principal?.name}|${deviceId}`)) pass('known_device', deviceId);
      else fail('known_device', `device ${deviceId} is not registered to ${principal?.name}`);
    }

    return { allowed: reasons.length === 0, reasons, checks };
  }
}

function parseCidr(cidr) {
  const [addr, bitsRaw] = String(cidr).split('/');
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const parts = addr.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255) || bits < 0 || bits > 32) {
    throw new VaultError('config', `"${cidr}" is not a valid IPv4 CIDR`);
  }
  const base = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask };
}

function inCidr(ip, { base, mask }) {
  const parts = String(ip).split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return false;
  const n = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  return ((n & mask) >>> 0) === base;
}

// ---------------------------------------------------------------------------
// MFA enrolment: TOTP and WebAuthn/FIDO2
// ---------------------------------------------------------------------------

export class MfaRegistry {
  /**
   * @param {object} [o]
   * @param {import('../storage/db.js').Collection|null} [o.collection] durable store
   */
  constructor({ ledger = null, collection = null } = {}) {
    this.ledger = ledger;
    this.col = collection;
    /** principal → factors. The working index; the collection is the truth. */
    this.factors = new Map();
    this.usedTotp = new Map();
    /**
     * Enrolments used to live in this Map and nowhere else, so every restart
     * silently unenrolled every user. With `requireMfa` on that is a
     * company-wide lockout; with it off it is worse, because the second factor
     * quietly stops existing and nothing says so. Passkeys went the same way,
     * which would have meant re-registering every hardware key after a deploy.
     *
     * The collection is sealed by default like every other, so the TOTP shared
     * secrets are ciphertext at rest rather than a file of seeds.
     */
    for (const rec of this.col?.all() ?? []) {
      this.factors.set(rec.principal, rec.factors ?? []);
    }
  }

  _persist(principal) {
    if (!this.col) return;
    const id = `mfa-${sha256(principal).slice(0, 24)}`;
    this.col.put({ id, principal, factors: this.factors.get(principal) ?? [] });
  }

  enrolTotp(principal, { actor, secret = null, at = now() } = {}) {
    const key = secret ?? base32(randomBytes(20));
    const list = this.factors.get(principal) ?? [];
    list.push({ kind: 'totp', secret: key, enrolledAt: at, amr: 'otp', phishingResistant: false });
    this.factors.set(principal, list);
    this._persist(principal);
    this.ledger?.append('admin.action', { subject: principal, actor: actor ?? principal, action: 'mfa.enrolled', kind: 'totp' });
    return {
      kind: 'totp', secret: key,
      uri: `otpauth://totp/Vault:${encodeURIComponent(principal)}?secret=${key}&issuer=Vault&algorithm=SHA1&digits=6&period=30`,
      warning: 'TOTP is multi-factor but is not phishing-resistant — a convincing proxy page collects the code and uses it. Roles handling content should use a passkey.'
    };
  }

  /**
   * Enrol a WebAuthn/FIDO2 credential.
   *
   * The registration ceremony (attestation parsing) happens at the browser
   * boundary; what is stored is the credential id and its public key, which is
   * what assertions are later verified against.
   */
  enrolWebauthn(principal, { credentialId, publicKeyJwk, actor, transports = [], at = now() }) {
    if (!credentialId || !publicKeyJwk) throw new VaultError('invalid', 'a WebAuthn factor needs a credential id and a public key');
    const list = this.factors.get(principal) ?? [];
    list.push({
      kind: 'webauthn', credentialId, publicKeyJwk, transports, signCount: 0, enrolledAt: at,
      amr: 'hwk', phishingResistant: true
    });
    this.factors.set(principal, list);
    this._persist(principal);
    this.ledger?.append('admin.action', { subject: principal, actor: actor ?? principal, action: 'mfa.enrolled', kind: 'webauthn' });
    return { kind: 'webauthn', credentialId, phishingResistant: true };
  }

  /** RFC 6238, with the replay window a real implementation needs. */
  verifyTotp(principal, code, { at = now(), window = 1 } = {}) {
    const factor = (this.factors.get(principal) ?? []).find((f) => f.kind === 'totp');
    if (!factor) return { ok: false, reason: 'no TOTP factor enrolled' };
    const step = Math.floor(at / 30000);
    for (let i = -window; i <= window; i++) {
      if (safeEq(totp(factor.secret, step + i), String(code))) {
        // A TOTP code is valid for 30 seconds, which is 30 seconds in which a
        // captured code can be replayed. Consuming it closes that window.
        const used = this.usedTotp.get(principal) ?? new Set();
        if (used.has(step + i)) return { ok: false, reason: 'this code has already been used' };
        used.add(step + i);
        this.usedTotp.set(principal, used);
        return { ok: true, amr: ['otp'], phishingResistant: false };
      }
    }
    return { ok: false, reason: 'incorrect code' };
  }

  /**
   * Verify a WebAuthn assertion.
   *
   * The origin and challenge bindings are the reason passkeys are
   * phishing-resistant: a proxy on a different origin produces clientData the
   * authenticator signed for THAT origin, and it will not match.
   */
  verifyWebauthn(principal, { credentialId, clientDataJSON, authenticatorData, signature, expectedChallenge, expectedOrigin, expectedRpId }) {
    const factor = (this.factors.get(principal) ?? []).find((f) => f.kind === 'webauthn' && f.credentialId === credentialId);
    if (!factor) return { ok: false, reason: 'no such credential for this principal' };

    let clientData;
    try { clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8')); }
    catch { return { ok: false, reason: 'clientDataJSON is not JSON' }; }

    if (clientData.type !== 'webauthn.get') return { ok: false, reason: `wrong ceremony type ${clientData.type}` };
    if (!safeEq(clientData.challenge, expectedChallenge)) return { ok: false, reason: 'challenge does not match' };
    if (expectedOrigin && clientData.origin !== expectedOrigin) {
      return { ok: false, reason: `assertion was produced for ${clientData.origin}, not ${expectedOrigin} — this is what stops a phishing proxy` };
    }

    const authData = Buffer.from(authenticatorData, 'base64url');
    if (authData.length < 37) return { ok: false, reason: 'authenticatorData too short' };
    const rpIdHash = authData.subarray(0, 32);
    if (expectedRpId && !rpIdHash.equals(createHash('sha256').update(expectedRpId).digest())) {
      return { ok: false, reason: 'relying party id hash does not match' };
    }
    const flags = authData[32];
    if (!(flags & 0x01)) return { ok: false, reason: 'user presence flag not set' };
    const signCount = authData.readUInt32BE(33);
    if (signCount !== 0 && signCount <= factor.signCount) {
      // A counter that does not advance means the credential was cloned.
      return { ok: false, reason: 'signature counter did not advance — the authenticator may have been cloned' };
    }

    const signedData = Buffer.concat([authData, createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest()]);
    try {
      const key = createPublicKey({ key: factor.publicKeyJwk, format: 'jwk' });
      const v = createVerify(factor.publicKeyJwk.kty === 'EC' ? 'sha256' : 'RSA-SHA256');
      v.update(signedData);
      v.end();
      if (!v.verify(key, Buffer.from(signature, 'base64url'))) return { ok: false, reason: 'signature does not verify' };
    } catch (e) { return { ok: false, reason: `signature check failed: ${e.message}` }; }

    factor.signCount = signCount;
    return { ok: true, amr: ['hwk', 'mfa'], phishingResistant: true };
  }

  factorsFor(principal) {
    return (this.factors.get(principal) ?? []).map((f) => ({
      kind: f.kind, enrolledAt: iso(f.enrolledAt), phishingResistant: f.phishingResistant,
      credentialId: f.credentialId ?? undefined
    }));
  }

  /** Does this principal hold a factor that survives a phishing proxy? */
  hasPhishingResistant(principal) {
    return (this.factors.get(principal) ?? []).some((f) => f.phishingResistant);
  }
}

function totp(secret, step) {
  const key = unbase32(secret);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(step / 2 ** 32), 0);
  buf.writeUInt32BE(step >>> 0, 4);
  const h = createHmac('sha1', key).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) {
  let bits = 0; let value = 0; let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function unbase32(s) {
  let bits = 0; let value = 0; const out = [];
  for (const c of String(s).toUpperCase().replace(/=+$/, '')) {
    const idx = B32.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

export { duration, DAY };
