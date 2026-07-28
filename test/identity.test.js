/**
 * Enterprise identity (§22) — attacked, not merely exercised.
 *
 * Everything here runs against real cryptography: real RSA keys, real X.509
 * certificates, real RSA-SHA256 signatures over really-canonicalised XML, real
 * JWTs. The assertions and tokens are generated the way Okta and Entra generate
 * them, so the verification code under test is the code that would run against
 * a live tenant.
 *
 * What that does NOT establish: this has never been pointed at a live Okta,
 * Entra or Google tenant, because the environment has no outbound network. The
 * bytes are right; the tenant round trip is untested. That limitation is stated
 * here rather than in a footnote because it is the difference between "the
 * protocol is implemented correctly" and "it works with your IdP".
 *
 * The tests that matter most are the ones that try to get in: signature
 * wrapping, unsigned assertions, audience confusion, replay, `alg: none`,
 * RS256→HS256 confusion, and a session that outlives its own deprovisioning.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, createSign, createHmac, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { SamlProvider, OidcProvider, SessionStore, AccessPolicy, MfaRegistry } from '../src/identity/identity.js';
import { ScimService } from '../src/identity/scim.js';
import { PrivilegedAccess } from '../src/identity/privileged.js';
import { parseXml, c14n, find } from '../src/identity/xmldsig.js';
import { MINUTE, HOUR, setClock } from '../src/util/time.js';

// ---------------------------------------------------------------------------
// A real IdP, in the only sense available offline: real keys, real signatures.
// ---------------------------------------------------------------------------
const IDP = (() => {
  const dir = mkdtempSync(join(tmpdir(), 'vault-idp-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', join(dir, 'k.pem'),
    '-out', join(dir, 'c.pem'), '-days', '365', '-nodes', '-subj', '/CN=idp.test'], { stdio: 'ignore' });
  const key = readFileSync(join(dir, 'k.pem'), 'utf8');
  const certPem = readFileSync(join(dir, 'c.pem'), 'utf8');
  rmSync(dir, { recursive: true, force: true });
  return { key, certPem, certB64: certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') };
})();

const SP = {
  entityId: 'https://vault.acme.internal',
  acsUrl: 'https://vault.acme.internal/api/auth/saml/acs',
  idpEntityId: 'http://idp.test',
  idpSsoUrl: 'https://idp.test/sso'
};

/**
 * Build a genuinely signed SAML Response, exactly as an IdP does: canonicalise,
 * digest, sign the SignedInfo with RSA-SHA256.
 */
function signedResponse({
  nameId = 'dana@acme.com', audience = SP.entityId, inResponseTo = '_req1',
  notBefore = '2026-07-28T09:59:00Z', notOnOrAfter = '2026-07-28T10:05:00Z',
  assertionId = '_a1', recipient = SP.acsUrl, issuer = SP.idpEntityId,
  groups = ['vault-security'], signIt = true, key = IDP.key, cert = IDP.certB64
} = {}) {
  const groupValues = groups.map((g) => `<saml:AttributeValue>${g}</saml:AttributeValue>`).join('');
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="2026-07-28T10:00:00Z" Version="2.0"><saml:Issuer>${issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${recipient}" InResponseTo="${inResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${nameId}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups">${groupValues}</saml:Attribute></saml:AttributeStatement></saml:Assertion>`;

  let body = assertion;
  if (signIt) {
    const digest = createHash('sha256').update(c14n(parseXml(assertion), {}), 'utf8').digest('base64');
    const signedInfo = `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#${assertionId}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
    const sig = createSign('sha256').update(c14n(parseXml(signedInfo), {}), 'utf8').sign(key, 'base64');
    const signature = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${signedInfo}<ds:SignatureValue>${sig}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`;
    body = assertion.replace('</saml:Issuer>', `</saml:Issuer>${signature}`);
  }
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" InResponseTo="${inResponseTo}" Destination="${SP.acsUrl}" Version="2.0" IssueInstant="2026-07-28T10:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>${body}</samlp:Response>`;
  return { xml, b64: Buffer.from(xml).toString('base64'), assertion: body };
}

const AT = Date.parse('2026-07-28T10:01:00Z');
function sp(extra = {}) {
  const provider = new SamlProvider({ ...SP, certificates: [IDP.certB64], preset: 'okta', ...extra });
  provider.pending.set('_req1', { at: AT, relayState: null });
  return provider;
}

describe('SAML — a real signed assertion, and the attacks that break naive verifiers', () => {
  test('a genuinely signed assertion is accepted and its attributes extracted', () => {
    const { b64 } = signedResponse();
    const out = sp().consume(b64, { at: AT });
    assert.equal(out.email, 'dana@acme.com');
    assert.deepEqual(out.groups, ['vault-security']);
    assert.equal(out.algorithm, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    assert.ok(out.signedBy, 'the fingerprint of the certificate that verified must be recorded');
  });

  test('altering one character of the assertion invalidates it', () => {
    const { xml } = signedResponse();
    const tampered = Buffer.from(xml.replace('dana@acme.com', 'root@acme.com')).toString('base64');
    assert.throws(() => sp().consume(tampered, { at: AT }), /does not match its own digest/);
  });

  test('an UNSIGNED assertion is refused — this is the whole point of the protocol', () => {
    const { b64 } = signedResponse({ signIt: false });
    assert.throws(() => sp().consume(b64, { at: AT }), /not itself signed/);
  });

  test('signature wrapping: a signed assertion smuggling an unsigned one is refused', () => {
    // XSW — the classic SAML bypass. Take a legitimately signed assertion and
    // add a second, unsigned, attacker-controlled one. A verifier that checks
    // "is there a valid signature in this document?" and then reads the first
    // assertion it finds is fully compromised by this.
    const legit = signedResponse({ nameId: 'nobody@acme.com', assertionId: '_a1' });
    const evil = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil" IssueInstant="2026-07-28T10:00:00Z" Version="2.0"><saml:Issuer>${SP.idpEntityId}</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion>`;
    const wrapped = legit.xml.replace('</samlp:Response>', `${evil}</samlp:Response>`);
    assert.throws(() => sp().consume(Buffer.from(wrapped).toString('base64'), { at: AT }),
      /more than one assertion/,
      'a document with two assertions must be refused, not resolved by picking one');
  });

  test('an assertion signed by a DIFFERENT key is refused', () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { b64 } = signedResponse({ key: other.privateKey.export({ type: 'pkcs1', format: 'pem' }) });
    assert.throws(() => sp().consume(b64, { at: AT }), /no configured IdP certificate verifies/);
  });

  test('an assertion minted for another service provider is refused', () => {
    // Perfectly valid, correctly signed by the same IdP — for someone else.
    const { b64 } = signedResponse({ audience: 'https://someone-elses-app.example.com' });
    assert.throws(() => sp().consume(b64, { at: AT }), /addressed to https:\/\/someone-elses-app/);
  });

  test('an expired assertion is refused, and so is one from the future', () => {
    const { b64 } = signedResponse();
    assert.throws(() => sp().consume(b64, { at: Date.parse('2026-07-28T11:00:00Z') }), /expired/);
    assert.throws(() => sp().consume(b64, { at: Date.parse('2026-07-28T09:00:00Z') }), /not valid yet/);
  });

  test('a replayed assertion is refused the second time', () => {
    const provider = sp();
    const { b64 } = signedResponse();
    provider.consume(b64, { at: AT });
    provider.pending.set('_req1', { at: AT });   // pretend a fresh login started
    assert.throws(() => provider.consume(b64, { at: AT }), /already been used/);
  });

  test('an unsolicited assertion is refused', () => {
    const provider = new SamlProvider({ ...SP, certificates: [IDP.certB64] });
    const { b64 } = signedResponse();
    assert.throws(() => provider.consume(b64, { at: AT }), /does not answer a login this service started/);
  });

  test('an assertion for the wrong ACS URL is refused', () => {
    const { b64 } = signedResponse({ recipient: 'https://evil.example.com/acs' });
    assert.throws(() => sp().consume(b64, { at: AT }), /different recipient/);
  });

  test('a provider with no certificate refuses to exist', () => {
    assert.throws(() => new SamlProvider({ ...SP, certificates: [] }),
      /any assertion would be accepted from anyone/);
  });

  test('the IdP presets differ where the vendors actually differ', () => {
    // Entra sends long claim URIs; Okta sends short names. A single hardcoded
    // map would silently produce users with no email on one of them.
    const entra = new SamlProvider({ ...SP, certificates: [IDP.certB64], preset: 'entra' });
    assert.match(entra.attributeMap.email, /schemas\.xmlsoap\.org/);
    const okta = new SamlProvider({ ...SP, certificates: [IDP.certB64], preset: 'okta' });
    assert.equal(okta.attributeMap.email, 'email');
    assert.match(entra.preset.note, /group OBJECT IDs/);
  });

  test('SP metadata is well-formed XML naming this SP\'s real endpoints', () => {
    const xml = sp().metadata();
    const doc = parseXml(xml.replace(/<\?xml[^>]*\?>/, ''));
    assert.equal(doc.attrs.entityID, SP.entityId);
    assert.equal(find(doc, 'AssertionConsumerService').attrs.Location, SP.acsUrl);
    assert.equal(doc.children.find((c) => c.name === 'SPSSODescriptor').attrs.WantAssertionsSigned, 'true');
  });

  test('SHA-1 signatures are refused outright', () => {
    const { xml } = signedResponse();
    const downgraded = xml.replace(
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    );
    assert.throws(() => sp().consume(Buffer.from(downgraded).toString('base64'), { at: AT }),
      /SHA-1|not collision resistant/);
  });
});

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------
const RP = (() => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
  return { publicKey, privateKey, jwk };
})();

function idToken(claims = {}, { alg = 'RS256', key = RP.privateKey, kid = 'k1' } = {}) {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT', kid })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: 'https://idp.test', aud: 'vault-client', sub: 'user-1', email: 'dana@acme.com',
    exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
    nonce: 'n1', ...claims
  })).toString('base64url');
  if (alg === 'none') return `${header}.${payload}.`;
  if (alg.startsWith('HS')) {
    return `${header}.${payload}.${createHmac('sha256', key).update(`${header}.${payload}`).digest('base64url')}`;
  }
  return `${header}.${payload}.${createSign('RSA-SHA256').update(`${header}.${payload}`).sign(key, 'base64url')}`;
}

const rp = () => new OidcProvider({
  issuer: 'https://idp.test', clientId: 'vault-client',
  authorizationEndpoint: 'https://idp.test/authorize', tokenEndpoint: 'https://idp.test/token',
  jwks: [RP.jwk], redirectUri: 'https://vault.acme.internal/callback'
});

describe('OIDC — real JWT verification, and the confusion attacks', () => {
  test('a genuinely signed ID token is accepted', () => {
    const out = rp().verifyIdToken(idToken(), { nonce: 'n1' });
    assert.equal(out.email, 'dana@acme.com');
    assert.equal(out.algorithm, 'RS256');
  });

  test('alg:none is refused', () => {
    assert.throws(() => rp().verifyIdToken(idToken({}, { alg: 'none' })), /alg "none"/);
  });

  test('RS256 to HS256 confusion is refused — the public key is not an HMAC secret', () => {
    // The attack: sign with HS256 using the RSA *public* key as the shared
    // secret. A verifier that trusts header.alg will happily verify it.
    const pub = RP.publicKey.export({ type: 'spki', format: 'pem' });
    const forged = idToken({}, { alg: 'HS256', key: pub });
    assert.throws(() => rp().verifyIdToken(forged), /only accepts asymmetric signatures/);
  });

  test('a token from another issuer, or for another client, is refused', () => {
    assert.throws(() => rp().verifyIdToken(idToken({ iss: 'https://evil.test' })), /issued by https:\/\/evil\.test/);
    assert.throws(() => rp().verifyIdToken(idToken({ aud: 'someone-else' })), /is for someone-else/);
  });

  test('an expired token and a wrong nonce are both refused', () => {
    assert.throws(() => rp().verifyIdToken(idToken({ exp: Math.floor(Date.now() / 1000) - 3600 })), /expired/);
    assert.throws(() => rp().verifyIdToken(idToken(), { nonce: 'different' }), /nonce does not match/);
  });

  test('a token signed by an unknown key is refused', () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    assert.throws(() => rp().verifyIdToken(idToken({}, { key: other.privateKey })), /does not verify/);
  });

  test('a replayed token is refused', () => {
    const provider = rp();
    const t = idToken();
    provider.verifyIdToken(t, { nonce: 'n1' });
    assert.throws(() => provider.verifyIdToken(t, { nonce: 'n1' }), /already been used/);
  });

  test('the authorization URL carries PKCE and a fresh state each time', () => {
    const provider = rp();
    const a = provider.authorizationUrl();
    const b = provider.authorizationUrl();
    assert.notEqual(a.state, b.state);
    const url = new URL(a.url);
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(
      url.searchParams.get('code_challenge'),
      createHash('sha256').update(a.codeVerifier).digest('base64url'),
      'the challenge must actually be the hash of the verifier'
    );
  });

  test('a callback with an unknown state is refused before any network call', async () => {
    let called = false;
    await assert.rejects(
      () => rp().exchangeCode('code', { state: 'never-issued', fetchImpl: () => { called = true; } }),
      /does not answer a login this service started/
    );
    assert.equal(called, false, 'an unknown state must not even reach the token endpoint');
  });

  test('a provider with no JWKS refuses to exist', () => {
    assert.throws(() => new OidcProvider({
      issuer: 'x', clientId: 'y', authorizationEndpoint: 'a', tokenEndpoint: 'b', redirectUri: 'c', jwks: []
    }), /any token would be accepted/);
  });
});

// ---------------------------------------------------------------------------
// SCIM — the deprovisioning boundary
// ---------------------------------------------------------------------------
function scimSetup() {
  const sessions = new SessionStore({ maxConcurrent: 0 });
  const scim = new ScimService({ sessions });
  const user = scim.createUser({ userName: 'dana@acme.com', active: true, groups: [{ display: 'vault-security' }] });
  const { token } = sessions.create({ principal: { name: 'dana@acme.com', role: 'security' }, amr: ['hwk'] });
  return { sessions, scim, user, token };
}

describe('SCIM — provisioning, and deprovisioning that takes effect NOW', () => {
  test('a provisioned user gets the role their group maps to, and nothing else', () => {
    const { user } = scimSetup();
    assert.equal(user['urn:vault:params:scim:extension:2.0'].role, 'security');
    assert.equal(user.active, true);
  });

  test('an unmapped group grants nothing rather than defaulting to something', () => {
    const scim = new ScimService({ sessions: new SessionStore() });
    const u = scim.createUser({ userName: 'x@acme.com', groups: [{ display: 'some-random-okta-group' }] });
    assert.equal(u['urn:vault:params:scim:extension:2.0'].role, 'end_user',
      'a new group in the IdP must not silently become an entitlement in Vault');
    assert.ok(scim.status().unmappedGroups.includes('some-random-okta-group'),
      'and the administrator must be able to see which groups are unmapped');
  });

  test('DEACTIVATION revokes the live session on the very next request', () => {
    const { sessions, scim, user, token } = scimSetup();
    assert.equal(sessions.verify(token).valid, true, 'the session works before deprovisioning');

    scim.patchUser(user.id, { Operations: [{ op: 'replace', path: 'active', value: false }] });

    // Not "on next refresh". Not "within 15 minutes". Now.
    const after = sessions.verify(token);
    assert.equal(after.valid, false,
      'the session survived deprovisioning — this is the exact gap that lets a dismissed employee keep reading');
    assert.match(after.reason, /active:false/);
    assert.equal(scim.stats.sessionsRevoked, 1);
  });

  test('DELETE revokes too, and keeps a tombstone for the audit trail', () => {
    const { sessions, scim, user, token } = scimSetup();
    const out = scim.deleteUser(user.id);
    assert.equal(out.deleted, true);
    assert.equal(sessions.verify(token).valid, false);
    assert.ok(scim.users.get(user.id), 'the record survives as a tombstone — a deleted row cannot answer what they did');
    assert.equal(scim.listUsers().totalResults, 0, 'but it does not appear in listings');
  });

  test('a PUT that sets active:false revokes as surely as a PATCH', () => {
    const { sessions, scim, user, token } = scimSetup();
    scim.replaceUser(user.id, { userName: 'dana@acme.com', active: false });
    assert.equal(sessions.verify(token).valid, false, 'Entra sends PUT where Okta sends PATCH; both must revoke');
  });

  test('a ROLE CHANGE revokes existing sessions rather than leaving them stale', () => {
    const { sessions, scim, user, token } = scimSetup();
    scim.patchUser(user.id, { Operations: [{ op: 'replace', path: 'groups', value: [{ display: 'vault-users' }] }] });
    const after = sessions.verify(token);
    assert.equal(after.valid, false,
      'a session minted as security must not keep security after the role is reduced');
    assert.match(after.reason, /role changed/);
  });

  test('PATCH add appends to groups where PATCH replace substitutes them', () => {
    // RFC 7644 §3.5.2. Getting these the same way round is how a demotion
    // silently leaves the old privileged group attached.
    const scim = new ScimService({ sessions: new SessionStore() });
    const u = scim.createUser({ userName: 'eve@acme.com', groups: [{ display: 'vault-users' }] });
    scim.patchUser(u.id, { Operations: [{ op: 'add', path: 'groups', value: [{ display: 'vault-legal' }] }] });
    assert.deepEqual(scim.require(u.id).groups, ['vault-users', 'vault-legal'], 'add must not drop what was there');
    scim.patchUser(u.id, { Operations: [{ op: 'replace', path: 'groups', value: [{ display: 'vault-users' }] }] });
    assert.deepEqual(scim.require(u.id).groups, ['vault-users'], 'replace must substitute the whole attribute');
    assert.equal(scim.require(u.id).role, 'end_user');
  });

  test('removing someone from a group through the Groups endpoint reduces their role immediately', () => {
    const sessions = new SessionStore({ maxConcurrent: 0 });
    const scim = new ScimService({ sessions });
    const u = scim.createUser({ userName: 'ops@acme.com', groups: [{ display: 'vault-admins' }] });
    assert.equal(u['urn:vault:params:scim:extension:2.0'].role, 'admin');
    const g = scim.createGroup({ displayName: 'vault-admins', members: [{ value: u.id }] });
    const { token } = sessions.create({ principal: { name: 'ops@acme.com', role: 'admin' }, amr: ['hwk'] });

    scim.patchGroup(g.id, { Operations: [{ op: 'remove', path: 'members', value: [{ value: u.id }] }] });
    assert.equal(sessions.verify(token).valid, false, 'losing vault-admins must not leave them admin until logout');
    assert.equal(scim.require(u.id).role, 'end_user');
  });

  test('reactivation is possible and is logged, but does not resurrect the old session', () => {
    const { sessions, scim, user, token } = scimSetup();
    scim.patchUser(user.id, { Operations: [{ op: 'replace', path: 'active', value: false }] });
    scim.patchUser(user.id, { Operations: [{ op: 'replace', path: 'active', value: true }] });
    assert.equal(scim.require(user.id).active, true);
    assert.equal(sessions.verify(token).valid, false, 'a revoked session stays revoked; they log in again');
  });

  test('a duplicate userName is a 409, not a silent second account', () => {
    const { scim } = scimSetup();
    assert.throws(() => scim.createUser({ userName: 'dana@acme.com' }), (e) => {
      assert.equal(e.code, 'conflict');
      assert.equal(ScimService.error(e).status, 409);
      return true;
    });
  });

  test('an unsupported filter returns 501 rather than an unfiltered list', () => {
    const { scim } = scimSetup();
    // Okta probes with `userName eq "x"` before every create. Answering a
    // filter it cannot parse with EVERYBODY is an access-control failure.
    assert.equal(scim.listUsers({ filter: 'userName eq "dana@acme.com"' }).totalResults, 1);
    assert.equal(scim.listUsers({ filter: 'userName eq "nobody@acme.com"' }).totalResults, 0);
    assert.throws(() => scim.listUsers({ filter: 'emails[type eq "work"].value co "acme"' }), (e) => {
      assert.equal(ScimService.error(e).status, 501);
      assert.match(e.message, /refuses to answer .* with an unfiltered list/);
      return true;
    });
  });

  test('SCIM omitting `active` means active — getting that backwards deactivates everyone', () => {
    const scim = new ScimService({ sessions: new SessionStore() });
    assert.equal(scim.createUser({ userName: 'a@acme.com' }).active, true);
  });

  test('unmapped attributes are recorded rather than dropped', () => {
    const scim = new ScimService({ sessions: new SessionStore() });
    const u = scim.createUser({ userName: 'b@acme.com' });
    scim.patchUser(u.id, { Operations: [{ op: 'replace', path: 'costCenter', value: 'CC-42' }] });
    assert.deepEqual(scim.require(u.id).unmapped, { costCenter: 'CC-42' });
  });
});

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
describe('sessions are server-side state, with real limits', () => {
  test('an idle session expires, and says so specifically', () => {
    let clock = Date.parse('2026-07-28T10:00:00Z');
    setClock(() => clock);
    try {
      const s = new SessionStore({ idleTimeoutMs: 30 * MINUTE, absoluteTimeoutMs: 12 * HOUR });
      const { token } = s.create({ principal: { name: 'a', role: 'admin' }, at: clock });
      clock += 20 * MINUTE;
      assert.equal(s.verify(token, { at: clock }).valid, true, 'activity within the window keeps it alive');
      clock += 45 * MINUTE;
      const out = s.verify(token, { at: clock });
      assert.equal(out.valid, false);
      assert.match(out.reason, /idle for longer than 30 minutes/);
    } finally { setClock(() => Date.now()); }
  });

  test('the absolute lifetime is enforced even on a busy session', () => {
    let clock = Date.parse('2026-07-28T10:00:00Z');
    setClock(() => clock);
    try {
      const s = new SessionStore({ idleTimeoutMs: 30 * MINUTE, absoluteTimeoutMs: 2 * HOUR });
      const { token } = s.create({ principal: { name: 'a', role: 'admin' }, at: clock });
      for (let i = 0; i < 10; i++) { clock += 15 * MINUTE; s.verify(token, { at: clock }); }
      const out = s.verify(token, { at: clock });
      assert.equal(out.valid, false, 'staying active must not extend a session forever');
      assert.match(out.reason, /maximum lifetime/);
    } finally { setClock(() => Date.now()); }
  });

  test('the concurrent limit evicts the oldest, and logs it', () => {
    const s = new SessionStore({ maxConcurrent: 2 });
    const a = s.create({ principal: { name: 'dana', role: 'admin' } });
    const b = s.create({ principal: { name: 'dana', role: 'admin' } });
    const c = s.create({ principal: { name: 'dana', role: 'admin' } });
    assert.equal(s.verify(a.token).valid, false, 'the oldest goes');
    assert.match(s.verify(a.token).reason, /concurrent session limit/);
    assert.equal(s.verify(b.token).valid, true);
    assert.equal(s.verify(c.token).valid, true);
    assert.equal(s.forPrincipal('dana').length, 2);
  });

  test('a token presented from a different device is revoked, not merely refused', () => {
    const s = new SessionStore({ bindToDevice: true });
    const { token } = s.create({ principal: { name: 'dana', role: 'admin' }, deviceId: 'laptop-1' });
    const out = s.verify(token, { deviceId: 'unknown-machine' });
    assert.equal(out.valid, false);
    // A bound token appearing elsewhere is a stolen token until proven
    // otherwise, so the real device loses it too and has to re-authenticate.
    assert.equal(s.verify(token, { deviceId: 'laptop-1' }).valid, false,
      'a session seen on a second device must be killed, not just refused there');
  });

  test('the raw token is never stored — only its hash', () => {
    const s = new SessionStore();
    const { token } = s.create({ principal: { name: 'dana', role: 'admin' } });
    const dumped = JSON.stringify([...s.sessions.values()]);
    assert.equal(dumped.includes(token), false, 'a session store that keeps tokens is a credential database');
    assert.ok(s.sessions.has(SessionStore.hash(token)));
  });

  test('phishing-resistant factors are distinguished from ordinary MFA', () => {
    const s = new SessionStore();
    const otp = s.create({ principal: { name: 'a', role: 'admin' }, amr: ['otp'] });
    const fido = s.create({ principal: { name: 'b', role: 'admin' }, amr: ['hwk'] });
    assert.equal(otp.session.mfa, true);
    assert.equal(otp.session.phishingResistant, false, 'TOTP is MFA but a proxy page collects it');
    assert.equal(fido.session.phishingResistant, true);
  });
});

// ---------------------------------------------------------------------------
// Access policy
// ---------------------------------------------------------------------------
describe('access conditions', () => {
  test('IP allowlisting works on real CIDR arithmetic', () => {
    const p = new AccessPolicy({ ipAllowlist: ['10.0.0.0/8', '192.168.1.0/24'] });
    const session = { mfa: true, phishingResistant: true, amr: ['hwk'] };
    const principal = { name: 'a', role: 'end_user' };
    assert.equal(p.evaluate({ principal, session, ip: '10.4.5.6' }).allowed, true);
    assert.equal(p.evaluate({ principal, session, ip: '192.168.1.44' }).allowed, true);
    assert.equal(p.evaluate({ principal, session, ip: '192.168.2.1' }).allowed, false);
    assert.equal(p.evaluate({ principal, session, ip: '11.0.0.1' }).allowed, false);
    assert.equal(p.evaluate({ principal, session, ip: null }).allowed, false, 'no address, with a list configured, is a refusal');
  });

  test('geo-fencing fails CLOSED when the address cannot be located', () => {
    const p = new AccessPolicy({ allowedCountries: ['GB', 'DE'] });
    const session = { mfa: true, phishingResistant: true, amr: ['hwk'] };
    const principal = { name: 'a', role: 'end_user' };
    assert.equal(p.evaluate({ principal, session, country: 'GB' }).allowed, true);
    assert.equal(p.evaluate({ principal, session, country: 'RU' }).allowed, false);
    const unknown = p.evaluate({ principal, session, country: null });
    assert.equal(unknown.allowed, false, 'geo-fencing that fails open is decoration');
    assert.match(unknown.reasons[0], /could not be located/);
  });

  test('privileged roles need a phishing-resistant factor, not just any MFA', () => {
    const p = new AccessPolicy({ requireMfa: true, phishingResistantRoles: ['admin', 'security'] });
    const totp = { mfa: true, phishingResistant: false, amr: ['otp'] };
    const passkey = { mfa: true, phishingResistant: true, amr: ['hwk'] };
    assert.equal(p.evaluate({ principal: { name: 'a', role: 'end_user' }, session: totp }).allowed, true);
    const denied = p.evaluate({ principal: { name: 'b', role: 'admin' }, session: totp });
    assert.equal(denied.allowed, false);
    assert.match(denied.reasons[0], /TOTP and SMS do not qualify/);
    assert.equal(p.evaluate({ principal: { name: 'b', role: 'admin' }, session: passkey }).allowed, true);
  });

  test('device registration is required when configured, and unknown devices are refused', () => {
    const p = new AccessPolicy({ requireKnownDevice: true });
    const session = { mfa: true, phishingResistant: true, amr: ['hwk'] };
    const principal = { name: 'dana', role: 'end_user' };
    assert.equal(p.evaluate({ principal, session, deviceId: 'laptop' }).allowed, false);
    p.registerDevice('dana', 'laptop', { actor: 'it' });
    assert.equal(p.evaluate({ principal, session, deviceId: 'laptop' }).allowed, true);
    assert.equal(p.evaluate({ principal, session, deviceId: 'other' }).allowed, false);
  });

  test('a malformed CIDR is rejected at configuration time, not silently ignored', () => {
    assert.throws(() => new AccessPolicy({ ipAllowlist: ['999.0.0.0/8'] }), /not a valid IPv4 CIDR/);
    assert.throws(() => new AccessPolicy({ ipAllowlist: ['10.0.0.0/64'] }), /not a valid IPv4 CIDR/);
  });
});

// ---------------------------------------------------------------------------
// MFA
// ---------------------------------------------------------------------------
describe('MFA factors', () => {
  test('TOTP verifies a real RFC 6238 code and refuses a wrong one', () => {
    const m = new MfaRegistry();
    const { secret } = m.enrolTotp('dana', { actor: 'dana' });
    const at = 1_700_000_000_000;
    const step = Math.floor(at / 30000);
    // Compute the expected code independently, from the RFC, not from the
    // implementation under test.
    const key = base32Decode(secret);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(step / 2 ** 32), 0);
    buf.writeUInt32BE(step >>> 0, 4);
    const h = createHmac('sha1', key).update(buf).digest();
    const off = h[h.length - 1] & 0x0f;
    const code = String((((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1e6).padStart(6, '0');

    assert.equal(m.verifyTotp('dana', code, { at }).ok, true);
    assert.equal(m.verifyTotp('dana', '000000', { at }).ok, false);
  });

  test('a TOTP code cannot be used twice inside its own window', () => {
    const m = new MfaRegistry();
    const { secret } = m.enrolTotp('dana');
    const at = 1_700_000_000_000;
    const key = base32Decode(secret);
    const step = Math.floor(at / 30000);
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(0, 0); buf.writeUInt32BE(step, 4);
    const h = createHmac('sha1', key).update(buf).digest();
    const off = h[h.length - 1] & 0x0f;
    const code = String((((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1e6).padStart(6, '0');
    assert.equal(m.verifyTotp('dana', code, { at }).ok, true);
    const second = m.verifyTotp('dana', code, { at });
    assert.equal(second.ok, false, 'a captured code stays valid for 30s unless it is consumed');
    assert.match(second.reason, /already been used/);
  });

  test('TOTP enrolment warns that it is not phishing-resistant', () => {
    const m = new MfaRegistry();
    assert.match(m.enrolTotp('dana').warning, /not phishing-resistant/);
    assert.equal(m.hasPhishingResistant('dana'), false);
  });

  test('a WebAuthn assertion from the wrong ORIGIN is refused — this is what stops a proxy', () => {
    const m = new MfaRegistry();
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    m.enrolWebauthn('dana', { credentialId: 'cred1', publicKeyJwk: publicKey.export({ format: 'jwk' }) });

    const challenge = randomBytes(32).toString('base64url');
    const make = (origin, signCount = 1) => {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin })).toString('base64url');
      const authData = Buffer.concat([
        createHash('sha256').update('vault.acme.internal').digest(),
        Buffer.from([0x05]),
        (() => { const b = Buffer.alloc(4); b.writeUInt32BE(signCount); return b; })()
      ]);
      const signed = Buffer.concat([authData, createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest()]);
      const signature = createSign('sha256').update(signed).sign(privateKey, 'base64url');
      return { credentialId: 'cred1', clientDataJSON, authenticatorData: authData.toString('base64url'), signature };
    };

    const good = m.verifyWebauthn('dana', {
      ...make('https://vault.acme.internal'),
      expectedChallenge: challenge, expectedOrigin: 'https://vault.acme.internal', expectedRpId: 'vault.acme.internal'
    });
    assert.equal(good.ok, true, good.reason);
    assert.equal(good.phishingResistant, true);

    // The phishing case: the authenticator signed for the attacker's origin.
    const phished = m.verifyWebauthn('dana', {
      ...make('https://vau1t.acme.internal.evil.com'),
      expectedChallenge: challenge, expectedOrigin: 'https://vault.acme.internal', expectedRpId: 'vault.acme.internal'
    });
    assert.equal(phished.ok, false);
    assert.match(phished.reason, /stops a phishing proxy/);
  });

  test('a signature counter that does not advance reads as a cloned authenticator', () => {
    const m = new MfaRegistry();
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    m.enrolWebauthn('dana', { credentialId: 'c', publicKeyJwk: publicKey.export({ format: 'jwk' }) });
    const challenge = randomBytes(32).toString('base64url');
    const make = (signCount) => {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://v.test' })).toString('base64url');
      const counter = Buffer.alloc(4); counter.writeUInt32BE(signCount);
      const authData = Buffer.concat([createHash('sha256').update('v.test').digest(), Buffer.from([0x05]), counter]);
      const signed = Buffer.concat([authData, createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest()]);
      return {
        credentialId: 'c', clientDataJSON, authenticatorData: authData.toString('base64url'),
        signature: createSign('sha256').update(signed).sign(privateKey, 'base64url'),
        expectedChallenge: challenge, expectedOrigin: 'https://v.test', expectedRpId: 'v.test'
      };
    };
    assert.equal(m.verifyWebauthn('dana', make(5)).ok, true);
    const replayed = m.verifyWebauthn('dana', make(5));
    assert.equal(replayed.ok, false);
    assert.match(replayed.reason, /cloned/);
  });
});

// ---------------------------------------------------------------------------
// Privileged access / break-glass
// ---------------------------------------------------------------------------
describe('break-glass can now be granted, not only enforced', () => {
  const pa = () => new PrivilegedAccess({ maxDurationMs: 2 * HOUR });

  test('before this existed, nothing in the product could mint a break-glass credential', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });
    try {
      // The enforcement in folders.check() has always honoured this shape. The
      // regression this guards: a grant path that stops producing it.
      const req = v.privileged.request({
        requester: 'ciso', folders: ['hr/'], reason: 'investigating a reported data incident on ticket INC-88'
      });
      v.privileged.approve(req.id, { approver: 'gc', chain: 'legal' });
      v.privileged.approve(req.id, { approver: 'cto', chain: 'engineering' });
      const cred = v.privileged.credentialFor('ciso', { folder: 'hr/' });
      assert.ok(cred?.active);
      assert.equal(v.folders.check('read', { id: 'ciso', kind: 'human', department: 'security', breakGlass: cred }, 'hr/').allowed, true,
        'the credential this mints must be the shape the wall check already enforces');
    } finally { v.close(); }
  });

  test('a requester cannot approve their own request', () => {
    const p = pa();
    const r = p.request({ requester: 'ciso', folders: ['hr/'], reason: 'investigating incident INC-88 as reported' });
    assert.throws(() => p.approve(r.id, { approver: 'ciso', chain: 'security' }), /cannot approve their own/);
  });

  test('one person cannot be both approvers', () => {
    const p = pa();
    const r = p.request({ requester: 'ciso', folders: ['sales/'], reason: 'investigating incident INC-88 as reported' });
    p.approve(r.id, { approver: 'gc' });
    assert.throws(() => p.approve(r.id, { approver: 'gc' }), /already approved/);
  });

  test('hr/, legal/ and security/ need approvers from two separate chains', () => {
    const p = pa();
    const r = p.request({ requester: 'ciso', folders: ['hr/'], reason: 'investigating incident INC-88 as reported' });
    assert.equal(r.separateChainRequired, true);
    assert.throws(() => p.approve(r.id, { approver: 'a' }), /state which chain/);
    p.approve(r.id, { approver: 'a', chain: 'legal' });
    assert.throws(() => p.approve(r.id, { approver: 'b', chain: 'legal' }), /two separate chains/);
    const granted = p.approve(r.id, { approver: 'b', chain: 'engineering' });
    assert.equal(granted.state, 'granted');
  });

  test('a vague reason is refused — this is the sentence an auditor reads first', () => {
    const p = pa();
    assert.throws(() => p.request({ requester: 'a', folders: ['hr/'], reason: 'incident' }), /needs a specific reason/);
    assert.throws(() => p.request({ requester: 'a', folders: [], reason: 'a properly stated reason here' }), /name the folders/);
  });

  test('the time box is enforced on use, and a longer request is capped', () => {
    let clock = Date.parse('2026-07-28T10:00:00Z');
    setClock(() => clock);
    try {
      const p = new PrivilegedAccess({ maxDurationMs: 30 * MINUTE });
      const r = p.request({ requester: 'ciso', folders: ['sales/'], reason: 'investigating incident INC-88 as reported', duration: '8h', at: clock });
      assert.match(r.truncatedFrom, /capped at 30 minutes/);
      p.approve(r.id, { approver: 'a', at: clock });
      p.approve(r.id, { approver: 'b', at: clock });
      assert.ok(p.credentialFor('ciso', { at: clock }));
      clock += 31 * MINUTE;
      assert.equal(p.credentialFor('ciso', { at: clock }), null, 'the credential must expire on use, not on a promise to log out');
      assert.equal(p.sessionReport(r.id).state, 'expired');
    } finally { setClock(() => Date.now()); }
  });

  test('the session report says what was read, not merely that a session happened', () => {
    const p = pa();
    const r = p.request({ requester: 'ciso', folders: ['hr/'], reason: 'investigating incident INC-88 as reported' });
    p.approve(r.id, { approver: 'a', chain: 'legal' });
    p.approve(r.id, { approver: 'b', chain: 'eng' });
    p.record(r.id, { actor: 'ciso', folder: 'hr/reviews/', subject: 'Sarah Reyes', action: 'read', detail: 'f-123' });
    const report = p.close(r.id, { actor: 'ciso', summary: 'confirmed the report' });
    assert.equal(report.accesses.length, 1);
    assert.deepEqual(report.subjectsAccessed, ['Sarah Reyes']);
    assert.match(report.statement, /accessed 1 item/);
  });

  test('a granted-but-unused session says so explicitly rather than leaving it ambiguous', () => {
    const p = pa();
    const r = p.request({ requester: 'ciso', folders: ['sales/'], reason: 'investigating incident INC-88 as reported' });
    p.approve(r.id, { approver: 'a' });
    p.approve(r.id, { approver: 'b' });
    assert.match(p.close(r.id, { actor: 'ciso' }).statement, /nothing was accessed under it/);
  });

  test('the monthly summary is the §27 report, with the subjects named', () => {
    const p = pa();
    const r = p.request({ requester: 'ciso', folders: ['hr/'], reason: 'investigating incident INC-88 as reported' });
    p.approve(r.id, { approver: 'a', chain: 'legal' });
    p.approve(r.id, { approver: 'b', chain: 'eng' });
    p.record(r.id, { actor: 'ciso', folder: 'hr/', subject: 'Sarah Reyes' });
    const s = p.monthlySummary();
    assert.equal(s.requested, 1);
    assert.equal(s.granted, 1);
    assert.deepEqual(s.subjectsAffected, ['Sarah Reyes']);
    assert.match(s.note, /approved by two distinct people/);
  });

  test('every step reaches the ledger', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['a', 'b'], seedRules: false });
    try {
      const r = v.privileged.request({ requester: 'ciso', folders: ['sales/'], reason: 'investigating incident INC-88 as reported' });
      v.privileged.approve(r.id, { approver: 'a' });
      v.privileged.approve(r.id, { approver: 'b' });
      v.privileged.close(r.id, { actor: 'ciso' });
      const actions = v.ledger.entries({ limit: Infinity }).filter((e) => e.type === 'admin.breakglass').map((e) => e.action);
      for (const expected of ['requested', 'approved', 'granted', 'closed']) {
        assert.ok(actions.includes(expected), `${expected} is not in the ledger`);
      }
    } finally { v.close(); }
  });
});

function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0; let value = 0; const out = [];
  for (const c of String(s).toUpperCase().replace(/=+$/, '')) {
    const i = A.indexOf(c);
    if (i === -1) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
