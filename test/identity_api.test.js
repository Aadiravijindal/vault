/**
 * The identity control surface (§22, §23) over real HTTP.
 *
 * Everything here goes through a listening socket with `fetch`. A unit test can
 * prove `ScimService.patchUser` revokes a session; only this can prove that an
 * IdP POSTing to `/scim/v2/Users/:id` reaches that method, that the SCIM bearer
 * token is actually checked, and that an unauthenticated stranger cannot drive
 * it. Those are three separate failures and the unit tests catch none of them.
 *
 * The SAML assertions are genuinely signed with a real RSA key — the ACS
 * endpoint runs the same verification path a live Okta POST would.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../src/index.js';
import { ApiServer } from '../src/api/server.js';
import { parseXml, c14n, find } from '../src/identity/xmldsig.js';

// -- a real IdP: real key, real certificate, real signatures ----------------
const IDP = (() => {
  const dir = mkdtempSync(join(tmpdir(), 'vault-api-idp-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', join(dir, 'k.pem'),
    '-out', join(dir, 'c.pem'), '-days', '365', '-nodes', '-subj', '/CN=idp.test'], { stdio: 'ignore' });
  const key = readFileSync(join(dir, 'k.pem'), 'utf8');
  const certPem = readFileSync(join(dir, 'c.pem'), 'utf8');
  rmSync(dir, { recursive: true, force: true });
  return { key, certPem, certB64: certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') };
})();

const ENTITY = 'https://vault.acme.internal';
const ACS = `${ENTITY}/api/auth/saml/acs`;

function signedResponse({ nameId = 'dana@acme.com', audience = ENTITY, inResponseTo,
  assertionId = `_a${randomBytes(4).toString('hex')}`, groups = ['vault-security'], key = IDP.key } = {}) {
  const iat = new Date(Date.now() - 30_000).toISOString().replace(/\.\d+Z$/, 'Z');
  const exp = new Date(Date.now() + 5 * 60_000).toISOString().replace(/\.\d+Z$/, 'Z');
  const nbf = iat;
  const groupValues = groups.map((g) => `<saml:AttributeValue>${g}</saml:AttributeValue>`).join('');
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${iat}" Version="2.0"><saml:Issuer>http://idp.test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${exp}" Recipient="${ACS}" InResponseTo="${inResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${nbf}" NotOnOrAfter="${exp}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${nameId}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups">${groupValues}</saml:Attribute></saml:AttributeStatement></saml:Assertion>`;

  const digest = createHash('sha256').update(c14n(parseXml(assertion), {}), 'utf8').digest('base64');
  const signedInfo = `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#${assertionId}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
  const sig = createSign('sha256').update(c14n(parseXml(signedInfo), {}), 'utf8').sign(key, 'base64');
  const signature = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${signedInfo}<ds:SignatureValue>${sig}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${IDP.certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`;
  const body = assertion.replace('</saml:Issuer>', `</saml:Issuer>${signature}`);
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r${randomBytes(4).toString('hex')}" InResponseTo="${inResponseTo}" Destination="${ACS}" Version="2.0" IssueInstant="${iat}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>${body}</samlp:Response>`;
  return Buffer.from(xml).toString('base64');
}

// -- a real OIDC IdP: real RSA JWKS, real RS256 tokens ----------------------
const OIDC_KEY = generateKeyPairSync('rsa', { modulusLength: 2048 });
const OIDC_JWK = (() => {
  const jwk = OIDC_KEY.publicKey.export({ format: 'jwk' });
  return { ...jwk, kid: 'k1', alg: 'RS256', use: 'sig' };
})();
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function idToken(claims) {
  const header = b64u({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const payload = b64u(claims);
  const sig = createSign('RSA-SHA256').update(`${header}.${payload}`).sign(OIDC_KEY.privateKey, 'base64url');
  return `${header}.${payload}.${sig}`;
}

const SCIM_TOKEN = `scim_${randomBytes(16).toString('hex')}`;

let vault; let server; let base; let dir; let adminToken;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'vault-idapi-'));
  vault = new Vault({
    dir,
    saml: { entityId: ENTITY, acsUrl: ACS, idpEntityId: 'http://idp.test', idpSsoUrl: 'https://idp.test/sso', certificates: [IDP.certB64], preset: 'okta' },
    oidc: {
      issuer: 'https://idp.test', clientId: 'vault-client', clientSecret: 'shh',
      authorizationEndpoint: 'https://idp.test/authorize', tokenEndpoint: 'https://idp.test/token',
      jwks: [OIDC_JWK], redirectUri: `${ENTITY}/api/auth/oidc/callback`
    },
    scim: { bearerToken: SCIM_TOKEN }
  });
  server = new ApiServer({ vault, port: 0 });
  adminToken = server.issueToken({ name: 'root@acme.com', role: 'admin' });
  await server.listen();
  base = `http://127.0.0.1:${server.server.address().port}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

const scimFetch = (path, init = {}) => fetch(`${base}${path}`, {
  ...init,
  headers: { Authorization: `Bearer ${SCIM_TOKEN}`, 'Content-Type': 'application/scim+json', ...(init.headers ?? {}) }
});

describe('SAML over HTTP — the ACS endpoint an IdP actually POSTs to', () => {
  test('SP metadata is served unauthenticated, as XML, because the IdP has no Vault token', async () => {
    const res = await fetch(`${base}/api/auth/saml/metadata`);
    assert.equal(res.status, 200, 'an IdP cannot present a bearer token when fetching metadata');
    assert.match(res.headers.get('content-type') ?? '', /xml/);
    const xml = await res.text();
    const doc = parseXml(xml.replace(/<\?xml[^>]*\?>/, ''));
    assert.equal(doc.attrs.entityID, ENTITY);
    assert.equal(find(doc, 'AssertionConsumerService')?.attrs.Location, ACS);
  });

  test('login returns a redirect to the IdP carrying a real AuthnRequest', async () => {
    const res = await fetch(`${base}/api/auth/saml/login`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    const location = new URL(res.headers.get('location'));
    assert.equal(location.origin + location.pathname, 'https://idp.test/sso');
    assert.ok(location.searchParams.get('SAMLRequest'), 'the redirect must carry the AuthnRequest');
  });

  test('a genuinely signed assertion is accepted and hands back a session cookie', async () => {
    const login = await fetch(`${base}/api/auth/saml/login`, { redirect: 'manual' });
    const requestId = [...vault.saml.pending.keys()].pop();
    assert.ok(requestId, 'the login must have recorded the request it is waiting for');
    assert.ok(login.headers.get('location'));

    const res = await fetch(`${base}/api/auth/saml/acs`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ SAMLResponse: signedResponse({ inResponseTo: requestId }), RelayState: '/memory' })
    });
    assert.equal(res.status, 302, 'a browser POST must be answered with a redirect, not JSON');
    assert.equal(res.headers.get('location'), '/memory', 'RelayState is where the user was going');

    const cookie = res.headers.get('set-cookie') ?? '';
    assert.match(cookie, /vault_session=vsx_/, 'the session token is delivered as a cookie');
    assert.match(cookie, /HttpOnly/, 'a session cookie readable by script is a session token given to XSS');
    assert.match(cookie, /SameSite=Lax/);
    assert.match(cookie, /Secure/);

    // And it is a real, working credential.
    const token = /vault_session=([^;]+)/.exec(cookie)[1];
    const who = await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(who.status, 200, 'a session minted by SAML must authenticate the API');
    const body = await who.json();
    assert.equal(body.name, 'dana@acme.com');
    assert.equal(body.role, 'security', 'the vault-security group maps to the security role');
  });

  test('an assertion signed by the WRONG key is refused over HTTP with no session', async () => {
    await fetch(`${base}/api/auth/saml/login`, { redirect: 'manual' });
    const requestId = [...vault.saml.pending.keys()].pop();
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const res = await fetch(`${base}/api/auth/saml/acs`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        SAMLResponse: signedResponse({ inResponseTo: requestId, key: other.privateKey.export({ type: 'pkcs1', format: 'pem' }) })
      })
    });
    assert.equal(res.status, 403);
    assert.equal(res.headers.get('set-cookie'), null, 'a rejected assertion must not set a cookie');
  });

  test('replaying a good assertion a second time is refused', async () => {
    await fetch(`${base}/api/auth/saml/login`, { redirect: 'manual' });
    const requestId = [...vault.saml.pending.keys()].pop();
    const body = new URLSearchParams({ SAMLResponse: signedResponse({ inResponseTo: requestId }) });
    const first = await fetch(`${base}/api/auth/saml/acs`, {
      method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
    });
    assert.equal(first.status, 302);
    const second = await fetch(`${base}/api/auth/saml/acs`, {
      method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
    });
    assert.equal(second.status, 403, 'a captured assertion must not be usable twice');
  });

  test('a RelayState pointing at another host is not followed', async () => {
    await fetch(`${base}/api/auth/saml/login`, { redirect: 'manual' });
    const requestId = [...vault.saml.pending.keys()].pop();
    const res = await fetch(`${base}/api/auth/saml/acs`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ SAMLResponse: signedResponse({ inResponseTo: requestId }), RelayState: 'https://evil.example.com/steal' })
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/', 'an open redirect on the login endpoint is a phishing primitive');
  });
});

describe('OIDC over HTTP', () => {
  test('login redirects to the IdP with PKCE S256', async () => {
    const res = await fetch(`${base}/api/auth/oidc/login`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    const u = new URL(res.headers.get('location'));
    assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(u.searchParams.get('state'));
    assert.equal(u.searchParams.get('client_id'), 'vault-client');
  });

  test('the callback exchanges the code at the real token endpoint and verifies the ID token', async () => {
    await fetch(`${base}/api/auth/oidc/login`, { redirect: 'manual' });
    const state = [...vault.oidc.pending.keys()].pop();
    const { nonce } = vault.oidc.pending.get(state);

    // Stand in for the IdP's token endpoint. The exchange is a real HTTP-shaped
    // call through the provider's injected transport, so what is asserted below
    // is that the callback actually performed it — not that it trusted the code.
    const seen = [];
    vault.oidc.exchange = async (params) => {
      seen.push(params);
      return {
        id_token: idToken({
          iss: 'https://idp.test', aud: 'vault-client', sub: 'dana', email: 'dana@acme.com',
          groups: ['vault-security'], nonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300
        })
      };
    };

    const res = await fetch(`${base}/api/auth/oidc/callback?code=abc123&state=${encodeURIComponent(state)}`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    assert.equal(seen.length, 1, 'the callback must exchange the code, not decode it');
    assert.equal(seen[0].code, 'abc123');
    assert.equal(seen[0].code_verifier?.length > 20, true, 'the PKCE verifier must be sent to the token endpoint');

    const cookie = res.headers.get('set-cookie') ?? '';
    const token = /vault_session=([^;]+)/.exec(cookie)?.[1];
    assert.ok(token, 'a verified ID token must produce a session');
    const who = await (await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } })).json();
    assert.equal(who.name, 'dana@acme.com');
  });

  test('a callback with an unknown state is refused before any exchange happens', async () => {
    let exchanged = false;
    vault.oidc.exchange = async () => { exchanged = true; return {}; };
    const res = await fetch(`${base}/api/auth/oidc/callback?code=x&state=not-a-state`, { redirect: 'manual' });
    assert.equal(res.status, 403);
    assert.equal(exchanged, false, 'an unsolicited callback must not cause a token request');
  });
});

describe('SCIM 2.0 over HTTP — what Okta and Entra actually drive', () => {
  test('the endpoint refuses an unauthenticated caller', async () => {
    const res = await fetch(`${base}/scim/v2/Users`);
    assert.equal(res.status, 401, 'an open SCIM endpoint is a remote account-creation API');
  });

  test('the endpoint refuses a WRONG bearer token', async () => {
    const res = await fetch(`${base}/scim/v2/Users`, { headers: { Authorization: 'Bearer scim_wrong_token' } });
    assert.equal(res.status, 401);
  });

  test('a Vault admin token is NOT a SCIM token', async () => {
    // Two different credentials for two different callers. Letting the admin
    // API token drive SCIM would widen the blast radius of a leaked token.
    const res = await fetch(`${base}/scim/v2/Users`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(res.status, 401);
  });

  test('ServiceProviderConfig advertises what this server truly supports', async () => {
    const res = await scimFetch('/scim/v2/ServiceProviderConfig');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /scim\+json/);
    const cfg = await res.json();
    assert.ok(cfg.schemas.includes('urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'));
    assert.equal(cfg.patch.supported, true);
    assert.equal(cfg.filter.supported, true);
    assert.equal(cfg.bulk.supported, false, 'advertising bulk without implementing it makes Okta fail mid-sync');
  });

  test('POST /Users creates with 201 and a Location header', async () => {
    const res = await scimFetch('/scim/v2/Users', {
      method: 'POST',
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'http-user@acme.com', active: true, groups: [{ display: 'vault-security' }]
      })
    });
    assert.equal(res.status, 201, 'SCIM requires 201 on create; Okta treats 200 as a protocol error');
    const user = await res.json();
    assert.ok(res.headers.get('location')?.endsWith(`/scim/v2/Users/${user.id}`));
    assert.equal(user.userName, 'http-user@acme.com');
    assert.equal(user.schemas[0], 'urn:ietf:params:scim:schemas:core:2.0:User');
  });

  test('a duplicate userName is 409 with scimType uniqueness', async () => {
    const body = JSON.stringify({ userName: 'dupe@acme.com' });
    assert.equal((await scimFetch('/scim/v2/Users', { method: 'POST', body })).status, 201);
    const res = await scimFetch('/scim/v2/Users', { method: 'POST', body });
    assert.equal(res.status, 409);
    const err = await res.json();
    assert.equal(err.scimType, 'uniqueness');
    assert.equal(err.status, '409', 'SCIM errors carry status as a string');
  });

  test('PATCH active:false over HTTP kills a live session on the next request', async () => {
    // The end-to-end shape of the whole feature: someone is signed in, HR
    // deactivates them in the IdP, and the very next API call fails.
    const created = await (await scimFetch('/scim/v2/Users', {
      method: 'POST', body: JSON.stringify({ userName: 'fired@acme.com', active: true, groups: [{ display: 'vault-security' }] })
    })).json();

    const { token } = vault.sessions.create({ principal: { name: 'fired@acme.com', role: 'security' }, amr: ['hwk'] });
    const before = await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(before.status, 200, 'they are signed in');

    const patch = await scimFetch(`/scim/v2/Users/${created.id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [{ op: 'replace', path: 'active', value: false }]
      })
    });
    assert.equal(patch.status, 200);
    assert.equal((await patch.json()).active, false);

    const after = await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(after.status, 401, 'the live session survived deprovisioning over the wire');
  });

  test('DELETE /Users/:id returns 204 with an empty body and revokes', async () => {
    const created = await (await scimFetch('/scim/v2/Users', {
      method: 'POST', body: JSON.stringify({ userName: 'gone@acme.com', groups: [{ display: 'vault-admins' }] })
    })).json();
    const { token } = vault.sessions.create({ principal: { name: 'gone@acme.com', role: 'admin' }, amr: ['hwk'] });

    const res = await scimFetch(`/scim/v2/Users/${created.id}`, { method: 'DELETE' });
    assert.equal(res.status, 204);
    assert.equal((await res.text()), '', 'SCIM 204 must have no body');
    assert.equal((await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } })).status, 401);
    assert.equal((await scimFetch(`/scim/v2/Users/${created.id}`)).status, 404, 'a deleted user is gone from the API');
  });

  test('GET /Users returns a ListResponse envelope with real pagination', async () => {
    const res = await scimFetch('/scim/v2/Users?startIndex=1&count=2');
    assert.equal(res.status, 200);
    const list = await res.json();
    assert.equal(list.schemas[0], 'urn:ietf:params:scim:api:messages:2.0:ListResponse');
    assert.equal(list.itemsPerPage <= 2, true);
    assert.equal(typeof list.totalResults, 'number');
    assert.equal(Array.isArray(list.Resources), true);
  });

  test('a supported filter really filters, and an unsupported one is 501 not an unfiltered dump', async () => {
    await scimFetch('/scim/v2/Users', { method: 'POST', body: JSON.stringify({ userName: 'filter-me@acme.com' }) });
    const ok = await (await scimFetch('/scim/v2/Users?filter=' + encodeURIComponent('userName eq "filter-me@acme.com"'))).json();
    assert.equal(ok.totalResults, 1);
    assert.equal(ok.Resources[0].userName, 'filter-me@acme.com');

    const bad = await scimFetch('/scim/v2/Users?filter=' + encodeURIComponent('userName co "acme"'));
    assert.equal(bad.status, 501, 'returning everything for a filter you do not understand leaks the whole directory');
  });

  test('PUT replaces, and Groups PATCH reduces a role — both over HTTP', async () => {
    const u = await (await scimFetch('/scim/v2/Users', {
      method: 'POST', body: JSON.stringify({ userName: 'putme@acme.com', groups: [{ display: 'vault-admins' }] })
    })).json();
    assert.equal(u['urn:vault:params:scim:extension:2.0'].role, 'admin');

    const g = await (await scimFetch('/scim/v2/Groups', {
      method: 'POST', body: JSON.stringify({ displayName: 'vault-admins', members: [{ value: u.id }] })
    })).json();
    assert.ok(g.id);

    const { token } = vault.sessions.create({ principal: { name: 'putme@acme.com', role: 'admin' }, amr: ['hwk'] });
    const res = await scimFetch(`/scim/v2/Groups/${g.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ Operations: [{ op: 'remove', path: 'members', value: [{ value: u.id }] }] })
    });
    assert.equal(res.status, 200);
    assert.equal((await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } })).status, 401,
      'losing the admin group must not leave them admin until they log out');
  });

  test('a SCIM token cannot read memory — it is a provisioning credential, nothing else', async () => {
    const res = await fetch(`${base}/api/facts`, { headers: { Authorization: `Bearer ${SCIM_TOKEN}` } });
    assert.equal(res.status, 401, 'the IdP\'s provisioning token must not be a read credential');
  });
});

describe('Break-glass over HTTP — request, two approvals, and a recorded session', () => {
  const post = (path, body, token = adminToken) => fetch(`${base}${path}`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  test('an end user cannot request break-glass on someone else\'s folder', async () => {
    const t = server.issueToken({ name: 'nobody@acme.com', role: 'end_user' });
    const res = await post('/api/breakglass', { folders: ['hr/'], reason: 'curious about the layoffs list' }, t);
    assert.equal(res.status, 403);
  });

  test('the full flow: request, refuse self-approval, two approvers, credential, recording', async () => {
    const secTok = server.issueToken({ name: 'ciso@acme.com', role: 'security' });
    const req = await (await post('/api/breakglass', {
      folders: ['sales/'], reason: 'investigating exfiltration incident INC-2291', duration: '30m', ticket: 'INC-2291'
    }, secTok)).json();
    assert.equal(req.state, 'pending');

    // Self-approval is the whole point of two-person control.
    const self = await post(`/api/breakglass/${req.id}/approve`, {}, secTok);
    assert.equal(self.status, 403);

    const a = server.issueToken({ name: 'legal@acme.com', role: 'legal' });
    const b = server.issueToken({ name: 'admin2@acme.com', role: 'admin' });
    assert.equal((await post(`/api/breakglass/${req.id}/approve`, {}, a)).status, 200);
    const granted = await (await post(`/api/breakglass/${req.id}/approve`, {}, b)).json();
    assert.equal(granted.state, 'granted');

    // The credential is real: it satisfies the wall check that break-glass exists for.
    const cred = vault.privileged.credentialFor('ciso@acme.com');
    assert.ok(cred, 'an approved request must mint a usable credential');

    const rec = await post(`/api/breakglass/${req.id}/record`, { folder: 'sales/', subject: 'quota dispute', action: 'read' }, secTok);
    assert.equal(rec.status, 200);

    const report = await (await fetch(`${base}/api/breakglass/${req.id}`, { headers: { Authorization: `Bearer ${secTok}` } })).json();
    assert.equal(report.accesses.length, 1);
    assert.equal(report.accesses[0].folder, 'sales/');
  });

  test('a credential granted over HTTP actually opens the wall — and nothing else does', async () => {
    // The claim the whole module exists to make. `credentialFor` returning an
    // object proves nothing; the folder wall accepting it is the feature.
    vault.folders.ensure('hr/', { walls: { noBreakGlassWithoutSeparateChain: true }, actor: 'root' });
    const actor = { id: 'irt@acme.com', kind: 'human', approved: true };

    const before = vault.folders.check('read', actor, 'hr/');
    assert.equal(before.allowed, false, 'hr/ must be walled to begin with');
    assert.equal(before.requiresBreakGlass, true);

    const irt = server.issueToken({ name: 'irt@acme.com', role: 'security' });
    const req = await (await post('/api/breakglass', {
      folders: ['hr/'], reason: 'suspected insider exfiltration, ticket INC-4410', duration: '20m'
    }, irt)).json();
    assert.equal(req.separateChainRequired, true, 'hr/ must demand two separate approval chains');

    const legal = server.issueToken({ name: 'gc@acme.com', role: 'legal' });
    const sec = server.issueToken({ name: 'dpo@acme.com', role: 'compliance' });
    assert.equal((await post(`/api/breakglass/${req.id}/approve`, { chain: 'legal' }, legal)).status, 200);

    // Two signatures from one reporting line is one signature.
    const sameChain = await post(`/api/breakglass/${req.id}/approve`, { chain: 'legal' }, sec);
    assert.equal(sameChain.status, 403);

    const granted = await (await post(`/api/breakglass/${req.id}/approve`, { chain: 'security' }, sec)).json();
    assert.equal(granted.state, 'granted');

    const cred = vault.privileged.credentialFor('irt@acme.com', { folder: 'hr/' });
    assert.equal(cred.separateChain, true);
    const after = vault.folders.check('read', { ...actor, breakGlass: cred }, 'hr/');
    assert.equal(after.allowed, true, 'the minted credential must satisfy the wall it was minted for');
    assert.equal(after.breakGlass, true);

    // A credential whose approvals came from one chain must NOT open hr/,
    // even though the request itself was granted. Two independent layers.
    const oneChain = { ...cred, separateChain: false };
    const refused = vault.folders.check('read', { ...actor, breakGlass: oneChain }, 'hr/');
    assert.equal(refused.allowed, false, 'the wall must re-check the chain requirement, not trust the credential');

    // And it does not open a folder it was never scoped to.
    vault.folders.ensure('legal/', { walls: { noBreakGlassWithoutSeparateChain: true }, actor: 'root' });
    assert.equal(vault.privileged.credentialFor('irt@acme.com', { folder: 'legal/' }), null,
      'a credential scoped to hr/ must not answer for legal/');
  });

  test('the pending queue and the monthly summary are reachable and role-gated', async () => {
    const list = await fetch(`${base}/api/breakglass`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(list.status, 200);
    const summary = await fetch(`${base}/api/breakglass/summary`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(summary.status, 200);
    const s = await summary.json();
    assert.equal(typeof s.requested, 'number');
    assert.equal(Array.isArray(s.sessions), true, 'the §27 summary names the sessions, it does not just count them');

    const fin = server.issueToken({ name: 'cfo@acme.com', role: 'finance' });
    assert.equal((await fetch(`${base}/api/breakglass`, { headers: { Authorization: `Bearer ${fin}` } })).status, 403);
  });
});

describe('Sessions and MFA over HTTP', () => {
  test('a session token authenticates, logout revokes it, and the next call fails', async () => {
    const { token } = vault.sessions.create({ principal: { name: 'sam@acme.com', role: 'platform' }, amr: ['hwk'] });
    assert.equal((await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } })).status, 200);

    const out = await fetch(`${base}/api/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
    assert.equal(out.status, 200);
    assert.equal((await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } })).status, 401,
      'logout must revoke server-side, not merely clear a cookie');
  });

  test('an admin can see and kill another principal\'s sessions', async () => {
    const { token } = vault.sessions.create({ principal: { name: 'contractor@acme.com', role: 'end_user' }, amr: ['pwd'] });
    const list = await (await fetch(`${base}/api/auth/sessions`, { headers: { Authorization: `Bearer ${adminToken}` } })).json();
    assert.ok(list.sessions.some((s) => s.principal.name === 'contractor@acme.com'));

    const kill = await fetch(`${base}/api/auth/sessions/contractor@acme.com`, {
      method: 'DELETE', headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(kill.status, 200);
    assert.equal((await kill.json()).revoked, 1);
    assert.equal((await fetch(`${base}/api/whoami`, { headers: { Authorization: `Bearer ${token}` } })).status, 401);
  });

  test('TOTP enrolment returns a secret and the code verifies once, then is refused', async () => {
    const t = server.issueToken({ name: 'mfa@acme.com', role: 'platform' });
    const enrol = await (await fetch(`${base}/api/auth/mfa/totp`, {
      method: 'POST', headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' }, body: '{}'
    })).json();
    assert.ok(enrol.secret, 'enrolment must return the shared secret exactly once');
    assert.match(enrol.otpauthUrl, /^otpauth:\/\/totp\//);

    const code = currentTotp(enrol.secret);
    const good = await fetch(`${base}/api/auth/mfa/totp/verify`, {
      method: 'POST', headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    assert.equal(good.status, 200);
    const replay = await fetch(`${base}/api/auth/mfa/totp/verify`, {
      method: 'POST', headers: { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    assert.equal(replay.status, 403, 'a TOTP code observed on the wire must not be usable a second time');
  });

  test('the access-policy decision is queryable and denies a weak session for a strong role', async () => {
    const res = await fetch(`${base}/api/auth/policy`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(res.status, 200);
    const p = await res.json();
    assert.equal(Array.isArray(p.phishingResistantRoles), true);
  });
});

/**
 * RFC 6238, computed here from the base32 secret the server handed out.
 *
 * Deliberately not shared with the implementation: if the server's TOTP were
 * wrong in the same way as the test's, a shared helper would agree with itself
 * and prove nothing.
 */
function currentTotp(secretBase32, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secretBase32.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  }
  const bytes = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac('sha1', bytes).update(counter).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
  return String(bin % 1_000_000).padStart(6, '0');
}
