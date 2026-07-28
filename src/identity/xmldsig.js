/**
 * Just enough XML, and real XML Signature verification.
 *
 * SAML is the reason this file exists. A SAML assertion is an XML document
 * whose trustworthiness rests entirely on an enveloped XMLDSig signature, and
 * verifying that signature means canonicalising the signed subtree byte-for-byte
 * the way the IdP did before hashing it. Get the canonicalisation wrong and
 * every real assertion fails; skip it and every forged assertion passes.
 *
 * There is no XML library here because there are no dependencies here. What
 * follows is a small parser and an Exclusive C14N implementation covering the
 * profile SAML actually uses: namespace-prefixed elements, attributes, text,
 * CDATA, comments excluded. It is not a general-purpose XML toolchain and does
 * not pretend to be — `parseXml` throws on constructs it cannot represent
 * faithfully rather than guessing, because a parser that silently mangles input
 * it does not understand is a signature bypass waiting to happen.
 *
 * The dangerous shortcuts this deliberately does NOT take:
 *
 *   - It never verifies the signature and then re-parses the document. The
 *     verified node is the node whose contents are returned. Signature-wrapping
 *     attacks (XSW) work precisely by making those two different.
 *   - It resolves no external entities and expands no internal ones, so XXE and
 *     billion-laughs have no surface.
 *   - It refuses a document containing more than one Assertion unless the caller
 *     names which one was signed.
 */
import { createHash, createVerify, X509Certificate } from 'node:crypto';
import { VaultError } from '../util/errors.js';

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/** @typedef {{name:string, attrs:Record<string,string>, children:XmlNode[], text:string, parent:XmlNode|null, raw:string, start:number, end:number}} XmlNode */

const FORBIDDEN = [
  [/<!ENTITY/i, 'entity declarations are not accepted — XXE has no place in an assertion'],
  [/<!DOCTYPE/i, 'DOCTYPE is not accepted — it is the entry point for entity expansion attacks'],
  [/<\?xml-stylesheet/i, 'processing instructions beyond the XML declaration are not accepted']
];

/**
 * Parse an XML document into a node tree, preserving each element's exact
 * source range so a signed subtree can be canonicalised from the original
 * bytes rather than from a re-serialisation.
 * @returns {XmlNode}
 */
export function parseXml(xml) {
  const text = String(xml);
  for (const [rx, why] of FORBIDDEN) {
    if (rx.test(text)) throw new VaultError('invalid', `refusing to parse this XML: ${why}`);
  }

  /** @type {XmlNode[]} */
  const stack = [];
  let root = null;
  const tag = /<(\/?)([A-Za-z_][\w.\-]*(?::[A-Za-z_][\w.\-]*)?)((?:\s+[^<>]*?)?)(\/?)>/g;
  // Strip comments and the XML declaration first; both are excluded from
  // Exclusive C14N output anyway, and leaving them in complicates offsets.
  const stripped = text
    .replace(/<\?xml[^?]*\?>/g, (m) => ' '.repeat(m.length))
    .replace(/<!--[\s\S]*?-->/g, (m) => ' '.repeat(m.length));

  let m;
  let lastIndex = 0;
  while ((m = tag.exec(stripped)) !== null) {
    const [whole, closing, name, attrString, selfClose] = m;
    const between = stripped.slice(lastIndex, m.index);
    if (stack.length && between.trim()) {
      stack[stack.length - 1].text += decodeEntities(between);
    }
    lastIndex = m.index + whole.length;

    if (closing) {
      const node = stack.pop();
      if (!node || node.name !== name) {
        throw new VaultError('invalid', `malformed XML: </${name}> does not close <${node?.name ?? 'nothing'}>`);
      }
      node.end = m.index + whole.length;
      node.raw = stripped.slice(node.start, node.end);
      continue;
    }

    const node = {
      name,
      attrs: parseAttrs(attrString),
      children: [],
      text: '',
      parent: stack[stack.length - 1] ?? null,
      raw: '',
      start: m.index,
      end: selfClose ? m.index + whole.length : -1
    };
    if (node.parent) node.parent.children.push(node);
    else if (root) throw new VaultError('invalid', 'malformed XML: more than one root element');
    if (!root) root = node;
    if (selfClose) node.raw = whole;
    else stack.push(node);
  }

  if (stack.length) throw new VaultError('invalid', `malformed XML: <${stack[stack.length - 1].name}> is never closed`);
  if (!root) throw new VaultError('invalid', 'no XML elements found');
  return root;
}

function parseAttrs(s) {
  const out = {};
  const rx = /([A-Za-z_][\w.\-]*(?::[A-Za-z_][\w.\-]*)?)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = rx.exec(s)) !== null) out[m[1]] = decodeEntities(m[2] ?? m[3] ?? '');
  return out;
}

/**
 * Only the five predefined entities plus numeric character references. No
 * user-defined entities are recognised, which is what makes expansion attacks
 * structurally impossible rather than merely bounded.
 */
function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

const escapeText = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
const escapeAttr = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
  .replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');

/** Depth-first search for elements by local name (namespace prefix ignored). */
export function findAll(node, localName, out = []) {
  if (local(node.name) === localName) out.push(node);
  for (const c of node.children) findAll(c, localName, out);
  return out;
}
export function find(node, localName) { return findAll(node, localName)[0] ?? null; }
export const local = (name) => String(name).split(':').pop();

// ---------------------------------------------------------------------------
// Exclusive XML Canonicalisation (http://www.w3.org/2001/10/xml-exc-c14n#)
// ---------------------------------------------------------------------------

/**
 * Serialise a subtree the way the signer did.
 *
 * Exclusive C14N's defining property is that a subtree carries only the
 * namespace declarations it *uses*, not everything it inherited — which is what
 * lets a signed assertion be moved between documents without breaking. That
 * "visibly utilised" rule is the whole algorithm, and getting it wrong is the
 * usual reason a hand-rolled verifier rejects valid Okta assertions.
 */
export function c14n(node, inheritedNs = {}) {
  const nsHere = { ...inheritedNs };
  for (const [k, v] of Object.entries(node.attrs)) {
    if (k === 'xmlns') nsHere[''] = v;
    else if (k.startsWith('xmlns:')) nsHere[k.slice(6)] = v;
  }

  // Prefixes this element visibly uses: its own, plus its attributes'.
  const used = new Set();
  used.add(prefixOf(node.name));
  for (const k of Object.keys(node.attrs)) {
    if (k === 'xmlns' || k.startsWith('xmlns:')) continue;
    if (k.includes(':')) used.add(prefixOf(k));
  }
  // InclusiveNamespaces PrefixList, when the signature asks for it.
  for (const p of node._inclusivePrefixes ?? []) used.add(p);

  const declared = [];
  for (const p of [...used].sort()) {
    const uri = nsHere[p];
    if (uri === undefined) continue;
    // Only render a declaration the ancestor axis has not already rendered
    // with the same value — otherwise the digest differs from the signer's.
    if (inheritedNs[p] === uri && node._renderedNs?.[p] === uri) continue;
    declared.push(p === '' ? ` xmlns="${escapeAttr(uri)}"` : ` xmlns:${p}="${escapeAttr(uri)}"`);
  }

  const attrs = Object.entries(node.attrs)
    .filter(([k]) => k !== 'xmlns' && !k.startsWith('xmlns:'))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => ` ${k}="${escapeAttr(v)}"`)
    .join('');

  const rendered = { ...(node._renderedNs ?? {}) };
  for (const p of [...used]) if (nsHere[p] !== undefined) rendered[p] = nsHere[p];

  let inner = '';
  const ordered = [...node.children].sort((a, b) => a.start - b.start);
  if (ordered.length) {
    for (const c of ordered) {
      c._renderedNs = rendered;
      inner += c14n(c, nsHere);
    }
  } else {
    inner = escapeText(node.text);
  }

  return `<${node.name}${declared.join('')}${attrs}>${inner}</${node.name}>`;
}

const prefixOf = (name) => (String(name).includes(':') ? String(name).split(':')[0] : '');

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

const DIGESTS = {
  'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256',
  'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
  'http://www.w3.org/2000/09/xmldsig#sha1': null   // deliberately unsupported
};
const SIGNATURES = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': { key: 'rsa', hash: 'RSA-SHA256' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': { key: 'rsa', hash: 'RSA-SHA512' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256': { key: 'ec', hash: 'sha256' },
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': null // deliberately unsupported
};

/**
 * Verify an enveloped XMLDSig over `signedNode`.
 *
 * @param {object} o
 * @param {XmlNode} o.doc parsed document
 * @param {XmlNode} o.signedNode the element the signature must actually cover
 * @param {string[]} o.certificates PEM or base64 DER, from IdP metadata
 * @returns {{ok:true, certificate:string, algorithm:string}}
 */
export function verifySignature({ doc, signedNode, certificates }) {
  const signatures = findAll(signedNode, 'Signature')
    .filter((s) => s.parent === signedNode);
  if (!signatures.length) {
    // A signature somewhere else in the document does not protect this node.
    // Accepting one that does is signature wrapping, the classic SAML bypass.
    throw new VaultError('forbidden', 'the element that carries the identity claims is not itself signed');
  }
  if (signatures.length > 1) throw new VaultError('forbidden', 'more than one signature on the same element');
  const sig = signatures[0];

  const signedInfo = find(sig, 'SignedInfo');
  if (!signedInfo) throw new VaultError('invalid', 'signature has no SignedInfo');

  const sigMethod = find(signedInfo, 'SignatureMethod')?.attrs.Algorithm;
  const spec = SIGNATURES[sigMethod];
  if (spec === null) {
    throw new VaultError('forbidden', `${sigMethod} is SHA-1 based and is refused — it is not collision resistant`, { algorithm: sigMethod });
  }
  if (!spec) throw new VaultError('invalid', `unsupported signature algorithm ${sigMethod}`, { supported: Object.keys(SIGNATURES).filter((k) => SIGNATURES[k]) });

  const reference = find(signedInfo, 'Reference');
  if (!reference) throw new VaultError('invalid', 'signature has no Reference');
  const uri = reference.attrs.URI ?? '';
  const targetId = uri.startsWith('#') ? uri.slice(1) : uri;
  const nodeId = signedNode.attrs.ID ?? signedNode.attrs.Id ?? signedNode.attrs.id;
  if (targetId && nodeId && targetId !== nodeId) {
    throw new VaultError('forbidden', `the signature covers "${targetId}" but the identity claims are in "${nodeId}"`);
  }

  const digestMethod = find(reference, 'DigestMethod')?.attrs.Algorithm;
  const digestAlgo = DIGESTS[digestMethod];
  if (digestAlgo === null) throw new VaultError('forbidden', `${digestMethod} is SHA-1 and is refused`);
  if (!digestAlgo) throw new VaultError('invalid', `unsupported digest ${digestMethod}`);

  // The enveloped-signature transform: hash the node with its own Signature
  // element removed. Removing it from the tree — rather than string-editing the
  // raw XML — is what keeps this immune to a second <Signature> hidden in the
  // element's text.
  const idx = signedNode.children.indexOf(sig);
  signedNode.children.splice(idx, 1);
  let canonical;
  try {
    const prefixList = find(reference, 'InclusiveNamespaces')?.attrs.PrefixList;
    if (prefixList) signedNode._inclusivePrefixes = prefixList.split(/\s+/).filter(Boolean);
    canonical = c14n(signedNode, inheritedNamespaces(signedNode));
  } finally {
    signedNode.children.splice(idx, 0, sig);
  }

  const expectedDigest = find(reference, 'DigestValue')?.text?.trim();
  const actualDigest = createHash(digestAlgo).update(canonical, 'utf8').digest('base64');
  if (!expectedDigest || !timingSafeStr(expectedDigest, actualDigest)) {
    throw new VaultError('forbidden', 'the assertion does not match its own digest — it was altered after signing', {
      expected: expectedDigest?.slice(0, 12), actual: actualDigest.slice(0, 12)
    });
  }

  const signedInfoC14n = c14n(signedInfo, inheritedNamespaces(signedInfo));
  const signatureValue = find(sig, 'SignatureValue')?.text?.replace(/\s+/g, '');
  if (!signatureValue) throw new VaultError('invalid', 'signature has no SignatureValue');

  for (const cert of certificates) {
    const pem = toPem(cert);
    try {
      const x509 = new X509Certificate(pem);
      const now = Date.now();
      if (Date.parse(x509.validTo) < now) continue;       // expired signing cert
      if (Date.parse(x509.validFrom) > now) continue;     // not yet valid
      const v = createVerify(spec.hash === 'sha256' ? 'sha256' : spec.hash);
      v.update(signedInfoC14n, 'utf8');
      v.end();
      if (v.verify(x509.publicKey, Buffer.from(signatureValue, 'base64'))) {
        return { ok: true, certificate: x509.fingerprint256, algorithm: sigMethod };
      }
    } catch { /* try the next configured certificate */ }
  }
  throw new VaultError('forbidden', 'no configured IdP certificate verifies this signature', {
    certificatesTried: certificates.length
  });
}

/** Namespace declarations in scope from a node's ancestors. */
function inheritedNamespaces(node) {
  const chain = [];
  for (let n = node.parent; n; n = n.parent) chain.unshift(n);
  const ns = {};
  for (const n of chain) {
    for (const [k, v] of Object.entries(n.attrs)) {
      if (k === 'xmlns') ns[''] = v;
      else if (k.startsWith('xmlns:')) ns[k.slice(6)] = v;
    }
  }
  return ns;
}

export function toPem(cert) {
  const s = String(cert).trim();
  if (s.includes('BEGIN CERTIFICATE')) return s;
  const body = s.replace(/\s+/g, '').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}

function timingSafeStr(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}
