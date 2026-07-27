/**
 * Jurisdiction packs (§15.3–15.5) — the documents, not just the settings.
 *
 * The failure mode these tests exist to catch is subtle and expensive: a pack
 * that has the right *settings* but hands the works council the wrong
 * *instrument*. A Dutch OR presented with a German Betriebsvereinbarung, or a
 * Swedish union handed a "consent request" when the law gives them a
 * negotiation right and no veto, reads that as an employer who has not done the
 * work — and the six-week approval becomes an eighteen-month one.
 *
 * So these assert on the legal mechanism each document invokes, in the language
 * the reading body actually works in.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { JURISDICTIONS, jurisdictionPack, listJurisdictions } from '../src/privacy/jurisdictions.js';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';

const render = (id) => {
  const pack = JURISDICTIONS[id];
  return pack.documents.map((d) => ({
    name: d.name,
    body: d.body({ settings: pack.settings, generatedAt: '2026-07-27' })
  }));
};
const joined = (id) => render(id).map((d) => `${d.name}\n${d.body}`).join('\n\n');

describe('co-determination packs name the right instrument, in the right language', () => {
  test('Austria cites ArbVG §96(1) Z3 and says the works council cannot be overruled', () => {
    const text = joined('at');
    assert.match(text, /§\s*96 Abs\. 1 Z 3 ArbVG/, 'the consent-based paragraph must be cited');
    assert.match(text, /§\s*96a/, 'and the §96a alternative, because which one applies decides who holds the veto');
    assert.match(text, /Schlichtungsstelle/, 'Austria arbitrates through the Schlichtungsstelle, not the Einigungsstelle');
    assert.equal(/Einigungsstelle/.test(text), false,
      'the Einigungsstelle is a German body — citing it in an Austrian agreement is the tell that the pack was copied');
    assert.match(text, /Nachwirkung nach § 32 Abs\. 3 ArbVG wird ausdrücklich ausgeschlossen/,
      'the after-effect clause is the one an Austrian employer most regrets omitting');
    assert.match(text, /Menschenwürde/, 'the §96(1) Z3 trigger is human dignity, and must appear as such');
  });

  test('the Netherlands asks for instemming under Article 27 and names the nullity clock', () => {
    const text = joined('nl');
    assert.match(text, /artikel 27 WOR/i);
    assert.match(text, /instemming/i, 'Dutch law gives consent, not advice');
    assert.match(text, /nietigheid/, 'the OR can void the decision — an employer who does not know that gets surprised by it');
    assert.match(text, /binnen één maand/, 'and the window is one month');
    assert.match(text, /kantonrechter/, 'substitute consent under Art 27(4) must be named');
    assert.match(text, /ondernemingsraad/i);
    assert.equal(/Betriebsrat|Betriebsvereinbarung/.test(text), false, 'no German text in a Dutch consent request');
  });

  test('Sweden summons a negotiation under MBL §11 — not a consent request', () => {
    const text = joined('se');
    assert.match(text, /11 § MBL/);
    assert.match(text, /19 § MBL/, 'the §19 information duty is what the union is actually owed');
    assert.match(text, /förhandling/i);
    assert.match(text, /intresseavvägning/i, 'and the Art 6(1)(f) balancing test is a separate Swedish document');
    // The single most common error: treating Sweden like the Netherlands.
    assert.equal(/instemming|consent request|samtyckesbegäran/i.test(text), false,
      'MBL is a duty to negotiate before deciding, not a consent regime');
    assert.match(text, /14 § MBL/, 'central negotiation must be offered if local negotiation fails');
  });

  test('France consults the CSE, informs each employee, and gets the deadlines right', () => {
    const text = joined('fr');
    assert.match(text, /L\.\s*2312-38/);
    assert.match(text, /L\.\s*2312-8/);
    assert.match(text, /L\.\s*1222-4/, 'the individual notice is the step that decides prud\'hommes admissibility');
    assert.match(text, /un mois/, 'the CSE opinion deadline');
    assert.match(text, /deux mois/, 'extended where an expert is appointed');
    assert.match(text, /L\.\s*1121-1/, 'proportionality has its own article and must be cited');
    assert.match(text, /déconnexion/);
    assert.match(text, /registre des traitements/);
    assert.equal(/works council agreement|Betriebsvereinbarung/i.test(text), false);
  });

  test('India states plainly that there is no dedicated monitoring statute, then maps the five that apply', () => {
    const text = joined('in');
    assert.match(text, /no dedicated employee-monitoring statute/i,
      'inventing an Indian equivalent of BetrVG would be exactly the overclaim this product exists to prevent');
    for (const cite of [/§\s*7\(i\)/, /43A/, /SPDI Rules/, /72A/, /Puttaswamy/, /Standing Orders/]) {
      assert.match(text, cite, `missing citation: ${cite}`);
    }
    assert.match(text, /frequently over-read|over-read/i, 'the §7(i) exemption is over-read, and the pack should say so');
    assert.match(text, /issues an employee notice regardless|despite the § 7\(i\) exemption/,
      'relying on an exemption to avoid telling people is the position that loses');
    assert.match(text, /Data Protection Board of India/);
    assert.match(text, /₹250 crore/);
  });
});

describe('packs are generated from live configuration, not pasted', () => {
  test('changing a setting changes the text of every affected document', () => {
    const pack = JURISDICTIONS.fr;
    const strict = pack.documents.map((d) => d.body({ settings: { ...pack.settings, kAnonymityFloor: 25, employeeRetention: '30d', workingHoursOnly: true }, generatedAt: 'X' })).join('\n');
    const loose = pack.documents.map((d) => d.body({ settings: { ...pack.settings, kAnonymityFloor: 3, employeeRetention: '24mo', workingHoursOnly: false }, generatedAt: 'X' })).join('\n');
    assert.match(strict, /k = 25/);
    assert.match(strict, /30d/);
    assert.match(loose, /k = 3/);
    assert.match(loose, /24mo/);
    assert.match(loose, /sans limitation horaire/, 'turning off the working-hours limit must change the French text');
    assert.notEqual(strict, loose, 'a document that does not move when the configuration moves is a PDF, not evidence');
  });

  test('a pack whose individual dashboards are enabled says so, rather than claiming they are absent', () => {
    const pack = JURISDICTIONS.nl;
    const on = pack.documents[0].body({ settings: { ...pack.settings, noIndividualDashboards: false }, generatedAt: 'X' });
    assert.match(on, /beschikbaar/, 'if individual views are on, the consent request must admit it');
    const off = pack.documents[0].body({ settings: pack.settings, generatedAt: 'X' });
    assert.match(off, /bestaan niet in het systeem/);
  });

  test('every document in every pack renders, is substantial, and disclaims legal advice', () => {
    for (const id of Object.keys(JURISDICTIONS)) {
      const pack = JURISDICTIONS[id];
      for (const doc of pack.documents) {
        const body = doc.body({ settings: pack.settings, generatedAt: '2026-07-27' });
        assert.equal(typeof body, 'string', `${id}/${doc.name} did not render`);
        assert.ok(body.length > 500, `${id}/${doc.name} is ${body.length} chars — too thin to hand a regulator`);
        assert.match(body, /not legal advice|keine Rechtsberatung|geen juridisch advies|inte juridisk rådgivning|pas un avis juridique/,
          `${id}/${doc.name} must disclaim`);
        assert.equal(/undefined|\[object Object\]|NaN/.test(body), false,
          `${id}/${doc.name} rendered a template hole`);
      }
    }
  });
});

describe('packs are honest about their own limits', () => {
  test('every consultation-requiring pack states what it does NOT cover', () => {
    for (const [id, pack] of Object.entries(JURISDICTIONS)) {
      if (!pack.requiresConsultation || id === 'global_strictest') continue;
      assert.ok(pack.doesNotCover, `${id} claims to require consultation but never says where its coverage stops`);
      assert.ok(pack.doesNotCover.length > 60, `${id}'s doesNotCover is too vague to be useful`);
    }
  });

  test('the crosswalk cites real provisions, and grew where the packs grew', () => {
    for (const id of ['at', 'nl', 'se', 'fr', 'in']) {
      const keys = Object.keys(JURISDICTIONS[id].crosswalk);
      assert.ok(keys.length >= 4, `${id} crosswalk has only ${keys.length} entries — that is a placeholder, not a mapping`);
      for (const k of keys) assert.ok(JURISDICTIONS[id].crosswalk[k].length > 10, `${id}/${k} maps to nothing meaningful`);
    }
  });

  test('an unknown jurisdiction is a typed error listing the real ones', () => {
    assert.throws(() => jurisdictionPack('atlantis'), (e) => {
      assert.equal(e.code, 'not_found');
      assert.ok(e.meta.available.includes('at'));
      return true;
    });
    assert.equal(jurisdictionPack('AT').id, 'at', 'case should not decide whether a customer gets their pack');
  });
});

describe('the packs reach the product, not just the module', () => {
  test('applying a preset changes enforcement, and the documents come with it', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'], seedRules: false, privacy: { enabled: true, jurisdiction: 'off' } });
    try {
      // Preview first — a works council pack should never arrive as a surprise.
      const preview = v.privacy.preview('nl');
      assert.equal(preview.requiresConsultation, true);
      assert.ok(preview.documentsGenerated.some((n) => /instemmingsverzoek/i.test(n)),
        `preview must name the Dutch instrument, got ${preview.documentsGenerated.join(' | ')}`);

      const applied = v.privacy.apply('nl', { actor: 'dpo' });
      assert.equal(applied.jurisdiction, 'nl');

      const pack = v.privacy.compliancePack();
      assert.ok(pack.documents.length >= 3, 'the pack must bring its paperwork with it');
      const consent = pack.documents.find((d) => /instemmingsverzoek/i.test(d.name));
      assert.ok(consent, 'the Article 27 consent request must be generated, not linked to');
      assert.match(consent.body, /nietigheid/, 'and rendered from live settings');

      // The setting is not decorative: the k-floor really applies afterwards.
      assert.equal(v.privacy.settings.kAnonymityFloor, JURISDICTIONS.nl.settings.kAnonymityFloor);
      assert.equal(v.privacy.isOn(), true);
      assert.equal(v.privacy.settings.noIndividualDashboards, true);
      assert.ok(v.ledger.entries({ limit: Infinity }).some((e) => /jurisdiction|privacy/.test(e.type) || /jurisdiction/.test(JSON.stringify(e))),
        'switching jurisdiction is a governance event and belongs in the ledger');
    } finally { v.close(); }
  });

  test('the listing surfaces every pack with its consultation flag and document count', () => {
    const listed = listJurisdictions();
    assert.equal(listed.length, Object.keys(JURISDICTIONS).length);
    const byId = Object.fromEntries(listed.map((l) => [l.id, l]));
    for (const id of ['at', 'nl', 'se', 'fr']) {
      assert.equal(byId[id].requiresConsultation, true, `${id} requires consultation and the UI must show that before setup, not after`);
      assert.ok(byId[id].documents >= 3, `${id} should ship at least three documents, has ${byId[id].documents}`);
    }
    assert.equal(byId.off.requiresConsultation, false);
  });
});
