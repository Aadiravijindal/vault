/**
 * SOC 2 readiness — and the refusal to imply an audit.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Vault } from '../src/index.js';
import { Ledger } from '../src/ledger/ledger.js';
import { assessReadiness, renderReadiness, TSC } from '../src/comply/readiness.js';
import { runRedTeam, recordRedTeamRun } from '../src/security/redteam.js';

function busyVault() {
  const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] });
  v.registerAgent({
    id: 'a1', name: 'a', purpose: 'p', businessOwner: 'O', technicalOwner: 'T',
    department: 'sales', mode: 'inline', pinnedModel: 'm', folders: ['sales/'],
    rateLimitPerHour: 20000
  });
  const credential = v.issueCredential('a1', {}).credential;
  for (let i = 0; i < 5; i++) {
    v.ingest({
      agentId: 'a1', channel: 'phone_call_authenticated',
      participants: [{ name: 'C', kind: 'external', org: 'Acme' }],
      turns: [{ speaker: 'C', text: `Acme wants a Q3 start date and the contract value is ${1000 + i}.` }]
    }, { credential });
  }
  return { v, credential };
}

describe('readiness measures the system, not a checklist', () => {
  test('an untouched system is not audit ready, and says so', () => {
    const v = new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] });
    const r = assessReadiness(v);
    assert.ok(r.ready < r.total, 'a system with no traffic cannot have operating controls');
    assert.ok(r.notReady.length > 0);
    for (const c of r.notReady) assert.ok(c.blocker, `${c.id} is not ready but names no blocker`);
  });

  test('using the system moves the number', () => {
    const before = assessReadiness(new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] })).ready;
    const { v } = busyVault();
    assert.ok(assessReadiness(v).ready > before,
      'if traffic does not change readiness, it is measuring a checklist rather than the system');
  });

  test('a red-team run is what makes the adversarial control operate', () => {
    const { v, credential } = busyVault();
    const before = assessReadiness(v).controls.find((c) => c.id === 'VLT-12');
    assert.notEqual(before.status, 'operating');

    recordRedTeamRun(v.comply, runRedTeam({ vault: v, credential, agentId: 'a1' }), 'ciso');
    const after = assessReadiness(v).controls.find((c) => c.id === 'VLT-12');
    assert.equal(after.status, 'operating');
  });

  test('a control outside the observation window does not count as operating', () => {
    const { v } = busyVault();
    // Nothing can have happened in a zero-day window.
    const r = assessReadiness(v, { windowDays: 0 });
    assert.ok(r.ready <= assessReadiness(v, { windowDays: 90 }).ready);
  });
});

describe('what code cannot close is stated, not implied', () => {
  test('the report names the external parties an audit requires', () => {
    const r = assessReadiness(new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] }));
    const items = r.requiresAnExternalParty.map((x) => x.item.toLowerCase()).join(' | ');
    assert.match(items, /soc 2 type ii opinion/);
    assert.match(items, /penetration test/);
    assert.match(items, /observation window/);
  });

  test('the red team is never described as a penetration test', () => {
    const r = assessReadiness(new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] }));
    const pen = r.requiresAnExternalParty.find((x) => /penetration/i.test(x.item));
    assert.match(pen.why, /[Nn]either is a penetration test/);
    assert.equal(pen.status, 'not engaged');
  });

  test('readiness is never rendered as an audit', () => {
    const text = renderReadiness(assessReadiness(new Vault({ signingKey: Ledger.newSigningKey(), administrators: ['ciso'] })));
    assert.match(text, /CANNOT BE CLOSED BY CODE/);
    assert.match(text, /audit readiness, not an audit/);
  });

  test('organisational criteria are marked as not carried by the product', () => {
    assert.equal(TSC.CC1.vaultCarries, false);
    assert.match(TSC.CC1.note, /No product can evidence this for you/i);
  });
});
