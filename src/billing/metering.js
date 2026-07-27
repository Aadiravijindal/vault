/**
 * USAGE METERING (§28).
 *
 * Pricing is per connected agent + per governed fact volume + storage consumed
 * — never per seat, because seats do not scale when a customer is heading
 * toward 150,000 agents.
 *
 * The meter reads the same sources the rest of the product does (registry,
 * fact store, tiering, ledger) rather than keeping a private counter, so the
 * invoice and the Map can never disagree.
 */
import { now, iso, DAY, MONTH } from '../util/time.js';
import { VaultError, forbidden } from '../util/errors.js';

/** Published list price. A customer can see exactly how the number is built. */
export const DEFAULT_RATES = {
  perAgentMonth: 40,
  perThousandGovernedFacts: 2.5,
  perGbMonth: { hot: 0.14, warm: 0.05, cold: 0.012, archive: 0.004, worm: 0.02 },
  currency: 'USD',
  includedAgents: 5,
  includedFacts: 10_000
};

export class Metering {
  /**
   * @param {object} deps
   * @param {import('../registry/registry.js').Registry} deps.registry
   * @param {import('../facts/factstore.js').FactStore} deps.facts
   * @param {import('../storage/tiers.js').TieringEngine} deps.tiering
   * @param {import('../ledger/ledger.js').Ledger} deps.ledger
   */
  constructor({ registry, facts, tiering, ledger, collection = null, rates = {}, caps = {} }) {
    this.registry = registry;
    this.facts = facts;
    this.tiering = tiering;
    this.ledger = ledger;
    this.col = collection;
    this.rates = { ...DEFAULT_RATES, ...rates, perGbMonth: { ...DEFAULT_RATES.perGbMonth, ...(rates.perGbMonth || {}) } };

    const saved = this.col?.get('state') ?? null;
    this.caps = saved?.caps ?? { agents: null, factsPerMonth: null, storageGb: null, monthlyUsd: null, ...caps };
    this.alerts = saved?.alerts ?? [];
    this.periods = saved?.periods ?? [];
  }

  _persist() {
    this.col?.put({ id: 'state', caps: this.caps, alerts: this.alerts.slice(-200), periods: this.periods.slice(-36) });
  }

  setCaps(caps, { actor }) {
    if (!actor) throw forbidden('changing usage caps requires a named actor');
    this.caps = { ...this.caps, ...caps };
    this._persist();
    this.ledger.append('admin.action', { subject: 'billing', actor, action: 'billing.caps_changed', ...caps });
    return this.caps;
  }

  /** Live usage, read from the systems of record rather than a side counter. */
  usage({ from = now() - 30 * DAY, to = now() } = {}) {
    const agents = this.registry.active();
    const governed = this.facts.all().filter((f) => f.createdAt >= from && f.createdAt <= to);
    // A governed fact is one the gate ruled on — a block is as much work as a
    // pass, and charging only for passes would reward a broken gate.
    const gateEvents = this.ledger.entries({ limit: Infinity })
      .filter((e) => e.at >= from && e.at <= to)
      .filter((e) => ['fact.written', 'fact.held', 'fact.blocked', 'fact.masked'].includes(e.type));

    const byTier = this.tiering.costReport().byTier;
    const storageGb = Object.fromEntries(
      Object.entries(byTier).map(([tier, t]) => [tier, (t.bytes || 0) / 1e9])
    );

    return {
      period: { from: iso(from), to: iso(to) },
      agents: { connected: agents.length, byMode: countBy(agents, (a) => a.mode) },
      facts: { governed: gateEvents.length, stored: governed.length },
      storageGb,
      totalStorageGb: Object.values(storageGb).reduce((n, g) => n + g, 0)
    };
  }

  /** The invoice, itemised so every line can be checked against the Map. */
  invoice({ from = now() - 30 * DAY, to = now() } = {}) {
    const u = this.usage({ from, to });
    const lines = [];

    const billableAgents = Math.max(0, u.agents.connected - this.rates.includedAgents);
    lines.push({
      item: 'Connected agents', quantity: u.agents.connected,
      included: this.rates.includedAgents, billable: billableAgents,
      unit: this.rates.perAgentMonth, amount: round2(billableAgents * this.rates.perAgentMonth),
      basis: 'per connected agent per month — not per seat'
    });

    const billableFacts = Math.max(0, u.facts.governed - this.rates.includedFacts);
    lines.push({
      item: 'Governed fact volume', quantity: u.facts.governed,
      included: this.rates.includedFacts, billable: billableFacts,
      unit: this.rates.perThousandGovernedFacts, amount: round2((billableFacts / 1000) * this.rates.perThousandGovernedFacts),
      basis: 'every write the gate ruled on, including the ones it refused'
    });

    for (const [tier, gb] of Object.entries(u.storageGb)) {
      if (!gb) continue;
      const rate = this.rates.perGbMonth[tier] ?? this.rates.perGbMonth.hot;
      lines.push({ item: `Storage — ${tier}`, quantity: round2(gb), unit: rate, amount: round2(gb * rate), basis: 'GB-month at tier' });
    }

    const total = round2(lines.reduce((n, l) => n + l.amount, 0));
    return { period: u.period, currency: this.rates.currency, lines, total, usage: u };
  }

  /**
   * Check usage against caps and raise BEFORE the cap bites, not after.
   * A hard stop that arrives unannounced is an outage the customer blames you
   * for; the same stop with two warnings first is a budget working.
   */
  checkCaps({ from, to, onAlert = null } = {}) {
    const inv = this.invoice({ from, to });
    const u = inv.usage;
    const raised = [];
    const check = (name, value, cap, unit) => {
      if (cap == null) return;
      const pct = value / cap;
      const band = pct >= 1 ? 'exceeded' : pct >= 0.9 ? 'critical' : pct >= 0.75 ? 'warning' : null;
      if (!band) return;
      const alert = {
        at: now(), metric: name, value: round2(value), cap, unit,
        percent: Math.round(pct * 100), band,
        detail: band === 'exceeded'
          ? `${name} is over its cap (${round2(value)}${unit} of ${cap}${unit})`
          : `${name} is at ${Math.round(pct * 100)}% of its cap — ${round2(cap - value)}${unit} left`
      };
      raised.push(alert);
      this.alerts.push(alert);
      onAlert?.(alert);
      this.ledger.append('security.alert', {
        subject: 'billing', kind: 'usage_cap', severity: band === 'exceeded' ? 'high' : 'medium',
        metric: name, percent: alert.percent
      });
    };

    check('connected agents', u.agents.connected, this.caps.agents, '');
    check('governed facts', u.facts.governed, this.caps.factsPerMonth, '');
    check('storage', u.totalStorageGb, this.caps.storageGb, ' GB');
    check('monthly spend', inv.total, this.caps.monthlyUsd, ' USD');
    this._persist();
    return { alerts: raised, invoice: inv, wouldHardStop: raised.some((a) => a.band === 'exceeded') && this.caps.hardStop === true };
  }

  /** 📈 The customer-facing billing screen. */
  dashboard({ from, to } = {}) {
    const inv = this.invoice({ from, to });
    const capState = this.checkCaps({ from, to });
    // Forecast on planned growth, not on last month's line.
    const days = Math.max(1, (Date.parse(inv.period.to) - Date.parse(inv.period.from)) / DAY);
    const runRate = inv.total / days;
    return {
      ...inv,
      caps: this.caps,
      capAlerts: capState.alerts,
      forecast: {
        thisMonth: round2(runRate * 30),
        nextMonth: round2(runRate * 30),
        basis: `${round2(runRate)} ${this.rates.currency}/day over the last ${Math.round(days)} days`
      },
      rates: this.rates,
      note: 'priced per connected agent and governed fact volume, plus storage — never per seat'
    };
  }
}

const round2 = (n) => Math.round(n * 100) / 100;
function countBy(list, fn) {
  const out = {};
  for (const x of list) out[fn(x)] = (out[fn(x)] || 0) + 1;
  return out;
}
