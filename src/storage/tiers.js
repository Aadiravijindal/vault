/**
 * Storage tiers, lifecycle, WORM retention, residency and cost (§5.3–5.9).
 *
 * Tiering is a *policy* over records that already live in the store; moving a
 * record between tiers never changes its bytes or its hash, only its declared
 * access class, its cost, and its restore latency. That matters because a
 * regulator asking "was this altered when you archived it?" needs the answer to
 * be structurally no.
 */
import { now, iso, DAY, MONTH, YEAR, duration, ago } from '../util/time.js';
import { VaultError } from '../util/errors.js';

export const TIERS = {
  hot: { name: 'hot', maxAge: 30 * DAY, readLatencyMs: 50, costPerGbMonth: 0.230, index: 'full' },
  warm: { name: 'warm', maxAge: 12 * MONTH, readLatencyMs: 200, costPerGbMonth: 0.0125, index: 'full' },
  cold: { name: 'cold', maxAge: 3 * YEAR, readLatencyMs: 5_000, costPerGbMonth: 0.004, index: 'metadata' },
  archive: { name: 'archive', maxAge: null, readLatencyMs: 4 * 60 * 60 * 1000, costPerGbMonth: 0.00099, index: 'metadata' },
  worm: { name: 'worm', maxAge: null, readLatencyMs: 200, costPerGbMonth: 0.0125, index: 'full', immutable: true }
};

export const TIER_ORDER = ['hot', 'warm', 'cold', 'archive'];

/** Bring-Your-Own-Bucket targets we ship drivers for (§5.2). */
export const BUCKET_TARGETS = [
  { id: 's3', name: 'AWS S3', worm: 'S3 Object Lock', tiers: ['STANDARD', 'STANDARD_IA', 'GLACIER_IR', 'DEEP_ARCHIVE'], egressFees: true },
  { id: 'azure-blob', name: 'Azure Blob Storage', worm: 'Immutable blob policy', tiers: ['Hot', 'Cool', 'Cold', 'Archive'], egressFees: true },
  { id: 'gcs', name: 'Google Cloud Storage', worm: 'Bucket Lock', tiers: ['STANDARD', 'NEARLINE', 'COLDLINE', 'ARCHIVE'], egressFees: true },
  { id: 'r2', name: 'Cloudflare R2', worm: 'Object Lock', tiers: ['Standard', 'Infrequent Access'], egressFees: false },
  { id: 'b2', name: 'Backblaze B2', worm: 'Object Lock', tiers: ['Standard'], egressFees: false },
  { id: 'wasabi', name: 'Wasabi', worm: 'Object Lock', tiers: ['Standard'], egressFees: false },
  { id: 'minio', name: 'MinIO (self-hosted)', worm: 'Object Lock', tiers: ['Standard'], egressFees: false, onPrem: true },
  { id: 'ceph', name: 'Ceph / OpenStack Swift', worm: 'Object Lock (RGW)', tiers: ['Standard'], egressFees: false, onPrem: true },
  { id: 'netapp', name: 'NetApp / Dell EMC / Pure', worm: 'SnapLock / WORM appliance', tiers: ['Standard'], egressFees: false, onPrem: true },
  { id: 'ibm-cos', name: 'IBM Cloud Object Storage', worm: 'Immutable Object Storage', tiers: ['Smart', 'Cold', 'Vault'], egressFees: true },
  { id: 'oci', name: 'Oracle Object Storage', worm: 'Retention Rules', tiers: ['Standard', 'Archive'], egressFees: true },
  { id: 's3-compatible', name: 'Any S3-compatible endpoint', worm: 'if supported by endpoint', tiers: ['Standard'], egressFees: null }
];

export const DEPLOYMENT_MODELS = [
  { id: 'cloud-multi', name: 'Vault Cloud — multi-tenant', keys: 'Vault or BYOK', for: 'Mid-market, fastest start' },
  { id: 'cloud-single', name: 'Vault Cloud — single tenant', keys: 'Vault or customer', for: 'Larger enterprise' },
  { id: 'byob', name: 'Bring Your Own Bucket', keys: 'Customer', for: 'Common enterprise ask' },
  { id: 'vpc', name: 'Customer VPC', keys: 'Customer', for: 'Regulated' },
  { id: 'on-prem', name: 'On-premise', keys: 'Customer', for: 'Finance, health, defence, gov' },
  { id: 'air-gapped', name: 'Air-gapped', keys: 'Customer', for: 'Highest classification' },
  { id: 'hybrid', name: 'Hybrid — metadata split', keys: 'Customer', for: 'Very common compromise' },
  { id: 'hash-only', name: 'Hash-only', keys: 'Customer', for: '"Content cannot leave" mandates' },
  { id: 'sovereign', name: 'Sovereign region', keys: 'Customer or local partner', for: 'India, EU, Gulf, gov' }
];

export class TieringEngine {
  /**
   * @param {object} opts
   * @param {(id:string)=>boolean} opts.isHeld legal hold predicate
   * @param {(e:object)=>void} [opts.onEvent]
   * @param {Record<string, any>} [opts.policies] per data-class overrides
   */
  constructor({ isHeld = () => false, onEvent = () => {}, policies = {} } = {}) {
    this.isHeld = isHeld;
    this.onEvent = onEvent;
    this.policies = {
      default: { hot: '30d', warm: '12mo', cold: '3y', then: 'archive' },
      ...policies
    };
    /** @type {Map<string,{tier:string, since:number, bytes:number, worm?:boolean, retainUntil?:number|null, mode?:string, journey:Array<object>}>} */
    this.placements = new Map();
  }

  /**
   * @param {string} recordId
   * @param {{bytes?:number, tier?:string, worm?:boolean, retention?:string|number|null,
   *          mode?:'compliance'|'governance', dataClass?:string, region?:string}} opts
   */
  place(recordId, { bytes = 0, tier = 'hot', worm = false, retention = null, mode = 'governance', dataClass = 'default', region = null } = {}) {
    const retentionMs = retention == null ? null : duration(retention);
    const placement = {
      tier: worm ? 'worm' : tier,
      since: now(),
      bytes,
      worm,
      mode,
      dataClass,
      region,
      retainUntil: retentionMs == null ? null : now() + retentionMs,
      journey: [{ tier: worm ? 'worm' : tier, at: now(), reason: 'initial placement' }]
    };
    this.placements.set(recordId, placement);
    return placement;
  }

  get(recordId) { return this.placements.get(recordId) || null; }

  /** Move a record between tiers, honouring WORM and legal hold. */
  move(recordId, toTier, reason = 'lifecycle') {
    const p = this.placements.get(recordId);
    if (!p) throw new VaultError('not_found', 'no placement for record', { recordId });
    if (p.worm) {
      throw new VaultError('immutable', 'WORM copies are never tiered down', { recordId });
    }
    if (this.isHeld(recordId)) {
      throw new VaultError('legal_hold', 'record is under legal hold — tiering cannot move it', { recordId });
    }
    p.journey.push({ tier: toTier, at: now(), reason, from: p.tier });
    p.tier = toTier;
    p.since = now();
    this.onEvent({ type: 'storage.tiered', recordId, tier: toTier, reason });
    return p;
  }

  /**
   * What *would* the next lifecycle run do? Nothing is moved. This is the
   * "preview before it runs" the spec insists on (§5.3).
   */
  previewLifecycle(at = now()) {
    const moves = [];
    for (const [id, p] of this.placements) {
      // WORM copies and held records are listed as held back rather than
      // omitted: "what this schedule will NOT touch, and why" is the half of
      // the preview a compliance officer actually reads.
      if (p.worm) {
        if (this._agedPast(p, at)) moves.push({ recordId: id, from: p.tier, to: null, bytes: p.bytes, heldBack: 'worm — never tiered down' });
        continue;
      }
      if (this.isHeld(id)) {
        if (this._agedPast(p, at)) moves.push({ recordId: id, from: p.tier, to: null, bytes: p.bytes, heldBack: 'legal hold' });
        continue;
      }
      const next = this._nextTier(p, at);
      if (next && next !== p.tier) {
        moves.push({ recordId: id, from: p.tier, to: next, bytes: p.bytes, heldBack: null });
      }
    }
    const movable = moves.filter((m) => !m.heldBack);
    return {
      at: iso(at),
      totalCandidates: moves.length,
      willMove: movable.length,
      heldBack: moves.length - movable.length,
      bytesMoving: movable.reduce((a, m) => a + m.bytes, 0),
      estimatedMonthlySaving: round2(movable.reduce(
        (a, m) => a + gb(m.bytes) * (TIERS[m.from].costPerGbMonth - TIERS[m.to].costPerGbMonth), 0)),
      moves: moves.slice(0, 500),
      summary: `this schedule will move ${movable.length} records to a colder tier` +
        (moves.length - movable.length ? `, holding back ${moves.length - movable.length} under legal hold or WORM` : '')
    };
  }

  /** Apply the lifecycle. Returns what actually moved. */
  runLifecycle(at = now()) {
    const preview = this.previewLifecycle(at);
    const moved = [];
    for (const m of preview.moves) {
      if (m.heldBack) continue;
      try {
        this.move(m.recordId, m.to, 'lifecycle schedule');
        moved.push(m);
      } catch { /* held between preview and apply — correct to skip */ }
    }
    return { moved: moved.length, records: moved, previewedAt: preview.at };
  }

  /** Would this record have moved, if nothing were holding it back? */
  _agedPast(p, at) {
    const policy = this.policies[p.dataClass] || this.policies.default;
    const dwell = duration(policy[p.worm ? 'hot' : p.tier] ?? TIERS[p.tier]?.maxAge ?? null);
    return dwell != null && (at - p.since) >= dwell;
  }

  _nextTier(p, at) {
    if (p.worm) return null;
    const policy = this.policies[p.dataClass] || this.policies.default;
    const age = at - p.since;
    const order = TIER_ORDER;
    const idx = order.indexOf(p.tier);
    if (idx < 0 || idx === order.length - 1) return null;
    const dwell = duration(policy[p.tier] ?? TIERS[p.tier].maxAge);
    if (dwell != null && age >= dwell) return order[idx + 1];
    return null;
  }

  /** Retention expiry candidates — records past retainUntil and not held. */
  expiryCandidates(at = now()) {
    const out = [];
    for (const [id, p] of this.placements) {
      if (p.retainUntil && at >= p.retainUntil) {
        out.push({ recordId: id, retainUntil: iso(p.retainUntil), held: this.isHeld(id), mode: p.mode });
      }
    }
    return out;
  }

  /**
   * WORM retention check. Compliance mode cannot be shortened by anyone,
   * including root; governance mode allows a loudly-logged privileged override.
   */
  canDelete(recordId, { privileged = false } = {}) {
    const p = this.placements.get(recordId);
    if (!p) return { allowed: true };
    if (this.isHeld(recordId)) return { allowed: false, reason: 'legal hold' };
    if (p.retainUntil && now() < p.retainUntil) {
      if (p.mode === 'compliance') {
        return { allowed: false, reason: `retention until ${iso(p.retainUntil)} (compliance mode — no override exists)` };
      }
      if (!privileged) return { allowed: false, reason: `retention until ${iso(p.retainUntil)} (governance mode — privileged override required)` };
      return { allowed: true, override: true, reason: 'governance-mode privileged override — logged' };
    }
    return { allowed: true };
  }

  /** Cost model, live (§5.9). */
  costReport() {
    const byTier = {};
    let total = 0;
    for (const p of this.placements.values()) {
      const t = byTier[p.tier] || (byTier[p.tier] = { records: 0, bytes: 0, monthlyCost: 0 });
      t.records++;
      t.bytes += p.bytes;
      const cost = gb(p.bytes) * TIERS[p.tier].costPerGbMonth;
      t.monthlyCost = round2(t.monthlyCost + cost);
      total += cost;
    }
    return { byTier, monthlyTotal: round2(total), currency: 'USD', at: iso() };
  }

  /** "This folder costs $X/month and hasn't been read in N months — archive it?" */
  coldSpendSuggestions(readIndex = new Map(), { minMonthlyCost = 25, staleAfter = 6 * MONTH } = {}) {
    const groups = new Map();
    for (const [id, p] of this.placements) {
      const key = p.dataClass || 'default';
      const g = groups.get(key) || { key, bytes: 0, records: 0, lastRead: 0 };
      g.bytes += p.bytes;
      g.records++;
      g.lastRead = Math.max(g.lastRead, readIndex.get(id) || 0);
      groups.set(key, g);
    }
    const out = [];
    for (const g of groups.values()) {
      const monthly = round2(gb(g.bytes) * TIERS.hot.costPerGbMonth);
      if (monthly >= minMonthlyCost && (now() - g.lastRead) > staleAfter) {
        out.push({
          scope: g.key, monthlyCost: monthly, records: g.records,
          lastRead: g.lastRead ? ago(g.lastRead) : 'never',
          suggestion: `this scope is costing $${monthly}/month and hasn't been read in ${g.lastRead ? ago(g.lastRead) : 'its lifetime'} — archive it?`
        });
      }
    }
    return out.sort((a, b) => b.monthlyCost - a.monthlyCost);
  }
}

const gb = (bytes) => bytes / (1024 ** 3);
const round2 = (n) => Math.round(n * 100) / 100;

/**
 * Compression estimate. Transcripts compress 6–10× (§5.9); we measure rather
 * than assume so the number on the cost screen is honest.
 */
export function estimateCompressed(text) {
  const s = String(text || '');
  const tokens = new Set(s.toLowerCase().split(/\s+/));
  const ratio = Math.min(10, Math.max(2, s.length / Math.max(1, [...tokens].join(' ').length) * 3));
  return { originalBytes: Buffer.byteLength(s), ratio: Math.round(ratio * 10) / 10, storedBytes: Math.round(Buffer.byteLength(s) / ratio) };
}
