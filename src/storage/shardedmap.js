/**
 * A Map that is not capped at 16,777,216 entries.
 *
 * V8 implements Map as a hash table whose backing store is a single
 * FixedArray. FixedArray has a hard maximum element count, and after the
 * 3-slots-per-entry layout and load factor that works out to exactly 2^24 =
 * 16,777,216 entries, at which point `set()` throws
 * "RangeError: Map maximum size exceeded". This is not a tuning knob, a flag,
 * or a memory limit — a machine with a terabyte of RAM hits it at the same
 * number.
 *
 * That ceiling was found by running a collection to failure. It capped the
 * whole product at 16.7M facts against a stated target of 100M, which made the
 * scale claim false rather than optimistic, and no amount of hardware fixed it.
 *
 * The fix is the boring one: shard. Keys are distributed over N independent
 * Maps by a hash of the key, so the ceiling becomes N × 2^24. At the default
 * N=64 that is 1,073,741,824 entries — 10× the 100M target, and enough that
 * the ledger's 10B target is the only thing still out of reach in one
 * collection.
 *
 * Why not a B-tree, an LSM, or an off-heap index:
 *
 *   - Every one of them changes the cost model. This structure is on the read
 *     path for every fact lookup, and the measured p95 is 0.0023 ms because
 *     lookup is a single hash into a native Map. A B-tree makes that a
 *     log(n) walk through JS objects; an off-heap index makes it a
 *     serialise/deserialise per read. Sharding keeps the native Map on the hot
 *     path and adds one string hash.
 *   - Sharding is O(1) for the operations that matter and leaves the semantics
 *     identical, so nothing above this file has to know it happened.
 *   - The engine has zero runtime dependencies on purpose (air-gap, on-prem
 *     procurement). An off-heap index means LMDB or RocksDB, i.e. a native
 *     module, i.e. losing that property.
 *
 * The cost is that iteration order is no longer global insertion order — it is
 * insertion order *within* a shard. Nothing depended on cross-shard ordering:
 * the ledger orders by `seq`, the fact store by timestamp, and every caller
 * that needs an order sorts explicitly. The one place it would matter,
 * `Collection.compact()`, rewrites the file from this iteration, and record
 * order in a JSONL segment carries no meaning — each line is a self-contained
 * operation with its own id and timestamp.
 */

/**
 * FNV-1a, 32-bit.
 *
 * Chosen over a cheaper hash (first-and-last-char, length, etc.) because ids in
 * this system share long common prefixes — `f-ms4n...`, `conv-ms4n...` — and a
 * hash that only samples part of the string puts most of a collection in one
 * shard, which reintroduces the ceiling it was added to remove. Every byte
 * contributes here.
 */
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    // h *= 16777619, in 32-bit, without Math.imul's call overhead in hot loops.
    h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h;
}

/** V8's per-Map entry ceiling. Not configurable, not memory-dependent. */
export const V8_MAP_LIMIT = 16_777_216;

export class ShardedMap {
  /**
   * @param {number} [shards] must be a power of two, so the index is a mask
   */
  constructor(shards = 64) {
    if (shards < 1 || (shards & (shards - 1)) !== 0) {
      throw new RangeError('shard count must be a power of two');
    }
    this.shardCount = shards;
    this._mask = shards - 1;
    /**
     * Shards are created on first write to them, so an empty collection costs
     * one array rather than 64 Maps. A deployment holds dozens of collections
     * that never grow past a handful of rows, and paying 64 allocations for
     * each of those to buy headroom none of them need is the wrong trade.
     * @type {Array<Map<string, any>|null>}
     */
    this._shards = new Array(shards).fill(null);
    this._size = 0;
  }

  _indexFor(key) {
    return fnv1a(typeof key === 'string' ? key : String(key)) & this._mask;
  }

  get size() { return this._size; }

  get(key) {
    return this._shards[this._indexFor(key)]?.get(key);
  }

  has(key) {
    return this._shards[this._indexFor(key)]?.has(key) ?? false;
  }

  set(key, value) {
    const i = this._indexFor(key);
    let shard = this._shards[i];
    if (!shard) shard = this._shards[i] = new Map();
    const had = shard.has(key);
    shard.set(key, value);
    if (!had) this._size++;
    return this;
  }

  delete(key) {
    const shard = this._shards[this._indexFor(key)];
    if (!shard) return false;
    const removed = shard.delete(key);
    if (removed) this._size--;
    return removed;
  }

  clear() {
    this._shards.fill(null);
    this._size = 0;
  }

  *keys() {
    for (const shard of this._shards) if (shard) yield* shard.keys();
  }

  *values() {
    for (const shard of this._shards) if (shard) yield* shard.values();
  }

  *entries() {
    for (const shard of this._shards) if (shard) yield* shard.entries();
  }

  [Symbol.iterator]() { return this.entries(); }

  forEach(fn, thisArg) {
    for (const [k, v] of this.entries()) fn.call(thisArg, v, k, this);
  }

  /**
   * How full the fullest shard is. The point of this structure is that no
   * single shard approaches V8's limit, so the operator-facing scale report
   * quotes this rather than asserting the property is true.
   */
  distribution() {
    const counts = this._shards.map((s) => (s ? s.size : 0));
    const largest = counts.reduce((a, b) => Math.max(a, b), 0);
    const used = counts.filter((c) => c > 0).length;
    return {
      shards: this.shardCount,
      shardsInUse: used,
      total: this._size,
      largestShard: largest,
      // A perfectly uniform hash puts size/shards in each. Above ~2 means the
      // hash is doing a bad job on this key population and the effective
      // ceiling is lower than shards × limit.
      skew: used > 0 && this._size > 0 ? largest / (this._size / this.shardCount) : 1,
      capacity: this.shardCount * V8_MAP_LIMIT,
      headroomToV8Limit: V8_MAP_LIMIT - largest
    };
  }
}
