/**
 * THE AI MEMORY FILE (.vmem) — what the model has learned, in one small file.
 *
 * Everywhere else in this system, memory means facts: things somebody said,
 * with provenance, behind a wall. This is the other kind — what the FILING has
 * learned about this particular company. That "purchase order" means sales
 * here and procurement somewhere else. That anything mentioning Acme is
 * confidential because a human said so, three times, and the AI was corrected
 * each time. That there is a recurring case it keeps getting wrong.
 *
 * That knowledge used to live nowhere. Every model call started from zero, paid
 * full latency, and made the same mistake a human had already corrected. This
 * file is where it accumulates.
 *
 * ── WHY IT IS A FILE AND NOT A TABLE ────────────────────────────────────────
 *
 * Because it has to be moved, held, verified and thrown away as one thing. An
 * operator can back it up, ship it to the DR site, hand it to an auditor, diff
 * two of them, or delete it and lose nothing but speed. A row in a database is
 * none of those.
 *
 * ── WHAT IS IN IT, AND WHAT IS DELIBERATELY NOT ─────────────────────────────
 *
 * IN:  token → folder associations with counts, client profiles, corrections a
 *      human made, cases the model was unsure about, aggregate statistics.
 * OUT: claims. Verbatim text never enters this file. It holds fact IDs and
 *      counts, never the sentence.
 *
 * That line is not tidiness. A knowledge file that accumulated claim text would
 * become a second copy of the vault with none of the vault's walls — readable
 * by anyone who could read the file, no folder, no sensitivity label, no audit.
 * The single most dangerous thing this file could do is become interesting to
 * steal, so it is built to be boring: counts, ids, and vocabulary.
 *
 * ── WHY IT IS SMALL, AND STAYS SMALL ────────────────────────────────────────
 *
 * Everything is a counter, nothing is a document. Entries decay and the weakest
 * are evicted at a hard cap, so the file has a bounded size no matter how long
 * it runs — a memory that grows forever is a memory nobody keeps. Serialised it
 * is gzipped JSON: a mature file over a busy estate is tens of kilobytes.
 *
 * ── WHY IT IS HARD TO TAMPER WITH ───────────────────────────────────────────
 *
 * Every revision is hash-chained to the last, exactly like the ledger, and the
 * whole file is signed with the customer's key. Editing a learned association
 * to make the AI file a fraud fact into a folder nobody reads breaks the chain,
 * and `verify()` says which revision broke. The chain is the honest claim here:
 * it does not prevent an edit, it makes an edit impossible to hide.
 *
 * ── WHY THIS IS ALSO THE SPEED ANSWER ───────────────────────────────────────
 *
 * A model call is hundreds of milliseconds hosted and seconds locally. A recall
 * against this file is microseconds. So filing consults the memory first, and
 * only calls the model when the memory has no confident prior — which after a
 * few thousand facts is the minority of them. The model teaches the file; the
 * file then answers most of the questions the model used to.
 */
import { gzipSync, gunzipSync } from 'node:zlib';
import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import { sha256, hashObject, chainHash, signMessage, verifyMessage } from '../util/crypto.js';
import { now, iso } from '../util/time.js';
import { contentTokens } from '../util/text.js';
import { VaultError } from '../util/errors.js';

/** Magic bytes, so a wrong file is rejected as a wrong file, not parsed as garbage. */
export const MAGIC = 'VMEM';
export const FORMAT_VERSION = 1;

/** Hard caps. A memory that grows without bound is one nobody keeps. */
export const LIMITS = {
  tokens: 4000,        // distinct vocabulary entries
  clients: 500,        // named entities profiled
  corrections: 1000,   // human corrections retained
  uncertain: 200,      // open cases the model flagged
  revisions: 500       // chain entries kept in the file
};

/**
 * Confidence below which a recall is not acted on.
 *
 * Set where it is because a prior is evidence, not proof: it is what happened
 * last time, and last time is not always this time. Below this the model is
 * asked; above it, the model call is skipped and the prior stands.
 */
export const RECALL_THRESHOLD = 0.72;

export class MemoryFile {
  /**
   * @param {object} [opts]
   * @param {string} [opts.path] where to persist. Absent = in-memory only.
   * @param {{privateKeyPem?:string, publicKeyPem?:string}} [opts.signingKey]
   * @param {string} [opts.tenant] a label, so two files cannot be confused
   */
  constructor({ path = null, signingKey = null, tenant = 'default' } = {}) {
    this.path = path;
    this.signingKey = signingKey;
    this.tenant = tenant;
    this.state = emptyState(tenant);
    if (path && existsSync(path)) this.load();
  }

  // == learning ============================================================

  /**
   * Record where a fact ended up and who decided.
   *
   * `by` matters more than anything else recorded here. A human correction is
   * worth far more than a model's own guess — it is the one signal in the
   * system that is known to be right — so it carries several times the weight
   * and is kept verbatim in `corrections` for an auditor to read back. A model
   * agreeing with itself forever would otherwise harden its own mistakes into
   * confident priors, which is the classic way these systems rot.
   *
   * @param {object} o
   * @param {string} o.factId
   * @param {string} o.folder where it ended up
   * @param {string} o.claim used for vocabulary only; never stored
   * @param {string} o.sensitivity
   * @param {'human'|'model'|'rules'} o.by who decided
   * @param {string[]} [o.entities] named entities in the fact
   * @param {string} [o.correctedFrom] the folder this was moved away from
   */
  learn({ factId, folder, claim, sensitivity = 'internal', by = 'rules', entities = [], correctedFrom = null }) {
    if (!folder) return this;
    const weight = by === 'human' ? 5 : by === 'model' ? 1 : 2;

    for (const token of vocabularyOf(claim)) {
      const entry = this.state.tokens[token] ?? (this.state.tokens[token] = { n: 0, folders: {}, sens: {}, seen: 0 });
      entry.n += weight;
      entry.folders[folder] = (entry.folders[folder] ?? 0) + weight;
      entry.sens[sensitivity] = (entry.sens[sensitivity] ?? 0) + weight;
      entry.seen = now();
    }

    for (const e of entities) {
      const key = entityKey(e);
      if (!key) continue;
      const c = this.state.clients[key] ?? (this.state.clients[key] = { n: 0, type: e.type ?? 'unknown', folders: {}, sens: {}, seen: 0 });
      c.n += weight;
      c.folders[folder] = (c.folders[folder] ?? 0) + weight;
      c.sens[sensitivity] = (c.sens[sensitivity] ?? 0) + weight;
      c.seen = now();
    }

    if (correctedFrom && correctedFrom !== folder) {
      this.state.corrections.push({
        at: now(), factId, from: correctedFrom, to: folder, by,
        // Vocabulary, not text: enough to learn from, not enough to reconstruct.
        terms: vocabularyOf(claim).slice(0, 12)
      });
      if (this.state.corrections.length > LIMITS.corrections) this.state.corrections.shift();
    }

    this.state.counters.learned++;
    this.state.counters[by] = (this.state.counters[by] ?? 0) + 1;
    this.state.dirty = true;
    return this;
  }

  /** A case the model was not confident about, kept so it can be reviewed later. */
  flagUncertain({ factId, folder, options = [], confidence = 0, why = null }) {
    this.state.uncertain.push({ at: now(), factId, folder, options: options.slice(0, 5), confidence, why: (why ?? '').slice(0, 160) });
    if (this.state.uncertain.length > LIMITS.uncertain) this.state.uncertain.shift();
    this.state.counters.uncertain++;
    this.state.dirty = true;
    return this;
  }

  // == recall ==============================================================

  /**
   * What does this file believe about where a claim belongs?
   *
   * Returns a folder and a confidence, or null when it has no opinion. Callers
   * act on it only above RECALL_THRESHOLD, and even then only within the closed
   * set of folders that already exist — this file can suggest, it can never
   * widen anything, and a folder it remembers that has since been deleted is
   * simply not offered.
   *
   * @param {object} o
   * @param {string} o.claim
   * @param {string[]} [o.entities]
   * @param {string[]} [o.allowedFolders] restrict to folders that exist now
   */
  recall({ claim, entities = [], allowedFolders = null }) {
    const scores = new Map();
    const sens = new Map();
    // Two different quantities, and conflating them is the easy mistake here.
    // `evidence` is how many distinct signals in this claim had an opinion;
    // `mass` is how much accumulated history is behind each folder. Five words
    // from one sentence is five signals but still only ONE past observation,
    // and treating that as strong is how a single filing becomes a confident
    // prior that then teaches itself.
    const mass = new Map();
    let evidence = 0;
    let matched = 0;

    const add = (map, key, v) => map.set(key, (map.get(key) ?? 0) + v);

    for (const token of vocabularyOf(claim)) {
      const e = this.state.tokens[token];
      if (!e || e.n < 2) continue;
      // A token that appears everywhere discriminates nothing. Weighting by how
      // concentrated its folder distribution is stops common words from voting.
      const strength = concentration(e.folders);
      if (strength < 0.5) continue;
      evidence += 1;
      matched += 1;
      for (const [folder, n] of Object.entries(e.folders)) {
        add(scores, folder, (n / e.n) * strength);
        add(mass, folder, n);
      }
      for (const [level, n] of Object.entries(e.sens)) add(sens, level, n / e.n);
    }

    // A named entity is far stronger evidence than a word: "Acme" appearing in
    // a claim tells you more about where it belongs than any three verbs do.
    for (const ent of entities) {
      const key = entityKey(ent);
      const c = this.state.clients[key];
      if (!c || c.n < 2) continue;
      evidence += 3;
      matched += 1;
      for (const [folder, n] of Object.entries(c.folders)) {
        add(scores, folder, 3 * (n / c.n));
        add(mass, folder, n);
      }
      for (const [level, n] of Object.entries(c.sens)) add(sens, level, 3 * (n / c.n));
    }

    if (!scores.size || evidence < 2) return null;

    let ranked = [...scores.entries()].sort((a, b) => b[1] - a[1]);
    if (allowedFolders?.length) ranked = ranked.filter(([f]) => allowedFolders.includes(f));
    if (!ranked.length) return null;

    const total = ranked.reduce((a, [, v]) => a + v, 0);
    const [folder, top] = ranked[0];
    const runnerUp = ranked[1]?.[1] ?? 0;
    // Confidence is share of the vote AND margin over the runner-up. A folder
    // that wins 51-49 is a coin toss, and reporting that as confident is how a
    // prior quietly becomes a bad decision nobody questioned.
    const share = top / total;
    const margin = (top - runnerUp) / top;
    // How many times has this actually been seen before? A rules filing carries
    // weight 2, so dividing the winner's accumulated mass by the signals that
    // matched recovers roughly a count of past observations. Three of them for
    // full confidence — or a single human correction, which carries weight 5
    // and is the one signal in the system known to be right.
    const observations = round2((mass.get(folder) ?? 0) / Math.max(1, matched * 2));
    const depth = Math.min(1, observations / 3);
    const confidence = round2(share * (0.5 + 0.5 * margin) * depth);

    const topSens = [...sens.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
    this.state.counters.recalls++;
    return {
      folder,
      sensitivity: topSens,
      confidence,
      confident: confidence >= RECALL_THRESHOLD,
      evidence,
      observations,
      alternatives: ranked.slice(1, 4).map(([f, v]) => ({ folder: f, score: round2(v / total) })),
      why: `${observations} prior filing(s) in this company's own history put material like this in ${folder}`
    };
  }

  /** What the file knows about one named client or entity. */
  client(name) {
    const c = this.state.clients[entityKey(name)];
    if (!c) return null;
    const folders = Object.entries(c.folders).sort((a, b) => b[1] - a[1]);
    const levels = Object.entries(c.sens).sort((a, b) => b[1] - a[1]);
    return {
      name, type: c.type, observations: c.n,
      usualFolder: folders[0]?.[0] ?? null,
      usualSensitivity: levels[0]?.[0] ?? null,
      lastSeen: iso(c.seen),
      folders: folders.map(([f, n]) => ({ folder: f, n }))
    };
  }

  // == housekeeping ========================================================

  /**
   * Decay old signal and evict the weakest entries.
   *
   * Both halves matter. Decay is how the file forgets a reorganisation from two
   * years ago that is no longer how anything is filed; eviction is how it stays
   * a file rather than a database. Without them a "memory" is just an
   * append-only log of everything that ever happened, which is the thing this
   * is supposed to be an alternative to.
   */
  compact({ decay = 0.98 } = {}) {
    const before = this.size();
    for (const map of [this.state.tokens, this.state.clients]) {
      for (const [k, v] of Object.entries(map)) {
        v.n *= decay;
        for (const f of Object.keys(v.folders)) {
          v.folders[f] *= decay;
          if (v.folders[f] < 0.5) delete v.folders[f];
        }
        if (v.n < 1 || !Object.keys(v.folders).length) delete map[k];
      }
    }
    evict(this.state.tokens, LIMITS.tokens);
    evict(this.state.clients, LIMITS.clients);
    if (this.state.revisions.length > LIMITS.revisions) {
      this.state.revisions = this.state.revisions.slice(-LIMITS.revisions);
    }
    this.state.dirty = true;
    return { before, after: this.size(), evicted: before.entries - this.size().entries };
  }

  size() {
    return {
      tokens: Object.keys(this.state.tokens).length,
      clients: Object.keys(this.state.clients).length,
      corrections: this.state.corrections.length,
      uncertain: this.state.uncertain.length,
      revisions: this.state.revisions.length,
      entries: Object.keys(this.state.tokens).length + Object.keys(this.state.clients).length
    };
  }

  // == persistence =========================================================

  /**
   * Seal the current state as a new revision and write it out.
   *
   * The chain link covers the state hash, so a later edit to any learned value
   * cannot be made consistent without also forging every revision after it —
   * and the head is signed, so forging those requires the customer's key.
   */
  save({ actor = 'system', reason = 'learning pass' } = {}) {
    const payload = this._integrityView();
    const stateHash = hashObject(payload);
    const prev = this.state.revisions[this.state.revisions.length - 1];
    const prevHash = prev?.hash ?? 'GENESIS';
    const revision = {
      seq: (prev?.seq ?? 0) + 1,
      at: now(),
      actor,
      reason,
      stateHash,
      prevHash,
      hash: chainHash(prevHash, stateHash),
      size: this.size()
    };
    this.state.revisions.push(revision);
    this.state.signature = this.signingKey?.privateKeyPem
      ? signMessage(this.signingKey.privateKeyPem, revision.hash)
      : null;

    const bytes = this._serialise({ ...payload, counters: this.state.counters }, revision);
    this.state.dirty = false;
    this.state.lastSaved = revision;

    if (this.path) {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(this.path, bytes);
    }
    return { revision, bytes: bytes.length, path: this.path, signed: Boolean(this.state.signature) };
  }

  /** Seal and serialise without writing, for callers that hold their own storage. */
  toBuffer(opts = {}) {
    const path = this.path;
    this.path = null;
    try {
      this.save(opts);
      const head = this.state.revisions[this.state.revisions.length - 1];
      return this._serialise({ ...this._integrityView(), counters: this.state.counters }, head);
    } finally {
      this.path = path;
    }
  }

  /**
   * The fields the revision hash covers.
   *
   * Usage counters are excluded, exactly as the fact store excludes read counts
   * from a fact's content hash and for the same reason: reading a thing must
   * never make it look tampered with. `recall()` increments a counter on every
   * lookup, and if that were sealed then simply consulting the memory — which
   * is the entire point of it — would report the file as altered.
   */
  _integrityView() {
    return {
      tokens: this.state.tokens,
      clients: this.state.clients,
      corrections: this.state.corrections,
      uncertain: this.state.uncertain
    };
  }

  _serialise(payload, revision) {
    const doc = {
      magic: MAGIC,
      format: FORMAT_VERSION,
      tenant: this.tenant,
      writtenAt: now(),
      head: revision.hash,
      revisions: this.state.revisions,
      ...payload
    };
    if (this.state.signature) {
      doc.signature = this.state.signature;
      doc.publicKeyPem = this.signingKey?.publicKeyPem ?? null;
    }
    return gzipSync(Buffer.from(JSON.stringify(doc), 'utf8'), { level: 9 });
  }

  load(path = this.path) {
    const doc = MemoryFile.parse(readFileSync(path));
    this.state = {
      ...emptyState(doc.tenant ?? this.tenant),
      tokens: doc.tokens ?? {},
      clients: doc.clients ?? {},
      corrections: doc.corrections ?? [],
      uncertain: doc.uncertain ?? [],
      counters: { ...emptyState().counters, ...(doc.counters ?? {}) },
      revisions: doc.revisions ?? [],
      signature: doc.signature ?? null
    };
    this.tenant = doc.tenant ?? this.tenant;
    return this;
  }

  static parse(bytes) {
    let json;
    try {
      json = gunzipSync(bytes).toString('utf8');
    } catch {
      throw new VaultError('validation', 'not a .vmem file — it is not gzip. A memory file is gzipped JSON with a VMEM header.');
    }
    let doc;
    try { doc = JSON.parse(json); } catch { throw new VaultError('validation', 'memory file is corrupt — the compressed payload is not JSON'); }
    if (doc?.magic !== MAGIC) throw new VaultError('validation', `not a .vmem file — expected magic ${MAGIC}, found ${doc?.magic ?? 'nothing'}`);
    if (doc.format > FORMAT_VERSION) {
      throw new VaultError('unsupported', `memory file is format v${doc.format}; this build understands up to v${FORMAT_VERSION}. Refusing to read it rather than misreading it.`);
    }
    return doc;
  }

  /**
   * Does the chain hold, and is the head signed by the key we hold?
   *
   * The two questions are separate on purpose. A broken chain means the file was
   * edited. A valid chain with an invalid signature means it was rebuilt by
   * somebody without the customer's key — which is a different, worse finding,
   * and reporting them as one boolean would lose that.
   */
  verify() {
    const problems = [];
    let prev = 'GENESIS';
    for (const r of this.state.revisions) {
      if (r.prevHash !== prev) problems.push({ seq: r.seq, problem: 'chain_break', expected: prev, actual: r.prevHash });
      if (chainHash(r.prevHash, r.stateHash) !== r.hash) problems.push({ seq: r.seq, problem: 'link_hash_mismatch' });
      prev = r.hash;
    }
    const head = this.state.revisions[this.state.revisions.length - 1];
    // The current state must hash to what the last revision sealed — otherwise
    // somebody changed a learned association after the file was written.
    if (head) {
      const recomputed = hashObject(this._integrityView());
      if (!this.state.dirty && recomputed !== head.stateHash) {
        problems.push({ seq: head.seq, problem: 'state_altered_after_seal' });
      }
    }
    let signatureOk = null;
    if (this.state.signature && this.signingKey?.publicKeyPem && head) {
      signatureOk = verifyMessage(this.signingKey.publicKeyPem, head.hash, this.state.signature);
      if (!signatureOk) problems.push({ seq: head.seq, problem: 'signature_invalid' });
    }
    return {
      ok: problems.length === 0,
      revisions: this.state.revisions.length,
      head: head?.hash ?? null,
      signatureOk,
      problems,
      statement: problems.length === 0
        ? 'The memory file is intact: every revision links to the one before it, and the current contents hash to what the last revision sealed.'
        : `${problems.length} integrity problem(s). This file has been altered outside the normal write path — the chain cannot stop an edit, it makes one impossible to hide.`
    };
  }

  /** What an operator or an auditor sees. */
  status() {
    const s = this.size();
    const head = this.state.revisions[this.state.revisions.length - 1];
    const topClients = Object.entries(this.state.clients)
      .sort((a, b) => b[1].n - a[1].n).slice(0, 10)
      .map(([name, c]) => ({ name, observations: Math.round(c.n), usualFolder: topKey(c.folders) }));
    return {
      format: `${MAGIC} v${FORMAT_VERSION}`,
      tenant: this.tenant,
      path: this.path,
      bytesOnDisk: this.path && existsSync(this.path) ? statSync(this.path).size : null,
      size: s,
      revisions: this.state.revisions.length,
      lastWrite: head ? { seq: head.seq, at: iso(head.at), actor: head.actor, reason: head.reason } : null,
      counters: this.state.counters,
      topClients,
      openUncertain: this.state.uncertain.length,
      recentCorrections: this.state.corrections.slice(-5).map((c) => ({ at: iso(c.at), from: c.from, to: c.to, by: c.by })),
      integrity: this.verify(),
      statement: `This file holds what filing has learned about this company — ${s.tokens} vocabulary entries and ${s.clients} named `
        + 'entities, as counts and folder associations. It contains no claim text: only ids, vocabulary and counters, so it is '
        + 'not a second copy of the memory and there is nothing in it worth stealing. It is consulted before any model call, '
        + 'which is why most facts are filed without one. Deleting it costs speed and nothing else.'
    };
  }
}

// ---------------------------------------------------------------------------

function emptyState(tenant = 'default') {
  return {
    tenant,
    tokens: {},
    clients: {},
    corrections: [],
    uncertain: [],
    revisions: [],
    signature: null,
    dirty: false,
    lastSaved: null,
    counters: { learned: 0, recalls: 0, uncertain: 0, human: 0, model: 0, rules: 0 }
  };
}

/**
 * The vocabulary of a claim, with anything identifying stripped out.
 *
 * Tokens carrying three or more consecutive digits are dropped. A salary, an
 * account number, a phone number and a case reference are all worthless for
 * deciding which folder something belongs in — no future claim will contain the
 * same salary — and keeping them would put the one part of a sentence worth
 * stealing into the one file in this system that has no wall around it. Short
 * digit runs survive, because "q3" and "2fa" are ordinary vocabulary.
 */
function vocabularyOf(claim) {
  return [...new Set(contentTokens(claim || ''))].filter((t) => !/\d{3,}/.test(t));
}

/**
 * The key an entity is stored and looked up under.
 *
 * One function, used by learn, recall and client, because these three deriving
 * it separately is exactly what went wrong: learn truncated at 80 characters and
 * recall did not, so any entity with a longer name was written under one key and
 * searched for under another. Nothing failed — the memory simply never
 * recognised that client again, silently, forever.
 */
export function entityKey(entity) {
  const raw = typeof entity === 'string' ? entity : (entity?.id || entity?.name || '');
  return String(raw).trim().toLowerCase().slice(0, 80);
}

/** How concentrated a distribution is: 1 = always one folder, 0 = spread evenly. */
function concentration(dist) {
  const values = Object.values(dist);
  if (values.length <= 1) return 1;
  const total = values.reduce((a, b) => a + b, 0);
  if (!total) return 0;
  const top = Math.max(...values);
  return round2((top / total - 1 / values.length) / (1 - 1 / values.length));
}

function evict(map, limit) {
  const keys = Object.keys(map);
  if (keys.length <= limit) return;
  keys.sort((a, b) => map[a].n - map[b].n);
  for (const k of keys.slice(0, keys.length - limit)) delete map[k];
}

function topKey(dist) {
  return Object.entries(dist).sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
}

function round2(n) { return Math.round(n * 100) / 100; }
