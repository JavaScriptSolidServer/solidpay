// SolidPay engine — Ryan Fugger's original Ripple (2004) with Solid ideas:
// every user is a URI, every transition is hash-chained (and, from v1,
// signed with did:nostr keys). No blockchain, no token, no consensus —
// bilateral credit and routed payments over a web of trust.
//
// This module is pure model + a Ledger class: no HTTP, no auth, no I/O
// besides the persist hook the host passes in. It is consumed by the
// standalone server (../server.js) and by the JSS plugin adapter
// (jss-plugins/ripple), which proved this design end-to-end first.
//
//   Trustline  a UNILATERAL grant: creditor extends debtor up to `limit`
//              of `currency`. Only the creditor may create/resize/remove
//              it — it is their risk.
//   Balance    ONE signed number per unordered pair+currency ("lo owes
//              hi") — never two mirrored entries, so books cannot desync.
//   Payment    BFS shortest path where EVERY hop carries the full amount;
//              capacity(x→y) = limit(y→x) − debt(x→y). Intermediaries
//              need no per-payment consent: each hop only consumes credit
//              its next node already granted. Signed debt gives clearing
//              free — owed-to-you credit is spendable with no trustline.
//   Settle     the creditor records out-of-band repayment; only the party
//              whose CLAIM shrinks may do so.
//   Log        every transition hash-chained: seq, prev, sha256 of the
//              RFC 8785-canonical entry. v1 adds a schnorr signature by
//              the actor's did:nostr key over the same canonical bytes.
//
// Amounts cross the API as decimals (≤ 6 dp); ALL arithmetic is integer
// micro-units (bigint) — no float drift in anyone's ledger.

import crypto from 'node:crypto';

// ------------------------------------------------------------------ amounts
const MAX_UNITS = 1_000_000_000_000; // 1e12 units ceiling on limits/amounts
export const CUR_RE = /^[A-Z0-9]{1,12}$/;
const SEP = '|'; // agent ids are URIs / DIDs — '|' appears in neither grammar

/** Decimal number → integer micro-units (bigint), or null if invalid. */
export function toMicro(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return null;
  if (v <= 0 || v > MAX_UNITS) return null;
  const micro = Math.round(v * 1e6);
  if (Math.abs(v * 1e6 - micro) > 1e-6) return null; // > 6 dp
  return BigInt(micro);
}
/** Integer micro-units (bigint) → decimal number. */
export const fromMicro = (m) => Number(m) / 1e6;

// ----------------------------------------------------------------- identity
/**
 * One agent, one spelling. Solid WebIDs appear both as the document form
 * (`/profile/card.jsonld#me`) and the fragment form (`/profile/card#me`) —
 * the same agent as two strings, which silently SPLITS an identity-keyed
 * graph (found live in the JSS adapter). Canonicalize the document form to
 * the fragment form at every id entry point. did:* ids pass through.
 */
export const normalizeAgent = (id) => (typeof id === 'string'
  ? id.replace(/\/profile\/card\.jsonld#/, '/profile/card#')
  : id);

// -------------------------------------------------------------- pure model
/** Canonical unordered pair: [lo, hi]. */
export const pair = (a, b) => (a < b ? [a, b] : [b, a]);
export const pairKey = (a, b, cur) => pair(a, b).join(SEP) + SEP + cur;
export const lineKey = (creditor, debtor, cur) => creditor + SEP + debtor + SEP + cur;

/** What x currently owes y in `cur` (micro, signed; ≥ 0 means x owes y). */
export function debtOf(state, x, y, cur) {
  const bal = BigInt(state.balances[pairKey(x, y, cur)] ?? '0'); // lo owes hi
  const [lo] = pair(x, y);
  return x === lo ? bal : -bal;
}
/** Shift debt(x→y) by deltaMicro (signed). */
export function adjustDebt(state, x, y, cur, deltaMicro) {
  const k = pairKey(x, y, cur);
  const [lo] = pair(x, y);
  const next = BigInt(state.balances[k] ?? '0') + (x === lo ? deltaMicro : -deltaMicro);
  if (next === 0n) delete state.balances[k];
  else state.balances[k] = next.toString();
}
/** Spendable capacity on hop x→y: limit(y→x) − debt(x→y). */
export function capacityOf(state, x, y, cur) {
  const line = state.trustlines[lineKey(y, x, cur)];
  const limit = line ? BigInt(line.limit) : 0n;
  return limit - debtOf(state, x, y, cur);
}

const MAX_HOPS = 8;

/**
 * BFS shortest path from→to where EVERY hop carries amountMicro.
 * Neighbours of x are peers that extended x credit OR share a balance with
 * x (signed debt makes owed-to-you credit spendable with no trustline).
 */
export function findPath(state, from, to, cur, amountMicro) {
  const neighbours = new Map();
  const add = (x, y) => {
    if (!neighbours.has(x)) neighbours.set(x, new Set());
    neighbours.get(x).add(y);
  };
  for (const line of Object.values(state.trustlines)) {
    if (line.currency === cur) add(line.debtor, line.creditor);
  }
  for (const k of Object.keys(state.balances)) {
    const [lo, hi, c] = k.split(SEP);
    if (c === cur) { add(lo, hi); add(hi, lo); }
  }
  const prev = new Map([[from, null]]);
  let frontier = [from];
  for (let depth = 0; depth < MAX_HOPS && frontier.length; depth += 1) {
    const next = [];
    for (const x of frontier) {
      for (const y of neighbours.get(x) ?? []) {
        if (prev.has(y)) continue;
        if (capacityOf(state, x, y, cur) < amountMicro) continue;
        prev.set(y, x);
        if (y === to) {
          const p = [to];
          for (let n = x; n !== null; n = prev.get(n)) p.unshift(n);
          return p;
        }
        next.push(y);
      }
    }
    frontier = next;
  }
  return null;
}

// ----------------------------------------- RFC 8785 canonical JSON + chain
export function canonicalize(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'string') return JSON.stringify(value.normalize('NFC'));
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys
      .map((k) => JSON.stringify(k.normalize('NFC')) + ':' + canonicalize(value[k]))
      .join(',') + '}';
  }
  throw new Error(`JCS: unserializable ${t}`);
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** Hash a log entry (its own `hash` and `sig` fields excluded). */
export function entryHash(entry) {
  const { hash, sig, ...core } = entry;
  return 'sha256:' + sha256(canonicalize(core));
}

// -------------------------------------------------------------------- errors
export class LedgerError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (m) => { throw new LedgerError(400, m); };
const conflict = (m) => { throw new LedgerError(409, m); };
const notFound = (m) => { throw new LedgerError(404, m); };
const bigMax = (a, b) => (a > b ? a : b);

// -------------------------------------------------------------------- Ledger
/**
 * The mutable ledger. All writes go through transitions that validate,
 * mutate synchronously (multi-hop payments are atomic by construction),
 * append a hash-chained log entry, and call `persist(state)`.
 *
 *   const ledger = new Ledger({ state?, persist? })
 */
export class Ledger {
  constructor({ state, persist } = {}) {
    this.state = state ?? { seq: 0, tip: null, trustlines: {}, balances: {}, log: [] };
    this.persist = persist ?? (() => {});
  }

  _transition(actor, type, params, event = null) {
    const entry = {
      seq: this.state.seq + 1, prev: this.state.tip,
      ts: new Date().toISOString(), actor, type, params,
      ...(event ? { event } : {}),
    };
    entry.hash = entryHash(entry);
    this.state.seq = entry.seq;
    this.state.tip = entry.hash;
    this.state.log.push(entry);
    this.persist(this.state);
    return entry;
  }

  _currency(v) {
    const cur = String(v ?? '').toUpperCase();
    if (!CUR_RE.test(cur)) bad('currency must match [A-Z0-9]{1,12}');
    return cur;
  }
  _amount(v, what = 'amount') {
    const m = toMicro(v);
    if (m === null) bad(`${what} must be a positive number with at most 6 decimal places`);
    return m;
  }

  /** Creditor `actor` extends/updates credit to `peer`. limit 0 freezes. */
  setTrustline(actor, peer, currency, limit, event = null) {
    peer = normalizeAgent(peer);
    if (!peer || typeof peer !== 'string' || peer.includes(SEP)) bad('peer (agent URI) required');
    if (peer === actor) bad('cannot extend credit to yourself');
    const cur = this._currency(currency);
    const lim = limit === 0 ? 0n : this._amount(limit, 'limit');
    const k = lineKey(actor, peer, cur);
    const existed = !!this.state.trustlines[k];
    this.state.trustlines[k] = { creditor: actor, debtor: peer, currency: cur, limit: lim.toString() };
    const entry = this._transition(actor, existed ? 'update-trustline' : 'create-trustline',
      { peer, currency: cur, limit: fromMicro(lim) }, event);
    return { trustline: { creditor: actor, debtor: peer, currency: cur, limit: fromMicro(lim) }, entry, created: !existed };
  }

  removeTrustline(actor, peer, currency, event = null) {
    peer = normalizeAgent(peer);
    const cur = this._currency(currency);
    if (!peer) bad('peer required');
    const k = lineKey(actor, peer, cur);
    if (!this.state.trustlines[k]) notFound('no such trustline');
    if (debtOf(this.state, peer, actor, cur) > 0n) {
      conflict('peer has outstanding debt on this line — settle before removing');
    }
    delete this.state.trustlines[k];
    const entry = this._transition(actor, 'remove-trustline', { peer, currency: cur }, event);
    return { removed: { creditor: actor, debtor: peer, currency: cur }, entry };
  }

  /** Route `amount` from `actor` to `to`; atomic across every hop. */
  pay(actor, to, currency, amount, event = null) {
    to = normalizeAgent(to);
    if (!to || typeof to !== 'string') bad('to (agent URI) required');
    if (to === actor) bad('cannot pay yourself');
    const cur = this._currency(currency);
    const amt = this._amount(amount);
    const p = findPath(this.state, actor, to, cur, amt);
    if (!p) notFound('no route with sufficient credit');
    for (let i = 0; i < p.length - 1; i += 1) adjustDebt(this.state, p[i], p[i + 1], cur, amt);
    const entry = this._transition(actor, 'send-payment',
      { from: actor, to, currency: cur, amount: fromMicro(amt), path: p }, event);
    return { payment: { from: actor, to, currency: cur, amount: fromMicro(amt), path: p }, entry };
  }

  /** Creditor `actor` records `peer` repaying out of band. */
  settle(actor, peer, currency, amount, event = null) {
    peer = normalizeAgent(peer);
    if (!peer) bad('peer required');
    const cur = this._currency(currency);
    const amt = this._amount(amount);
    const owed = debtOf(this.state, peer, actor, cur);
    if (owed < amt) {
      conflict(`peer owes ${fromMicro(bigMax(owed, 0n))} ${cur} — cannot settle ${fromMicro(amt)}`);
    }
    adjustDebt(this.state, peer, actor, cur, -amt);
    const entry = this._transition(actor, 'settle', { peer, currency: cur, amount: fromMicro(amt) }, event);
    return { settled: { peer, currency: cur, amount: fromMicro(amt), remaining: fromMicro(owed - amt) }, entry };
  }

  /** Dry-run pathfind (decimal amount). */
  path(from, to, currency, amount) {
    from = normalizeAgent(from); to = normalizeAgent(to);
    const cur = this._currency(currency);
    const amt = this._amount(amount);
    if (!from || !to) bad('from and to required');
    const p = findPath(this.state, from, to, cur, amt);
    if (!p) notFound('no route with sufficient credit');
    return { path: p, hops: p.length - 1 };
  }

  /** Public view of every line + IOU (decimals). */
  graph() {
    const s = this.state;
    return {
      trustlines: Object.values(s.trustlines).map((l) => ({
        creditor: l.creditor, debtor: l.debtor, currency: l.currency,
        limit: fromMicro(BigInt(l.limit)),
        debt: fromMicro(bigMax(debtOf(s, l.debtor, l.creditor, l.currency), 0n)),
        available: fromMicro(bigMax(capacityOf(s, l.debtor, l.creditor, l.currency), 0n)),
      })),
      balances: Object.entries(s.balances).map(([k, v]) => {
        const [lo, hi, currency] = k.split(SEP);
        const m = BigInt(v);
        return m >= 0n
          ? { debtor: lo, creditor: hi, currency, amount: fromMicro(m) }
          : { debtor: hi, creditor: lo, currency, amount: fromMicro(-m) };
      }),
      seq: s.seq, tip: s.tip,
    };
  }

  /** Net + per-peer positions for one agent. */
  balancesFor(agent) {
    agent = normalizeAgent(agent);
    if (!agent) bad('agent required');
    const positions = [];
    const net = {};
    for (const [k, v] of Object.entries(this.state.balances)) {
      const [lo, hi, currency] = k.split(SEP);
      if (lo !== agent && hi !== agent) continue;
      const peer = lo === agent ? hi : lo;
      const owes = debtOf(this.state, agent, peer, currency);
      positions.push({ peer, currency, balance: fromMicro(-owes) });
      net[currency] = (net[currency] ?? 0n) - owes;
    }
    return { agent, positions,
      net: Object.fromEntries(Object.entries(net).map(([c, m]) => [c, fromMicro(m)])) };
  }

  log(limit = 50) {
    const n = Math.min(Number(limit) || 50, 500);
    return { seq: this.state.seq, tip: this.state.tip, entries: this.state.log.slice(-n) };
  }

  verifyLog() {
    let prev = null;
    for (const e of this.state.log) {
      if (e.prev !== prev || entryHash(e) !== e.hash) {
        return { valid: false, brokenAt: e.seq, seq: this.state.seq };
      }
      prev = e.hash;
    }
    return { valid: true, seq: this.state.seq, tip: this.state.tip };
  }
}
