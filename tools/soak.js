// Concurrency soak — hammer a node in parallel, then prove the books.
//
//   node tools/soak.js                     # heavy: in-process node, no throttles
//   node tools/soak.js <url> --live        # light: gentle fire at a public node
//
// The final word is not the ops/sec — it is the REPLAY AUDIT: balances are
// reconstructed independently from the log's recorded transitions and
// compared exactly against the node's reported state. If any concurrent
// interleaving lost or double-applied anything, the shadow books diverge.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const LIVE = process.argv.includes('--live');
const urlArg = process.argv.slice(2).find((a) => a.startsWith('http'));
const jsonH = { 'content-type': 'application/json' };
const say = (s) => console.log(s);

const post = (base, p, token, body) => fetch(base + p, {
  method: 'POST', headers: { ...jsonH, ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

/** Reconstruct pair balances from the log's own recorded transitions. */
function shadowBooks(entries) {
  const bal = new Map(); // "lo|hi|cur" -> micro (lo owes hi)
  const adjust = (x, y, cur, amt) => {
    const [lo, hi] = x < y ? [x, y] : [y, x];
    const k = `${lo}|${hi}|${cur}`;
    const delta = Math.round(amt * 1e6) * (x === lo ? 1 : -1);
    bal.set(k, (bal.get(k) || 0) + delta);
    if (bal.get(k) === 0) bal.delete(k);
  };
  for (const e of entries) {
    if (e.type === 'send-payment') {
      const { path: p, currency, amount } = e.params;
      for (let i = 0; i < p.length - 1; i += 1) adjust(p[i], p[i + 1], currency, amount);
    } else if (e.type === 'settle') {
      adjust(e.params.peer, e.actor, e.params.currency, -e.params.amount);
    }
  }
  return bal;
}

async function audit(base, label, stateFile = null) {
  const v = await (await fetch(`${base}/api/log/verify`)).json();
  // The API pages the log at 500; for the local soak read the state file so
  // the replay audit always covers EVERY entry.
  const log = stateFile
    ? { seq: v.seq, entries: JSON.parse(fs.readFileSync(stateFile, 'utf8')).log }
    : await (await fetch(`${base}/api/log?limit=500`)).json();
  const graph = await (await fetch(`${base}/api/graph`)).json();
  const full = log.entries.length === log.seq; // replay audit needs the whole log
  const problems = [];
  if (!v.valid) problems.push(`chain/signature audit failed: ${JSON.stringify(v)}`);
  if (v.signatures.invalid !== 0) problems.push(`${v.signatures.invalid} invalid signatures`);
  const seqs = new Set(log.entries.map((e) => e.seq));
  if (seqs.size !== log.entries.length) problems.push('duplicate seq numbers');
  const ids = log.entries.filter((e) => e.event).map((e) => e.event.id);
  if (new Set(ids).size !== ids.length) problems.push('duplicate event ids in log');
  if (full) {
    const shadow = shadowBooks(log.entries);
    const reported = new Map(graph.balances.map((b) => {
      const [lo, hi] = b.debtor < b.creditor ? [b.debtor, b.creditor] : [b.creditor, b.debtor];
      const sign = b.debtor === lo ? 1 : -1;
      return [`${lo}|${hi}|${b.currency}`, sign * Math.round(b.amount * 1e6)];
    }));
    const keys = new Set([...shadow.keys(), ...reported.keys()]);
    for (const k of keys) {
      if ((shadow.get(k) || 0) !== (reported.get(k) || 0)) {
        problems.push(`REPLAY MISMATCH ${k}: log says ${(shadow.get(k) || 0) / 1e6}, node says ${(reported.get(k) || 0) / 1e6}`);
      }
    }
  }
  say(`  ${label}: seq=${v.seq} signed=${v.signatures.signed} invalid=${v.signatures.invalid}`
    + `${full ? ` · replay audit over ${log.entries.length} entries: ${problems.length ? 'FAILED' : 'books match exactly'}` : ' · (log truncated; replay audit skipped)'}`);
  for (const p of problems) say(`  ✗ ${p}`);
  return problems.length === 0;
}

const batches = async (n, size, fn) => {
  const out = [];
  for (let i = 0; i < n; i += size) {
    out.push(...await Promise.all(Array.from({ length: Math.min(size, n - i) }, (_, j) => fn(i + j))));
  }
  return out;
};

if (LIVE) {
  // ---- light live fire: parallel payments among the demo accounts ---------
  const base = (urlArg || 'https://solidpay.melvin.me').replace(/\/$/, '');
  say(`\n— live soak (light): ${base} —`);
  const who = {};
  for (const n of ['alice', 'bob', 'carol']) {
    const r = await post(base, '/api/login', null, { username: n, password: 'solidpay-demo' });
    if (!r.body.token) { say(`cannot log in ${n}: ${r.body.error}`); process.exit(1); }
    who[n] = r.body;
  }
  const t0 = Date.now();
  const flows = [['alice', 'carol'], ['carol', 'bob'], ['bob', 'alice']];
  const results = await batches(45, 15, async (i) => {
    const [f, t] = flows[i % flows.length];
    return (await post(base, '/api/payments', who[f].token, { to: who[t].agent, currency: 'USD', amount: 1 })).status;
  });
  const ok = results.filter((s) => s === 200).length;
  say(`  45 parallel payments: ${ok} routed, ${results.length - ok} no-route (capacity) · ${(45000 / (Date.now() - t0)).toFixed(0)} ops/s`);
  process.exit((await audit(base, 'audit')) ? 0 : 1);
}

// ---- heavy local soak -------------------------------------------------------
process.env.SOLIDPAY_REGISTER_PER_HOUR = '1000000';
process.env.SOLIDPAY_TX_PER_HOUR = '1000000';
const { createNode } = await import('../server.js');
const { buildTxEvent } = await import('../lib/tx.js');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solidpay-soak-'));
const node = createNode({ dataDir });
const { port } = await node.listen(0, '127.0.0.1');
const base = `http://127.0.0.1:${port}`;
say(`\n— heavy soak: local node ${base} —`);
let failures = 0;

// 1. registration storm + same-name race
const W = 24;
let t0 = Date.now();
const regs = await batches(W, 12, (i) => post(base, '/api/register', null, { username: `w${i}`, password: 'soak-pass-1234' }));
const workers = regs.map((r) => r.body);
const race = await Promise.all(Array.from({ length: 10 }, () => post(base, '/api/register', null, { username: 'contested', password: 'soak-pass-1234' })));
const raceOk = race.filter((r) => r.status === 201).length;
say(`  1. ${W} parallel registrations in ${Date.now() - t0}ms; same-name race: ${raceOk} × 201, ${race.length - raceOk} × 409 ${raceOk === 1 ? '✓' : '✗ RACE BUG'}`);
if (raceOk !== 1) failures += 1;

// 2. ring of trust (parallel)
await batches(W, 12, (i) => post(base, '/api/trustlines', workers[i].token,
  { peer: workers[(i + 1) % W].agent, currency: 'USD', limit: 1000 }));

// 3. payment storm — random ring-adjacent + long-path payments
t0 = Date.now();
const N = 400;
const pays = await batches(N, 25, (i) => {
  const from = i % W;
  const hop = 1 + (i % 5); // up to 5 hops around the ring
  // i extends credit to i+1, so capacity flows i+1 → i: pay BACKWARD.
  return post(base, '/api/payments', workers[from].token,
    { to: workers[(from - hop + W) % W].agent, currency: 'USD', amount: 1 + (i % 3) });
});
const paid = pays.filter((r) => r.status === 200).length;
say(`  2. ${N} parallel payments (1–5 hops): ${paid} routed, ${N - paid} no-route · ${(N * 1000 / (Date.now() - t0)).toFixed(0)} ops/s`);

// 4. signed-transition swarm + replay burst
t0 = Date.now();
const keys = Array.from({ length: 8 }, () => crypto.randomBytes(32).toString('hex'));
const txs = await batches(80, 16, async (i) => {
  const ev = buildTxEvent(keys[i % 8], 'set-trustline', { peer: workers[i % W].agent, currency: 'USD', limit: 50 + i });
  return (await fetch(`${base}/api/tx`, { method: 'POST', headers: jsonH, body: JSON.stringify(ev) })).status;
});
const txOk = txs.filter((s) => s === 200 || s === 201).length;
say(`  3. 80 parallel signed transitions: ${txOk} applied · ${(80000 / (Date.now() - t0)).toFixed(0)} ops/s`);
const replayEv = buildTxEvent(keys[0], 'send-payment', { to: workers[0].agent, currency: 'USD', amount: 2 });
// give key[0] capacity: worker0 pays the did first? Simpler: worker0 extends the key credit... key0 already extended trust above; worker0 pays key0 to give it a claim
await post(base, '/api/payments', workers[0].token, { to: `did:nostr:${replayEv.pubkey}`, currency: 'USD', amount: 10 });
const burst = await Promise.all(Array.from({ length: 12 }, () => fetch(`${base}/api/tx`, { method: 'POST', headers: jsonH, body: JSON.stringify(replayEv) }).then((r) => r.status)));
const applied = burst.filter((s) => s === 200).length;
say(`  4. identical signed event × 12 parallel: ${applied} applied, ${burst.filter((s) => s === 409).length} replay-refused ${applied === 1 ? '✓' : '✗ REPLAY RACE'}`);
if (applied !== 1) failures += 1;

// 5. settle storm (creditors settling in parallel)
await batches(W, 12, async (i) => {
  const b = await (await fetch(`${base}/api/balances?agent=${encodeURIComponent(workers[i].agent)}`)).json();
  const owed = (b.positions || []).find((p) => p.balance > 0.5 && p.currency === 'USD');
  if (!owed) return null;
  return post(base, '/api/settle', workers[i].token, { peer: owed.peer, currency: 'USD', amount: 0.5 });
});
say('  5. parallel settles done');

// 6. the verdict
const ok = await audit(base, '6. audit', path.join(dataDir, 'state.json'));
await node.close();
fs.rmSync(dataDir, { recursive: true, force: true });
if (!ok || failures) { say('\nSOAK FAILED'); process.exit(1); }
say('\nSOAK PASSED — races refused, books reconstruct exactly from the log');
