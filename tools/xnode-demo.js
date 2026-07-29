// Cross-node payment demo — federation with today's primitives.
//
//   node tools/xnode-demo.js http://nodeA:3480 http://nodeB:3480
//
// alice@A pays carol@B through a GATEWAY agent G — a did:nostr key that
// exists on both nodes at once (identity is a URI/DID, so "which node" is
// just where a trustline happens to live):
//
//   1. G signs set-trustline(alice@A)  on A   — G trusts alice on A
//   2. carol@B extends trust to G      on B   — carol trusts G on B
//   3. alice pays G 25 USD             on A   — uses credit G granted
//   4. G signs send-payment(carol@B)   on B   — uses credit carol granted
//
// Net: value moved alice@A → carol@B. G's books balance across nodes:
// +25 owed to it on A, −25 owed by it on B. No server-to-server protocol —
// the gateway's signatures ARE the coordination. (Atomic two-node commit —
// holds/hashlocks — is the level-2 protocol this demo motivates; see
// docs/spec/ § 13.)

import crypto from 'node:crypto';
import { buildTxEvent } from '../lib/tx.js';

const [A, B] = [process.argv[2] || 'http://localhost:3480', process.argv[3] || 'http://localhost:3481']
  .map((u) => u.replace(/\/$/, ''));
const PASS = 'solidpay-demo';
const say = (s) => console.log(s);
const jsonH = { 'content-type': 'application/json' };

const post = (base, p, token, body) => fetch(base + p, {
  method: 'POST', headers: { ...jsonH, ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));
const tx = (base, ev) => post(base, '/api/tx', null, ev);
async function login(base, name) {
  let r = await post(base, '/api/login', null, { username: name, password: PASS });
  if (r.status !== 200) r = await post(base, '/api/register', null, { username: name, password: PASS });
  if (!r.body.token) throw new Error(`${name}@${base}: ${r.body.error}`);
  return r.body;
}

// The gateway: a fresh throwaway did:nostr key.
const gPriv = crypto.randomBytes(32).toString('hex');

say(`\n— SolidPay cross-node payment —\n  node A: ${A}\n  node B: ${B}\n`);

const alice = await login(A, 'alice');
const carol = await login(B, 'carol');

// 1. G trusts alice on A (signed by G, submitted to A).
const t1 = await tx(A, buildTxEvent(gPriv, 'set-trustline', { peer: alice.agent, currency: 'USD', limit: 100 }));
if (t1.status !== 201 && t1.status !== 200) throw new Error(`step1: ${t1.body.error}`);
const G = t1.body.trustline.creditor;
say(`1. gateway ${G.slice(0, 30)}… trusts alice@A for 100 USD   [node A, signed by G]`);

// 2. carol trusts G on B.
const t2 = await post(B, '/api/trustlines', carol.token, { peer: G, currency: 'USD', limit: 100 });
if (t2.status !== 201 && t2.status !== 200) throw new Error(`step2: ${t2.body.error}`);
say(`2. carol@B trusts the gateway for 100 USD                  [node B, custodially signed]`);

// 3. alice pays G 25 on A.
const p1 = await post(A, '/api/payments', alice.token, { to: G, currency: 'USD', amount: 25 });
if (p1.status !== 200) throw new Error(`step3: ${p1.body.error}`);
say(`3. alice@A pays the gateway 25 USD                          [node A, ${p1.body.payment.path.length - 1} hop(s)]`);

// 4. G pays carol 25 on B (signed by G, submitted to B).
const p2 = await tx(B, buildTxEvent(gPriv, 'send-payment', { to: carol.agent, currency: 'USD', amount: 25 }));
if (p2.status !== 200) throw new Error(`step4: ${p2.body.error}`);
say(`4. gateway pays carol@B 25 USD                              [node B, signed by G]`);

// ---- the books, both sides ------------------------------------------------
const gA = await (await fetch(`${A}/api/balances?agent=${encodeURIComponent(G)}`)).json();
const gB = await (await fetch(`${B}/api/balances?agent=${encodeURIComponent(G)}`)).json();
const cB = await (await fetch(`${B}/api/balances?agent=${encodeURIComponent(carol.agent)}`)).json();
const vA = await (await fetch(`${A}/api/log/verify`)).json();
const vB = await (await fetch(`${B}/api/log/verify`)).json();

say(`\n— result —`);
say(`  gateway on A: ${gA.net.USD > 0 ? '+' : ''}${gA.net.USD ?? 0} USD (owed to it)`);
say(`  gateway on B: ${gB.net.USD > 0 ? '+' : ''}${gB.net.USD ?? 0} USD (it owes)`);
say(`  carol@B net:  +${cB.net.USD} USD — value crossed nodes`);
say(`  audit A: valid=${vA.valid} signed=${vA.signatures.signed} invalid=${vA.signatures.invalid}`);
say(`  audit B: valid=${vB.valid} signed=${vB.signatures.signed} invalid=${vB.signatures.invalid}`);
say(`\nThe gateway's signatures were the only coordination. Level 2 makes\nsteps 3+4 atomic (hold/commit); the anchors make either side's history\nindisputable. See docs/spec/ § 13.\n`);
