// Seed a demo trust network on a running node — idempotent.
//
//   node tools/seed.js http://localhost:3480
//
// Creates alice, bob, carol (password: solidpay-demo), the canonical
// topology (bob trusts alice 1000 USD, carol trusts bob 500 USD), and one
// routed payment (alice → carol 300 USD via bob) so the graph, balances,
// and activity feed have something to show the moment the UI opens.

const base = (process.argv[2] || 'http://localhost:3480').replace(/\/$/, '');
const PASS = 'solidpay-demo';

const post = (path, token, body) => fetch(base + path, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

async function agent(name) {
  const reg = await post('/api/register', null, { username: name, password: PASS });
  if (reg.status === 201) return reg.body;
  const login = await post('/api/login', null, { username: name, password: PASS });
  if (login.status !== 200) throw new Error(`${name}: cannot register or log in (${login.body.error})`);
  return login.body;
}

const alice = await agent('alice');
const bob = await agent('bob');
const carol = await agent('carol');
console.log('agents:', alice.agent, '·', bob.agent, '·', carol.agent);

const t1 = await post('/api/trustlines', bob.token, { peer: alice.agent, currency: 'USD', limit: 1000 });
const t2 = await post('/api/trustlines', carol.token, { peer: bob.agent, currency: 'USD', limit: 500 });
console.log(`trustlines: bob→alice 1000 USD (${t1.status}), carol→bob 500 USD (${t2.status})`);

// Only pay if the books are still empty — keeps reseeding idempotent.
const graph = await (await fetch(`${base}/api/graph`)).json();
if (graph.balances.length === 0) {
  const pay = await post('/api/payments', alice.token, { to: carol.agent, currency: 'USD', amount: 300 });
  console.log(`payment: alice → carol 300 USD via bob (${pay.status})`, pay.body.payment?.path?.length === 3 ? '2 hops ✓' : pay.body.error || '');
} else {
  console.log('books already have balances — skipping the demo payment');
}

const verify = await (await fetch(`${base}/api/log/verify`)).json();
console.log(`chain: valid=${verify.valid} seq=${verify.seq}`);
