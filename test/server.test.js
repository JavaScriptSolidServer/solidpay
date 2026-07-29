// SolidPay standalone server — integration tests over real HTTP.
//
// Boots a node on an ephemeral port with a throwaway data dir and drives the
// whole product surface: register/login (agent = a dereferenceable URI),
// trustlines, live routing, an atomic multi-hop payment, settle, the
// hash-chained log, and persistence across a restart.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createNode } from '../server.js';

const post = (url, token, obj) => fetch(url, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(obj),
});

describe('solidpay node', () => {
  let node; let base; let dataDir;
  const tokens = {}; const agents = {};

  before(async () => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solidpay-'));
    node = createNode({ dataDir });
    const { port } = await node.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${port}`;
  });
  after(async () => {
    if (node) await node.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it('registers users — every agent is a URI on this node', async () => {
    for (const name of ['alice', 'bob', 'carol']) {
      const res = await post(`${base}/api/register`, null, { username: name, password: 'test-pass-1234' });
      assert.strictEqual(res.status, 201, await res.clone().text());
      const body = await res.json();
      assert.strictEqual(body.agent, `${base}/u/${name}#me`);
      assert.ok(body.token);
      tokens[name] = body.token; agents[name] = body.agent;
    }
    const dup = await post(`${base}/api/register`, null, { username: 'alice', password: 'test-pass-1234' });
    assert.strictEqual(dup.status, 409, 'duplicate username refused');
    const weak = await post(`${base}/api/register`, null, { username: 'dan', password: 'short' });
    assert.strictEqual(weak.status, 400, 'weak password refused');
  });

  it('the agent URI dereferences to a profile document', async () => {
    const res = await fetch(`${base}/u/alice`);
    assert.strictEqual(res.status, 200);
    const doc = await res.json();
    assert.strictEqual(doc['@id'], agents.alice);
    assert.strictEqual(doc.name, 'alice');
    assert.strictEqual((await fetch(`${base}/u/nobody`)).status, 404);
  });

  it('login round-trips; whoami resolves the bearer', async () => {
    const res = await post(`${base}/api/login`, null, { username: 'alice', password: 'test-pass-1234' });
    assert.strictEqual(res.status, 200);
    const wrong = await post(`${base}/api/login`, null, { username: 'alice', password: 'wrong-password' });
    assert.strictEqual(wrong.status, 401);
    const who = await (await fetch(`${base}/api/whoami`, { headers: { authorization: `Bearer ${tokens.alice}` } })).json();
    assert.strictEqual(who.agent, agents.alice);
  });

  it('trustlines: creditor-only writes; anonymous refused', async () => {
    assert.strictEqual((await post(`${base}/api/trustlines`, null, { peer: 'x', currency: 'USD', limit: 1 })).status, 401);
    const r1 = await post(`${base}/api/trustlines`, tokens.bob, { peer: agents.alice, currency: 'usd', limit: 1000 });
    assert.strictEqual(r1.status, 201);
    assert.strictEqual((await r1.json()).trustline.creditor, agents.bob, 'the authenticated agent IS the creditor');
    const r2 = await post(`${base}/api/trustlines`, tokens.carol, { peer: agents.bob, currency: 'USD', limit: 500 });
    assert.strictEqual(r2.status, 201);
  });

  it('routes and pays alice → bob → carol atomically', async () => {
    const path1 = await (await fetch(`${base}/api/path?from=${encodeURIComponent(agents.alice)}&to=${encodeURIComponent(agents.carol)}&currency=USD&amount=300`)).json();
    assert.deepStrictEqual(path1.path, [agents.alice, agents.bob, agents.carol]);
    const pay = await post(`${base}/api/payments`, tokens.alice, { to: agents.carol, currency: 'USD', amount: 300 });
    assert.strictEqual(pay.status, 200, await pay.clone().text());
    const over = await post(`${base}/api/payments`, tokens.alice, { to: agents.carol, currency: 'USD', amount: 900 });
    assert.strictEqual(over.status, 404, 'beyond capacity → no route');
    const bal = await (await fetch(`${base}/api/balances?agent=${encodeURIComponent(agents.carol)}`)).json();
    assert.strictEqual(bal.net.USD, 300);
  });

  it('settle is creditor-only and bounded', async () => {
    assert.strictEqual((await post(`${base}/api/settle`, tokens.bob, { peer: agents.carol, currency: 'USD', amount: 200 })).status, 409);
    const ok = await post(`${base}/api/settle`, tokens.carol, { peer: agents.bob, currency: 'USD', amount: 150 });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual((await ok.json()).settled.remaining, 150);
  });

  it('the hash chain verifies over the whole run', async () => {
    const v = await (await fetch(`${base}/api/log/verify`)).json();
    assert.strictEqual(v.valid, true);
    const log = await (await fetch(`${base}/api/log`)).json();
    assert.ok(log.entries.length >= 4);
    assert.strictEqual(log.tip, log.entries[log.entries.length - 1].hash);
  });

  it('serves the app UI at /', async () => {
    const res = await fetch(`${base}/`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type') || '', /text\/html/);
    assert.match(await res.text(), /SolidPay/);
  });

  it('state survives a restart — accounts, books, and chain intact', async () => {
    const seqBefore = (await (await fetch(`${base}/api/log`)).json()).seq;
    await node.close();
    node = createNode({ dataDir });
    const { port } = await node.listen(0, '127.0.0.1');
    const base2 = `http://127.0.0.1:${port}`;
    const login = await post(`${base2}/api/login`, null, { username: 'carol', password: 'test-pass-1234' });
    assert.strictEqual(login.status, 200, 'accounts persisted');
    const v = await (await fetch(`${base2}/api/log/verify`)).json();
    assert.strictEqual(v.valid, true, 'chain persisted and verifies');
    assert.strictEqual(v.seq, seqBefore, 'no transitions lost');
  });
});
