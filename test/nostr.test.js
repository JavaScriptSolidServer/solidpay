// NIP-98 nostr authentication — did:nostr agents are first-class.
//
// A fixed secp256k1 key drives the whole surface over real HTTP: whoami
// resolves the signed header to did:nostr:<hex>; a nostr agent extends
// trust to a password agent and gets paid by one (mixed identity schemes,
// one graph); and every way a NIP-98 header can be wrong — bad signature,
// stale timestamp, wrong URL, wrong method, body swap, replayed GET header
// on a write — is refused with 401.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createNode } from '../server.js';
import { buildNip98, verifyNip98, eventId } from '../lib/nip98.js';
import { buildTxEvent } from '../lib/tx.js';

// A fixed test key (never reuse outside tests).
const PRIV = '0000000000000000000000000000000000000000000000000000000000000001';
const PRIV2 = '0000000000000000000000000000000000000000000000000000000000000002';

const jsonHeaders = { 'content-type': 'application/json' };

describe('nostr auth (NIP-98)', () => {
  let node; let base; let dataDir; let DAVE; let daveTok; let NOSTR;

  before(async () => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solidpay-nostr-'));
    node = createNode({ dataDir });
    const { port } = await node.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${port}`;
    // one password agent for the mixed-scheme scenario
    const reg = await fetch(`${base}/api/register`, {
      method: 'POST', headers: jsonHeaders,
      body: JSON.stringify({ username: 'dave', password: 'test-pass-1234' }),
    });
    const regBody = await reg.json();
    DAVE = regBody.agent; daveTok = regBody.token;
  });
  after(async () => {
    if (node) await node.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  const nostrFetch = (priv, urlPath, { method = 'GET', body = null } = {}) => {
    const url = `${base}${urlPath}`;
    return fetch(url, {
      method,
      headers: { ...jsonHeaders, authorization: buildNip98(priv, url, method, body) },
      ...(body != null ? { body } : {}),
    });
  };

  it('whoami resolves a signed header to did:nostr:<hex>', async () => {
    const res = await nostrFetch(PRIV, '/api/whoami');
    const { agent } = await res.json();
    assert.match(agent, /^did:nostr:[0-9a-f]{64}$/);
    NOSTR = agent;
  });

  it('a nostr agent extends trust; a password agent pays it — one graph', async () => {
    // did:nostr extends dave 100 USD of credit — via the SIGNED lane
    // (level 1: did:* writes are signed transitions on /api/tx).
    const ev = buildTxEvent(PRIV, 'set-trustline', { peer: DAVE, currency: 'USD', limit: 100 });
    const tl = await fetch(`${base}/api/tx`, { method: 'POST', headers: jsonHeaders, body: JSON.stringify(ev) });
    assert.strictEqual(tl.status, 201, await tl.clone().text());
    assert.strictEqual((await tl.json()).trustline.creditor, NOSTR);
    // dave (bearer auth) pays the nostr agent 40 across that line.
    const pay = await fetch(`${base}/api/payments`, {
      method: 'POST',
      headers: { ...jsonHeaders, authorization: `Bearer ${daveTok}` },
      body: JSON.stringify({ to: NOSTR, currency: 'USD', amount: 40 }),
    });
    assert.strictEqual(pay.status, 200, await pay.clone().text());
    const bal = await (await fetch(`${base}/api/balances?agent=${encodeURIComponent(NOSTR)}`)).json();
    assert.strictEqual(bal.net.USD, 40, 'the nostr agent holds a 40 USD claim on dave');
    // The log's actor for the trustline is the DID.
    const log = await (await fetch(`${base}/api/log`)).json();
    assert.ok(log.entries.some((e) => e.actor === NOSTR && e.type === 'create-trustline'));
  });

  it('the nostr agent settles its own claim (signed transition)', async () => {
    const ev = buildTxEvent(PRIV, 'settle', { peer: DAVE, currency: 'USD', amount: 15 });
    const res = await fetch(`${base}/api/tx`, { method: 'POST', headers: jsonHeaders, body: JSON.stringify(ev) });
    assert.strictEqual(res.status, 200, await res.clone().text());
    assert.strictEqual((await res.json()).settled.remaining, 25);
  });

  it('refuses every malformed header shape (401)', async () => {
    const url = `${base}/api/trustlines`;
    const body = JSON.stringify({ peer: DAVE, currency: 'USD', limit: 5 });
    const post = (auth, b = body) => fetch(url, {
      method: 'POST', headers: { ...jsonHeaders, authorization: auth }, body: b,
    });

    // Signature by a different key than the claimed pubkey.
    const forged = JSON.parse(Buffer.from(buildNip98(PRIV, url, 'POST', body).slice(6), 'base64').toString());
    const other = JSON.parse(Buffer.from(buildNip98(PRIV2, url, 'POST', body).slice(6), 'base64').toString());
    forged.sig = other.sig;
    assert.strictEqual((await post('Nostr ' + Buffer.from(JSON.stringify(forged)).toString('base64'))).status, 401, 'forged sig');

    // Stale timestamp.
    const stale = JSON.parse(Buffer.from(buildNip98(PRIV, url, 'POST', body).slice(6), 'base64').toString());
    stale.created_at -= 3600;
    stale.id = eventId(stale); // re-id but the sig no longer matches either
    assert.strictEqual((await post('Nostr ' + Buffer.from(JSON.stringify(stale)).toString('base64'))).status, 401, 'stale ts');

    // Signed for a different URL.
    assert.strictEqual((await post(buildNip98(PRIV, `${base}/api/settle`, 'POST', body))).status, 401, 'url mismatch');

    // Signed for a different method.
    assert.strictEqual((await post(buildNip98(PRIV, url, 'GET'))).status, 401, 'method mismatch');

    // Body swapped after signing (payload tag mismatch).
    assert.strictEqual((await post(buildNip98(PRIV, url, 'POST', '{"peer":"x"}'))).status, 401, 'payload mismatch');

    // A (valid) bodyless header replayed onto a body-carrying write —
    // refused as unauthenticated (401), never reaching the did:* lane check.
    const noPayload = buildNip98(PRIV, url, 'POST', null);
    assert.strictEqual((await post(noPayload)).status, 401, 'missing payload tag on a write');
  });

  it('verifyNip98 unit: accepts its own builder, returns the DID', () => {
    const url = 'https://n.example/api/whoami';
    const h = buildNip98(PRIV, url, 'GET');
    assert.match(verifyNip98(h, url, 'GET'), /^did:nostr:[0-9a-f]{64}$/);
    assert.strictEqual(verifyNip98(h, url, 'POST'), null);
    assert.strictEqual(verifyNip98(h, 'https://other.example/', 'GET'), null);
  });

  it('serves the vendored xlogin widget at /xlogin.js', async () => {
    const res = await fetch(`${base}/xlogin.js`);
    assert.strictEqual(res.status, 200);
    assert.match(res.headers.get('content-type') || '', /javascript/);
    assert.match(await res.text(), /xlogin/i);
  });
});
