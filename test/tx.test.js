// Level 1 — signed transitions over /api/tx.
//
// A transition is a nostr event (kinds 8801-8804, content = RFC 8785
// canonical intent, BIP-340 sig). The signature is the authentication.
// Covered: the full mixed-custody scenario (a did:nostr agent and a
// password agent transacting on one graph, every entry signed — externally
// or custodially), replay refusal, canonical-form enforcement, tamper
// refusal, and the auditor's log/verify reporting authorship.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createNode } from '../server.js';
import { buildTxEvent, verifyTxEvent, verifyEntryEvent, KINDS } from '../lib/tx.js';
import { canonicalize } from '../lib/engine.js';

const PRIV = '0000000000000000000000000000000000000000000000000000000000000003';
const jsonHeaders = { 'content-type': 'application/json' };

describe('signed transitions (level 1)', () => {
  let node; let base; let dataDir; let DAVE; let daveTok; let NOSTR;

  before(async () => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'solidpay-tx-'));
    node = createNode({ dataDir });
    const { port } = await node.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${port}`;
    const reg = await fetch(`${base}/api/register`, {
      method: 'POST', headers: jsonHeaders,
      body: JSON.stringify({ username: 'dave', password: 'test-pass-1234' }),
    });
    const b = await reg.json();
    DAVE = b.agent; daveTok = b.token;
  });
  after(async () => {
    if (node) await node.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  const postTx = (ev) => fetch(`${base}/api/tx`, { method: 'POST', headers: jsonHeaders, body: JSON.stringify(ev) });

  // ---- pure units ----------------------------------------------------------
  it('build → verify round-trips; the DID is the pubkey', () => {
    const ev = buildTxEvent(PRIV, 'send-payment', { to: 'https://n/u/x#me', currency: 'USD', amount: 5 });
    const v = verifyTxEvent(ev);
    assert.strictEqual(v.error, undefined);
    assert.strictEqual(v.type, 'send-payment');
    assert.strictEqual(v.actor, `did:nostr:${ev.pubkey}`);
    assert.deepStrictEqual(v.intent, { to: 'https://n/u/x#me', currency: 'USD', amount: 5 });
  });

  it('refuses non-canonical content, stale events, unknown kinds', () => {
    const good = buildTxEvent(PRIV, 'settle', { peer: 'https://n/u/x#me', currency: 'USD', amount: 1 });
    // Same meaning, different bytes (keys unsorted) — must be refused even
    // if someone re-signed it, or replay ids could be sidestepped.
    const sloppy = { ...good, content: '{"currency":"USD","peer":"https://n/u/x#me","amount":1}' };
    assert.match(verifyTxEvent(sloppy).error || '', /id mismatch|canonical/);
    const stale = buildTxEvent(PRIV, 'settle', { peer: 'x', currency: 'USD', amount: 1 }, { created_at: Math.floor(Date.now() / 1000) - 999 });
    assert.match(verifyTxEvent(stale).error, /created_at/);
    assert.match(verifyTxEvent({ ...good, kind: 1 }).error, /unknown kind/);
  });

  // ---- the mixed-custody scenario -----------------------------------------
  it('a did:nostr agent extends trust via /api/tx — no Authorization header at all', async () => {
    const ev = buildTxEvent(PRIV, 'set-trustline', { peer: DAVE, currency: 'USD', limit: 100 });
    NOSTR = `did:nostr:${ev.pubkey}`;
    const res = await postTx(ev);
    assert.strictEqual(res.status, 201, await res.clone().text());
    const body = await res.json();
    assert.strictEqual(body.trustline.creditor, NOSTR);
    assert.deepStrictEqual(body.entry.event, ev, 'the signed event is embedded in the log entry');
  });

  it('replaying the same signed event is refused (409)', async () => {
    const ev = buildTxEvent(PRIV, 'set-trustline', { peer: DAVE, currency: 'EUR', limit: 9 });
    assert.strictEqual((await postTx(ev)).status, 201);
    assert.strictEqual((await postTx(ev)).status, 409, 'identical event id must not apply twice');
  });

  it('tampered intent and non-canonical intents are refused', async () => {
    const ev = buildTxEvent(PRIV, 'set-trustline', { peer: DAVE, currency: 'GBP', limit: 5 });
    const tampered = { ...ev, content: canonicalize({ peer: DAVE, currency: 'GBP', limit: 5000 }) };
    assert.strictEqual((await postTx(tampered)).status, 401, 'content change breaks the id');
    // Signed lowercase currency: valid signature, but the node cannot rewrite
    // signed bytes, so non-canonical form is a 400.
    const lower = buildTxEvent(PRIV, 'set-trustline', { peer: DAVE, currency: 'usd', limit: 5 });
    assert.strictEqual((await postTx(lower)).status, 400);
  });

  it('a password agent pays the did:nostr agent — custodially signed entry', async () => {
    const pay = await fetch(`${base}/api/payments`, {
      method: 'POST', headers: { ...jsonHeaders, authorization: `Bearer ${daveTok}` },
      body: JSON.stringify({ to: NOSTR, currency: 'USD', amount: 40 }),
    });
    assert.strictEqual(pay.status, 200, await pay.clone().text());
    const { entry } = await pay.json();
    assert.ok(entry.event, 'the custodial lane also signs');
    // The custodial key is published in dave's profile document.
    const prof = await (await fetch(DAVE.replace('#me', '').replace('/u/', '/u/'))).json();
    assert.strictEqual(prof.pubkey, entry.event.pubkey, 'profile publishes the key the entry verifies against');
    assert.strictEqual(prof['solidpay:keyCustody'], 'node', 'custody is disclosed');
  });

  it('the did:nostr agent pays back signed — clearing, zero trustline', async () => {
    const ev = buildTxEvent(PRIV, 'send-payment', { to: DAVE, currency: 'USD', amount: 15 });
    const res = await postTx(ev);
    assert.strictEqual(res.status, 200, await res.clone().text());
    const bal = await (await fetch(`${base}/api/balances?agent=${encodeURIComponent(NOSTR)}`)).json();
    assert.strictEqual(bal.net.USD, 25, '40 received − 15 paid back');
  });

  it('legacy write lanes refuse did:* agents (their lane is /api/tx)', async () => {
    // A NIP-98-authenticated write on the legacy endpoint would produce an
    // entry the node cannot sign for — refused with a pointer.
    const { buildNip98 } = await import('../lib/nip98.js');
    const url = `${base}/api/trustlines`;
    const body = JSON.stringify({ peer: DAVE, currency: 'USD', limit: 5 });
    const res = await fetch(url, {
      method: 'POST',
      headers: { ...jsonHeaders, authorization: buildNip98(PRIV, url, 'POST', body) },
      body,
    });
    assert.strictEqual(res.status, 400);
    assert.match((await res.json()).error, /api\/tx/);
  });

  // ---- the auditor ---------------------------------------------------------
  it('log/verify audits authorship: every entry signed and valid', async () => {
    const v = await (await fetch(`${base}/api/log/verify`)).json();
    assert.strictEqual(v.valid, true);
    assert.strictEqual(v.signatures.unsigned, 0, 'level 1: nothing unsigned');
    assert.strictEqual(v.signatures.invalid, 0);
    assert.ok(v.signatures.signed >= 4);
  });

  it('an auditor can verify entries independently with verifyEntryEvent', async () => {
    const log = await (await fetch(`${base}/api/log`)).json();
    const daveProfile = await (await fetch(`${base}/u/dave`)).json();
    const keyOf = (actor) => (actor === DAVE ? daveProfile.pubkey : null);
    for (const e of log.entries) {
      const r = verifyEntryEvent(e, keyOf);
      assert.strictEqual(r.valid, true, `entry ${e.seq}: ${r.error || 'ok'}`);
    }
    // Forge an entry: swap the amount in a payment entry — the audit catches it.
    const paid = log.entries.find((e) => e.type === 'send-payment');
    const forged = { ...paid, params: { ...paid.params, amount: 999999 } };
    assert.strictEqual(verifyEntryEvent(forged, keyOf).valid, false, 'forged params no longer match the signed intent');
  });

  it('spec Appendix A.4 vector: byte-exact id and sig', () => {
    const ev = buildTxEvent(PRIV, 'send-payment',
      { to: 'https://n.example/u/carol#me', currency: 'USD', amount: 300 },
      { created_at: 1785312000, auxRand: '00'.repeat(32), nonce: null });
    assert.strictEqual(ev.pubkey, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9');
    assert.strictEqual(ev.content, '{"amount":300,"currency":"USD","to":"https://n.example/u/carol#me"}');
    assert.strictEqual(ev.id, '0501ad5807e019a8609dbf18120956e4af64f2b5e9186c7033eb7cda7b49e88a');
    assert.strictEqual(ev.sig, 'b0766e770dd4627c00342255a809aba6f33a8ebc8e8b434fab2305b8dd229ab25e52063cccf1274ce9b99c6e52d6bf4c543ce69cb55d13dc7ba93ac55060c12f');
    assert.strictEqual(ev.kind, KINDS['send-payment']);
  });

  it('a custodial key submitted via /api/tx maps back to the ACCOUNT agent', async () => {
    // One agent, one spelling: the node's custodial key must never mint a
    // second did:nostr identity for an existing account.
    const daveKeys = JSON.parse(fs.readFileSync(path.join(dataDir, 'keys.json'), 'utf8'));
    const ev = buildTxEvent(daveKeys.dave, 'set-trustline', { peer: NOSTR, currency: 'HRS', limit: 3 });
    const res = await postTx(ev);
    assert.strictEqual(res.status, 201, await res.clone().text());
    assert.strictEqual((await res.json()).trustline.creditor, DAVE, 'actor is the account URI, not a new DID');
  });

  it('the audit catches a double-applied signed intent (duplicate event id)', async () => {
    // Simulate a malicious node: append the same event twice by editing
    // state on disk, then ask the audit.
    const stateFile = path.join(dataDir, 'state.json');
    const st = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    const signedEntry = st.log.find((e) => e.event);
    const { entryHash } = await import('../lib/engine.js');
    const dup = { ...signedEntry, seq: st.seq + 1, prev: st.tip, ts: new Date().toISOString() };
    dup.hash = entryHash(dup);
    st.log.push(dup); st.seq = dup.seq; st.tip = dup.hash;
    fs.writeFileSync(stateFile, JSON.stringify(st));
    // A fresh node over the tampered state: chain verifies (the node hashed
    // its own tampering), but the AUTHORSHIP audit refuses the duplicate.
    const node2 = createNode({ dataDir });
    const { port } = await node2.listen(0, '127.0.0.1');
    const v = await (await fetch(`http://127.0.0.1:${port}/api/log/verify`)).json();
    await node2.close();
    assert.strictEqual(v.signatures.invalid >= 1, true, 'duplicate id flagged');
    assert.strictEqual(v.valid, false, 'a double-applied intent fails the audit');
    assert.ok((v.problems || []).some((p) => /duplicate event id/.test(p.error)));
  });
});
