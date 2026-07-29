// Appendix A test vectors — the spec (docs/spec/index.html) and the engine
// must agree byte-for-byte. If this file fails, either the code or the spec
// changed; update BOTH deliberately or revert.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { canonicalize, entryHash, pairKey, toMicro } from '../lib/engine.js';

const A = 'https://n.example/u/alice#me';
const B = 'https://n.example/u/bob#me';
const C = 'https://n.example/u/carol#me';

describe('spec Appendix A vectors', () => {
  it('A.1 canonicalization', () => {
    assert.strictEqual(canonicalize({ b: 1, a: 'x', 'é': true }), '{"a":"x","b":1,"é":true}');
  });

  it('A.2 balance key and micro-units', () => {
    assert.strictEqual(pairKey(B, A, 'USD'),
      'https://n.example/u/alice#me|https://n.example/u/bob#me|USD');
    assert.strictEqual(toMicro(300), 300000000n);
    assert.strictEqual(toMicro(0.000001), 1n);
    assert.strictEqual(toMicro(0.0000001), null);
  });

  it('A.3 three-entry chain hashes', () => {
    const e1 = {
      seq: 1, prev: null, ts: '2026-07-29T12:00:00.000Z', actor: B,
      type: 'create-trustline', params: { peer: A, currency: 'USD', limit: 1000 },
    };
    const h1 = entryHash(e1);
    assert.strictEqual(h1, 'sha256:27ae26a0a5abe78b3dca9cba1fdb73bd5df6652f32e5d7dc8396e06a0e84ec86');

    const e2 = {
      seq: 2, prev: h1, ts: '2026-07-29T12:01:00.000Z', actor: C,
      type: 'create-trustline', params: { peer: B, currency: 'USD', limit: 500 },
    };
    const h2 = entryHash(e2);
    assert.strictEqual(h2, 'sha256:151bb238b8aa204bda446bc6574fd237bbac398c82a4335683a8749bdb408ef5');

    const e3 = {
      seq: 3, prev: h2, ts: '2026-07-29T12:02:00.000Z', actor: A,
      type: 'send-payment',
      params: { from: A, to: C, currency: 'USD', amount: 300, path: [A, B, C] },
    };
    assert.strictEqual(entryHash(e3),
      'sha256:cf5289f9be4010c23ce11838819dab7fa287259d94530183aa77bd1de23786c4');
    // The exact hashed bytes of entry 3, as printed in the appendix.
    assert.strictEqual(canonicalize(e3),
      '{"actor":"https://n.example/u/alice#me","params":{"amount":300,"currency":"USD",'
      + '"from":"https://n.example/u/alice#me","path":["https://n.example/u/alice#me",'
      + '"https://n.example/u/bob#me","https://n.example/u/carol#me"],'
      + '"to":"https://n.example/u/carol#me"},'
      + '"prev":"sha256:151bb238b8aa204bda446bc6574fd237bbac398c82a4335683a8749bdb408ef5",'
      + '"seq":3,"ts":"2026-07-29T12:02:00.000Z","type":"send-payment"}');
  });
});
