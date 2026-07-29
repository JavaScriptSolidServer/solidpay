// SolidPay engine — pure-model unit tests.

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  toMicro, fromMicro, pairKey, debtOf, capacityOf, findPath,
  entryHash, normalizeAgent, Ledger, LedgerError,
} from '../lib/engine.js';

describe('engine: amounts', () => {
  it('micro-unit conversion round-trips and rejects float garbage', () => {
    assert.strictEqual(toMicro(0.1), 100000n);
    assert.strictEqual(fromMicro(toMicro(1234.567891)), 1234.567891);
    assert.strictEqual(toMicro(0.1234567), null, '> 6 dp refused');
    assert.strictEqual(toMicro(-5), null);
    assert.strictEqual(toMicro(NaN), null);
  });
});

describe('engine: identity', () => {
  it('canonicalizes the WebID document form; DIDs pass through', () => {
    assert.strictEqual(normalizeAgent('http://x/alice/profile/card.jsonld#me'),
      'http://x/alice/profile/card#me');
    assert.strictEqual(normalizeAgent('did:nostr:abc'), 'did:nostr:abc');
  });
});

describe('engine: signed single-balance bookkeeping', () => {
  it('the two directions of a pair are the same number, negated', () => {
    const state = { trustlines: {}, balances: {} };
    state.balances[pairKey('a', 'b', 'USD')] = toMicro(40).toString();
    assert.strictEqual(debtOf(state, 'a', 'b', 'USD'), 40000000n);
    assert.strictEqual(debtOf(state, 'b', 'a', 'USD'), -40000000n);
  });

  it('owed-to-you credit is spendable with zero trustline (clearing)', () => {
    const state = { trustlines: {}, balances: {} };
    state.balances[pairKey('x', 'y', 'USD')] = (-toMicro(30)).toString(); // y owes x 30
    assert.strictEqual(capacityOf(state, 'x', 'y', 'USD'), 30000000n);
    assert.deepStrictEqual(findPath(state, 'x', 'y', 'USD', toMicro(30)), ['x', 'y']);
    assert.strictEqual(findPath(state, 'x', 'y', 'USD', toMicro(31)), null);
  });
});

describe('engine: Ledger transitions', () => {
  const A = 'https://n.example/u/alice#me';
  const B = 'https://n.example/u/bob#me';
  const C = 'https://n.example/u/carol#me';

  it('runs the canonical scenario: trust → route → pay → settle, chain intact', () => {
    let persisted = 0;
    const ledger = new Ledger({ persist: () => { persisted += 1; } });

    // bob trusts alice 1000; carol trusts bob 500 → alice pays carol via bob.
    ledger.setTrustline(B, A, 'usd', 1000);
    ledger.setTrustline(C, B, 'USD', 500);
    assert.deepStrictEqual(ledger.path(A, C, 'USD', 300).path, [A, B, C]);

    const { payment } = ledger.pay(A, C, 'USD', 300);
    assert.deepStrictEqual(payment.path, [A, B, C]);
    const g = ledger.graph();
    const owes = (d, c) => g.balances.find((b) => b.debtor === d && b.creditor === c)?.amount;
    assert.strictEqual(owes(A, B), 300);
    assert.strictEqual(owes(B, C), 300);
    assert.strictEqual(ledger.balancesFor(C).net.USD, 300);
    assert.strictEqual(ledger.balancesFor(A).net.USD, -300);

    // Beyond capacity: no route, books untouched.
    assert.throws(() => ledger.pay(A, C, 'USD', 900), (e) => e instanceof LedgerError && e.status === 404);
    assert.strictEqual(ledger.graph().balances.length, 2);

    // Settle: creditor-only, bounded by the debt.
    assert.throws(() => ledger.settle(B, C, 'USD', 200), (e) => e.status === 409, 'carol owes bob nothing');
    assert.strictEqual(ledger.settle(C, B, 'USD', 150).settled.remaining, 150);

    // Removal refused while debt outstanding.
    assert.throws(() => ledger.removeTrustline(B, A, 'USD'), (e) => e.status === 409);

    // The chain verifies; every transition persisted.
    assert.strictEqual(ledger.verifyLog().valid, true);
    assert.strictEqual(ledger.state.seq, persisted);
    const last = ledger.state.log[ledger.state.log.length - 1];
    assert.strictEqual(entryHash(last), last.hash);
  });

  it('refuses self-trust, bad currencies, and bad amounts loudly', () => {
    const ledger = new Ledger({});
    assert.throws(() => ledger.setTrustline(A, A, 'USD', 10), (e) => e.status === 400);
    assert.throws(() => ledger.setTrustline(A, B, 'not a currency!', 10), (e) => e.status === 400);
    assert.throws(() => ledger.setTrustline(A, B, 'USD', -1), (e) => e.status === 400);
    assert.throws(() => ledger.pay(A, B, 'USD', 0.1234567), (e) => e.status === 400);
  });

  it('currencies are isolated', () => {
    const ledger = new Ledger({});
    ledger.setTrustline(B, A, 'EUR', 9999);
    assert.throws(() => ledger.pay(A, B, 'USD', 1), (e) => e.status === 404, 'EUR line lends no USD capacity');
    assert.strictEqual(ledger.pay(A, B, 'EUR', 1).payment.amount, 1);
  });
});
