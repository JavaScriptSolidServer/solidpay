// Signed transitions — protocol level 1.
//
// The wire format of a signed transition IS a nostr event (NIP-01): kind
// per transition type, content = the RFC 8785-canonical intent params,
// pubkey = the actor's x-only key, standard id + BIP-340 sig. Deliberate
// consequences:
//   * any NIP-07 signer (extensions, xlogin) signs transitions natively —
//     no bespoke wallet code anywhere;
//   * a transition is relayable over nostr infrastructure as-is, which is
//     the transport story for federation (level 2).
//
// The actor signs INTENT, not chain position: {to, currency, amount} — not
// seq/prev/path. Ordering is the node's assertion (proven by the hash
// chain); authorship is the actor's (proven by the event signature); routing
// is the network's business (authorized by the intermediaries' own signed
// trustlines — Fugger's consent model). This split is what makes signing
// race-free for client-held keys: no round trip, nothing to re-sign when
// the chain moves.
//
// Replay protection: created_at freshness (±FRESH_SECS) + the node refuses
// an event id it has already applied (§ server).

import crypto from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';
import { canonicalize } from './engine.js';

export const FRESH_SECS = 120;

/** Transition type ↔ nostr kind. One kind for set (create/update is derived
 *  by the node from whether the line existed). */
export const KINDS = {
  'set-trustline': 8801,
  'remove-trustline': 8802,
  'send-payment': 8803,
  settle: 8804,
};
export const KIND_TO_TYPE = Object.fromEntries(Object.entries(KINDS).map(([t, k]) => [k, t]));

const sha256hex = (data) => crypto.createHash('sha256').update(data).digest('hex');

/** NIP-01 event id: sha256 over the canonical serialization array. */
export function eventId(ev) {
  return sha256hex(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]));
}

/**
 * The signable intent params for a transition type — the subset of entry
 * params the ACTOR asserts. Node-added annotations (path, from) are excluded.
 * Values must arrive pre-normalized (resolved peer URI, uppercase currency):
 * signatures cover exact bytes, so the node validates rather than rewrites.
 */
export function intentOf(type, params) {
  switch (type) {
    case 'set-trustline':
    case 'create-trustline': // entry-type aliases of the 8801 intent
    case 'update-trustline':
      return { peer: params.peer, currency: params.currency, limit: params.limit };
    case 'remove-trustline':
      return { peer: params.peer, currency: params.currency };
    case 'send-payment':
      return { to: params.to, currency: params.currency, amount: params.amount };
    case 'settle':
      return { peer: params.peer, currency: params.currency, amount: params.amount };
    default:
      return null;
  }
}

/** Entry type → the kind its embedded event must carry. */
export function kindForEntryType(type) {
  if (type === 'create-trustline' || type === 'update-trustline') return KINDS['set-trustline'];
  return KINDS[type] ?? null;
}

/**
 * Build + sign a transition event (server/test side — browsers use
 * window.nostr.signEvent on the same shape).
 * @param {string} privkeyHex 32-byte hex
 * @param {'set-trustline'|'remove-trustline'|'send-payment'|'settle'} type
 * @param {object} intentParams pre-normalized intent (see intentOf)
 * @param {object} [opts] created_at override; auxRand (hex) for deterministic test vectors
 */
export function buildTxEvent(privkeyHex, type, intentParams, opts = {}) {
  const kind = KINDS[type];
  if (!kind) throw new Error(`unknown transition type ${type}`);
  const ev = {
    pubkey: Buffer.from(schnorr.getPublicKey(privkeyHex)).toString('hex'),
    created_at: opts.created_at ?? Math.floor(Date.now() / 1000),
    kind,
    tags: [],
    content: canonicalize(intentParams),
  };
  ev.id = eventId(ev);
  ev.sig = Buffer.from(
    opts.auxRand
      ? schnorr.sign(ev.id, privkeyHex, Buffer.from(opts.auxRand, 'hex'))
      : schnorr.sign(ev.id, privkeyHex),
  ).toString('hex');
  return ev;
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

/**
 * Structurally + cryptographically verify a transition event.
 * Returns { actor, type, intent } or { error } — never throws.
 * Freshness is checked here; replay (seen ids) is the caller's ledger state.
 */
export function verifyTxEvent(ev, { now = Date.now() } = {}) {
  if (!ev || typeof ev !== 'object') return { error: 'not an event' };
  const type = KIND_TO_TYPE[ev.kind];
  if (!type) return { error: `unknown kind ${ev.kind}` };
  if (!HEX64.test(ev.pubkey || '')) return { error: 'bad pubkey' };
  if (!HEX64.test(ev.id || '')) return { error: 'bad id' };
  if (!HEX128.test(ev.sig || '')) return { error: 'bad sig encoding' };
  if (!Array.isArray(ev.tags) || ev.tags.length !== 0) return { error: 'tags must be []' };
  if (typeof ev.content !== 'string') return { error: 'bad shape' };
  if (!Number.isInteger(ev.created_at)) return { error: 'bad created_at' };
  if (Math.abs(Math.floor(now / 1000) - ev.created_at) > FRESH_SECS) {
    return { error: `created_at outside ±${FRESH_SECS}s` };
  }
  let intent;
  try { intent = JSON.parse(ev.content); } catch { return { error: 'content is not JSON' }; }
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)) return { error: 'content is not an object' };
  // The content MUST be the canonical serialization of its own value —
  // otherwise two byte-different contents could carry one meaning and the
  // node's "seen id" replay check could be sidestepped.
  if (canonicalize(intent) !== ev.content) return { error: 'content is not canonical (RFC 8785)' };
  if (eventId(ev) !== ev.id) return { error: 'id mismatch' };
  try {
    if (!schnorr.verify(ev.sig, ev.id, ev.pubkey)) return { error: 'signature invalid' };
  } catch { return { error: 'signature invalid' }; }
  return { actor: `did:nostr:${ev.pubkey}`, type, intent };
}

/**
 * Verify that a LOG ENTRY's embedded event authorizes that entry:
 * kind matches the entry type, content equals the canonical intent derived
 * from the entry params, pubkey matches the actor's key, sig verifies.
 * `keyOf(actor)` maps a non-DID actor URI to its published pubkey (custodial
 * accounts); did:nostr actors carry their key in the id.
 * Freshness is NOT rechecked — it was enforced at apply time; history ages.
 */
export function verifyEntryEvent(entry, keyOf = () => null) {
  const ev = entry.event;
  if (!ev) return { signed: false };
  const type = KIND_TO_TYPE[ev.kind];
  if (!type) return { signed: true, valid: false, error: `unknown kind ${ev.kind}` };
  if (kindForEntryType(entry.type) !== ev.kind) {
    return { signed: true, valid: false, error: 'kind does not match entry type' };
  }
  const expected = canonicalize(intentOf(entry.type, entry.params ?? {}));
  if (ev.content !== expected) return { signed: true, valid: false, error: 'content does not match entry intent' };
  const m = /^did:nostr:([0-9a-f]{64})$/.exec(entry.actor || '');
  const key = m ? m[1] : keyOf(entry.actor);
  if (!key) return { signed: true, valid: false, error: 'no key known for actor' };
  if (ev.pubkey !== key) return { signed: true, valid: false, error: 'pubkey does not match actor' };
  if (eventId(ev) !== ev.id) return { signed: true, valid: false, error: 'id mismatch' };
  try {
    if (!schnorr.verify(ev.sig, ev.id, ev.pubkey)) return { signed: true, valid: false, error: 'signature invalid' };
  } catch { return { signed: true, valid: false, error: 'signature invalid' }; }
  return { signed: true, valid: true };
}
