// Server-side NIP-98 (HTTP Auth for Nostr) verification.
//
// Companion to the `nip98` client library (github.com/nip98/nip98), which
// creates the header and validates its STRUCTURE but deliberately leaves
// signature verification to a schnorr library — this module is that half:
// structure checks + NIP-01 event id + BIP-340 verification via
// @noble/curves (the repo's one dependency).
//
//   Authorization: Nostr <base64(signed kind-27235 event)>
//   tags: [["u", <absolute url>], ["method", <verb>], ["payload", <sha256 hex>]?]
//
// A verified header authenticates the actor as `did:nostr:<64-hex-pubkey>` —
// the hex form canonical, npub display-only. This is signed AUTHENTICATION
// (the request is signed); signed TRANSITIONS (the ledger entry itself) are
// protocol level 1, spec §9.

import crypto from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';

const WINDOW_SECS = 60;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

const sha256hex = (data) => crypto.createHash('sha256').update(data).digest('hex');

/** NIP-01 event id: sha256 over the canonical serialization array. */
export function eventId(ev) {
  return sha256hex(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]));
}

/**
 * Verify a NIP-98 Authorization header against the request it arrived on.
 * Returns `did:nostr:<hex>` on success, or null (never throws).
 *
 * @param {string} header  the Authorization header value
 * @param {string} url     the absolute URL the client addressed
 * @param {string} method  the HTTP method
 * @param {string|null} rawBody  the exact body bytes as a string, if any
 */
export function verifyNip98(header, url, method, rawBody = null) {
  if (typeof header !== 'string' || !header.startsWith('Nostr ')) return null;
  let ev;
  try { ev = JSON.parse(Buffer.from(header.slice(6), 'base64').toString('utf8')); }
  catch { return null; }
  if (!ev || typeof ev !== 'object' || ev.kind !== 27235) return null;
  if (!HEX64.test(ev.pubkey || '') || !HEX128.test(ev.sig || '')) return null;
  if (!Array.isArray(ev.tags) || typeof ev.content !== 'string') return null;
  if (!Number.isInteger(ev.created_at)) return null;
  if (Math.abs(Math.floor(Date.now() / 1000) - ev.created_at) > WINDOW_SECS) return null;

  const tag = (name) => ev.tags.find((t) => Array.isArray(t) && t[0] === name)?.[1];
  if (tag('u') !== url) return null;
  if ((tag('method') || '').toUpperCase() !== method.toUpperCase()) return null;
  // Payload binding: when the event carries a payload tag it must match the
  // body; when a body is present a payload tag is required (else a signed
  // GET header could be replayed onto a write within the time window).
  const payload = tag('payload');
  if (rawBody != null && rawBody !== '') {
    if (payload !== sha256hex(rawBody)) return null;
  } else if (payload != null) return null;

  if (eventId(ev) !== ev.id) return null;
  try {
    if (!schnorr.verify(ev.sig, ev.id, ev.pubkey)) return null;
  } catch { return null; }
  return `did:nostr:${ev.pubkey}`;
}

/**
 * Build a signed NIP-98 header from a raw private key (server/test side —
 * browsers use the `nip98`/xlogin client instead).
 */
export function buildNip98(privkeyHex, url, method, rawBody = null) {
  const pubkey = Buffer.from(schnorr.getPublicKey(privkeyHex)).toString('hex');
  const tags = [['u', url], ['method', method.toUpperCase()]];
  if (rawBody != null && rawBody !== '') tags.push(['payload', sha256hex(rawBody)]);
  const ev = { kind: 27235, created_at: Math.floor(Date.now() / 1000), tags, content: '', pubkey };
  ev.id = eventId(ev);
  ev.sig = Buffer.from(schnorr.sign(ev.id, privkeyHex)).toString('hex');
  return 'Nostr ' + Buffer.from(JSON.stringify(ev)).toString('base64');
}
