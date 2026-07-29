# SolidPay roadmap

## v0 — standalone testnet node (this release)

- [x] Engine: trustlines, signed single-balance bookkeeping, BFS routing,
      atomic multi-hop payments, settle, hash-chained log (RFC 8785 + SHA-256)
- [x] Standalone server, zero dependencies: accounts (scrypt), stateless HMAC
      bearers, every user a dereferenceable URI (`/u/name#me`)
- [x] Product UI: sign-in/signup, overview tiles, pay with live route
      preview, trustline management, chain-verified activity feed
- [x] 16 tests including a full-HTTP integration run and restart persistence
- [x] did:nostr sign-in — NIP-98 signed requests verified server-side
      (BIP-340 via @noble/curves); xlogin widget in the UI (extension, guest
      key, or pasted privkey — it's a testnet); hex canonical, npub
      display-only. did:nostr agents are first-class in one graph with
      password agents.
- [x] Public testnet instance — http://melvin.me:3480/ (pm2 `solidpay-testnet` on melvin.me, seeded; https + testnet.solidpay.org promotion pending)
- [x] Seed script for a demo trust network (tools/seed.js, idempotent)

## v1 — signatures & identity
- [ ] `sig` on every transition over the JCS bytes (spec §9); node rejects
      unverifiable transitions — verify-don't-trust
- [ ] WebID / external-URI agents alongside node-local `/u/name#me`
- [ ] Privacy: per-agent graph views (own lines + paths that touch you)
- [ ] Append-log storage (NDJSON) replacing whole-file rewrite

## v2 — federation

- [ ] Node-to-node peering: cross-node trustlines and routed payments
      (two-phase hold/commit; evaluate hashlocks à la LN)
- [ ] Signed transitions as nostr events over relays (discovery + transport)
- [ ] Multiple public testnets, then peering between them

## v3 — anchoring & beyond

- [ ] Anchor chain tips to Bitcoin via Blocktrails (public timestamps)
- [ ] Pod-delivered statements (Solid pods as citizen-controlled copies,
      the recordweb pattern)
- [ ] Agents as participants (autonomous trust management, routing fees?)
- [ ] solidpay.org: site, spec home, and the 2018 → 2026 story
