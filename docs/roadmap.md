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
- [x] Signed transitions (spec §9) — every transition is a nostr event
      (kinds 8801–8804, content = RFC 8785 canonical intent, BIP-340 sig)
      submitted at `POST /api/tx`; the signature IS the authentication.
      did:nostr agents self-sign (NIP-07/xlogin in the UI); node-local
      accounts are custodially signed with disclosed custody; `log/verify`
      audits authorship over the whole chain — verify-don't-trust.
- [ ] WebID / external-URI agents alongside node-local `/u/name#me`
- [ ] Privacy: per-agent graph views (own lines + paths that touch you)
- [ ] Append-log storage (NDJSON) replacing whole-file rewrite

## v2 — federation

- [x] TWO public testnet nodes (melvin.me:3480 + melvincarvalho.com:3480)
- [x] Gateway-pattern cross-node payments (spec §13.2, tools/xnode-demo.js):
      alice@A → carol@B through a did:nostr gateway — signatures are the
      only coordination; demonstrated live between the two nodes
- [ ] Atomic routes: hold/commit transitions with TTL + hashlocks (spec §13.3)
- [ ] Signed transitions as nostr events over relays (discovery + transport)

## v3 — anchoring & beyond

- [x] Anchor chain tips to Bitcoin via Blocktrails (spec §13.4,
      tools/anchor.js + GET /api/anchors) — LIVE on testnet4: a federation
      trail carrying both nodes' audited tips as chained P2TR marks
- [ ] Pod-delivered statements (Solid pods as citizen-controlled copies,
      the recordweb pattern)
- [ ] Agents as participants (autonomous trust management, routing fees?)
- [ ] solidpay.org: site, spec home, and the 2018 → 2026 story

## v4 — the machine economy

- [x] Currency registry: every currency is a URI (registry.json +
      GET /api/currencies; codes are aliases; kinds fiat-iou / chain /
      service / mutual). TBTC3/TBTC4 registered as chain-settled; LLM
      inference tokens registered as service-settled (serving IS the
      settlement).
- [ ] Settlement verification for chain currencies (settle carries a txid;
      the node checks the testnet3/testnet4 transaction pays the creditor)
- [ ] 402 loop: request → 402 → signed payment over a trustline → retry
      (composes with the JSS pay plugin and ollama-proxy)
- [ ] LLM agents as first-class participants (a did:nostr key + a policy:
      extend trust, price tokens, settle by serving)
