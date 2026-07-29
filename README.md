# SolidPay

**Money is trust. SolidPay makes it routable.**

SolidPay revives [Ryan Fugger's original Ripple](https://classic.ripplepay.com/)
(2004) — bilateral credit lines and payments routed through chains of trust —
with Solid ideas: **every user is a URI**, **every transition is
hash-chained**, and (v1) **signatures via did:nostr**. No blockchain, no
token, no consensus, no bank in the middle.

Landing page: <https://jss.live/solidpay/> ·
Spec: <https://jss.live/solidpay/docs/spec/> · Roadmap: [docs/roadmap.md](docs/roadmap.md)

## Quickstart

```bash
git clone https://github.com/JavaScriptSolidServer/solidpay
cd solidpay
node server.js
# solidpay node listening on port 3480 → open http://localhost:3480
```

Zero dependencies — plain Node.js ≥ 20. Behind a proxy:

```bash
PUBLIC_URL=https://testnet.solidpay.org PORT=3480 DATA=/var/solidpay node server.js
```

Open the app, create an account (you become `<origin>/u/you#me` — a URI that
dereferences), extend a friend some credit, and pay through the graph: the
route previews live before you commit.

## How it works

- **Trustline** — one-way credit: "you may owe me up to 500 USD." Only the
  creditor creates, resizes, or removes it.
- **Payment** — BFS-routed through unused credit; every hop rides a grant its
  next node already made, so intermediaries need no per-payment consent.
  Multi-hop payments settle atomically. Owed-to-you credit spends with no
  trustline at all — paying back clears debt first.
- **Settle** — IOUs clear out-of-band; the creditor records repayment.
- **Ledger** — every transition hash-chained (RFC 8785 canonical JSON +
  SHA-256); `GET /api/log/verify` re-derives the whole chain, and so can you.

Books are one **signed** number per pair+currency — the two directions are
the same number negated, so they cannot desync. All arithmetic is integer
micro-units; no float drift.

## Repo

```
server.js         the node: HTTP API + accounts + UI serving (zero deps)
lib/engine.js     the ledger engine (pure model + transitions)
lib/ui.js         the product UI (one server-rendered document)
docs/spec/        the protocol spec (Editor's Draft, HTML) + pointer md
docs/roadmap.md   v0 testnet → v1 signatures → v2 federation → v3 anchoring
test/             engine units + full-HTTP integration (npm test)
index.html        the landing page (GitHub Pages)
```

## Lineage

Proven first as the [`ripple` plugin](https://github.com/JavaScriptSolidServer/plugins)
for [JavaScript Solid Server](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)
(which remains the JSS adapter of this design), specified as
[webcontracts trustline.v1](https://github.com/webcontracts/webcontracts.github.io/issues/4),
and named for [solidpay.org](https://solidpay.org) — an idea from 2018, an
engine from 2026.

## License

MIT
