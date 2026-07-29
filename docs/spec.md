# SolidPay protocol — v0 (with the v1 signature draft)

SolidPay is Ryan Fugger's original Ripple (2004) — bilateral credit lines and
payments routed through chains of trust — rebuilt on Solid ideas: every user
is a URI, every transition is hash-chained, and (from v1) every transition is
signed with a key the actor holds. No blockchain, no native token, no global
consensus.

Lineage: [classic.ripplepay.com](https://classic.ripplepay.com/) · Fugger,
*"Money as IOUs in Social Trust Networks"* ·
[webcontracts trustline.v1](https://github.com/webcontracts/webcontracts.github.io/issues/4)
· proven first as the [JSS `ripple` plugin](https://github.com/JavaScriptSolidServer/plugins).

## 1. Identity — every user is a URI

An **agent** is identified by a URI:

- a node-local agent: `https://<node>/u/<name>#me` — MUST dereference to a
  profile document (JSON) whose `@id` is the agent URI;
- a Solid WebID: `https://<host>/<pod>/profile/card#me`;
- a DID, e.g. `did:nostr:<hex>` (hex form canonical; npub is display-only).

**Canonical spelling.** One agent MUST have exactly one spelling everywhere in
the ledger. Implementations MUST canonicalize known aliases at every id entry
point; specifically the WebID *document* form `/profile/card.jsonld#me`
normalizes to the *fragment* form `/profile/card#me`. (An identity-keyed graph
silently splits on spelling drift — this rule exists because we hit it live.)

## 2. Amounts

Amounts cross APIs as decimal numbers with at most **6 decimal places**,
`0 < amount ≤ 10^12`. All arithmetic is integer micro-units (amount × 10⁶).
A currency code matches `[A-Z0-9]{1,12}` (uppercased on input) and carries no
built-in meaning — USD, SATS, HRS, BEER are equally valid.

## 3. Trustlines

A **trustline** `(creditor, debtor, currency, limit)` is a unilateral grant:
the creditor permits the debtor to owe them up to `limit` of `currency`.

- Only the creditor MAY create, resize (including to 0 = freeze), or remove
  their line. The authenticated actor **is** the creditor — never a parameter.
- Self-trust is invalid.
- Removal MUST be refused (409) while the debtor owes on the line; the IOU
  record itself lives in the balance (§4), not the line.

## 4. Balances

One **signed** balance per unordered pair + currency, stored as "lo owes hi"
with `[lo, hi] = sort(a, b)`. The two directions are the same number negated —
two mirrored entries are forbidden (they can desync; one signed number
cannot). A zero balance is removed.

`debt(x→y)` = what x currently owes y (may be negative).
`capacity(x→y) = limit(y→x) − debt(x→y)` — spendable on a hop from x to y.
Negative debt makes owed-to-you credit spendable with **no trustline at all**:
paying back clears debt first ("clearing").

## 5. Payments

A payment `(from, to, currency, amount)`:

1. Find a path from→to where **every** hop has `capacity ≥ amount`
   (breadth-first, shortest hops, path length ≤ 8; single path, no partial
   fills — a payment either routes whole or fails with "no route").
2. Shift `debt(pᵢ→pᵢ₊₁) += amount` along every hop **atomically**.

Intermediaries need no per-payment consent: each hop consumes credit its next
node already granted. Pre-authorization *is* the routing permission; the only
per-request authorization is the sender's.

**Settle**: the creditor records out-of-band repayment, reducing
`debt(peer→creditor)` by at most its current value. Only the party whose
claim shrinks may record it.

## 6. The transition log

Every state change appends an entry:

```json
{ "seq": 7, "prev": "sha256:…", "ts": "2026-07-29T00:01:57Z",
  "actor": "<agent URI>", "type": "send-payment",
  "params": { "from": "…", "to": "…", "currency": "USD",
              "amount": 300, "path": ["…","…","…"] },
  "hash": "sha256:…" }
```

`hash = sha256( JCS(entry \ {hash, sig}) )` with JCS = RFC 8785 canonical
JSON. `prev` is the previous entry's hash (`null` for seq 1); the newest hash
is the **tip**. Types: `create-trustline`, `update-trustline`,
`remove-trustline`, `send-payment`, `settle`. `GET /api/log/verify` re-derives
the chain; anyone can do the same from `GET /api/log`.

## 7. Signatures — v1 (draft)

v0 authenticates writes with node-local sessions; the node is trusted to
attribute actors honestly. v1 removes that trust:

- Each transition gains `sig`: a BIP340 schnorr signature by the **actor's**
  secp256k1 key over the same canonical bytes the hash covers
  (`JCS(entry \ {hash, sig})`).
- The actor URI binds to the key via `did:nostr:<hex>` directly, or via a
  verification method in the agent's profile document / WebID card.
- A node MUST reject a transition whose signature does not verify against the
  actor's key — including its own; the node becomes a coordinator, not an
  authority. Anyone replaying the log re-verifies every signature.
- A signed transition is deliberately shaped like a nostr event (pubkey,
  created_at, kind, content, sig) so the ledger can be carried by nostr
  infrastructure — which is the on-ramp to federation (v2): cross-node routes
  as signed, relayable, independently verifiable events.

## 8. HTTP API (v0)

```
POST /api/register {username,password}      → 201 {agent, token}
POST /api/login    {username,password}      → 200 {agent, token}
GET  /api/whoami                            → {agent|null}
GET  /u/<name>                              → profile document
GET  /api/graph                             → {trustlines[], balances[], seq, tip}
GET  /api/balances?agent=<uri>              → {agent, positions[], net{}}
GET  /api/path?from&to&currency&amount      → {path[], hops} | 404
POST /api/trustlines {peer,currency,limit}  → 201/200   [creditor]
POST /api/trustlines/remove {peer,currency} → 200 | 409 [creditor]
POST /api/payments {to,currency,amount}     → 200 | 404 [sender]
POST /api/settle {peer,currency,amount}     → 200 | 409 [creditor]
GET  /api/log?limit=N                       → {seq, tip, entries[]}
GET  /api/log/verify                        → {valid, seq, tip}
```

Writes are `Authorization: Bearer` (stateless HMAC in v0; signature-bearing
bodies in v1 make the bearer optional). Errors are `{error}` with honest
status codes. The graph is public in v0 — per-agent visibility is an open
design question tracked in the roadmap.

## 9. Known limits of v0

- **Single node.** Atomicity comes free in-process; cross-node payment is the
  federation problem (v2) — hold/commit or hashlocks, not hand-waving.
- **Public graph.** Fugger's RipplePay showed users only their own lines;
  a privacy model (per-agent views, maybe pod-mirrored statements) is v1+.
- **Log growth.** The state file rewrites whole; an append-log is the obvious
  fix when it matters.
