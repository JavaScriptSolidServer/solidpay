// SolidPay standalone server — a testnet node in one file, zero dependencies.
//
//   node server.js                     # http://localhost:3480, data in ./data
//   PORT=8080 DATA=/var/solidpay node server.js
//   PUBLIC_URL=https://testnet.solidpay.org node server.js   # behind a proxy
//
// Every user is a URI: registering `alice` mints the agent id
// `<origin>/u/alice#me`, and GET /u/alice dereferences to a small profile
// document — identity you can point at, Solid-style. Passwords are scrypt-
// hashed on disk; sessions are stateless HMAC bearer tokens (the capability
// pattern). Level 1: transitions are signed nostr events (POST /api/tx —
// the signature is the authentication; docs/spec/ § 9); node-local accounts
// are custodially signed so the whole log audits uniformly.
//
//   POST /api/register {username,password}   → {agent, token}
//   POST /api/login    {username,password}   → {agent, token}
//   GET  /api/whoami                          → {agent}
//   GET  /u/:name                             the agent's profile document
//   GET  /api/graph | /api/balances?agent= | /api/path?from&to&currency&amount
//   POST /api/tx                              a signed transition event (§ 9)
//   POST /api/trustlines | /api/trustlines/remove | /api/payments | /api/settle
//   GET  /api/log?limit= | /api/log/verify
//   GET  /                                    the app UI

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Ledger, LedgerError, normalizeAgent, CUR_RE } from './lib/engine.js';
import { uiPage } from './lib/ui.js';
import { verifyNip98 } from './lib/nip98.js';
import { buildTxEvent, verifyTxEvent, verifyEntryEvent, intentOf, FRESH_SECS } from './lib/tx.js';
import { schnorr } from '@noble/curves/secp256k1';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const NAME_RE = /^[a-z0-9][a-z0-9._-]{1,30}$/;
const TOKEN_TTL_MS = 30 * 24 * 3600 * 1000; // 30 days
const b64u = (b) => Buffer.from(b).toString('base64url');

// Public-testnet armor: registrations per source IP per hour (in-memory —
// resets on restart, which is the right amount of state for a throttle).
const REGISTER_PER_HOUR = 10;

export function createNode({ dataDir = './data', publicUrl = null, trustProxy = process.env.TRUST_PROXY === '1' } = {}) {
  fs.mkdirSync(dataDir, { recursive: true });

  // The vendored xlogin widget (lib/xlogin.js, AGPL, © the same author),
  // served byte-identical at /xlogin.js. Immutable for a running server.
  const xloginSrc = fs.readFileSync(path.join(__dirname, 'lib', 'xlogin.js'), 'utf8');

  // Currency registry: every currency is a URI; short codes are aliases that
  // resolve here (registry.json seed + optional operator extensions in
  // <data>/currencies.json). Unknown codes still transact — the registry is
  // discovery, not permission.
  let currencies = {};
  try { currencies = JSON.parse(fs.readFileSync(path.join(__dirname, 'registry.json'), 'utf8')).currencies || {}; } catch { /* none */ }
  try {
    const extra = JSON.parse(fs.readFileSync(path.join(dataDir, 'currencies.json'), 'utf8'));
    currencies = { ...currencies, ...(extra.currencies || extra) };
  } catch { /* none */ }

  // ---- persistent bits ---------------------------------------------------
  const stateFile = path.join(dataDir, 'state.json');
  const accountsFile = path.join(dataDir, 'accounts.json');
  const secretFile = path.join(dataDir, 'secret');

  let secret;
  try { secret = fs.readFileSync(secretFile); } catch {
    secret = crypto.randomBytes(32);
    fs.writeFileSync(secretFile, secret, { mode: 0o600 });
  }
  let accounts;
  try { accounts = JSON.parse(fs.readFileSync(accountsFile, 'utf8')); } catch { accounts = {}; }
  const saveAccounts = () => fs.writeFileSync(accountsFile, JSON.stringify(accounts, null, 2));

  // Custodial signing keys for node-local accounts (level 1): the node holds
  // a secp256k1 key per account and signs their transitions, so the whole
  // log verifies uniformly. Custody is disclosed in the profile document —
  // did:nostr agents hold their own keys and never appear in this file.
  const keysFile = path.join(dataDir, 'keys.json');
  let custodialKeys;
  try { custodialKeys = JSON.parse(fs.readFileSync(keysFile, 'utf8')); } catch { custodialKeys = {}; }
  const saveKeys = () => fs.writeFileSync(keysFile, JSON.stringify(custodialKeys, null, 2), { mode: 0o600 });
  function custodialPriv(name) {
    if (!custodialKeys[name]) {
      custodialKeys[name] = crypto.randomBytes(32).toString('hex');
      saveKeys();
    }
    return custodialKeys[name];
  }
  const custodialPub = (name) => (custodialKeys[name]
    ? Buffer.from(schnorr.getPublicKey(custodialKeys[name])).toString('hex') : null);
  /** actor URI → published pubkey (custodial accounts only; DIDs self-carry). */
  function keyOfActor(actor) {
    const m = /\/u\/([a-z0-9._-]+)#me$/.exec(String(actor || ''));
    return m ? custodialPub(m[1]) : null;
  }
  const nameOfAgent = (agent) => {
    const m = /\/u\/([a-z0-9._-]+)#me$/.exec(String(agent || ''));
    return m && accounts[m[1]] ? m[1] : null;
  };

  let state;
  try { state = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { state = undefined; }
  const ledger = new Ledger({
    state,
    persist(s) {
      const tmp = stateFile + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(s));
      fs.renameSync(tmp, stateFile);
    },
  });

  // Replay guard: applied event ids within the freshness window. Rebuilt
  // from the log tail on boot (only fresh ids can replay — older events
  // fail the created_at check on their own).
  const seenEvents = new Map(); // id → created_at (seconds)
  {
    const cutoff = Math.floor(Date.now() / 1000) - 2 * FRESH_SECS;
    for (const e of ledger.state.log.slice(-500)) {
      if (e.event?.id && e.event.created_at >= cutoff) seenEvents.set(e.event.id, e.event.created_at);
    }
  }
  function pruneSeen() {
    if (seenEvents.size > 5000) {
      const cutoff = Math.floor(Date.now() / 1000) - 2 * FRESH_SECS;
      for (const [id, t] of seenEvents) if (t < cutoff) seenEvents.delete(id);
    }
  }

  /** A signed intent must arrive in canonical form — the node validates
   *  instead of rewriting (it cannot rewrite signed bytes). */
  function intentCanonError(type, intent) {
    const uriFields = type === 'send-payment' ? ['to'] : ['peer'];
    for (const f of uriFields) {
      const v = intent[f];
      if (typeof v !== 'string' || !v) return `${f} required`;
      if (normalizeAgent(v) !== v) return `${f} must be the canonical agent spelling`;
    }
    if (typeof intent.currency !== 'string' || !CUR_RE.test(intent.currency)) {
      return 'currency must be uppercase [A-Z0-9]{1,12} (signed intents are not rewritten)';
    }
    return null;
  }

  /** Dispatch a verified signed transition to the ledger. */
  function applySigned(actor, type, intent, ev) {
    switch (type) {
      case 'set-trustline': return ledger.setTrustline(actor, intent.peer, intent.currency, intent.limit, ev);
      case 'remove-trustline': return ledger.removeTrustline(actor, intent.peer, intent.currency, ev);
      case 'send-payment': return ledger.pay(actor, intent.to, intent.currency, intent.amount, ev);
      case 'settle': return ledger.settle(actor, intent.peer, intent.currency, intent.amount, ev);
      default: throw new LedgerError(400, `unknown transition type ${type}`);
    }
  }

  // ---- identity ----------------------------------------------------------
  let origin = publicUrl ? String(publicUrl).replace(/\/$/, '') : null;
  const agentUri = (name) => `${origin}/u/${name}#me`;

  const hashPassword = (password, salt) => b64u(crypto.scryptSync(password, salt, 32));
  function mintToken(agent) {
    const payload = b64u(JSON.stringify({ a: agent, exp: Date.now() + TOKEN_TTL_MS }));
    const mac = b64u(crypto.createHmac('sha256', secret).update(payload).digest());
    return `v1.${payload}.${mac}`;
  }
  function verifyToken(token) {
    const m = /^v1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(token || '');
    if (!m) return null;
    const mac = b64u(crypto.createHmac('sha256', secret).update(m[1]).digest());
    const a = Buffer.from(mac); const b = Buffer.from(m[2]);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const { a: agent, exp } = JSON.parse(Buffer.from(m[1], 'base64url').toString());
      return exp > Date.now() ? normalizeAgent(agent) : null;
    } catch { return null; }
  }
  /**
   * Resolve the acting agent from either auth scheme:
   *   Bearer <hmac token>          → node-local account (agent baked in)
   *   Nostr  <base64 NIP-98 event> → did:nostr:<hex>, schnorr-verified
   * NIP-98 signs the absolute URL + method (+ body hash), so both are needed.
   */
  const agentOf = (req, url, rawBody = null) => {
    const h = req.headers.authorization || '';
    if (h.startsWith('Bearer ')) return verifyToken(h.slice(7));
    if (h.startsWith('Nostr ')) return verifyNip98(h, url.href, req.method, rawBody);
    return null;
  };

  // ---- tx throttle + custodial pubkey map --------------------------------
  const txHits = new Map();
  function txAllowed(req) {
    const ip = clientIp(req);
    const now = Date.now();
    const hits = (txHits.get(ip) || []).filter((t) => now - t < 3600_000);
    if (hits.length >= 120) return false;
    hits.push(now);
    txHits.set(ip, hits);
    if (txHits.size > 10_000) txHits.clear();
    return true;
  }
  function nameForPubkey(pub) {
    for (const name of Object.keys(custodialKeys)) {
      if (custodialPub(name) === pub) return name;
    }
    return null;
  }

  // ---- register throttle -------------------------------------------------
  // Client address for throttling. x-forwarded-for is only meaningful when a
  // reverse proxy WE control sets it (TRUST_PROXY=1); on a direct-port deploy
  // the header is attacker-controlled and must be ignored, or one client
  // could rotate past every throttle.
  const clientIp = (req) => (trustProxy
    ? String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim()
    : String(req.socket.remoteAddress || '?'));

  const regHits = new Map(); // ip → [timestamps]
  function registerAllowed(req) {
    const ip = clientIp(req);
    const now = Date.now();
    const hits = (regHits.get(ip) || []).filter((t) => now - t < 3600_000);
    if (hits.length >= REGISTER_PER_HOUR) return false;
    hits.push(now);
    regHits.set(ip, hits);
    if (regHits.size > 10_000) regHits.clear(); // bound the map, crudely
    return true;
  }

  // ---- http plumbing -----------------------------------------------------
  const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'authorization, content-type',
  };
  const send = (res, code, body, type = 'application/json; charset=utf-8') => {
    const buf = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body, null, 2));
    res.writeHead(code, { ...CORS, 'content-type': type, 'content-length': buf.length });
    res.end(buf);
  };
  /** Buffer the body (≤ 64 KiB) and return { raw, json } — raw is kept for
   *  NIP-98's payload-tag verification, which hashes the exact wire bytes. */
  const readBody = (req) => new Promise((resolve) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size <= 65536) chunks.push(c); });
    req.on('end', () => {
      if (size > 65536) return resolve({ raw: null, json: null });
      const raw = Buffer.concat(chunks).toString();
      try { resolve({ raw, json: JSON.parse(raw || '{}') }); }
      catch { resolve({ raw, json: null }); }
    });
    req.on('error', () => resolve({ raw: null, json: null }));
  });

  // ---- request handler ---------------------------------------------------
  async function handle(req, res) {
    const url = new URL(req.url, origin || `http://${req.headers.host || 'localhost'}`);
    if (!origin) origin = url.origin; // first-request fallback when no PUBLIC_URL
    const p = url.pathname;

    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

    try {
      // ---- app UI + profile URIs ----
      if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
        return send(res, 200, uiPage(origin), 'text/html; charset=utf-8');
      }
      if (req.method === 'GET' && p === '/xlogin.js') {
        return send(res, 200, xloginSrc, 'application/javascript; charset=utf-8');
      }
      const prof = /^\/u\/([a-z0-9._-]+)$/.exec(p);
      if (req.method === 'GET' && prof) {
        const name = prof[1];
        if (!accounts[name]) return send(res, 404, { error: 'no such agent' });
        const pub = custodialPub(name);
        return send(res, 200, {
          '@context': { solidpay: 'https://solidpay.org/ns#' },
          '@id': agentUri(name),
          name,
          'solidpay:node': origin,
          'solidpay:since': accounts[name].created,
          // Level 1: the key this account's transitions verify against.
          // CUSTODIAL — the node holds it; did:nostr agents hold their own.
          ...(pub ? {
            pubkey: pub,
            alsoKnownAs: [`did:nostr:${pub}`],
            'solidpay:keyCustody': 'node',
          } : {}),
        });
      }

      // ---- auth ----
      if (req.method === 'POST' && (p === '/api/register' || p === '/api/login')) {
        const { json: body } = await readBody(req);
        if (!body) return send(res, 400, { error: 'invalid JSON body' });
        const name = String(body.username || '').toLowerCase();
        const password = String(body.password || '');
        if (!NAME_RE.test(name)) return send(res, 400, { error: 'username: 2–31 chars of a-z 0-9 . _ -' });
        if (password.length < 8) return send(res, 400, { error: 'password: at least 8 characters' });
        if (p === '/api/register') {
          if (!registerAllowed(req)) {
            return send(res, 429, { error: 'too many registrations from your address — try again in an hour' });
          }
          if (accounts[name]) return send(res, 409, { error: 'username already taken' });
          const salt = b64u(crypto.randomBytes(16));
          accounts[name] = { salt, hash: hashPassword(password, salt), created: new Date().toISOString() };
          saveAccounts();
          custodialPriv(name); // mint the signing key up front (level 1)
        } else {
          const acct = accounts[name];
          if (!acct || hashPassword(password, acct.salt) !== acct.hash) {
            return send(res, 401, { error: 'wrong username or password' });
          }
        }
        const agent = agentUri(name);
        return send(res, p === '/api/register' ? 201 : 200, { agent, token: mintToken(agent) });
      }

      // ---- reads ----
      if (req.method === 'GET' && p === '/api/whoami') return send(res, 200, { agent: agentOf(req, url) });
      if (req.method === 'GET' && p === '/api/graph') return send(res, 200, ledger.graph());
      if (req.method === 'GET' && p === '/api/currencies') {
        return send(res, 200, { currencies, note: 'codes are aliases; the uri is the currency\'s canonical identity. Unknown codes transact freely — the registry is discovery, not permission.' });
      }
      if (req.method === 'GET' && p === '/api/balances') {
        return send(res, 200, ledger.balancesFor(url.searchParams.get('agent')));
      }
      if (req.method === 'GET' && p === '/api/path') {
        const q = url.searchParams;
        return send(res, 200, ledger.path(q.get('from'), q.get('to'), q.get('currency'), Number(q.get('amount'))));
      }
      if (req.method === 'GET' && p === '/api/log') {
        return send(res, 200, ledger.log(url.searchParams.get('limit')));
      }
      // Bitcoin anchors (Blocktrails module) — written by tools/anchor.js
      // into <data>/anchor/, served read-only. Empty when the operator
      // doesn't anchor; the ledger works identically either way.
      if (req.method === 'GET' && p === '/api/anchors') {
        let anchors = []; let trail = null;
        try { anchors = JSON.parse(fs.readFileSync(path.join(dataDir, 'anchor', 'anchors.json'), 'utf8')); } catch { /* none */ }
        try {
          const t = JSON.parse(fs.readFileSync(path.join(dataDir, 'anchor', '.blocktrail.json'), 'utf8'));
          trail = { pubkeyBase: t.pubkeyBase, network: t.network, states: (t.states || []).length };
        } catch { /* none */ }
        return send(res, 200, { anchors, trail });
      }

      if (req.method === 'GET' && p === '/api/log/verify') {
        const chain = ledger.verifyLog();
        // Authorship audit on top of the chain audit (spec § 8.2 step 4):
        // every entry's embedded event must verify against the actor's key.
        const signatures = { signed: 0, unsigned: 0, invalid: 0 };
        const problems = [];
        const ids = new Set();
        for (const e of ledger.state.log) {
          const v = verifyEntryEvent(e, keyOfActor);
          if (!v.signed) signatures.unsigned += 1;
          else if (!v.valid) { signatures.invalid += 1; problems.push({ seq: e.seq, error: v.error }); }
          else if (ids.has(e.event.id)) {
            // A node that double-applies one signed intent forges value —
            // the audit, not the freshness window, is what catches history.
            signatures.invalid += 1;
            problems.push({ seq: e.seq, error: 'duplicate event id (double-applied intent)' });
          } else { signatures.signed += 1; ids.add(e.event.id); }
        }
        return send(res, 200, {
          ...chain,
          valid: chain.valid && signatures.invalid === 0,
          signatures,
          ...(problems.length ? { problems: problems.slice(0, 10) } : {}),
        });
      }

      // ---- signed transitions (level 1): POST /api/tx ----
      // The body IS a signed nostr event (kinds 8801-8804, content = the
      // RFC 8785-canonical intent). The signature is the authentication —
      // no Authorization header involved. See docs/spec/ § 9.
      if (req.method === 'POST' && p === '/api/tx') {
        const { json: ev } = await readBody(req);
        if (!ev) return send(res, 400, { error: 'invalid JSON body' });
        if (!txAllowed(req)) return send(res, 429, { error: 'too many transitions from your address — slow down' });
        const v = verifyTxEvent(ev);
        if (v.error) return send(res, 401, { error: `invalid transition event: ${v.error}` });
        // One agent, one spelling: an event signed by a CUSTODIAL key is the
        // account acting, not a new did:nostr identity — map it back, or the
        // same key would exist as two agents and split the graph.
        const custodialName = nameForPubkey(ev.pubkey);
        const actor = custodialName ? agentUri(custodialName) : v.actor;
        // Signatures cover exact bytes, so the node validates canonical form
        // rather than rewriting: agent URIs canonical, currency uppercase.
        const canonErr = intentCanonError(v.type, v.intent);
        if (canonErr) return send(res, 400, { error: canonErr });
        if (seenEvents.has(ev.id)) return send(res, 409, { error: 'event already applied (replay)' });
        const out = applySigned(actor, v.type, v.intent, ev);
        seenEvents.set(ev.id, ev.created_at);
        pruneSeen();
        return send(res, out.created === true ? 201 : 200, out);
      }

      // ---- writes (authenticated; custodially signed) ----
      // Body is read BEFORE auth: NIP-98's payload tag is a hash of the exact
      // wire bytes, so verification needs the raw body in hand.
      if (req.method === 'POST' && p.startsWith('/api/')) {
        const { raw, json: body } = await readBody(req);
        const agent = agentOf(req, url, raw);
        if (!agent) return send(res, 401, { error: 'authentication required' });
        if (!body) return send(res, 400, { error: 'invalid JSON body' });
        // did:nostr agents hold their own keys — the node cannot sign for
        // them, and level 1 refuses to write unsigned entries on their
        // behalf. Their lane is the signed one.
        if (agent.startsWith('did:')) {
          return send(res, 400, { error: 'did:* agents submit signed transitions: POST /api/tx (see docs/spec/ § 9)' });
        }
        const name = nameOfAgent(agent);
        const sign = (type, intent) => (name ? buildTxEvent(custodialPriv(name), type, intent) : null);
        if (p === '/api/trustlines') {
          const intent = { peer: normalizeAgent(String(body.peer ?? '')), currency: String(body.currency ?? '').toUpperCase(), limit: body.limit };
          const out = ledger.setTrustline(agent, intent.peer, intent.currency, intent.limit, sign('set-trustline', intent));
          return send(res, out.created ? 201 : 200, out);
        }
        if (p === '/api/trustlines/remove') {
          const intent = { peer: normalizeAgent(String(body.peer ?? '')), currency: String(body.currency ?? '').toUpperCase() };
          return send(res, 200, ledger.removeTrustline(agent, intent.peer, intent.currency, sign('remove-trustline', intent)));
        }
        if (p === '/api/payments') {
          const intent = { to: normalizeAgent(String(body.to ?? '')), currency: String(body.currency ?? '').toUpperCase(), amount: body.amount };
          return send(res, 200, ledger.pay(agent, intent.to, intent.currency, intent.amount, sign('send-payment', intent)));
        }
        if (p === '/api/settle') {
          const intent = { peer: normalizeAgent(String(body.peer ?? '')), currency: String(body.currency ?? '').toUpperCase(), amount: body.amount };
          return send(res, 200, ledger.settle(agent, intent.peer, intent.currency, intent.amount, sign('settle', intent)));
        }
      }

      return send(res, 404, { error: 'not found' });
    } catch (err) {
      if (err instanceof LedgerError) return send(res, err.status, { error: err.message });
      return send(res, 500, { error: 'internal error' });
    }
  }

  const server = http.createServer(handle);
  return {
    server,
    ledger,
    listen(port = 3480, host = '0.0.0.0') {
      return new Promise((resolve) => server.listen(port, host, () => {
        // Origin is NOT frozen here: with no PUBLIC_URL it locks to the Host
        // of the FIRST request (one node, one spelling — the identity lesson).
        // The value returned is display-only.
        resolve({ port: server.address().port, origin: origin ?? `http://localhost:${server.address().port}` });
      }));
    },
    close() { return new Promise((resolve) => server.close(resolve)); },
  };
}

// ---- CLI ------------------------------------------------------------------
// Entry detection must survive pm2: under its fork wrapper argv[1] is
// ProcessContainerFork.js, but pm2 exposes the real script as pm_exec_path.
const self = fileURLToPath(import.meta.url);
const entry = [process.argv[1], process.env.pm_exec_path]
  .some((p) => { try { return p && path.resolve(p) === self; } catch { return false; } });
if (entry) {
  const node = createNode({
    dataDir: process.env.DATA || './data',
    publicUrl: process.env.PUBLIC_URL || null,
  });
  // HOST=127.0.0.1 for reverse-proxy deployments: the proxy is the only
  // client, TRUST_PROXY=1 stays truthful, and the direct port disappears.
  const { port, origin } = await node.listen(Number(process.env.PORT || 3480), process.env.HOST || '0.0.0.0');
  console.log(`solidpay node listening on port ${port}`);
  console.log(`  app:     ${origin}/`);
  console.log(`  api:     ${origin}/api/graph`);
  console.log(`  ledger:  ${origin}/api/log/verify`);
}
