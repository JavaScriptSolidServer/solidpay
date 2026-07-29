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
// pattern). v1 adds did:nostr sign-in: a schnorr signature over the
// transition replaces the account entirely (docs/spec.md §7).
//
//   POST /api/register {username,password}   → {agent, token}
//   POST /api/login    {username,password}   → {agent, token}
//   GET  /api/whoami                          → {agent}
//   GET  /u/:name                             the agent's profile document
//   GET  /api/graph | /api/balances?agent= | /api/path?from&to&currency&amount
//   POST /api/trustlines | /api/trustlines/remove | /api/payments | /api/settle
//   GET  /api/log?limit= | /api/log/verify
//   GET  /                                    the app UI

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Ledger, LedgerError, normalizeAgent } from './lib/engine.js';
import { uiPage } from './lib/ui.js';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{1,30}$/;
const TOKEN_TTL_MS = 30 * 24 * 3600 * 1000; // 30 days
const b64u = (b) => Buffer.from(b).toString('base64url');

export function createNode({ dataDir = './data', publicUrl = null } = {}) {
  fs.mkdirSync(dataDir, { recursive: true });

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
  const agentOf = (req) => {
    const h = req.headers.authorization || '';
    return h.startsWith('Bearer ') ? verifyToken(h.slice(7)) : null;
  };

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
  const readJson = (req) => new Promise((resolve) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size <= 65536) chunks.push(c); });
    req.on('end', () => {
      if (size > 65536) return resolve(null);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); }
      catch { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
  const requireAgent = (req, res) => {
    const agent = agentOf(req);
    if (!agent) send(res, 401, { error: 'authentication required' });
    return agent;
  };

  // ---- request handler ---------------------------------------------------
  async function handle(req, res) {
    const url = new URL(req.url, origin || `http://${req.headers.host || 'localhost'}`);
    if (!origin) origin = url.origin; // first-request fallback when no PUBLIC_URL
    const p = url.pathname;

    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

    try {
      // ---- app UI + profile URIs ----
      if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
        return send(res, 200, uiPage(), 'text/html; charset=utf-8');
      }
      const prof = /^\/u\/([a-z0-9._-]+)$/.exec(p);
      if (req.method === 'GET' && prof) {
        const name = prof[1];
        if (!accounts[name]) return send(res, 404, { error: 'no such agent' });
        return send(res, 200, {
          '@context': { solidpay: 'https://solidpay.org/ns#' },
          '@id': agentUri(name),
          name,
          'solidpay:node': origin,
          'solidpay:since': accounts[name].created,
        });
      }

      // ---- auth ----
      if (req.method === 'POST' && (p === '/api/register' || p === '/api/login')) {
        const body = await readJson(req);
        if (!body) return send(res, 400, { error: 'invalid JSON body' });
        const name = String(body.username || '').toLowerCase();
        const password = String(body.password || '');
        if (!NAME_RE.test(name)) return send(res, 400, { error: 'username: 2–31 chars of a-z 0-9 . _ -' });
        if (password.length < 8) return send(res, 400, { error: 'password: at least 8 characters' });
        if (p === '/api/register') {
          if (accounts[name]) return send(res, 409, { error: 'username already taken' });
          const salt = b64u(crypto.randomBytes(16));
          accounts[name] = { salt, hash: hashPassword(password, salt), created: new Date().toISOString() };
          saveAccounts();
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
      if (req.method === 'GET' && p === '/api/whoami') return send(res, 200, { agent: agentOf(req) });
      if (req.method === 'GET' && p === '/api/graph') return send(res, 200, ledger.graph());
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
      if (req.method === 'GET' && p === '/api/log/verify') return send(res, 200, ledger.verifyLog());

      // ---- writes (authenticated) ----
      if (req.method === 'POST' && p.startsWith('/api/')) {
        const agent = requireAgent(req, res);
        if (!agent) return;
        const body = await readJson(req);
        if (!body) return send(res, 400, { error: 'invalid JSON body' });
        if (p === '/api/trustlines') {
          const out = ledger.setTrustline(agent, body.peer, body.currency, body.limit);
          return send(res, out.created ? 201 : 200, out);
        }
        if (p === '/api/trustlines/remove') {
          return send(res, 200, ledger.removeTrustline(agent, body.peer, body.currency));
        }
        if (p === '/api/payments') {
          return send(res, 200, ledger.pay(agent, body.to, body.currency, body.amount));
        }
        if (p === '/api/settle') {
          return send(res, 200, ledger.settle(agent, body.peer, body.currency, body.amount));
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
if (import.meta.url === `file://${process.argv[1]}`) {
  const node = createNode({
    dataDir: process.env.DATA || './data',
    publicUrl: process.env.PUBLIC_URL || null,
  });
  const { port, origin } = await node.listen(Number(process.env.PORT || 3480));
  console.log(`solidpay node listening on port ${port}`);
  console.log(`  app:     ${origin}/`);
  console.log(`  api:     ${origin}/api/graph`);
  console.log(`  ledger:  ${origin}/api/log/verify`);
}
