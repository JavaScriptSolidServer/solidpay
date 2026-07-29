// Anchor a node's chain tip to Bitcoin — the Blocktrails settlement-assurance
// module (the first pluggable finality backend; docs/spec/ § 13).
//
//   ANCHOR_KEY=<privkey hex> node tools/anchor.js [nodeUrl] [--data <dir>]
//
// State string (git-mark convention: literal key order, hashed as-is):
//   {"node":"<origin>","seq":<n>,"tip":"sha256:…"}
//
// Each anchor advances a Blocktrails trail: a chained BIP-341 TapTweak of the
// anchor key by the state hash → a fresh P2TR address; the mark transaction
// pays the trail's whole balance forward to it. The chain of spends IS the
// anchor history, ordered and timestamped by Bitcoin. A node that later
// presents a different history for an anchored (seq, tip) is refuted by its
// own anchor. One trail can carry MANY nodes' tips (a federation trail) —
// the state names the node.
//
// The trail file (.blocktrail.json) and the anchor record (anchors.json)
// live in <data>/anchor/, which the server exposes read-only at
// GET /api/anchors. The key is env-only and never written to disk here.
//
// Uses the `blocktrails` reference CLI (same author) via npx — the server
// itself carries no Bitcoin code.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const dataFlag = args.indexOf('--data');
const dataDir = dataFlag >= 0 ? args[dataFlag + 1] : (process.env.DATA || './data');
const nodeUrl = (args.find((a) => a.startsWith('http')) || 'http://localhost:3480').replace(/\/$/, '');
const key = process.env.ANCHOR_KEY;
if (!key || !/^[0-9a-f]{64}$/.test(key)) {
  console.error('ANCHOR_KEY (64-hex privkey) required in the environment');
  process.exit(1);
}

const anchorDir = path.join(dataDir, 'anchor');
fs.mkdirSync(anchorDir, { recursive: true });
const trailFile = path.join(anchorDir, '.blocktrail.json');
const recordFile = path.join(anchorDir, 'anchors.json');

// ---- what to anchor: the node's audited tip -------------------------------
const verify = await (await fetch(`${nodeUrl}/api/log/verify`)).json();
if (!verify.valid) {
  console.error(`refusing to anchor an INVALID chain: ${JSON.stringify(verify)}`);
  process.exit(1);
}
const state = JSON.stringify({ node: nodeUrl, seq: verify.seq, tip: verify.tip });
console.log(`anchoring: ${state}`);

// Skip if this exact (node, seq, tip) is already anchored.
let records = [];
try { records = JSON.parse(fs.readFileSync(recordFile, 'utf8')); } catch { /* first run */ }
if (records.some((r) => r.state === state)) {
  console.log('already anchored — nothing to do');
  process.exit(0);
}

// ---- mark it via the blocktrails reference CLI ----------------------------
let out;
try {
  out = execFileSync('npx', ['-y', 'blocktrails@0.0.12', 'mark', state,
    '--key', key, '--file', trailFile, '--network', 'tbtc4'],
  { encoding: 'utf8', cwd: anchorDir, stdio: ['ignore', 'pipe', 'pipe'] });
} catch (err) {
  console.error('mark failed:');
  console.error(String(err.stdout || ''));
  console.error(String(err.stderr || err.message));
  process.exit(1);
}
console.log(out);

const txid = (out.match(/txid[:\s]+([0-9a-f]{64})/i) || out.match(/([0-9a-f]{64})/) || [])[1] || null;
const address = (out.match(/(tb1p[a-z0-9]+)/) || [])[1] || null;

records.push({
  state, node: nodeUrl, seq: verify.seq, tip: verify.tip,
  address, txid, network: 'tbtc4',
  explorer: txid ? `https://mempool.guide/testnet4/tx/${txid}` : null,
  at: new Date().toISOString(),
});
fs.writeFileSync(recordFile, JSON.stringify(records, null, 2));
console.log(`recorded → ${recordFile}`);
if (txid) console.log(`explorer: https://mempool.guide/testnet4/tx/${txid}`);
