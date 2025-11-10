// server.js
// Single-file simplified centralized ledger server.
// Dependencies: express, sqlite3, ws, tweetnacl, dotenv, express-rate-limit, node-fetch
//
// Usage:
//   npm init -y
//   npm i express sqlite3 ws tweetnacl dotenv express-rate-limit node-fetch
//   node server.js
//
// Default: listens PORT=10000 (or process.env.PORT)
//
// NOTE: This is a demo server. Do not use in production without security hardening.

require('dotenv').config();
const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const nacl = require('tweetnacl');
const crypto = require('crypto');
const WebSocket = require('ws');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');

const PORT = process.env.PORT ? Number(process.env.PORT) : 10000;
const DB_FILE = process.env.DATABASE_URL || path.join(__dirname, 'ledger.sqlite');
const FAUCET_AMOUNT = Number(process.env.FAUCET_AMOUNT || 100);
const FAUCET_COOLDOWN_SECONDS = Number(process.env.FAUCET_COOLDOWN_SECONDS || 86400);
const MAX_ADDRESSES_PER_IP = Number(process.env.MAX_ADDRESSES_PER_IP || 3);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

console.log('Starting server...');

// Ensure db dir
try { fs.mkdirSync(path.dirname(DB_FILE), { recursive: true }); } catch (e) {}

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) { console.error('DB open error', err); process.exit(1); }
});
const MIGRATION_SQL = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS addresses (
  address TEXT PRIMARY KEY,
  pubkey TEXT,
  balance NUMERIC DEFAULT 0,
  nonce INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS transactions (
  txid TEXT PRIMARY KEY,
  from_addr TEXT,
  to_addr TEXT,
  amount NUMERIC,
  fee NUMERIC,
  nonce INTEGER,
  signature TEXT,
  payload_hash TEXT,
  timestamp TIMESTAMP DEFAULT current_timestamp
);
CREATE TABLE IF NOT EXISTS blocks (
  idx INTEGER PRIMARY KEY AUTOINCREMENT,
  previous_hash TEXT,
  timestamp TIMESTAMP DEFAULT current_timestamp,
  txs JSON,
  hash TEXT
);
CREATE TABLE IF NOT EXISTS faucet_claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT,
  ip TEXT,
  claimed_at TIMESTAMP DEFAULT current_timestamp
);
CREATE INDEX IF NOT EXISTS idx_faucet_ip_time ON faucet_claims(ip, claimed_at);
CREATE INDEX IF NOT EXISTS idx_txs_from ON transactions(from_addr);
CREATE INDEX IF NOT EXISTS idx_txs_to ON transactions(to_addr);
`;
db.exec(MIGRATION_SQL, (err) => {
  if (err) { console.error('Migration error', err); process.exit(1); }
  console.log('DB ready:', DB_FILE);
});

// helper SQL promisified
function runAsync(sql, params=[]) {
  return new Promise((resolve,reject) => db.run(sql, params, function(err){ if(err) reject(err); else resolve(this); }));
}
function getAsync(sql, params=[]) {
  return new Promise((resolve,reject) => db.get(sql, params, (err,row)=>{ if(err) reject(err); else resolve(row); }));
}
function allAsync(sql, params=[]) {
  return new Promise((resolve,reject) => db.all(sql, params, (err,rows)=>{ if(err) reject(err); else resolve(rows); }));
}

// utils
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
function computePayloadHash(tx) {
  // Must match client: deterministic JSON order
  const payload = JSON.stringify({
    from: tx.from,
    to: tx.to,
    amount: Number(tx.amount),
    fee: Number(tx.fee || 0),
    nonce: Number(tx.nonce)
  });
  return sha256Hex(payload);
}
function makeAddressFromPubkeyHex(pubkeyHex) {
  const hash = crypto.createHash('sha256').update(Buffer.from(pubkeyHex, 'hex')).digest();
  return hash.slice(0,20).toString('hex'); // 40 hex chars
}

// Express app
const app = express();
app.use(express.json({ limit: '200kb' }));
// Basic rate limit
app.use('/api/', rateLimit({ windowMs: 10*1000, max: 300 }));

// Serve single-page client (we will serve the provided index.html below)
app.get('/', (req, res) => {
  // serve index.html from same dir if exists
  const clientFile = path.join(__dirname, 'index.html');
  if (fs.existsSync(clientFile)) {
    res.sendFile(clientFile);
    return;
  }
  res.send(`<h1>Ledger server</h1><p>Put index.html next to server.js to serve UI.</p>`);
});

// --- API: register pubkey (client calls after deriving keys locally) ---
app.post('/api/register', async (req, res) => {
  try {
    const { address, pubkeyHex } = req.body || {};
    if (!address || !pubkeyHex) return res.status(400).json({ ok:false, error:'address and pubkeyHex required' });
    const expected = makeAddressFromPubkeyHex(pubkeyHex);
    if (expected !== address) return res.status(400).json({ ok:false, error:'pubkey does not match address' });
    await runAsync(`INSERT OR IGNORE INTO addresses(address, pubkey, balance, nonce) VALUES(?,?,0,0)`, [address, pubkeyHex]);
    return res.json({ ok:true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error:'internal' });
  }
});

// --- API: balance ---
app.get('/api/balance/:address', async (req, res) => {
  const addr = req.params.address;
  const row = await getAsync(`SELECT balance, nonce FROM addresses WHERE address = ?`, [addr]);
  if (!row) return res.json({ ok:true, balance:0, nonce:0 });
  return res.json({ ok:true, balance: Number(row.balance||0), nonce: Number(row.nonce||0) });
});

// --- API: txs history ---
app.get('/api/txs/:address', async (req, res) => {
  const addr = req.params.address;
  const rows = await allAsync(`SELECT * FROM transactions WHERE from_addr = ? OR to_addr = ? ORDER BY timestamp DESC LIMIT 200`, [addr, addr]);
  return res.json({ ok:true, txs: rows });
});

// --- API: sendTx ---
app.post('/api/sendTx', async (req, res) => {
  const tx = req.body;
  if (!tx || !tx.from || !tx.to || tx.amount==null || tx.nonce==null || !tx.signature) {
    return res.status(400).json({ ok:false, error:'invalid tx format' });
  }
  try {
    // get sender pubkey
    const sender = await getAsync(`SELECT pubkey, balance, nonce FROM addresses WHERE address = ?`, [tx.from]);
    if (!sender || !sender.pubkey) return res.status(400).json({ ok:false, error:'sender unknown; register pubkey first' });

    // verify payload hash and signature
    const payload_hash = computePayloadHash(tx); // hex
    // server expects signature hex
    const sig = Buffer.from(tx.signature, 'hex');
    const pubkey = Buffer.from(sender.pubkey, 'hex');
    const payloadBytes = Buffer.from(payload_hash, 'hex');
    const verified = nacl.sign.detached.verify(new Uint8Array(payloadBytes), new Uint8Array(sig), new Uint8Array(pubkey));
    if (!verified) return res.status(400).json({ ok:false, error:'invalid signature' });

    // nonce check
    const expectedNonce = (sender.nonce || 0) + 1;
    if (Number(tx.nonce) !== expectedNonce) return res.status(400).json({ ok:false, error:`invalid nonce (expected ${expectedNonce})` });

    const amount = Number(tx.amount);
    const fee = Number(tx.fee || 0);
    if (amount < 0 || fee < 0) return res.status(400).json({ ok:false, error:'invalid amounts' });

    const balance = Number(sender.balance || 0);
    if (balance < amount + fee) return res.status(400).json({ ok:false, error:'insufficient balance' });

    // apply tx in DB
    const txid = crypto.randomBytes(12).toString('hex');
    const now = new Date().toISOString();
    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run(`UPDATE addresses SET balance = balance - ?, nonce = nonce + 1 WHERE address = ?`, [amount + fee, tx.from], function(err){
          if (err) return reject(err);
          db.run(`INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?, NULL, 0)`, [tx.to], (err2) => {
            if (err2) return reject(err2);
            db.run(`UPDATE addresses SET balance = balance + ? WHERE address = ?`, [amount, tx.to], (err3) => {
              if (err3) return reject(err3);
              db.run(`INSERT INTO transactions(txid, from_addr, to_addr, amount, fee, nonce, signature, payload_hash, timestamp) VALUES(?,?,?,?,?,?,?,?,?)`,
                [txid, tx.from, tx.to, amount, fee, tx.nonce, tx.signature, payload_hash, now], (err4) => {
                  if (err4) return reject(err4);
                  // simple block per tx
                  const txsJson = JSON.stringify([{ txid, from: tx.from, to: tx.to, amount, fee, nonce: tx.nonce }]);
                  db.get(`SELECT hash FROM blocks ORDER BY idx DESC LIMIT 1`, [], (err5, prev) => {
                    if (err5) return reject(err5);
                    const prevHash = prev ? prev.hash : null;
                    const blockHash = crypto.createHash('sha256').update((prevHash||'') + now + txsJson).digest('hex');
                    db.run(`INSERT INTO blocks(previous_hash, timestamp, txs, hash) VALUES(?,?,?,?)`, [prevHash, now, txsJson, blockHash], (err6) => {
                      if (err6) return reject(err6);
                      db.run('COMMIT', (err7) => { if (err7) return reject(err7); resolve(); });
                    });
                  });
                });
            });
          });
        });
      });
    });

    // broadcast via ws
    broadcastWS('newTx', { txid, from: tx.from, to: tx.to, amount, fee, nonce: tx.nonce });
    broadcastWS('balanceUpdate', { address: tx.from });
    broadcastWS('balanceUpdate', { address: tx.to });

    return res.json({ ok:true, txid });
  } catch (e) {
    console.error('sendTx err', e);
    return res.status(500).json({ ok:false, error:'internal error' });
  }
});

// --- API: faucet ---
app.post('/api/faucet', async (req,res) => {
  try {
    const { address, pubkeyHex, captcha } = req.body || {};
    const ip = (req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();

    if (!address || !pubkeyHex) return res.status(400).json({ ok:false, error:'address and pubkeyHex required' });
    const expected = makeAddressFromPubkeyHex(pubkeyHex);
    if (expected !== address) return res.status(400).json({ ok:false, error:'pubkey does not match address' });

    // captcha optional
    if (RECAPTCHA_SECRET) {
      if (!captcha) return res.status(400).json({ ok:false, error:'captcha required' });
      const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: `secret=${encodeURIComponent(RECAPTCHA_SECRET)}&response=${encodeURIComponent(captcha)}`
      });
      const j = await resp.json();
      if (!j.success) return res.status(400).json({ ok:false, error:'captcha failed' });
    }

    // per-address cooldown
    const last = await getAsync(`SELECT claimed_at FROM faucet_claims WHERE address = ? ORDER BY claimed_at DESC LIMIT 1`, [address]);
    if (last) {
      const lastTs = new Date(last.claimed_at).getTime();
      if ((Date.now() - lastTs)/1000 < FAUCET_COOLDOWN_SECONDS) {
        const wait = FAUCET_COOLDOWN_SECONDS - Math.floor((Date.now() - lastTs)/1000);
        return res.status(400).json({ ok:false, error:'faucet cooldown', wait_seconds: wait });
      }
    }

    // per-IP limit (distinct addresses within cooldown window)
    const since = new Date(Date.now() - FAUCET_COOLDOWN_SECONDS*1000).toISOString();
    const rows = await allAsync(`SELECT DISTINCT address FROM faucet_claims WHERE ip = ? AND claimed_at >= ?`, [ip, since]);
    if (rows.length >= MAX_ADDRESSES_PER_IP) return res.status(400).json({ ok:false, error:'IP limit reached' });

    // ensure address exists
    await runAsync(`INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?,?,0)`, [address, pubkeyHex]);
    // credit
    await new Promise((resolve,reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run(`UPDATE addresses SET balance = balance + ? WHERE address = ?`, [FAUCET_AMOUNT, address], (err)=>{
          if (err) return reject(err);
          db.run(`INSERT INTO faucet_claims(address, ip, claimed_at) VALUES(?,?,?)`, [address, ip, new Date().toISOString()], (err2)=>{
            if (err2) return reject(err2);
            db.run('COMMIT', (err3)=>{ if (err3) return reject(err3); resolve(); });
          });
        });
      });
    });

    broadcastWS('balanceUpdate', { address });
    return res.json({ ok:true, amount: FAUCET_AMOUNT });
  } catch (e) {
    console.error('faucet err', e);
    return res.status(500).json({ ok:false, error:'internal' });
  }
});

// --- WebSocket server ---
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });
const clients = new Set();
function broadcastWS(event, data) {
  const msg = JSON.stringify({ event, data });
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  }
}
wss.on('connection', (ws, req) => {
  clients.add(ws);
  ws.on('close', ()=> clients.delete(ws));
  ws.on('message', (m) => {
    try {
      const p = JSON.parse(m.toString());
      if (p && p.cmd === 'subscribe' && p.address) ws.subscribedAddress = p.address;
    } catch(e) {}
  });
});

// Serve a simple health endpoint
app.get('/health', (req,res)=> res.json({ok:true}));

server.listen(PORT, () => {
  console.log(`Server on ${PORT}`);
  console.log(`Open http://localhost:${PORT} (or deploy and point browser to the host)`);
});
