// server.js
// Node.js CommonJS version — run: node server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
const fetch = require('node-fetch');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util'); // convenience for server if needed

const PORT = process.env.PORT || 10000;
const DB_FILE = process.env.DATABASE_URL || path.join(__dirname, 'data', 'ledger.sqlite');
const FAUCET_AMOUNT = Number(process.env.FAUCET_AMOUNT || 100);
const FAUCET_COOLDOWN_SECONDS = Number(process.env.FAUCET_COOLDOWN_SECONDS || 86400);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

if (!fs.existsSync(path.dirname(DB_FILE))) fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

const db = new sqlite3.Database(DB_FILE);

// create tables if missing
const INIT_SQL = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS addresses (
  address TEXT PRIMARY KEY,
  pubkey TEXT,
  balance NUMERIC DEFAULT 0,
  nonce INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blocks (
  idx INTEGER PRIMARY KEY AUTOINCREMENT,
  previous_hash TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  txs JSON,
  hash TEXT
);
CREATE TABLE IF NOT EXISTS faucet_claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT,
  ip TEXT,
  claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_faucet_ip_time ON faucet_claims(ip, claimed_at);
CREATE INDEX IF NOT EXISTS idx_txs_from ON transactions(from_addr);
CREATE INDEX IF NOT EXISTS idx_txs_to ON transactions(to_addr);
`;
db.exec(INIT_SQL, (err)=> {
  if (err) {
    console.error('DB init error', err);
    process.exit(1);
  }
});

function runAsync(sql, params=[]) {
  return new Promise((res, rej) => {
    db.run(sql, params, function(err) { if (err) rej(err); else res(this); });
  });
}
function getAsync(sql, params=[]) {
  return new Promise((res, rej) => {
    db.get(sql, params, (err, row) => { if (err) rej(err); else res(row); });
  });
}
function allAsync(sql, params=[]) {
  return new Promise((res, rej) => {
    db.all(sql, params, (err, rows) => { if (err) rej(err); else res(rows); });
  });
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
function makeAddressFromPubkeyHex(pubkeyHex) {
  const h = crypto.createHash('sha256').update(Buffer.from(pubkeyHex, 'hex')).digest();
  return h.slice(0,20).toString('hex');
}
function computeTxPayloadHash(tx) {
  const payload = JSON.stringify({
    from: tx.from,
    to: tx.to,
    amount: Number(tx.amount),
    fee: Number(tx.fee || 0),
    nonce: Number(tx.nonce)
  });
  return sha256Hex(payload);
}

// express
const app = express();
app.use(helmet());
app.use(cors()); // allow cross-origin (frontend hosted elsewhere)
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true }));

// basic API rate limit
app.use('/api/', rateLimit({ windowMs: 15*1000, max: 300 }));

// register pubkey for address (client calls this after deriving wallet)
app.post('/api/register', async (req, res) => {
  const { address, pubkeyHex } = req.body || {};
  if (!address || !pubkeyHex) return res.status(400).json({ ok:false, error:'address and pubkeyHex required' });
  const expected = makeAddressFromPubkeyHex(pubkeyHex);
  if (expected !== address) return res.status(400).json({ ok:false, error:'pubkey does not match address' });
  try {
    await runAsync('INSERT OR IGNORE INTO addresses(address, pubkey) VALUES(?,?)', [address, pubkeyHex]);
    res.json({ ok:true });
  } catch(err) { res.status(500).json({ ok:false, error:'db error' }) }
});

// balance
app.get('/api/balance/:address', async (req, res) => {
  const address = req.params.address;
  try {
    const row = await getAsync('SELECT balance, nonce FROM addresses WHERE address = ?', [address]);
    if (!row) return res.json({ ok:true, balance:0, nonce:0 });
    res.json({ ok:true, balance:Number(row.balance||0), nonce:Number(row.nonce||0) });
  } catch(err){ res.status(500).json({ ok:false, error:'db error' }) }
});

// tx history
app.get('/api/txs/:address', async (req, res) => {
  const address = req.params.address;
  try {
    const rows = await allAsync('SELECT * FROM transactions WHERE from_addr = ? OR to_addr = ? ORDER BY timestamp DESC LIMIT 200', [address, address]);
    res.json({ ok:true, txs: rows });
  } catch(err){ res.status(500).json({ ok:false, error:'db error' }) }
});

// sendTx (signed by client)
app.post('/api/sendTx', async (req, res) => {
  const tx = req.body || {};
  if (!tx.from || !tx.to || tx.amount==null || tx.nonce==null || !tx.signature) return res.status(400).json({ ok:false, error:'invalid tx format' });

  try {
    const sender = await getAsync('SELECT pubkey, balance, nonce FROM addresses WHERE address = ?', [tx.from]);
    if (!sender || !sender.pubkey) return res.status(400).json({ ok:false, error:'sender unknown, register pubkey first' });

    // verify signature
    const payloadHash = computeTxPayloadHash(tx);
    const payloadBytes = Buffer.from(payloadHash, 'hex');
    const sig = Buffer.from(tx.signature, 'hex');
    const pub = Buffer.from(sender.pubkey, 'hex');
    const verified = nacl.sign.detached.verify(new Uint8Array(payloadBytes), new Uint8Array(sig), new Uint8Array(pub));
    if (!verified) return res.status(400).json({ ok:false, error:'invalid signature' });

    // nonce check
    const expectedNonce = Number(sender.nonce || 0) + 1;
    if (Number(tx.nonce) !== expectedNonce) return res.status(400).json({ ok:false, error:`invalid nonce (expected ${expectedNonce})` });

    const amount = Number(tx.amount);
    const fee = Number(tx.fee || 0);
    if (amount < 0 || fee < 0) return res.status(400).json({ ok:false, error:'invalid amounts' });
    const bal = Number(sender.balance || 0);
    if (bal < amount + fee) return res.status(400).json({ ok:false, error:'insufficient balance' });

    // apply tx (simple DB transaction)
    const txid = nanoid(16);
    const now = new Date().toISOString();
    const payload_hash = payloadHash;

    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run('UPDATE addresses SET balance = balance - ?, nonce = nonce + 1 WHERE address = ?', [amount + fee, tx.from], function(err){
          if (err) return reject(err);
          db.run('INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?,NULL,0)', [tx.to], (err2)=>{
            if (err2) return reject(err2);
            db.run('UPDATE addresses SET balance = balance + ? WHERE address = ?', [amount, tx.to], (err3)=>{
              if (err3) return reject(err3);
              db.run('INSERT INTO transactions(txid, from_addr, to_addr, amount, fee, nonce, signature, payload_hash, timestamp) VALUES(?,?,?,?,?,?,?,?,?)',
                [txid, tx.from, tx.to, amount, fee, tx.nonce, tx.signature, payload_hash, now], (err4)=>{
                  if (err4) return reject(err4);
                  // insert simple block with single tx
                  db.get('SELECT hash FROM blocks ORDER BY idx DESC LIMIT 1', [], (err5, rowPrev)=>{
                    if (err5) return reject(err5);
                    const prev = rowPrev ? rowPrev.hash : null;
                    const txsJson = JSON.stringify([{ txid, from:tx.from, to:tx.to, amount, fee, nonce: tx.nonce }]);
                    const blockHash = crypto.createHash('sha256').update((prev||'') + '|' + now + '|' + txsJson).digest('hex');
                    db.run('INSERT INTO blocks(previous_hash, timestamp, txs, hash) VALUES(?,?,?,?)', [prev, now, txsJson, blockHash], (err6)=>{
                      if (err6) return reject(err6);
                      db.run('COMMIT', (err7)=> { if (err7) reject(err7); else resolve(); });
                    });
                  });
                });
            });
          });
        });
      });
    });

    // notify websocket clients (handled below)
    broadcastWS('newTx', { txid, from: tx.from, to: tx.to, amount, fee, nonce: tx.nonce });
    broadcastWS('balanceUpdate', { address: tx.from });
    broadcastWS('balanceUpdate', { address: tx.to });

    res.json({ ok:true, txid });
  } catch(err){
    console.error('sendTx error', err);
    try { await runAsync('ROLLBACK'); } catch(e){}
    res.status(500).json({ ok:false, error: 'internal' });
  }
});

// faucet
app.post('/api/faucet', async (req, res) => {
  const { address, pubkeyHex, captcha } = req.body || {};
  const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();

  if (!address || !pubkeyHex) return res.status(400).json({ ok:false, error:'address and pubkeyHex required' });
  const expected = makeAddressFromPubkeyHex(pubkeyHex);
  if (expected !== address) return res.status(400).json({ ok:false, error:'pubkey does not match address' });

  // captcha (optional)
  if (RECAPTCHA_SECRET) {
    if (!captcha) return res.status(400).json({ ok:false, error:'captcha required' });
    try {
      const verify = await fetch('https://www.google.com/recaptcha/api/siteverify', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:`secret=${encodeURIComponent(RECAPTCHA_SECRET)}&response=${encodeURIComponent(captcha)}` });
      const vj = await verify.json();
      if (!vj.success) return res.status(400).json({ ok:false, error:'captcha failed' });
    } catch(e) { return res.status(500).json({ ok:false, error:'captcha verify error' }); }
  }

  try {
    const last = await getAsync('SELECT claimed_at FROM faucet_claims WHERE address = ? ORDER BY claimed_at DESC LIMIT 1', [address]);
    if (last) {
      const lastTs = new Date(last.claimed_at).getTime();
      if ((Date.now() - lastTs)/1000 < FAUCET_COOLDOWN_SECONDS) {
        return res.status(400).json({ ok:false, error:'faucet cooldown' });
      }
    }
    const since = new Date(Date.now() - FAUCET_COOLDOWN_SECONDS*1000).toISOString();
    const rows = await allAsync('SELECT DISTINCT address FROM faucet_claims WHERE ip = ? AND claimed_at >= ?', [ip, since]);
    if (rows.length >= 3) return res.status(400).json({ ok:false, error:'IP faucet limit reached' });

    await runAsync('INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?,?,0)', [address, pubkeyHex]);
    await new Promise((resolve, reject) => {
      db.serialize(()=> {
        db.run('BEGIN TRANSACTION');
        db.run('UPDATE addresses SET balance = balance + ? WHERE address = ?', [FAUCET_AMOUNT, address], function(err){
          if (err) return reject(err);
          db.run('INSERT INTO faucet_claims(address, ip, claimed_at) VALUES(?,?,?)', [address, ip, new Date().toISOString()], (err2)=>{
            if (err2) return reject(err2);
            db.run('COMMIT', (err3)=> { if (err3) reject(err3); else resolve(); });
          });
        });
      });
    });

    // broadcast balance update
    broadcastWS('balanceUpdate', { address });
    res.json({ ok:true, amount: FAUCET_AMOUNT });
  } catch(err){ console.error('faucet error', err); res.status(500).json({ ok:false, error:'internal' }) }
});

// Minimal root info
app.get('/', (req, res) => {
  res.send('MyChain API is running');
});

// WebSocket (ws)
const http = require('http');
const server = http.createServer(app);
const WebSocket = require('ws');
const wss = new WebSocket.Server({ server, path: '/ws' });
const clients = new Set();

function broadcastWS(event, data){
  const msg = JSON.stringify({ event, data });
  clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

wss.on('connection', (ws, req) => {
  clients.add(ws);
  ws.on('message', (msg)=> {
    try {
      const p = JSON.parse(msg.toString());
      if (p && p.cmd === 'subscribe' && p.address) ws.subscribed = p.address;
    } catch(e){}
  });
  ws.on('close', ()=> clients.delete(ws));
});

// start
server.listen(PORT, () => {
  console.log('Server on', PORT);
  console.log('API:', 'http://localhost:' + PORT + '/api (or your host)');
  console.log('WS:', 'ws://localhost:' + PORT + '/ws');
});
