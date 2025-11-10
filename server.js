// server.js
// Запуск: node server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
const fetch = require('node-fetch');
const WebSocket = require('ws');
const nacl = require('tweetnacl');

const PORT = process.env.PORT || 10000;
const DB_PATH = process.env.DATABASE_URL || path.join(__dirname, 'db', 'ledger.sqlite');
const FAUCET_AMOUNT = Number(process.env.FAUCET_AMOUNT || 100);
const FAUCET_COOLDOWN_SECONDS = Number(process.env.FAUCET_COOLDOWN_SECONDS || 86400);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

if (!fs.existsSync(path.dirname(DB_PATH))) fs.mkdirSync(path.dirname(DB_PATH), { recursive:true });

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
`;

const db = new sqlite3.Database(DB_PATH);
db.serialize(() => db.exec(MIGRATION_SQL, (err)=>{ if(err) console.error('MIGRATE ERR',err); else console.log('DB ready', DB_PATH); }));

// helpers for db as promises
function runAsync(sql, params=[]) {
  return new Promise((res, rej) => db.run(sql, params, function(err){ if(err) rej(err); else res(this); }));
}
function getAsync(sql, params=[]) {
  return new Promise((res, rej) => db.get(sql, params, (err,row)=>{ if(err) rej(err); else res(row); }));
}
function allAsync(sql, params=[]) {
  return new Promise((res, rej) => db.all(sql, params, (err,rows)=>{ if(err) rej(err); else res(rows); }));
}

// crypto helpers
function sha256HexFromString(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}
function sha256HexFromBuffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
function pubkeyToAddressHex(pubkeyHex) {
  const pubbuf = Buffer.from(pubkeyHex, 'hex');
  const hash = crypto.createHash('sha256').update(pubbuf).digest();
  return hash.slice(0,20).toString('hex');
}

// Express app
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit:'100kb' }));
const limiter = rateLimit({ windowMs: 15*1000, max: 200 });
app.use('/api/', limiter);

// Simple register endpoint
app.post('/api/register', async (req,res) => {
  const { address, pubkeyHex } = req.body || {};
  if (!address || !pubkeyHex) return res.status(400).json({ ok:false, error:'address and pubkeyHex required' });
  const expected = pubkeyToAddressHex(pubkeyHex);
  if (expected !== address) return res.status(400).json({ ok:false, error:'pubkey does not match address' });
  try {
    await runAsync(`INSERT OR IGNORE INTO addresses(address, pubkey) VALUES(?,?)`, [address, pubkeyHex]);
    res.json({ ok:true });
  } catch(e) {
    res.status(500).json({ ok:false, error:'internal' });
  }
});

// balance
app.get('/api/balance/:address', async (req,res) => {
  const address = req.params.address;
  try {
    const row = await getAsync(`SELECT balance, nonce FROM addresses WHERE address = ?`, [address]);
    if (!row) return res.json({ ok:true, balance:0, nonce:0 });
    res.json({ ok:true, balance: Number(row.balance || 0), nonce: Number(row.nonce || 0) });
  } catch(e) { res.status(500).json({ ok:false, error:'internal' }); }
});

// txs history
app.get('/api/txs/:address', async (req,res) => {
  const address = req.params.address;
  try {
    const rows = await allAsync(`SELECT * FROM transactions WHERE from_addr = ? OR to_addr = ? ORDER BY timestamp DESC LIMIT 200`, [address,address]);
    res.json({ ok:true, txs: rows });
  } catch(e) { res.status(500).json({ ok:false, error:'internal' }); }
});

// sendTx
app.post('/api/sendTx', async (req,res) => {
  const tx = req.body || {};
  if (!tx.from || !tx.to || tx.amount == null || tx.nonce == null || !tx.signature) {
    return res.status(400).json({ ok:false, error:'invalid tx format' });
  }
  try {
    const sender = await getAsync(`SELECT pubkey,balance,nonce FROM addresses WHERE address = ?`, [tx.from]);
    if (!sender || !sender.pubkey) return res.status(400).json({ ok:false, error:'sender unknown, register first' });

    // compute payload hash deterministic same as client:
    const payload = JSON.stringify({ from: tx.from, to: tx.to, amount: Number(tx.amount), fee: Number(tx.fee||0), nonce: Number(tx.nonce) });
    const payloadHash = sha256HexFromString(payload);
    // verify signature (signature hex)
    const sigBuf = Buffer.from(tx.signature, 'hex');
    const pubkeyBuf = Buffer.from(sender.pubkey, 'hex');
    const payloadBuf = Buffer.from(payloadHash, 'hex'); // server expects client signed sha256 hex bytes
    const okVerify = nacl.sign.detached.verify(new Uint8Array(payloadBuf), new Uint8Array(sigBuf), new Uint8Array(pubkeyBuf));
    if (!okVerify) return res.status(400).json({ ok:false, error:'invalid signature' });

    // nonce
    const expectedNonce = Number(sender.nonce||0) + 1;
    if (Number(tx.nonce) !== expectedNonce) return res.status(400).json({ ok:false, error:`invalid nonce (expected ${expectedNonce})` });

    // balance
    const totalCost = Number(tx.amount) + Number(tx.fee || 0);
    if (Number(sender.balance || 0) < totalCost) return res.status(400).json({ ok:false, error:'insufficient balance' });

    // apply tx within transaction
    const txid = nanoid(16);
    const now = new Date().toISOString();
    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run(`UPDATE addresses SET balance = balance - ?, nonce = nonce + 1 WHERE address = ?`, [totalCost, tx.from], function(err){
          if (err) return rollback(err);
          db.run(`INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?, NULL, 0)`, [tx.to], (err2) => {
            if (err2) return rollback(err2);
            db.run(`UPDATE addresses SET balance = balance + ? WHERE address = ?`, [Number(tx.amount), tx.to], (err3) => {
              if (err3) return rollback(err3);
              db.run(`INSERT INTO transactions(txid, from_addr, to_addr, amount, fee, nonce, signature, payload_hash, timestamp) VALUES(?,?,?,?,?,?,?,?,?)`,
                [txid, tx.from, tx.to, Number(tx.amount), Number(tx.fee||0), Number(tx.nonce), tx.signature, payloadHash, now], (err4) => {
                  if (err4) return rollback(err4);
                  // create simple block
                  db.get(`SELECT hash FROM blocks ORDER BY idx DESC LIMIT 1`, [], (err5, prevRow) => {
                    if (err5) return rollback(err5);
                    const prevHash = prevRow ? prevRow.hash : null;
                    const txsJson = JSON.stringify([{txid, from: tx.from, to: tx.to, amount: Number(tx.amount), fee: Number(tx.fee||0), nonce: Number(tx.nonce)}]);
                    const blockPayload = `${prevHash||''}|${now}|${txsJson}`;
                    const blockHash = crypto.createHash('sha256').update(blockPayload).digest('hex');
                    db.run(`INSERT INTO blocks(previous_hash, timestamp, txs, hash) VALUES(?,?,?,?)`, [prevHash, now, txsJson, blockHash], (err6) => {
                      if (err6) return rollback(err6);
                      db.run('COMMIT', (err7) => { if (err7) return rollback(err7); else resolve(); });
                    });
                  });
                });
            });
          });
        });

        function rollback(e) {
          db.run('ROLLBACK', ()=>{ reject(e); });
        }
      });
    });

    // broadcast via wss
    broadcast({ event:'newTx', data:{ txid, from: tx.from, to: tx.to, amount: tx.amount } });
    broadcast({ event:'balanceUpdate', data:{ address: tx.from } });
    broadcast({ event:'balanceUpdate', data:{ address: tx.to } });

    res.json({ ok:true, txid });
  } catch(e) {
    console.error('sendTx err', e);
    res.status(500).json({ ok:false, error:'internal' });
  }
});

// faucet
app.post('/api/faucet', async (req,res) => {
  const { address, pubkeyHex, captcha } = req.body || {};
  const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').split(',')[0].trim();
  if (!address || !pubkeyHex) return res.status(400).json({ ok:false, error:'address and pubkeyHex required' });
  const expected = pubkeyToAddressHex(pubkeyHex);
  if (expected !== address) return res.status(400).json({ ok:false, error:'pubkey does not match address' });

  // captcha optional (if secret set)
  if (RECAPTCHA_SECRET) {
    if (!captcha) return res.status(400).json({ ok:false, error:'captcha required' });
    try {
      const vRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body: `secret=${encodeURIComponent(RECAPTCHA_SECRET)}&response=${encodeURIComponent(captcha)}`
      });
      const vJson = await vRes.json();
      if (!vJson.success) return res.status(400).json({ ok:false, error:'captcha failed' });
    } catch(e) {
      return res.status(500).json({ ok:false, error:'captcha verify error' });
    }
  }

  try {
    // per-address cooldown
    const last = await getAsync(`SELECT claimed_at FROM faucet_claims WHERE address = ? ORDER BY claimed_at DESC LIMIT 1`, [address]);
    if (last) {
      const lastTs = new Date(last.claimed_at).getTime();
      const now = Date.now();
      if ((now - lastTs)/1000 < FAUCET_COOLDOWN_SECONDS) {
        return res.status(400).json({ ok:false, error:'faucet cooldown', wait_seconds: FAUCET_COOLDOWN_SECONDS - Math.floor((now - lastTs)/1000) });
      }
    }
    // per-IP distinct address limit in period
    const since = new Date(Date.now() - FAUCET_COOLDOWN_SECONDS*1000).toISOString();
    const rows = await allAsync(`SELECT DISTINCT address FROM faucet_claims WHERE ip = ? AND claimed_at >= ?`, [ip, since]);
    if (rows.length >= 3) return res.status(400).json({ ok:false, error:'IP faucet limit reached' });

    await runAsync(`INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?,?,0)`, [address, pubkeyHex]);
    await new Promise((resolve,reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run(`UPDATE addresses SET balance = balance + ? WHERE address = ?`, [FAUCET_AMOUNT, address], (e1) => {
          if (e1) return rollback(e1);
          db.run(`INSERT INTO faucet_claims(address, ip, claimed_at) VALUES(?,?,?)`, [address, ip, new Date().toISOString()], (e2) => {
            if (e2) return rollback(e2);
            db.run('COMMIT', (e3) => { if (e3) return rollback(e3); else resolve(); });
          });
        });
        function rollback(e){ db.run('ROLLBACK', ()=>reject(e)); }
      });
    });

    broadcast({ event:'balanceUpdate', data:{ address } });
    res.json({ ok:true, amount: FAUCET_AMOUNT });
  } catch(e) {
    console.error('faucet err', e);
    res.status(500).json({ ok:false, error:'internal' });
  }
});

// static health / root
app.get('/', (req,res)=>res.send('MyChain server running'));

// Start HTTP + WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });
const clients = new Set();
wss.on('connection', (ws, req) => {
  clients.add(ws);
  ws.on('message', (msg) => {
    try {
      const p = JSON.parse(msg.toString());
      // optional: subscription by address, currently ignored - we broadcast everything and clients filter
      ws.sub = p;
    } catch(e){}
  });
  ws.on('close', ()=>clients.delete(ws));
});
function broadcast(obj) {
  const s = JSON.stringify(obj);
  for (const c of clients) {
    if (c.readyState === WebSocket.OPEN) c.send(s);
  }
}

server.listen(PORT, ()=>{ console.log('Server on', PORT); console.log('API base:', 'http://localhost:'+PORT+'/api'); });
