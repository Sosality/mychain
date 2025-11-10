// server.js
// Большой однофайловый сервер — SQLite + Express + WS
// Убедитесь, что выполнили: npm install express ws sqlite3 dotenv express-rate-limit helmet tweetnacl tweetnacl-util bip39 nanoid node-fetch

require('dotenv').config();
const express = require('express');
const http = require('http');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');
const { nanoid } = require('nanoid');
const fetch = require('node-fetch');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const bip39 = require('bip39');

const PORT = process.env.PORT ? Number(process.env.PORT) : 10000;
const DB_PATH = process.env.DATABASE_URL || './db/ledger.sqlite';
const FAUCET_AMOUNT = Number(process.env.FAUCET_AMOUNT || 100);
const FAUCET_COOLDOWN_SECONDS = Number(process.env.FAUCET_COOLDOWN_SECONDS || 86400);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || ''; // optional

// ensure db dir exists
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

// create DB and apply simple migration if needed
const db = new sqlite3.Database(DB_PATH);
const MIGRATION = `
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
db.exec(MIGRATION, (err) => {
  if (err) console.error('DB migration error:', err);
  else console.log('DB ready:', DB_PATH);
});

// small helpers for promises
function runAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function getAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function allAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// address derivation: address = first 20 bytes of sha256(pubkey) hex
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
function makeAddressFromPubkeyHex(pubkeyHex) {
  const h = sha256Hex(Buffer.from(pubkeyHex, 'hex'));
  return h.slice(0, 40); // 20 bytes = 40 hex chars
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

// simple broadcast via WebSocket clients set
const wsClients = new Set();
function broadcast(event, data) {
  const msg = JSON.stringify({ event, data });
  for (const ws of wsClients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  }
}

// Express app
const app = express();
app.use(helmet());
app.use(express.json({ limit: '200kb' }));
// serve client static from ./client folder if exists
const clientPath = path.join(__dirname, 'client');
if (fs.existsSync(clientPath)) {
  app.use(express.static(clientPath));
}

// simple rate limiter for API
const limiter = rateLimit({ windowMs: 10 * 1000, max: 400 });
app.use('/api/', limiter);

// Endpoint: provide bip39 english wordlist for client-side mnemonic generation
app.get('/bip39', (req, res) => {
  // return wordlist array (client will pick 8 words from it)
  res.json({ ok: true, wordlist: bip39.wordlists.english });
});

// Endpoint: register (store pubkey for address) — client should call after deriving keys
app.post('/api/register', async (req, res) => {
  try {
    const { address, pubkeyHex } = req.body || {};
    if (!address || !pubkeyHex) return res.status(400).json({ ok: false, error: 'address and pubkeyHex required' });
    const expected = makeAddressFromPubkeyHex(pubkeyHex);
    if (expected !== address) return res.status(400).json({ ok: false, error: 'pubkey does not match address' });
    await runAsync('INSERT OR IGNORE INTO addresses(address, pubkey) VALUES(?,?)', [address, pubkeyHex]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// GET balance
app.get('/api/balance/:address', async (req, res) => {
  try {
    const address = req.params.address;
    const row = await getAsync('SELECT balance, nonce FROM addresses WHERE address = ?', [address]);
    if (!row) return res.json({ ok: true, balance: 0, nonce: 0 });
    return res.json({ ok: true, balance: Number(row.balance || 0), nonce: Number(row.nonce || 0) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// GET txs
app.get('/api/txs/:address', async (req, res) => {
  try {
    const a = req.params.address;
    const rows = await allAsync('SELECT * FROM transactions WHERE from_addr = ? OR to_addr = ? ORDER BY timestamp DESC LIMIT 100', [a, a]);
    return res.json({ ok: true, txs: rows });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// POST sendTx: verifies signature, nonce, balance; applies tx; creates simple block; returns txid
app.post('/api/sendTx', async (req, res) => {
  try {
    const tx = req.body;
    if (!tx || !tx.from || !tx.to || tx.amount == null || tx.nonce == null || !tx.signature) {
      return res.status(400).json({ ok: false, error: 'invalid tx format' });
    }

    const sender = await getAsync('SELECT pubkey, balance, nonce FROM addresses WHERE address = ?', [tx.from]);
    if (!sender || !sender.pubkey) return res.status(400).json({ ok: false, error: 'sender unknown, register pubkey first' });

    // verify signature: payload hash -> bytes -> verify detached with pubkey
    const payloadHash = computeTxPayloadHash(tx);
    const payloadBytes = Buffer.from(payloadHash, 'hex');
    const pubkeyBytes = Buffer.from(sender.pubkey, 'hex');
    const signatureBytes = Buffer.from(tx.signature, 'hex');
    const verified = nacl.sign.detached.verify(new Uint8Array(payloadBytes), new Uint8Array(signatureBytes), new Uint8Array(pubkeyBytes));
    if (!verified) return res.status(400).json({ ok: false, error: 'invalid signature' });

    const expectedNonce = Number(sender.nonce || 0) + 1;
    if (Number(tx.nonce) !== expectedNonce) return res.status(400).json({ ok: false, error: `invalid nonce (expected ${expectedNonce})` });

    const amount = Number(tx.amount);
    const fee = Number(tx.fee || 0);
    if (amount < 0 || fee < 0) return res.status(400).json({ ok: false, error: 'invalid amounts' });

    const bal = Number(sender.balance || 0);
    if (bal < amount + fee) return res.status(400).json({ ok: false, error: 'insufficient balance' });

    const txid = nanoid(16);
    const now = new Date().toISOString();

    // apply in DB transaction-like sequence
    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run('UPDATE addresses SET balance = balance - ?, nonce = nonce + 1 WHERE address = ?', [amount + fee, tx.from], function (err) {
          if (err) return rollback(err);
          db.run('INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?, NULL, 0)', [tx.to], function (err2) {
            if (err2) return rollback(err2);
            db.run('UPDATE addresses SET balance = balance + ? WHERE address = ?', [amount, tx.to], function (err3) {
              if (err3) return rollback(err3);
              db.run('INSERT INTO transactions(txid, from_addr, to_addr, amount, fee, nonce, signature, payload_hash, timestamp) VALUES(?,?,?,?,?,?,?,?,?)',
                [txid, tx.from, tx.to, amount, fee, tx.nonce, tx.signature, payloadHash, now], (err4) => {
                  if (err4) return rollback(err4);
                  // create simple block containing this tx
                  const txsJson = JSON.stringify([{ txid, from: tx.from, to: tx.to, amount, fee, nonce: tx.nonce }]);
                  db.get('SELECT hash FROM blocks ORDER BY idx DESC LIMIT 1', [], (err5, rowPrev) => {
                    if (err5) return rollback(err5);
                    const previous_hash = rowPrev ? rowPrev.hash : null;
                    const blockPayload = `${previous_hash || ''}|${now}|${txsJson}`;
                    const blockHash = crypto.createHash('sha256').update(blockPayload).digest('hex');
                    db.run('INSERT INTO blocks(previous_hash, timestamp, txs, hash) VALUES(?,?,?,?)', [previous_hash, now, txsJson, blockHash], (err6) => {
                      if (err6) return rollback(err6);
                      db.run('COMMIT', (err7) => {
                        if (err7) return rollback(err7);
                        resolve();
                      });
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

    // broadcasts
    broadcast('newTx', { txid, from: tx.from, to: tx.to, amount, fee, nonce: tx.nonce });
    broadcast('balanceUpdate', { address: tx.from });
    broadcast('balanceUpdate', { address: tx.to });

    return res.json({ ok: true, txid });
  } catch (e) {
    console.error('sendTx error', e);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// POST faucet
app.post('/api/faucet', async (req, res) => {
  try {
    const { address, pubkeyHex, captcha } = req.body || {};
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim() || req.connection.remoteAddress;

    if (!address || !pubkeyHex) return res.status(400).json({ ok: false, error: 'address and pubkeyHex required' });
    const expected = makeAddressFromPubkeyHex(pubkeyHex);
    if (expected !== address) return res.status(400).json({ ok: false, error: 'pubkey does not match address' });

    // captcha check if secret set
    if (RECAPTCHA_SECRET) {
      if (!captcha) return res.status(400).json({ ok: false, error: 'captcha required' });
      const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: `secret=${encodeURIComponent(RECAPTCHA_SECRET)}&response=${encodeURIComponent(captcha)}`
      });
      const vj = await verifyRes.json();
      if (!vj.success) return res.status(400).json({ ok: false, error: 'captcha failed' });
    }

    // per-address cooldown
    const last = await getAsync('SELECT claimed_at FROM faucet_claims WHERE address = ? ORDER BY claimed_at DESC LIMIT 1', [address]);
    if (last) {
      const lastTs = new Date(last.claimed_at).getTime();
      if ((Date.now() - lastTs) / 1000 < FAUCET_COOLDOWN_SECONDS) {
        return res.status(400).json({ ok: false, error: 'faucet cooldown' });
      }
    }

    // per-IP distinct addresses limit in cooldown window (3)
    const since = new Date(Date.now() - FAUCET_COOLDOWN_SECONDS*1000).toISOString();
    const rows = await allAsync('SELECT DISTINCT address FROM faucet_claims WHERE ip = ? AND claimed_at >= ?', [ip, since]);
    if (rows.length >= 3) return res.status(400).json({ ok: false, error: 'IP faucet limit reached (3 per cooldown window)' });

    // ensure address exists
    await runAsync('INSERT OR IGNORE INTO addresses(address, pubkey, balance) VALUES(?,?,0)', [address, pubkeyHex]);

    // credit and record claim
    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run('UPDATE addresses SET balance = balance + ? WHERE address = ?', [FAUCET_AMOUNT, address], (err) => {
          if (err) return rollback(err);
          db.run('INSERT INTO faucet_claims(address, ip, claimed_at) VALUES(?,?,?)', [address, ip, new Date().toISOString()], (err2) => {
            if (err2) return rollback(err2);
            db.run('COMMIT', (err3) => { if (err3) return rollback(err3); resolve(); });
          });
        });

        function rollback(e) { db.run('ROLLBACK', ()=> reject(e)); }
      });
    });

    broadcast('balanceUpdate', { address });

    return res.json({ ok: true, amount: FAUCET_AMOUNT });
  } catch (e) {
    console.error('faucet error', e);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// Start server and WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  wsClients.add(ws);
  const remote = req.socket.remoteAddress || '';
  console.log('WS connected', remote);
  ws.on('message', (msg) => {
    try {
      const m = JSON.parse(msg.toString());
      if (m && m.cmd === 'subscribe' && m.address) {
        ws.subscribedAddress = m.address;
      }
    } catch (e) {}
  });
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

server.listen(PORT, () => {
  console.log(`Server on ${PORT}`);
  console.log(`Open http://localhost:${PORT} (or your deploy URL)`);
});

