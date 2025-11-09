const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const { verify, utils } = require("@noble/ed25519");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const WebSocket = require("ws");
require("dotenv").config();

// CONFIG
const PORT = process.env.PORT || 3000;
const FAUCET_AMOUNT = Number(process.env.FAUCET_AMOUNT || 50);
const FAUCET_COOLDOWN = Number(process.env.FAUCET_COOLDOWN_SECONDS || 86400);

// DB INIT
const db = new sqlite3.Database("ledger.db");
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS addresses (
      address TEXT PRIMARY KEY,
      pubkey TEXT,
      nonce INTEGER DEFAULT 0,
      balance INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
      txid TEXT PRIMARY KEY,
      sender TEXT,
      receiver TEXT,
      amount INTEGER,
      nonce INTEGER,
      signature TEXT,
      timestamp INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS faucet_claims (
      address TEXT,
      ip TEXT,
      claimed_at INTEGER
  )`);
});

// WEB SERVER
const app = express();
app.use(bodyParser.json());
app.use(cors());

// RATE LIMIT (простая защита от спама на faucet)
const faucetLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
});

// WS
const wss = new WebSocket.Server({ noServer: true });
function broadcast(msg) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(c => c.readyState === 1 && c.send(data));
}

// Util: tx hash
function txHash(tx) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify({ from: tx.from, to: tx.to, amount: tx.amount, nonce: tx.nonce }))
    .digest("hex");
}

// API: баланс
app.get("/api/balance/:addr", (req, res) => {
  db.get("SELECT balance, nonce FROM addresses WHERE address = ?", [req.params.addr], (err, row) => {
    if (!row) return res.json({ balance: 0, nonce: 0 });
    res.json(row);
  });
});

// API: транзакции
app.get("/api/txs/:addr", (req, res) => {
  db.all("SELECT * FROM transactions WHERE sender = ? OR receiver = ? ORDER BY timestamp DESC", [req.params.addr, req.params.addr], (err, rows) => {
    res.json(rows || []);
  });
});

// API: Faucet
app.post("/api/faucet", faucetLimiter, (req, res) => {
  const { address } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (!address) return res.status(400).json({ error: "missing address" });

  db.get("SELECT claimed_at FROM faucet_claims WHERE address = ? ORDER BY claimed_at DESC LIMIT 1", [address], (err, row) => {
    const now = Math.floor(Date.now() / 1000);
    if (row && now - row.claimed_at < FAUCET_COOLDOWN) {
      return res.json({ error: "Wait before claiming again" });
    }

    db.run("INSERT INTO faucet_claims(address, ip, claimed_at) VALUES (?,?,?)", [address, ip, now]);

    db.run("INSERT INTO addresses(address, balance, nonce) VALUES (?, ?, 0) ON CONFLICT(address) DO NOTHING", [address, FAUCET_AMOUNT]);
    db.run("UPDATE addresses SET balance = balance + ? WHERE address = ?", [FAUCET_AMOUNT, address], () => {
      broadcast({ type: "balanceUpdate", address });
      res.json({ ok: true, amount: FAUCET_AMOUNT });
    });
  });
});

// API: SendTx
app.post("/api/sendTx", async (req, res) => {
  const tx = req.body;
  if (!tx.from || !tx.to || !tx.amount || tx.nonce === undefined) return res.json({ error: "bad tx" });

  const hash = txHash(tx);
  const hashBytes = Buffer.from(hash, "hex");
  const sig = Buffer.from(tx.signature, "hex");
  const pub = Buffer.from(tx.pubkey, "hex");

  try {
    const ok = await verify(sig, hashBytes, pub);
    if (!ok) return res.json({ error: "bad signature" });
  } catch {
    return res.json({ error: "signature error" });
  }

  db.get("SELECT balance, nonce FROM addresses WHERE address = ?", [tx.from], (err, rowFrom) => {
    if (!rowFrom || rowFrom.balance < tx.amount) return res.json({ error: "not enough funds" });
    if (rowFrom.nonce !== tx.nonce) return res.json({ error: "bad nonce" });

    db.run("UPDATE addresses SET balance = balance - ?, nonce = nonce + 1 WHERE address = ?", [tx.amount, tx.from]);
    db.run("INSERT INTO addresses(address, balance, nonce) VALUES (?, 0, 0) ON CONFLICT(address) DO NOTHING", [tx.to]);
    db.run("UPDATE addresses SET balance = balance + ? WHERE address = ?", [tx.amount, tx.to]);

    const txid = hash;
    db.run("INSERT INTO transactions(txid, sender, receiver, amount, nonce, signature, timestamp) VALUES (?,?,?,?,?,?,?)",
      [txid, tx.from, tx.to, tx.amount, tx.nonce, tx.signature, Date.now()]);

    broadcast({ type: "newTx", txid });
    broadcast({ type: "balanceUpdate", address: tx.from });
    broadcast({ type: "balanceUpdate", address: tx.to });

    res.json({ ok: true, txid });
  });
});

// UPGRADE WS
const server = app.listen(PORT, () => console.log("Server on", PORT));
server.on("upgrade", (req, socket, head) => {
  if (req.url === "/ws") wss.handleUpgrade(req, socket, head, ws => wss.emit("connection", ws, req));
});
