import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import nacl from "tweetnacl";
import * as naclUtil from "tweetnacl-util";

const app = express();
app.use(express.json());
app.use(cors());

let db;

(async () => {
  db = await open({
    filename: './chain.db',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS balances(address TEXT PRIMARY KEY, balance INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS faucet(address TEXT PRIMARY KEY, last INTEGER);
  `);

  console.log("DB Ready");
})();

async function getBalance(address) {
  const row = await db.get(`SELECT balance FROM balances WHERE address=?`, [address]);
  return row ? row.balance : 0;
}

async function setBalance(address, amount) {
  await db.run(`
    INSERT INTO balances(address,balance) VALUES(?,?)
    ON CONFLICT(address) DO UPDATE SET balance=excluded.balance
  `, [address, amount]);
}

app.get("/api/balance/:address", async (req, res) => {
  res.json({ balance: await getBalance(req.params.address) });
});

app.post("/api/sendTx", async (req, res) => {
  const tx = req.body;
  const {from,to,amount,nonce,signature} = tx;
  if (!from || !to || !amount || !signature) return res.status(400).send("Bad tx");

  const msg = JSON.stringify({from,to,amount,nonce});
  const ok = nacl.sign.detached.verify(
    new TextEncoder().encode(msg),
    naclUtil.decodeBase64(signature),
    naclUtil.decodeBase64(from)
  );
  if (!ok) return res.status(400).send("Invalid signature");

  const balFrom = await getBalance(from);
  if (balFrom < amount) return res.status(400).send("Not enough balance");

  await setBalance(from, balFrom - amount);
  await setBalance(to, await getBalance(to) + amount);

  res.send("OK");
});

app.post("/api/faucet", async (req,res)=>{
  const address = req.body.address;
  if (!address) return res.status(400).send("No address");

  const now = Date.now();
  const row = await db.get(`SELECT last FROM faucet WHERE address=?`, [address]);
  if (row && now - row.last < 24*60*60*1000) return res.send("Wait 24h");

  await setBalance(address, await getBalance(address) + 100);

  await db.run(`
    INSERT INTO faucet(address,last) VALUES(?,?)
    ON CONFLICT(address) DO UPDATE SET last=excluded.last
  `, [address, now]);

  res.send("Faucet granted +100");
});

app.listen(10000, () => console.log("Server running on 10000"));
