import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import nacl from "tweetnacl";
import bs58 from "bs58";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ХРАНИЛИЩЕ В ПАМЯТИ
const balances = {}; // { address: number }
const nonces = {};   // { address: number }

// Получить баланс
app.get("/api/balance/:address", (req, res) => {
  const address = req.params.address;
  res.json({ balance: balances[address] || 0 });
});

// Отправить транзакцию
app.post("/api/sendTx", (req, res) => {
  const { from, to, amount, nonce, signature, pubkey } = req.body;
  if (!from || !to || !amount || !signature || !pubkey || nonce == null)
    return res.status(400).json({ error: "Invalid tx" });

  // Проверяем nonce
  const currentNonce = nonces[from] || 0;
  if (nonce !== currentNonce) return res.status(400).json({ error: "Invalid nonce" });

  // Проверяем подпись
  const txData = JSON.stringify({ from, to, amount, nonce });
  const msg = new TextEncoder().encode(txData);
  const publicKeyBytes = bs58.decode(pubkey);
  const signatureBytes = bs58.decode(signature);

  const ok = nacl.sign.detached.verify(msg, signatureBytes, publicKeyBytes);
  if (!ok) return res.status(400).json({ error: "Bad signature" });

  // Проверяем баланс
  if ((balances[from] || 0) < amount) return res.status(400).json({ error: "Not enough balance" });

  // Применяем транзакцию
  balances[from] = (balances[from] || 0) - amount;
  balances[to] = (balances[to] || 0) + amount;
  nonces[from] = currentNonce + 1;

  res.json({ ok: true });
});

// Фаусет — выдаёт 100 токенов любому адресу
app.post("/api/faucet", (req, res) => {
  const { address } = req.body;
  if (!address) return res.status(400).json({ error: "No address" });
  balances[address] = (balances[address] || 0) + 100;
  res.json({ ok: true, balance: balances[address] });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
