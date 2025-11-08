const express = require("express");
const path = require("path");
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 3000;

// Блокчейн состояние
let blockchain = [];
let mempool = [];
let balances = {}; // Адрес → количество монет

// Пересчёт балансов по всей цепи
function recalcBalances() {
  balances = {};
  for (const block of blockchain) {
    for (const tx of block.transactions) {
      if (!balances[tx.from]) balances[tx.from] = 0;
      if (!balances[tx.to]) balances[tx.to] = 0;
      balances[tx.from] -= tx.amount;
      balances[tx.to] += tx.amount;
    }
  }
}

// Создать генезис-блок
function createGenesis() {
  const block = {
    index: 0,
    previousHash: "0".repeat(64),
    timestamp: Date.now(),
    transactions: [],
    nonce: 0,
    hash: "0".repeat(64)
  };
  blockchain.push(block);
  recalcBalances();
}
createGenesis();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.post("/tx", (req, res) => {
  const tx = req.body;
  if (!tx || !tx.from || !tx.to || typeof tx.amount !== "number") {
    return res.status(400).json({ error: "Invalid transaction format" });
  }
  mempool.push(tx);
  broadcast({ type: "mempool", mempool });
  res.json({ status: "ok" });
});

app.get("/chain", (req, res) => {
  res.json({ blockchain, balances });
});

const server = app.listen(PORT, () =>
  console.log("Blockchain server running on port", PORT)
);

const wss = new WebSocket.Server({ server });

function broadcast(msg) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  });
}

wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ type: "init", chain: blockchain, mempool, balances }));

  ws.on("message", (msg) => {
    try {
      const data = JSON.parse(msg);

      if (data.type === "block") {
        const block = data.block;
        const last = blockchain[blockchain.length - 1];

        if (block.previousHash === last.hash && block.index === last.index + 1) {
          blockchain.push(block);
          mempool = mempool.filter(tx =>
            !block.transactions.find(t2 => JSON.stringify(t2) === JSON.stringify(tx))
          );
          recalcBalances();
          broadcast({ type: "chain", chain: blockchain, mempool, balances });
        }
      }
    } catch {}
  });
});
