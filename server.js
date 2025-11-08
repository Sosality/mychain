// server.js
import express from 'express';
import http from 'http';
import { WebSocketServer } from 'ws';
import crypto from 'crypto';

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json());
app.use(express.static('public'));

let chain = [];
let mempool = [];
let difficulty = 4;
let reward = 50;

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function createGenesis() {
  const g = {
    index: 0,
    previousHash: '0'.repeat(64),
    timestamp: Date.now(),
    transactions: [],
    nonce: 0,
    hash: ''
  };
  g.hash = sha256Hex(JSON.stringify(g));
  return g;
}
chain.push(createGenesis());

function broadcast(type, payload) {
  const msg = JSON.stringify({ type, payload });
  for (const c of wss.clients) {
    if (c.readyState === 1) c.send(msg);
  }
}

function validBlock(b, prev) {
  if (prev.index + 1 !== b.index) return false;
  if (b.previousHash !== prev.hash) return false;
  const header = `${b.index}|${b.previousHash}|${b.timestamp}|${JSON.stringify(b.transactions)}`;
  const hash = sha256Hex(header + '|' + b.nonce);
  if (hash !== b.hash) return false;
  if (!hash.startsWith('0'.repeat(difficulty))) return false;
  for (const t of b.transactions) {
    if (t.amount <= 0) return false;
  }
  return true;
}

wss.on('connection', ws => {
  ws.send(JSON.stringify({ type: 'init', payload: { chainTip: chain[chain.length-1], mempool, difficulty } }));
  ws.on('message', msg => {
    try {
      const { type, payload } = JSON.parse(msg.toString());
      if (type === 'tx') {
        mempool.push(payload);
        broadcast('mempool', mempool);
      } else if (type === 'submitBlock') {
        const b = payload;
        const prev = chain[chain.length-1];
        if (validBlock(b, prev)) {
          const txset = new Set(b.transactions.map(t => JSON.stringify(t)));
          mempool = mempool.filter(t => !txset.has(JSON.stringify(t)));
          chain.push(b);
          broadcast('newBlock', { block: b, difficulty });
        } else {
          ws.send(JSON.stringify({ type: 'reject', payload: 'invalid block' }));
        }
      } else if (type === 'getChain') {
        ws.send(JSON.stringify({ type: 'chain', payload: chain }));
      }
    } catch(e){}
  });
});

const PORT = 3000;
server.listen(PORT, () => console.log(`Server http://localhost:${PORT}`));
