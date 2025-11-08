import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import http from 'http';
import WebSocket from 'ws';
import { simpleChain } from './blockchain';
import { db } from './db';
import { v4 as uuidv4 } from 'uuid';
import { sha256Hex } from './utils/crypto';
import { Tx } from './types';

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '2mb' }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = Number(process.env.PORT || 4000);

wss.on('connection', ws => {
  console.log('ws client connected');
});

// helper to broadcast
function broadcast(type: string, payload: any) {
  const msg = JSON.stringify({ type, payload });
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  });
}

app.post('/tx', async (req, res) => {
  try {
    const tx: Tx = req.body;
    if (!tx.id) tx.id = 'tx_' + uuidv4();
    // very light validation (signature should exist)
    if (!tx.signature) return res.status(400).json({ error: 'Missing signature' });
    await simpleChain.submitTx(tx);
    broadcast('newTx', { txid: tx.id, tx });
    // optionally trigger mining immediately
    simpleChain.mineIfNeeded().then(block => {
      if (block) broadcast('newBlock', block);
    }).catch(e => console.error(e));
    res.json({ txid: tx.id, status: 'accepted' });
  } catch (e:any) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/tx/:txid', async (req, res) => {
  const txid = req.params.txid;
  const rec = await simpleChain.getTx(txid);
  if (!rec) return res.status(404).json({ error: 'not found' });
  res.json(rec);
});

app.get('/address/:addr', async (req, res) => {
  const addr = req.params.addr;
  const page = Number(req.query.page || 0);
  const limit = Number(req.query.limit || 50);
  const balance = await simpleChain.computeBalance(addr);
  const txs = await simpleChain.getAddressTxs(addr, limit);
  res.json({ address: addr, balance, txs, page, limit });
});

app.get('/block/:hashOrIndex', async (req, res) => {
  const hi = req.params.hashOrIndex;
  let block = null;
  if (/^\d+$/.test(hi)) block = await simpleChain.getBlockByIndex(Number(hi));
  else block = await simpleChain.getBlockByHash(hi);
  if (!block) return res.status(404).json({ error: 'not found' });
  res.json(block);
});

app.get('/blocks/latest', async (req, res) => {
  const n = Number(req.query.n || 10);
  const blocks = await simpleChain.getLatestBlocks(n);
  res.json(blocks);
});

app.get('/health', (req, res) => res.json({ ok: true }));

async function start() {
  await simpleChain.init();
  server.listen(PORT, () => {
    console.log('SimpleChain node listening on', PORT);
  });
  // periodic miner
  setInterval(() => {
    simpleChain.mineIfNeeded().then(block => {
      if (block) broadcast('newBlock', block);
    }).catch(console.error);
  }, (Number(process.env.TARGET_BLOCK_TIME || 10) * 1000));
}

start();
