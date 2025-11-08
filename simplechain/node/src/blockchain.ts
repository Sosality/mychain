import { db } from './db';
import { Tx, Block } from './types';
import { sha256Hex } from './utils/crypto';
import { v4 as uuidv4 } from 'uuid';

const TARGET_BLOCK_TIME = Number(process.env.TARGET_BLOCK_TIME || 10); // seconds

export class SimpleChain {
  mempool: Map<string, Tx> = new Map();
  mining = false;

  constructor() {}

  async init() {
    try {
      const latest = await db.get('meta:latestBlock');
      console.log('Latest block index:', latest);
    } catch (e) {
      console.log('No genesis found, creating genesis...');
      await this.createGenesis();
    }
  }

  async createGenesis() {
    const genesis: Block = {
      header: {
        index: 0,
        prevHash: '0'.repeat(64),
        timestamp: new Date().toISOString(),
        merkleRoot: '0'.repeat(64),
        nonce: 0
      },
      transactions: [],
      hash: sha256Hex('genesis')
    };
    await db.put('block:0', genesis);
    await db.put('meta:latestBlock', 0);
  }

  async submitTx(tx: Tx) {
    if (!tx.id) tx.id = 'tx_' + uuidv4();
    // basic validation
    if (!tx.signature) throw new Error('Missing signature');
    // store in mempool and in db as mempool
    this.mempool.set(tx.id, tx);
    await db.put('tx:' + tx.id, { tx, status: 'mempool', timestamp: new Date().toISOString() });
    return tx.id;
  }

  async getTx(txid: string) {
    try {
      return await db.get('tx:' + txid);
    } catch (e) {
      return null;
    }
  }

  async getLatestBlockIndex(): Promise<number> {
    try {
      return await db.get('meta:latestBlock');
    } catch (e) {
      return -1;
    }
  }

  async mineIfNeeded() {
    if (this.mining) return;
    if (this.mempool.size === 0) return;
    this.mining = true;
    try {
      await this.mineBlock();
    } finally {
      this.mining = false;
    }
  }

  async mineBlock() {
    const latestIndex = await this.getLatestBlockIndex();
    const prev = latestIndex >= 0 ? await db.get('block:' + latestIndex) : null;
    const txs = Array.from(this.mempool.values());
    const txids = txs.map(t => t.id);
    const merkle = sha256Hex(txids.join('|') || '');
    const header = {
      index: latestIndex + 1,
      prevHash: prev ? prev.hash : '0'.repeat(64),
      timestamp: new Date().toISOString(),
      merkleRoot: merkle,
      nonce: 0
    };
    const blockRaw = JSON.stringify({ header, transactions: txids });
    const hash = sha256Hex(blockRaw);
    const block: Block = { header, transactions: txids, hash };
    // persist block
    await db.put('block:' + header.index, block);
    await db.put('blockHash:' + block.hash, header.index);
    await db.put('meta:latestBlock', header.index);
    // update tx states and index address -> tx
    for (const tx of txs) {
      await db.put('tx:' + tx.id, { tx, status: 'confirmed', blockIndex: header.index, timestamp: new Date().toISOString() });
      // append address->tx mapping using a key per tx: addr:<addr>:tx:<ts>:<txid> -> txid
      await db.put(`addr:${tx.from}:tx:${header.index}:${tx.id}`, tx.id);
      await db.put(`addr:${tx.to}:tx:${header.index}:${tx.id}`, tx.id);
      this.mempool.delete(tx.id);
    }
    return block;
  }

  async getBlockByIndex(index: number) {
    try {
      return await db.get('block:' + index);
    } catch (e) {
      return null;
    }
  }

  async getBlockByHash(hash: string) {
    try {
      const idx = await db.get('blockHash:' + hash);
      return await this.getBlockByIndex(idx);
    } catch (e) {
      return null;
    }
  }

  async getLatestBlocks(limit = 10) {
    const latest = await this.getLatestBlockIndex();
    const res = [];
    for (let i = Math.max(0, latest - limit + 1); i <= latest; i++) {
      const b = await this.getBlockByIndex(i);
      if (b) res.push(b);
    }
    return res.reverse();
  }

  async getAddressTxs(addr: string, limit=50) {
    const stream = db.createReadStream({ gte: `addr:${addr}:`, lte: `addr:${addr}:ÿ` });
    const txids = [];
    for await (const { key, value } of stream) {
      txids.push(value);
    }
    // fetch tx objects
    const txs = [];
    for (const id of txids.slice(0, limit)) {
      const t = await this.getTx(id);
      if (t) txs.push(t);
    }
    return txs;
  }

  async computeBalance(addr: string) {
    // Very simple: scan all txs for address
    const txs = await this.getAddressTxs(addr, 10000);
    let balance = 0;
    for (const rec of txs) {
      const tx = rec.tx;
      if (tx.to === addr) balance += tx.amount;
      if (tx.from === addr) balance -= (tx.amount + tx.fee);
    }
    return balance;
  }
}

export const simpleChain = new SimpleChain();
