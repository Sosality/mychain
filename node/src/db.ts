import level from 'level';
import path from 'path';

const dbPath = process.env.SIMPLECHAIN_DB || path.join(process.cwd(), 'data', 'leveldb');
export const db = level(dbPath, { valueEncoding: 'json' });

/*
Key schema (simple):
- block:<index> -> Block
- blockHash:<hash> -> index
- tx:<txid> -> { tx, status: 'mempool'|'confirmed', blockIndex?: number, timestamp }
- addr:<address>:txs -> [txid]  (we'll store as key per tx to append)
- meta:latestBlock -> index
*/
