# SimpleChain — minimal educational blockchain + explorer + wallet

This repository contains a minimal working prototype called **SimpleChain**:
- Node (Node.js + TypeScript) with LevelDB storage
- Frontend (React + Vite + TypeScript) with Explorer and Wallet
- Dockerfiles + docker-compose for quick start

## Goals
A simple single-node blockchain with:
- simplified PoA: node mines blocks periodically (TARGET_BLOCK_TIME, default 10s) when there are txs
- transactions signed client-side (noble-secp256k1)
- LevelDB storage for blocks and tx index
- REST API + WebSocket for live updates
- Basic wallet in browser — private key never sent to server

## Quick start (local, dev)
You need Node.js 18+ and npm/yarn.

### Backend
```bash
cd node
npm install
npm run dev
```
Server runs on http://localhost:4000

### Frontend
In another terminal:
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on http://localhost:3000 and talks to the backend (proxy via same origin assumed when using docker-compose).

## Quick start (docker)
Build and run both services:
```bash
docker compose up --build
```
Open:
- Frontend: http://localhost:3000
- API: http://localhost:4000

## Scripts
- `npm run dev` (backend) — starts ts-node-dev server
- `npm run build` (backend) — compile to dist
- `npm run init` — create genesis block (runs scripts/init.ts)
- `npm test` — simple signature test

## API (examples)

### POST /tx
Send a signed transaction (created in wallet):
```bash
curl -X POST http://localhost:4000/tx -H "Content-Type: application/json" -d '{
  "from":"addr_abc...",
  "to":"addr_def...",
  "amount":1.23,
  "fee":0.01,
  "nonce":0,
  "timestamp":"2025-11-08T12:34:56Z",
  "signature":"<hex>"
}'
```

Response:
```json
{ "txid":"tx_xxx", "status":"accepted" }
```

### GET /tx/:txid
Get transaction status:
```bash
curl http://localhost:4000/tx/tx_xxx
```

### GET /address/:addr
Get balance and txs:
```bash
curl http://localhost:4000/address/addr_abc
```

### GET /block/:hashOrIndex
```bash
curl http://localhost:4000/block/0
curl http://localhost:4000/block/0000abcd...
```

### GET /blocks/latest?n=10
Get latest N blocks.

### WebSocket /ws
Connect to ws://localhost:4000 and listen for `newTx` and `newBlock` events.

## Security notes
- Private keys are generated and used only in browser; server expects signed transactions.
- Do not use this for real funds or production usage.
- For production: terminate TLS (nginx + certbot). Example: use nginx reverse proxy to forward 443 to backend 4000 and frontend 3000.

## Tests
There is a simple signature test in `node/src/tests/test_signature.ts`. Run `npm test` in the `node` directory.

## Structure
- `node/` — backend (TypeScript)
- `frontend/` — React + Vite frontend
- `Dockerfile.backend`, `frontend/Dockerfile`, `docker-compose.yml`

## Example flow (wallet)
1. Create a new key in Wallet page (private key stays in browser)
2. Enter recipient address, amount and fee, press "Sign locally & Send"
3. Backend accepts tx into mempool; miner will include tx into next block (~10s) and explorer will update via WebSocket.

## Notes for extension
- Add proper ECDSA verification on server side (demonstration code uses signature storage only)
- Add nonce/balance checks server-side before accepting tx
- Improve address format (bech32), use HD wallets/mnemonic, add pagination.

