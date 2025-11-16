#!/usr/bin/env node
/**
 * blockchain.js
 * Minimal single-file blockchain server (Node.js, no external packages).
 * Дополненный WebSocket-интерфейс (минимальная реализация RFC6455).
 *
 * Запуск:
 *   node blockchain.js
 * Параметры окружения:
 *   PORT (HTTP/WS порт, по умолчанию 3000)
 *   DIFFICULTY (число ведущих нулей в hex для PoW, по умолчанию 3)
 *
 * HTTP API (как раньше):
 *  GET  /chain       -> возвращает цепочку
 *  GET  /pending     -> возвращает pending transactions
 *  POST /transactions -> добавляет транзакцию (JSON body)
 *  POST /mine        -> майнит блок с текущими транзакциями
 *  POST /validate    -> валидирует текущую цепочку
 *
 * WebSocket:
 *  - Подключение: ws://<host>:<PORT> с Upgrade-запросом WebSocket
 *  - Протокол: текстовые JSON-сообщения.
 *  - Команды (в JSON):
 *      { "cmd": "getChain" }
 *      { "cmd": "getPending" }
 *      { "cmd": "addTx", "tx": { "sender":"a","recipient":"b","amount":12 } }
 *      { "cmd": "mine" }
 *      { "cmd": "validate" }
 *  - Сервер отвечает JSON: { "ok": true/false, "id": optionalReqId, "result": ... , "error": ... }
 *  - Сервер рассылает нотификации при событиях:
 *      { "event":"newBlock", "block": { ... } }
 *      { "event":"newTx", "tx": { ... } }
 *
 * Простой HTML-клиент (пример) см. внизу инструкции.
 *
 * Ограничения:
 *  - Демонстрационный пример. Chain в памяти.
 *  - WebSocket — минимальная реализация, для простого тестирования.
 *
 * Автор: сгенерировано нейросетью по вашему запросу.
 */

const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');
const net = require('net');

// ---------------- Configuration ----------------
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const DIFFICULTY = process.env.DIFFICULTY ? parseInt(process.env.DIFFICULTY, 10) : 3;
const MINE_YIELD_ITERATIONS = 10000; // yield каждое N итераций
// ------------------------------------------------

// In-memory blockchain state
let chain = [];
let pendingTransactions = [];

/** Utility: SHA-256 hash of a string, returned as hex */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** Create the genesis block */
function createGenesisBlock() {
  const genesis = {
    index: 0,
    timestamp: new Date().toISOString(),
    transactions: [],
    nonce: 0,
    previousHash: '0'.repeat(64),
  };
  genesis.hash = computeHashForBlock(genesis);
  return genesis;
}

/** Compute hash for a block object (uses index, timestamp, transactions, nonce, previousHash) */
function computeHashForBlock(block) {
  const blockString = `${block.index}|${block.timestamp}|${JSON.stringify(block.transactions)}|${block.nonce}|${block.previousHash}`;
  return sha256(blockString);
}

/** Proof-of-Work check */
function isValidProof(hash, difficulty) {
  const prefix = '0'.repeat(difficulty);
  return hash.startsWith(prefix);
}

/** Validate entire chain, return { valid: boolean, errors: [] } */
function isValidChain(inputChain) {
  const errors = [];
  if (!Array.isArray(inputChain) || inputChain.length === 0) {
    errors.push('Chain must be a non-empty array.');
    return { valid: false, errors };
  }

  for (let i = 0; i < inputChain.length; i++) {
    const block = inputChain[i];
    if (typeof block.index !== 'number' || typeof block.nonce !== 'number' || typeof block.hash !== 'string') {
      errors.push(`Block at index ${i} has invalid structure.`);
      continue;
    }

    const recomputed = computeHashForBlock(block);
    if (recomputed !== block.hash) {
      errors.push(`Invalid hash at block ${i}: expected ${recomputed} got ${block.hash}`);
    }

    if (!isValidProof(block.hash, DIFFICULTY)) {
      errors.push(`PoW not satisfied at block ${i} (difficulty ${DIFFICULTY}).`);
    }

    if (i > 0) {
      const prev = inputChain[i - 1];
      if (block.previousHash !== prev.hash) {
        errors.push(`Block ${i} previousHash does not match hash of block ${i - 1}.`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/** Create a new block object (not yet mined) */
function createBlock(transactions, previousHash) {
  return {
    index: chain.length,
    timestamp: new Date().toISOString(),
    transactions: Array.isArray(transactions) ? transactions : [],
    nonce: 0,
    previousHash: previousHash || (chain.length ? chain[chain.length - 1].hash : '0'.repeat(64)),
    hash: '',
  };
}

/** Async mining: tries nonces until PoW satisfied.
 *  Returns Promise resolving to { block, miningTimeMs, iterations }.
 */
function mineBlockAsync(block, difficulty) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let nonce = 0;
    let iterations = 0;

    function loop() {
      try {
        for (let i = 0; i < MINE_YIELD_ITERATIONS; i++) {
          block.nonce = nonce;
          const hash = computeHashForBlock(block);
          iterations++;
          if (isValidProof(hash, difficulty)) {
            block.hash = hash;
            const miningTimeMs = Date.now() - start;
            return resolve({ block, miningTimeMs, iterations });
          }
          nonce++;
        }
        // yield to event loop
        setImmediate(loop);
      } catch (err) {
        return reject(err);
      }
    }

    loop();
  });
}

/** API helpers */
function sendJSON(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1e6) {
        req.connection.destroy();
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve(null);
      try {
        const parsed = JSON.parse(body);
        resolve(parsed);
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', err => reject(err));
  });
}

/** Initialize chain with genesis block if empty */
function ensureGenesis() {
  if (chain.length === 0) {
    const genesis = createGenesisBlock();
    chain.push(genesis);
  }
}

/** --- WebSocket minimal implementation --- **
 * We'll accept Upgrade requests and implement basic frame parsing/sending.
 * Supports only text frames (UTF-8), no fragmentation, clients MUST mask their frames (as per standard).
 * Server sends unmasked frames.
 */

// Active websocket clients (store sockets and helper send)
const wsClients = new Set();

/** Compute Sec-WebSocket-Accept header value from client's key */
function computeWebSocketAccept(key) {
  const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  return crypto.createHash('sha1').update(key + GUID).digest('base64');
}

/** Send a text frame to a socket (server->client; unmasked) */
function wsSendText(socket, message) {
  if (socket.destroyed) return;
  const payload = Buffer.from(String(message), 'utf8');
  const payloadLen = payload.length;
  let header;

  if (payloadLen <= 125) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN=1, text frame
    header[1] = payloadLen;
  } else if (payloadLen <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payloadLen, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    // write 64-bit length
    // High 32 bits (0 since JS buffers limited) and low 32 bits:
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(payloadLen, 6);
  }

  const frame = Buffer.concat([header, payload]);
  socket.write(frame);
}

/** Parse a single websocket frame from buffer; return {fin, opcode, payload, length, frameLen} or null if incomplete */
function wsParseFrame(buffer) {
  if (buffer.length < 2) return null;
  const b1 = buffer[0];
  const b2 = buffer[1];
  const fin = (b1 & 0x80) !== 0;
  const opcode = b1 & 0x0f;
  const masked = (b2 & 0x80) !== 0;
  let payloadLen = b2 & 0x7f;
  let offset = 2;

  if (payloadLen === 126) {
    if (buffer.length < offset + 2) return null;
    payloadLen = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (payloadLen === 127) {
    if (buffer.length < offset + 8) return null;
    // Note: support lengths up to 2^53-1 isn't straightforward; we'll read low 32 bits
    const high = buffer.readUInt32BE(offset);
    const low = buffer.readUInt32BE(offset + 4);
    // if high != 0 and payload too big, reject
    if (high !== 0) throw new Error('Payload too big');
    payloadLen = low;
    offset += 8;
  }

  const maskKey = masked ? buffer.slice(offset, offset + 4) : null;
  if (masked) {
    if (buffer.length < offset + 4) return null;
    offset += 4;
  }

  if (buffer.length < offset + payloadLen) return null;

  let payload = buffer.slice(offset, offset + payloadLen);
  if (masked && maskKey) {
    // unmask
    for (let i = 0; i < payload.length; i++) {
      payload[i] ^= maskKey[i % 4];
    }
  }

  const frameLen = offset + payloadLen;
  return {
    fin,
    opcode,
    payload: payload.toString('utf8'),
    length: payloadLen,
    frameLen,
  };
}

/** Broadcast JSON to all WS clients (text frame) */
function broadcastWS(obj) {
  const msg = JSON.stringify(obj);
  for (const client of wsClients) {
    try {
      wsSendText(client.socket, msg);
    } catch (err) {
      // ignore send errors
    }
  }
}

/** Handle a newly accepted websocket socket */
function attachWebSocket(socket) {
  // track per-socket buffer
  socket._wsBuffer = Buffer.alloc(0);
  const client = { socket };
  wsClients.add(client);

  socket.on('data', data => {
    // append to buffer and parse frames in a loop
    socket._wsBuffer = Buffer.concat([socket._wsBuffer, Buffer.from(data)]);
    try {
      while (true) {
        const frame = wsParseFrame(socket._wsBuffer);
        if (!frame) break;
        // remove processed bytes
        socket._wsBuffer = socket._wsBuffer.slice(frame.frameLen);

        // handle opcodes: 0x1 = text, 0x8 = close, 0x9 = ping, 0xA = pong
        if (frame.opcode === 0x8) {
          // close
          try {
            socket.end();
          } catch (e) {}
          wsClients.delete(client);
          break;
        } else if (frame.opcode === 0x9) {
          // ping -> pong with same payload
          const payload = Buffer.from(frame.payload, 'utf8');
          // send pong (0xA)
          const header = Buffer.alloc(2 + payload.length);
          header[0] = 0x8A; // FIN=1, opcode=10
          header[1] = payload.length;
          const frameBuf = Buffer.concat([header, payload]);
          socket.write(frameBuf);
        } else if (frame.opcode === 0x1) {
          // text frame
          handleWSMessage(client, frame.payload);
        } else {
          // ignore other opcodes for simplicity
        }
      }
    } catch (err) {
      // parsing error -> close
      try { socket.destroy(); } catch(e) {}
      wsClients.delete(client);
    }
  });

  socket.on('close', () => {
    wsClients.delete(client);
  });
  socket.on('error', () => {
    wsClients.delete(client);
  });

  // optionally send welcome
  wsSendText(socket, JSON.stringify({ ok: true, event: 'welcome', message: 'Connected to simple blockchain ws' }));
}

/** Handle incoming WS JSON command (as text) */
async function handleWSMessage(client, text) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    wsSendText(client.socket, JSON.stringify({ ok: false, error: 'Invalid JSON' }));
    return;
  }

  // optional id echo
  const reqId = obj.id;

  try {
    if (!obj.cmd) {
      wsSendText(client.socket, JSON.stringify({ ok: false, id: reqId, error: 'Missing cmd' }));
      return;
    }
    if (obj.cmd === 'getChain') {
      wsSendText(client.socket, JSON.stringify({ ok: true, id: reqId, result: { length: chain.length, chain } }));
    } else if (obj.cmd === 'getPending') {
      wsSendText(client.socket, JSON.stringify({ ok: true, id: reqId, result: { pendingCount: pendingTransactions.length, pendingTransactions } }));
    } else if (obj.cmd === 'addTx') {
      const tx = obj.tx;
      if (!tx || typeof tx.sender !== 'string' || typeof tx.recipient !== 'string' || (typeof tx.amount !== 'number' && typeof tx.amount !== 'string')) {
        wsSendText(client.socket, JSON.stringify({ ok: false, id: reqId, error: 'Invalid tx format' }));
        return;
      }
      const txn = { sender: tx.sender, recipient: tx.recipient, amount: Number(tx.amount) };
      pendingTransactions.push(txn);
      wsSendText(client.socket, JSON.stringify({ ok: true, id: reqId, result: { message: 'Transaction added', tx: txn, index: chain.length } }));
      // broadcast newTx to all clients
      broadcastWS({ event: 'newTx', tx: txn });
    } else if (obj.cmd === 'mine') {
      // start mining and send result when done
      const block = createBlock(pendingTransactions.slice(), chain.length ? chain[chain.length - 1].hash : undefined);
      try {
        const { block: minedBlock, miningTimeMs, iterations } = await mineBlockAsync(block, DIFFICULTY);
        chain.push(minedBlock);
        pendingTransactions = [];
        const resp = { ok: true, id: reqId, result: { block: minedBlock, miningTimeMs, iterations } };
        wsSendText(client.socket, JSON.stringify(resp));
        // broadcast newBlock
        broadcastWS({ event: 'newBlock', block: minedBlock });
      } catch (err) {
        wsSendText(client.socket, JSON.stringify({ ok: false, id: reqId, error: 'Mining failed', detail: String(err) }));
      }
    } else if (obj.cmd === 'validate') {
      const result = isValidChain(chain);
      wsSendText(client.socket, JSON.stringify({ ok: true, id: reqId, result }));
    } else {
      wsSendText(client.socket, JSON.stringify({ ok: false, id: reqId, error: 'Unknown cmd' }));
    }
  } catch (err) {
    wsSendText(client.socket, JSON.stringify({ ok: false, id: reqId, error: 'Server error', detail: String(err) }));
  }
}

/** --- HTTP server with Upgrade handling --- */
ensureGenesis();

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  try {
    if (req.method === 'GET' && pathname === '/chain') {
      return sendJSON(res, 200, { length: chain.length, chain });
    }

    if (req.method === 'GET' && pathname === '/pending') {
      return sendJSON(res, 200, { pendingCount: pendingTransactions.length, pendingTransactions });
    }

    if (req.method === 'POST' && pathname === '/transactions') {
      let body;
      try {
        body = await parseRequestBody(req);
      } catch (err) {
        return sendJSON(res, 400, { success: false, error: 'Invalid JSON body' });
      }
      if (!body || typeof body !== 'object') {
        return sendJSON(res, 400, { success: false, error: 'Missing request body' });
      }
      const { sender, recipient, amount } = body;
      if (typeof sender !== 'string' || typeof recipient !== 'string' || (typeof amount !== 'number' && typeof amount !== 'string')) {
        return sendJSON(res, 400, { success: false, error: 'Invalid transaction format. Expect { sender, recipient, amount }' });
      }
      const tx = { sender, recipient, amount: Number(amount) };
      pendingTransactions.push(tx);
      // notify WS clients
      broadcastWS({ event: 'newTx', tx });
      const nextIndex = chain.length;
      return sendJSON(res, 201, { success: true, message: 'Transaction added', index: nextIndex, tx });
    }

    if (req.method === 'POST' && pathname === '/mine') {
      const block = createBlock(pendingTransactions.slice(), chain.length ? chain[chain.length - 1].hash : undefined);
      try {
        const { block: minedBlock, miningTimeMs, iterations } = await mineBlockAsync(block, DIFFICULTY);
        chain.push(minedBlock);
        pendingTransactions = [];
        // notify WS clients
        broadcastWS({ event: 'newBlock', block: minedBlock });
        return sendJSON(res, 201, { success: true, block: minedBlock, miningTimeMs, iterations });
      } catch (err) {
        return sendJSON(res, 500, { success: false, error: 'Mining failed', detail: String(err) });
      }
    }

    if (req.method === 'POST' && pathname === '/validate') {
      const result = isValidChain(chain);
      if (result.valid) {
        return sendJSON(res, 200, { valid: true, message: 'Chain is valid', length: chain.length });
      } else {
        return sendJSON(res, 200, { valid: false, errors: result.errors });
      }
    }

    // small landing page for quick manual check
    if (req.method === 'GET' && pathname === '/') {
      const info = {
        message: 'Simple single-file blockchain. Use HTTP API or WebSocket.',
        endpoints: ['/chain', '/pending', '/transactions (POST)', '/mine (POST)', '/validate (POST)'],
        ws: 'ws://<host>:' + PORT,
      };
      return sendJSON(res, 200, info);
    }

    return sendJSON(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('Server error:', err);
    return sendJSON(res, 500, { error: 'Internal server error', detail: String(err) });
  }
});

// Handle Upgrade header for WebSocket
server.on('upgrade', (req, socket, head) => {
  const { url } = req;

  // Разрешаем webSocket только на /ws
  if (url !== '/ws') {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }

  const upgradeHeader = req.headers['upgrade'];
  if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  const secKey = req.headers['sec-websocket-key'];
  if (!secKey) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  const acceptKey = computeWebSocketAccept(secKey);

  const responseHeaders = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    'Sec-WebSocket-Accept: ' + acceptKey,
    '\r\n'
  ];

  socket.write(responseHeaders.join('\r\n'));

  attachWebSocket(socket);
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Difficulty: ${DIFFICULTY} leading zeros (hex).`);
  console.log(`HTTP endpoints: GET /, GET /chain, GET /pending, POST /transactions, POST /mine, POST /validate`);
  console.log(`WebSocket: ws://<host>:${PORT} (send JSON commands)`);
});

/** --- End of file --- */
