// mychain-server.js
// Single-file Express app for wallet creation + transfers (server-side)
// -------------------------------------------------------------
// Features:
// - GET / : serves single-page UI that lets user create wallets and send transfers
// - POST /api/create : server-side generate BIP39 mnemonic and returns address + mnemonic + privateKey
// - POST /api/send : server-side build and broadcast a transaction using the generated mnemonic
// - Uses ethers.js and bip39. RPC node URL must be provided via environment variable RPC_URL
// -------------------------------------------------------------
// Security and deployment notes (read before using):
// - This example is intentionally simple for learning. It transmits mnemonics/private keys
//   between server and client and can sign & broadcast transactions on your behalf.
// - DO NOT USE THIS FOR MAINNET FUNDS. For real funds, use hardware wallets, never expose
//   private keys to web servers, and follow best practices.
// - To test safely, use a testnet RPC (Sepolia, Goerli deprecated on many providers) and
//   use testnet faucets for ETH.

const express = require('express');
const bip39 = require('bip39');
const { ethers } = require('ethers');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic rate limiting to reduce abuse
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

const RPC_URL = process.env.RPC_URL || ''; // e.g. https://sepolia.infura.io/v3/<KEY>
const CHAIN_NAME = process.env.CHAIN_NAME || 'sepolia';

if (!RPC_URL) {
  console.warn('Warning: RPC_URL not set. /api/send will fail until RPC_URL environment variable is provided.');
}

function generateMnemonic(words = 12) {
  const entropyBytes = words === 12 ? 16 : 32;
  const entropy = crypto.randomBytes(entropyBytes).toString('hex');
  return bip39.entropyToMnemonic(entropy);
}

function walletFromMnemonic(mnemonic, path = "m/44'/60'/0'/0/0") {
  return ethers.Wallet.fromMnemonic(mnemonic, path);
}

app.get('/', (req, res) => {
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MyChain — Wallet & Transfers</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial;max-width:980px;margin:28px auto;padding:0 18px}
    .card{border:1px solid #eee;border-radius:10px;padding:18px;margin-bottom:14px}
    label{display:block;margin-top:8px}
    input,select,button,textarea{font:inherit;padding:8px;margin-top:6px;width:100%;box-sizing:border-box}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    pre{background:#f6f7f9;padding:12px;border-radius:8px;overflow:auto}
    small{color:#666}
  </style>
</head>
<body>
  <h1>MyChain — Создание кошелька и переводы</h1>

  <div class="card">
    <h2>1) Создать кошелёк</h2>
    <p>Нажмите, чтобы сгенерировать BIP39 seed (mnemonic), адрес и приватный ключ (сервер сгенерирует и вернёт их).</p>
    <p><button id="create">Создать кошелёк</button></p>
    <div id="walletInfo" style="display:none">
      <label>Seed-фраза (mnemonic)</label>
      <pre id="mnemonic">-</pre>
      <label>Адрес</label>
      <code id="address">-</code>
      <label>Приватный ключ</label>
      <pre id="priv">-</pre>
      <p><small>Скопируйте seed и храните его в безопасном месте. Приватный ключ виден — не используйте с реальными средствами.</small></p>
    </div>
  </div>

  <div class="card">
    <h2>2) Отправить перевод (на сервере)</h2>
    <p>Введите seed-фразу (mnemonic) и данные транзакции. Сервер подпишет и отправит транзакцию через RPC node.</p>

    <label>Seed-фраза (mnemonic)</label>
    <textarea id="sendMnemonic" rows="2" placeholder="Введите mnemonic сюда"></textarea>

    <div class="row">
      <div>
        <label>Кому (address)</label>
        <input id="to" placeholder="0x..." />
      </div>
      <div>
        <label>Сумма (ETH)</label>
        <input id="amount" placeholder="0.01" />
      </div>
    </div>

    <label>Gas limit (опционально)</label>
    <input id="gasLimit" placeholder="21000" />

    <p style="margin-top:8px">
      <button id="send">Отправить транзакцию</button>
    </p>

    <div id="txResult" style="display:none">
      <label>Результат</label>
      <pre id="result">-</pre>
    </div>
  </div>

  <div class="card">
    <h2>Замечания безопасности</h2>
    <ul>
      <li>Эта страница отправляет ваш mnemonic на сервер. Это НЕ безопасно для реальных средств.</li>
      <li>Для безопасной отправки подписывайте транзакции на клиенте или используйте hardware wallet.</li>
      <li>Настройте RPC_URL в окружении перед включением отправки транзакций: <code>RPC_URL</code>.</li>
    </ul>
  </div>

  <script>
    async function postJSON(url, body) {
      const res = await fetch(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + await res.text());
      return res.json();
    }

    document.getElementById('create').addEventListener('click', async () => {
      try {
        const j = await postJSON('/api/create', {});
        document.getElementById('mnemonic').textContent = j.mnemonic;
        document.getElementById('address').textContent = j.address;
        document.getElementById('priv').textContent = j.privateKey;
        document.getElementById('walletInfo').style.display = 'block';
      } catch (e) {
        alert('Ошибка: ' + e.message);
      }
    });

    document.getElementById('send').addEventListener('click', async () => {
      const mnemonic = document.getElementById('sendMnemonic').value.trim();
      const to = document.getElementById('to').value.trim();
      const amount = document.getElementById('amount').value.trim();
      const gasLimit = document.getElementById('gasLimit').value.trim();

      if (!mnemonic) return alert('Введите mnemonic');
      if (!to) return alert('Введите адрес получателя');
      if (!amount) return alert('Введите сумму');

      document.getElementById('txResult').style.display = 'block';
      document.getElementById('result').textContent = 'Отправка...';

      try {
        const payload = { mnemonic, to, amount, gasLimit: gasLimit || undefined };
        const j = await postJSON('/api/send', payload);
        document.getElementById('result').textContent = JSON.stringify(j, null, 2);
      } catch (e) {
        document.getElementById('result').textContent = 'Ошибка: ' + e.message;
      }
    });
  </script>
</body>
</html>`);
});

// Create wallet endpoint
app.post('/api/create', (req, res) => {
  try {
    const words = req.body.words === 24 ? 24 : 12;
    const mnemonic = generateMnemonic(words);
    const wallet = walletFromMnemonic(mnemonic);
    res.json({ mnemonic, address: wallet.address, privateKey: wallet.privateKey });
  } catch (err) {
    res.status(500).json({ error: 'generation_failed', message: err.message });
  }
});

// Send transaction endpoint: accepts { mnemonic, to, amount, gasLimit }
app.post('/api/send', async (req, res) => {
  try {
    const { mnemonic, to, amount, gasLimit } = req.body;
    if (!mnemonic || !to || !amount) return res.status(400).json({ error: 'missing_parameters' });

    if (!RPC_URL) return res.status(500).json({ error: 'rpc_not_configured', message: 'RPC_URL not set on server' });

    // Basic validation
    if (!bip39.validateMnemonic(mnemonic)) return res.status(400).json({ error: 'invalid_mnemonic' });
    if (!ethers.utils.isAddress(to)) return res.status(400).json({ error: 'invalid_address' });

    // Create provider and wallet
    const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
    const wallet = walletFromMnemonic(mnemonic).connect(provider);

    // Build tx
    const value = ethers.utils.parseEther(String(amount));
    const tx = {
      to,
      value
    };
    if (gasLimit) tx.gasLimit = ethers.BigNumber.from(String(gasLimit));

    // Optional: estimate gas if not provided
    if (!tx.gasLimit) {
      try {
        const estimated = await wallet.estimateGas(tx);
        tx.gasLimit = estimated;
      } catch (e) {
        tx.gasLimit = ethers.BigNumber.from(21000);
      }
    }

    // Fill gas price / max fees depending on network
    const feeData = await provider.getFeeData();
    if (feeData.maxFeePerGas && feeData.maxPriorityFeePerGas) {
      tx.maxFeePerGas = feeData.maxFeePerGas;
      tx.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas;
    } else if (feeData.gasPrice) {
      tx.gasPrice = feeData.gasPrice;
    }

    // Send tx
    const sent = await wallet.sendTransaction(tx);
    // Wait 1 confirmation but don't block too long
    const receipt = await sent.wait(1);

    res.json({
      txHash: sent.hash,
      blockNumber: receipt.blockNumber,
      confirmations: receipt.confirmations,
      gasUsed: receipt.gasUsed.toString()
    });
  } catch (err) {
    console.error('send error', err);
    res.status(500).json({ error: 'send_failed', message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MyChain server listening on port ${PORT}`));
