import React, { useState } from 'react';
import * as secp from 'noble-secp256k1';

function toHex(b: Uint8Array) { return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(''); }

export default function Wallet({ onBroadcast }:{ onBroadcast?:()=>void }) {
  const [priv, setPriv] = useState<string>('');
  const [pub, setPub] = useState<string>('');
  const [addr, setAddr] = useState<string>('');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('0');
  const [fee, setFee] = useState('0.01');
  const [nonce, setNonce] = useState(0);

  async function gen() {
    const privBytes = secp.utils.randomPrivateKey();
    const privHex = toHex(privBytes);
    const pubHex = secp.getPublicKey(privHex);
    setPriv(privHex);
    setPub(pubHex);
    // simple address: sha256(pub) truncated
    const sha = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubHex));
    const a = Array.from(new Uint8Array(sha)).map(b=>b.toString(16).padStart(2,'0')).slice(0,20).join('');
    setAddr('addr_' + a);
    setNonce(0);
  }

  async function importKey(raw: string) {
    setPriv(raw);
    const pub = secp.getPublicKey(raw);
    setPub(pub);
    const sha = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pub));
    const a = Array.from(new Uint8Array(sha)).map(b=>b.toString(16).padStart(2,'0')).slice(0,20).join('');
    setAddr('addr_' + a);
  }

  async function send() {
    if (!priv) { alert('No private key'); return; }
    const tx = {
      id: '',
      from: addr,
      to,
      amount: Number(amount),
      fee: Number(fee),
      nonce,
      timestamp: new Date().toISOString(),
      signature: ''
    };
    // create message to sign: hash of tx fields
    const payload = JSON.stringify({ from: tx.from, to: tx.to, amount: tx.amount, fee: tx.fee, nonce: tx.nonce, timestamp: tx.timestamp });
    const msgHex = Array.from(new TextEncoder().encode(payload)).map(b=>b.toString(16).padStart(2,'0')).join('');
    const sig = await secp.sign(msgHex, priv);
    tx.signature = sig;
    // post to node
    const res = await fetch('/tx', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(tx) });
    const data = await res.json();
    alert(JSON.stringify(data));
    setNonce(nonce + 1);
    onBroadcast && onBroadcast();
  }

  return (
    <div>
      <h2>Wallet</h2>
      <div>
        <button onClick={gen}>Create new keypair</button>
      </div>
      <div style={{ marginTop: 8 }}>
        <label>Private key:</label><br/>
        <textarea value={priv} onChange={e=>setPriv(e.target.value)} rows={2} cols={80} />
        <div><button onClick={()=>importKey(priv)}>Import private key</button></div>
      </div>
      <div style={{ marginTop:8 }}>
        <div>Address: <b>{addr}</b></div>
        <div>PubKey: <small>{pub}</small></div>
      </div>
      <hr/>
      <h3>Send transaction</h3>
      <div>To: <input value={to} onChange={e=>setTo(e.target.value)} /></div>
      <div>Amount: <input value={amount} onChange={e=>setAmount(e.target.value)} /></div>
      <div>Fee: <input value={fee} onChange={e=>setFee(e.target.value)} /></div>
      <div><button onClick={send}>Sign locally & Send</button></div>
      <p style={{ color: 'red' }}>Warning: private keys must remain in your browser. Do not share.</p>
    </div>
  );
}
