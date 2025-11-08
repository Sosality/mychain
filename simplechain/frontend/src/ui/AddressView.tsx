import React, { useState } from 'react';

export default function AddressView(){
  const [addr, setAddr] = useState('');
  const [data, setData] = useState<any>(null);

  async function lookup() {
    const res = await fetch('/address/' + encodeURIComponent(addr));
    const json = await res.json();
    setData(json);
  }

  return (
    <div>
      <h2>Address lookup</h2>
      <div>
        <input value={addr} onChange={e=>setAddr(e.target.value)} placeholder="addr_..." size={60} />
        <button onClick={lookup}>Lookup</button>
      </div>
      {data && (
        <div>
          <h3>Balance: {data.balance}</h3>
          <h4>Txs (showing up to {data.txs.length})</h4>
          <ul>
            {data.txs.map((t:any)=>(
              <li key={t.tx.id}>{t.tx.id} — {t.tx.from} → {t.tx.to} — {t.tx.amount} — {t.status}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
