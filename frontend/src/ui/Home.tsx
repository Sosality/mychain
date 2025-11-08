import React, { useEffect, useState } from 'react';

export default function Home({ onOpenTx }:{ onOpenTx?:(id:string)=>void }) {
  const [blocks, setBlocks] = useState<any[]>([]);
  const [txs, setTxs] = useState<any[]>([]);
  useEffect(()=> {
    fetch('/blocks/latest?n=10').then(r=>r.json()).then(setBlocks);
    // no endpoint for latest txs; we derive from blocks
  }, []);
  return (
    <div>
      <h2>Latest blocks</h2>
      <ul>
        {blocks.map(b=>(
          <li key={b.hash}>
            #{b.header.index} — {new Date(b.header.timestamp).toLocaleString()} — txs: {b.transactions.length}
          </li>
        ))}
      </ul>
      <p>Open "Address" to view a specific address or use the wallet to create transactions.</p>
    </div>
  )
}
