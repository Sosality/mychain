import React, { useEffect, useState } from 'react';

export default function TxView({ txid }:{ txid:string }) {
  const [tx, setTx] = useState<any>(null);
  useEffect(()=> {
    fetch('/tx/' + txid).then(r=>r.json()).then(setTx);
  }, [txid]);
  if (!tx) return <div>Loading...</div>;
  return (
    <div>
      <h2>Transaction {txid}</h2>
      <pre>{JSON.stringify(tx, null, 2)}</pre>
    </div>
  );
}
