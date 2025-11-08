import React, { useEffect, useState } from 'react';
import Home from './Home';
import Wallet from './Wallet';
import AddressView from './AddressView';
import TxView from './TxView';

type View = 'home'|'wallet'|'address'|'tx';

export default function App(){
  const [view, setView] = useState<View>('home');
  const [param, setParam] = useState<string|undefined>(undefined);

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', padding: 16 }}>
      <h1>SimpleChain — Explorer & Wallet</h1>
      <div style={{ marginBottom: 12 }}>
        <button onClick={()=>{setView('home')}}>Home</button>{' '}
        <button onClick={()=>{setView('wallet')}}>Wallet</button>{' '}
        <button onClick={()=>{setView('address')}}>Address</button>
      </div>
      <div style={{ border: '1px solid #ddd', padding: 12, borderRadius: 6 }}>
        {view === 'home' && <Home onOpenTx={(id)=>{setParam(id); setView('tx')}} />}
        {view === 'wallet' && <Wallet onBroadcast={()=>setView('home')} />}
        {view === 'address' && <AddressView />}
        {view === 'tx' && param && <TxView txid={param} />}
      </div>
    </div>
  )
}
