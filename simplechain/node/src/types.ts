export type Tx = {
  id: string;
  from: string;
  to: string;
  amount: number;
  fee: number;
  nonce: number;
  timestamp: string;
  signature: string;
};

export type BlockHeader = {
  index: number;
  prevHash: string;
  timestamp: string;
  merkleRoot: string;
  nonce: number;
};

export type Block = {
  header: BlockHeader;
  transactions: string[]; // txids
  hash: string;
};
