import { simpleChain } from '../blockchain';

async function main(){
  await simpleChain.createGenesis();
  console.log('Genesis created');
}
main().catch(e=>{console.error(e); process.exit(1)});
