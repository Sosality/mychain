/**
 * Simple test: generate keypair, sign a simple message, verify via noble.
 */
import * as secp from 'noble-secp256k1';
async function run() {
  const priv = secp.utils.randomPrivateKey();
  const privHex = Buffer.from(priv).toString('hex');
  const pub = secp.getPublicKey(privHex);
  const msg = 'hello';
  const msgHex = Buffer.from(msg).toString('hex');
  const sig = await secp.sign(msgHex, privHex);
  const ok = await secp.verify(sig, msgHex, pub);
  console.log('sig ok?', ok);
}
run();
