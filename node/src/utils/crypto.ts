import { createHash } from 'crypto';
import * as secp from 'noble-secp256k1';

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export async function verifySignature(messageHex: string, signatureHex: string, pubkeyHex: string): Promise<boolean> {
  try {
    const msg = Buffer.from(messageHex, 'hex');
    // noble expects messageHash or message string
    return await secp.verify(signatureHex, messageHex, pubkeyHex);
  } catch (e) {
    return false;
  }
}

export async function recoverPublicKey(messageHex: string, signatureHex: string): Promise<string> {
  return await secp.recoverPublicKey(messageHex, signatureHex);
}
