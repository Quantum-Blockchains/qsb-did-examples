import bs58 from 'bs58';
import { blake2b } from '@noble/hashes/blake2b';

export function deriveDidId(genesisHashHex, publicKey) {
  const genesisBytes = hexToBytes(stripHex(genesisHashHex));
  const material = concatBytes(
    new TextEncoder().encode('QSB_DID'),
    genesisBytes,
    publicKey
  );
  const didIdBytes = blake2b(material, { dkLen: 32 });
  return bs58.encode(didIdBytes);
}

export function deriveSchemaId(genesisHashHex, schemaJson) {
  const genesisBytes = hexToBytes(stripHex(genesisHashHex));
  const material = concatBytes(
    new TextEncoder().encode('QSB_SCHEMA'),
    genesisBytes,
    schemaJson
  );
  const schemaIdBytes = blake2b(material, { dkLen: 32 });
  const schemaIdB58 = bs58.encode(schemaIdBytes);
  return `did:qsb:schema:${schemaIdB58}`;
}

export function stripHex(hex) {
  return hex.startsWith('0x') ? hex.slice(2) : hex;
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function concatBytes(...parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
