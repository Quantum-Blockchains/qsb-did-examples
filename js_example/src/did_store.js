import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const LOG_OK = '✅';

function getStorePath() {
  const envPath = process.env.DID_STORE_PATH;
  if (envPath) return envPath;
  const cwd = path.dirname(fileURLToPath(import.meta.url));
  return path.join(cwd, '..', '..', 'did_store.json');
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 390000, 32, 'sha256');
}

export function encryptPrivateKey(privateKey, password, salt) {
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

export function decryptPrivateKey(encrypted, password, salt, ivHex, tagHex) {
  const key = deriveKey(password, salt);
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'base64')),
    decipher.final(),
  ]);
}

export async function storeDidKeys(did, publicKey, privateKey) {
  const storePath = getStorePath();
  const password = process.env.DID_STORE_PASSWORD;
  if (!password) {
    throw new Error('DID_STORE_PASSWORD is required');
  }
  const salt = crypto.randomBytes(16);
  const { encrypted, iv, tag } = encryptPrivateKey(privateKey, password, salt);
  const record = {
    did,
    public_key_hex: Buffer.from(publicKey).toString('hex'),
    private_key_enc: encrypted,
    salt_hex: salt.toString('hex'),
    iv_hex: iv,
    tag_hex: tag,
    kdf: 'pbkdf2_sha256_390000',
  };
  await fs.writeFile(storePath, JSON.stringify(record, null, 2));
  console.log(`${LOG_OK} DID keypair saved to ${storePath}`);
}

export async function loadDidKeys() {
  const storePath = getStorePath();
  if (!existsSync(storePath)) return null;
  const password = process.env.DID_STORE_PASSWORD;
  if (!password) {
    throw new Error('DID_STORE_PASSWORD is required');
  }
  const raw = await fs.readFile(storePath, 'utf-8');
  const record = JSON.parse(raw);
  const salt = Buffer.from(record.salt_hex, 'hex');
  const privateKey = decryptPrivateKey(
    record.private_key_enc,
    password,
    salt,
    record.iv_hex,
    record.tag_hex
  );
  const publicKey = Buffer.from(record.public_key_hex, 'hex');
  console.log(`${LOG_OK} DID keypair loaded from ${storePath}`);
  return {
    did: record.did,
    publicKey,
    privateKey,
  };
}
