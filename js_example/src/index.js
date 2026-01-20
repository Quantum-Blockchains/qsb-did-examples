import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa';
import { randomBytes } from '@noble/post-quantum/utils';

import { deriveDidId, deriveSchemaId, concatBytes } from './did_utils.js';
import { resolveDid } from './did_resolver.js';
import { loadDidKeys, storeDidKeys } from './did_store.js';
import {
  addService,
  createApi,
  createDid,
  deprecateSchema,
  getFreeBalance,
  registerSchema,
  removeService,
} from './substrate_client.js';
import { logReceipt } from './tx_logger.js';

const LOG_OK = '✅';
const LOG_WARN = '⚠️';
const LOG_DID = '🪪';
const LOG_SCHEMA = '📜';
const LOG_STEP = '➡️';

function getArgValue(flag) {
  const args = process.argv.slice(2);
  const index = args.indexOf(flag);
  if (index === -1) return null;
  return args[index + 1] || null;
}

function readEnvPath(value) {
  if (!value) return null;
  return path.isAbsolute(value) ? value : value;
}

async function loadAccount(jsonPath) {
  const raw = await fs.readFile(jsonPath, 'utf-8');
  const accountJson = JSON.parse(raw);
  const password = process.env.ACCOUNT_PASSWORD;
  if (!password) {
    throw new Error('ACCOUNT_PASSWORD is required');
  }
  await cryptoWaitReady();
  const keyring = new Keyring({ type: accountJson.type || 'sr25519' });
  const pair = keyring.addFromJson(accountJson);
  pair.decodePkcs8(password);
  return pair;
}

function buildSchemaJson() {
  const raw = process.env.SCHEMA_JSON || '{"name":"example","version":"1.0"}';
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      obj._nonce = cryptoRandomId();
      return JSON.stringify(obj);
    }
    return raw;
  } catch {
    return `${raw}|nonce=${cryptoRandomId()}`;
  }
}

function cryptoRandomId() {
  return crypto.randomUUID().replace(/-/g, '');
}

function toBytes(value) {
  return new TextEncoder().encode(value);
}

async function main() {
  dotenv.config();

  console.log(`${LOG_STEP} Step: load config`);
  const accountJsonArg = getArgValue('--account-json');
  const accountJsonEnv = readEnvPath(process.env.ACCOUNT_JSON);
  const accountJsonPath = accountJsonArg || accountJsonEnv;
  if (!accountJsonPath) {
    throw new Error('Provide --account-json or set ACCOUNT_JSON in .env');
  }

  console.log(`${LOG_STEP} Step: connect substrate`);
  const api = await createApi('wss://qsb.qbck.io:9945');

  console.log(`${LOG_STEP} Step: load account`);
  const account = await loadAccount(accountJsonPath);
  console.log(`${LOG_OK} Loaded account: ${account.address}`);

  console.log(`${LOG_STEP} Step: fetch balance`);
  const freeBalance = await getFreeBalance(api, account.address);
  console.log(`Free balance: ${freeBalance}`);

  console.log(`${LOG_STEP} Step: load or generate DID keys`);
  let did;
  let publicKey;
  let privateKey;
  const stored = await loadDidKeys();
  if (stored) {
    did = stored.did;
    publicKey = stored.publicKey;
    privateKey = stored.privateKey;
    console.log(`${LOG_DID} DID: ${did}`);
  } else {
    const keys = ml_dsa44.keygen(randomBytes(32));
    publicKey = keys.publicKey ?? keys[0];
    privateKey = keys.secretKey ?? keys[1];
    console.log(`${LOG_OK} ML-DSA-44 public key: ${Buffer.from(publicKey).toString('hex')}`);

    const genesisHash = (await api.rpc.chain.getBlockHash(0)).toHex();
    const didId = deriveDidId(genesisHash, publicKey);
    did = `did:qsb:${didId}`;
    console.log(`${LOG_DID} DID: ${did}`);

    const payload = concatBytes(toBytes('QSB_DID_CREATE'), publicKey);
    const signature = ml_dsa44.sign(privateKey, payload);
    const result = await createDid(api, account, publicKey, signature);
    logReceipt(result);
    if (result.dispatchError) {
      throw new Error('DID create failed; not saving DID keys');
    }
    await storeDidKeys(did, publicKey, privateKey);
  }

  const genesisHash = (await api.rpc.chain.getBlockHash(0)).toHex();

  console.log(`${LOG_STEP} Step: resolve DID document`);
  const didDoc = await resolveDid(api, did);
  if (didDoc) {
    console.log(`${LOG_DID} DID document:`);
    console.log(JSON.stringify(didDoc, null, 2));
  } else {
    console.log(`${LOG_WARN} DID not found or invalid response`);
  }

  console.log(`${LOG_STEP} Step: add DID service`);
  const serviceId = toBytes(process.env.SERVICE_ID || 'service-1');
  const serviceType = toBytes(process.env.SERVICE_TYPE || 'ExampleService');
  const serviceEndpoint = toBytes(process.env.SERVICE_ENDPOINT || 'https://example.com');
  let result = await addService(api, account, toBytes(did), serviceId, serviceType, serviceEndpoint);
  logReceipt(result);

  console.log(`${LOG_STEP} Step: resolve DID document (after add service)`);
  const didDoc2 = await resolveDid(api, did);
  if (didDoc2) {
    console.log(`${LOG_DID} DID document:`);
    console.log(JSON.stringify(didDoc2, null, 2));
  } else {
    console.log(`${LOG_WARN} DID not found or invalid response`);
  }

  console.log(`${LOG_STEP} Step: remove DID service`);
  result = await removeService(api, account, toBytes(did), serviceId);
  logReceipt(result);

  console.log(`${LOG_STEP} Step: register schema`);
  const schemaJsonRaw = buildSchemaJson();
  const schemaJson = toBytes(schemaJsonRaw);
  const schemaUri = toBytes(process.env.SCHEMA_URI || 'https://example.com/schema');
  const schemaId = deriveSchemaId(genesisHash, schemaJson);
  console.log(`${LOG_SCHEMA} Schema ID: ${schemaId}`);
  const schemaSignature = ml_dsa44.sign(privateKey, concatBytes(toBytes('QSB_SCHEMA'), schemaJson));
  result = await registerSchema(
    api,
    account,
    schemaJson,
    schemaUri,
    toBytes(did),
    schemaSignature
  );
  logReceipt(result);

  console.log(`${LOG_STEP} Step: deprecate schema`);
  result = await deprecateSchema(
    api,
    account,
    toBytes(schemaId),
    toBytes(did),
    schemaSignature
  );
  logReceipt(result);

  console.log(`${LOG_OK} Done.`);
  await api.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
