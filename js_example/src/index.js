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
  addKey,
  addService,
  createApi,
  createDid,
  deactivateDid,
  deprecateSchema,
  getFreeBalance,
  registerSchema,
  removeMetadata,
  removeService,
  revokeKey,
  rotateKey,
  setMetadata,
  updateRoles,
} from './substrate_client.js';
import { logReceipt } from './tx_logger.js';

const LOG_OK = '✅';
const LOG_WARN = '⚠️';
const LOG_DID = '🪪';
const LOG_SCHEMA = '📜';
const LOG_STEP = '➡️';
const DID_CREATE_PREFIX = 'QSB_DID_CREATE';
const DID_ADD_KEY_PREFIX = 'QSB_DID_ADD_KEY';
const DID_REVOKE_KEY_PREFIX = 'QSB_DID_REVOKE_KEY';
const DID_DEACTIVATE_PREFIX = 'QSB_DID_DEACTIVATE';
const DID_ADD_SERVICE_PREFIX = 'QSB_DID_ADD_SERVICE';
const DID_REMOVE_SERVICE_PREFIX = 'QSB_DID_REMOVE_SERVICE';
const DID_SET_METADATA_PREFIX = 'QSB_DID_SET_METADATA';
const DID_REMOVE_METADATA_PREFIX = 'QSB_DID_REMOVE_METADATA';
const DID_ROTATE_KEY_PREFIX = 'QSB_DID_ROTATE_KEY';
const DID_UPDATE_ROLES_PREFIX = 'QSB_DID_UPDATE_ROLES';
const DEFAULT_SERVICE_ID = 'service-1';
const DEFAULT_SERVICE_TYPE = 'ExampleService';
const DEFAULT_SERVICE_ENDPOINT = 'https://example.com';
const DEFAULT_SCHEMA_URI = 'https://example.com/schema';
const DEFAULT_SCHEMA_BASE = { name: 'example', version: '1.0' };

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
  const obj = { ...DEFAULT_SCHEMA_BASE, _nonce: cryptoRandomId() };
  return JSON.stringify(obj);
}

function cryptoRandomId() {
  return crypto.randomUUID().replace(/-/g, '');
}

function toBytes(value) {
  return new TextEncoder().encode(value);
}

function toBytesArg(value) {
  if (Array.isArray(value)) return value;
  return Array.from(value);
}

function buildDidPayload(prefix, call) {
  const encodedArgs = call.method.args
    .slice(0, Math.max(0, call.method.args.length - 1))
    .map((arg) => arg.toU8a());

  return concatBytes(toBytes(prefix), ...encodedArgs);
}

function signDidCall(privateKey, prefix, call) {
  const payload = buildDidPayload(prefix, call);
  return ml_dsa44.sign(privateKey, payload);
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

    const createDidCall = api.tx.did.createDid(toBytesArg(publicKey), []);
    const payload = buildDidPayload(DID_CREATE_PREFIX, createDidCall);
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

  const didId = toBytes(did);
  const didIdArg = toBytesArg(didId);

  console.log(`${LOG_STEP} Step: add DID key (assertion method)`);
  const secondary = ml_dsa44.keygen(randomBytes(32));
  const secondaryPublicKey = secondary.publicKey ?? secondary[0];
  const addKeyRoles = ['AssertionMethod'];
  const addKeyCall = api.tx.did.addKey(
    didIdArg,
    toBytesArg(secondaryPublicKey),
    addKeyRoles,
    []
  );
  const addKeySignature = signDidCall(privateKey, DID_ADD_KEY_PREFIX, addKeyCall);
  let result = await addKey(
    api,
    account,
    didIdArg,
    secondaryPublicKey,
    addKeyRoles,
    addKeySignature
  );
  logReceipt(result);

  console.log(`${LOG_STEP} Step: update DID key roles`);
  const updatedRoles = ['CapabilityInvocation'];
  const updateRolesCall = api.tx.did.updateRoles(
    didIdArg,
    toBytesArg(secondaryPublicKey),
    updatedRoles,
    []
  );
  const updateRolesSignature = signDidCall(privateKey, DID_UPDATE_ROLES_PREFIX, updateRolesCall);
  result = await updateRoles(
    api,
    account,
    didIdArg,
    secondaryPublicKey,
    updatedRoles,
    updateRolesSignature
  );
  logReceipt(result);

  console.log(`${LOG_STEP} Step: rotate DID key`);
  const rotated = ml_dsa44.keygen(randomBytes(32));
  const rotatedPublicKey = rotated.publicKey ?? rotated[0];
  const rotateRoles = ['CapabilityDelegation'];
  const rotateKeyCall = api.tx.did.rotateKey(
    didIdArg,
    toBytesArg(secondaryPublicKey),
    toBytesArg(rotatedPublicKey),
    rotateRoles,
    []
  );
  const rotateKeySignature = signDidCall(privateKey, DID_ROTATE_KEY_PREFIX, rotateKeyCall);
  result = await rotateKey(
    api,
    account,
    didIdArg,
    secondaryPublicKey,
    rotatedPublicKey,
    rotateRoles,
    rotateKeySignature
  );
  logReceipt(result);

  console.log(`${LOG_STEP} Step: set DID metadata`);
  const metadataKey = toBytes('profile');
  const metadataValue = toBytes('https://example.com/profile');
  const setMetadataCall = api.tx.did.setMetadata(
    didIdArg,
    { key: toBytesArg(metadataKey), value: toBytesArg(metadataValue) },
    []
  );
  const setMetadataSignature = signDidCall(privateKey, DID_SET_METADATA_PREFIX, setMetadataCall);
  result = await setMetadata(
    api,
    account,
    didIdArg,
    metadataKey,
    metadataValue,
    setMetadataSignature
  );
  logReceipt(result);

  console.log(`${LOG_STEP} Step: add DID service`);
  const serviceId = toBytes(DEFAULT_SERVICE_ID);
  const serviceType = toBytes(DEFAULT_SERVICE_TYPE);
  const serviceEndpoint = toBytes(DEFAULT_SERVICE_ENDPOINT);
  const serviceIdArg = toBytesArg(serviceId);
  const serviceTypeArg = toBytesArg(serviceType);
  const serviceEndpointArg = toBytesArg(serviceEndpoint);
  const addServiceCall = api.tx.did.addService(
    didIdArg,
    { id: serviceIdArg, service_type: serviceTypeArg, endpoint: serviceEndpointArg },
    []
  );
  const addServiceSignature = ml_dsa44.sign(
    privateKey,
    buildDidPayload(DID_ADD_SERVICE_PREFIX, addServiceCall)
  );
  result = await addService(
    api,
    account,
    didIdArg,
    serviceId,
    serviceType,
    serviceEndpoint,
    addServiceSignature
  );
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
  const removeServiceCall = api.tx.did.removeService(didIdArg, serviceIdArg, []);
  const removeServiceSignature = ml_dsa44.sign(
    privateKey,
    buildDidPayload(DID_REMOVE_SERVICE_PREFIX, removeServiceCall)
  );
  result = await removeService(api, account, didIdArg, serviceIdArg, removeServiceSignature);
  logReceipt(result);

  console.log(`${LOG_STEP} Step: remove DID metadata`);
  const removeMetadataCall = api.tx.did.removeMetadata(didIdArg, toBytesArg(metadataKey), []);
  const removeMetadataSignature = signDidCall(
    privateKey,
    DID_REMOVE_METADATA_PREFIX,
    removeMetadataCall
  );
  result = await removeMetadata(api, account, didIdArg, metadataKey, removeMetadataSignature);
  logReceipt(result);

  console.log(`${LOG_STEP} Step: revoke rotated DID key`);
  const revokeKeyCall = api.tx.did.revokeKey(didIdArg, toBytesArg(rotatedPublicKey), []);
  const revokeKeySignature = signDidCall(privateKey, DID_REVOKE_KEY_PREFIX, revokeKeyCall);
  result = await revokeKey(api, account, didIdArg, rotatedPublicKey, revokeKeySignature);
  logReceipt(result);

  console.log(`${LOG_STEP} Step: register schema`);
  const schemaJsonRaw = buildSchemaJson();
  const schemaJson = toBytes(schemaJsonRaw);
  const schemaUri = toBytes(DEFAULT_SCHEMA_URI);
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

  console.log(`${LOG_STEP} Step: deactivate DID`);
  const deactivateDidCall = api.tx.did.deactivateDid(didIdArg, []);
  const deactivateDidSignature = signDidCall(
    privateKey,
    DID_DEACTIVATE_PREFIX,
    deactivateDidCall
  );
  result = await deactivateDid(api, account, didIdArg, deactivateDidSignature);
  logReceipt(result);

  console.log(`${LOG_OK} Done.`);
  await api.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
