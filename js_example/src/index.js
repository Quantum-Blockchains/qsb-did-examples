import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import dotenv from 'dotenv';
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady, mnemonicGenerate } from '@polkadot/util-crypto';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa';
import { randomBytes } from '@noble/post-quantum/utils';

import { deriveDidId, concatBytes } from './did_utils.js';
import { resolveDid } from './did_resolver.js';
import { loadDidKeys, storeDidKeys, storeKey } from './did_store.js';
import {
  addKey,
  addService,
  createApi,
  createDid,
  didSupportsKeyMaterial,
  getFreeBalance,
  materialForRuntime,
  setMetadata,
} from './substrate_client.js';
import { logReceipt } from './tx_logger.js';

const LOG_OK = '✅';
const LOG_WARN = '⚠️';
const LOG_DID = '🪪';
const LOG_STEP = '➡️';
const DID_CREATE_PREFIX = 'QSB_DID_CREATE';
const DID_ADD_KEY_PREFIX = 'QSB_DID_ADD_KEY';
const DID_ADD_SERVICE_PREFIX = 'QSB_DID_ADD_SERVICE';
const DID_SET_METADATA_PREFIX = 'QSB_DID_SET_METADATA';
const MULTICODEC_ML_DSA_44 = 0x1210;
const MULTICODEC_ED25519_PUB = 0xed;
const MULTICODEC_P256_PUB = 0x1201;

async function createAndStoreAccount(jsonPath, password) {
  await cryptoWaitReady();
  const keyring = new Keyring({ type: 'sr25519' });
  const pair = keyring.addFromUri(mnemonicGenerate());
  const accountJson = pair.toJson(password);
  await fs.mkdir(path.dirname(jsonPath), { recursive: true });
  await fs.writeFile(jsonPath, JSON.stringify(accountJson, null, 2), 'utf-8');
  return pair;
}

async function loadOrCreateAccount(jsonPath, password) {
  try {
    await fs.access(jsonPath);
  } catch {
    console.log(`${LOG_WARN} Account file not found. Creating new account at: ${jsonPath}`);
    return createAndStoreAccount(jsonPath, password);
  }

  const raw = await fs.readFile(jsonPath, 'utf-8');
  const accountJson = JSON.parse(raw);
  await cryptoWaitReady();
  const keyring = new Keyring({ type: accountJson.type || 'sr25519' });
  const pair = keyring.addFromJson(accountJson);
  pair.decodePkcs8(password);
  return pair;
}

function toBytes(value) {
  return new TextEncoder().encode(value);
}

function toBytesArg(value) {
  if (Array.isArray(value)) return value;
  return Array.from(value);
}

function encodeUvarint(value) {
  const out = [];
  let v = value >>> 0;
  while (true) {
    let b = v & 0x7f;
    v >>>= 7;
    if (v !== 0) b |= 0x80;
    out.push(b);
    if (v === 0) break;
  }
  return Uint8Array.from(out);
}

function toMultikey(publicKey, codec = MULTICODEC_ML_DSA_44) {
  const prefixed = concatBytes(encodeUvarint(codec), publicKey);
  return `u${Buffer.from(prefixed).toString('base64url')}`;
}

function toMultikeyMaterial(multikeyBytes) {
  return { Multikey: toBytesArg(multikeyBytes) };
}

function toJwkMaterial(jwkBytes) {
  return { Jwk: toBytesArg(jwkBytes) };
}

function generateMlDsa44Key() {
  const keys = ml_dsa44.keygen(randomBytes(32));
  const publicKey = keys.publicKey ?? keys[0];
  const privateKey = keys.secretKey ?? keys[1];
  return { material: toMultikeyMaterial(toBytes(toMultikey(publicKey))), publicKey, privateKey };
}

function generateJwkKey(kind) {
  const options =
    kind === 'p256'
      ? ['ec', { namedCurve: 'P-256' }]
      : ['ed25519', undefined];
  const { publicKey, privateKey } = options[1]
    ? crypto.generateKeyPairSync(options[0], options[1])
    : crypto.generateKeyPairSync(options[0]);
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  return {
    material: toJwkMaterial(toBytes(JSON.stringify(publicJwk))),
    publicKey: Buffer.from(publicJwk.x, 'base64url'),
    privateKey: Buffer.from(privateJwk.d, 'base64url'),
  };
}

function generateEd25519MultikeyKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicKeyRaw = Buffer.from(publicJwk.x, 'base64url');
  const privateKeyRaw = Buffer.from(privateJwk.d, 'base64url');
  return {
    material: toMultikeyMaterial(toBytes(toMultikey(publicKeyRaw, MULTICODEC_ED25519_PUB))),
    publicKey: publicKeyRaw,
    privateKey: privateKeyRaw,
  };
}

function compressP256PublicKey(x, y) {
  const isEven = BigInt(`0x${y.toString('hex')}`) % 2n === 0n;
  return Buffer.concat([Buffer.from([isEven ? 0x02 : 0x03]), x]);
}

function generateP256MultikeyKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const x = Buffer.from(publicJwk.x, 'base64url');
  const y = Buffer.from(publicJwk.y, 'base64url');
  const compressed = compressP256PublicKey(x, y);
  const privateKeyRaw = Buffer.from(privateJwk.d, 'base64url');
  return {
    material: toMultikeyMaterial(toBytes(toMultikey(compressed, MULTICODEC_P256_PUB))),
    publicKey: compressed,
    privateKey: privateKeyRaw,
  };
}

function buildDemoKeyPlan(supportsKeyMaterial) {
  const auth = generateMlDsa44Key();
  const invocation = generateMlDsa44Key();

  if (supportsKeyMaterial) {
    const assertion = generateJwkKey('ed25519');
    const agreement = generateJwkKey('p256');
    return [
      { suffixText: '#auth-mldsa44', roles: ['Authentication'], ...auth },
      { suffixText: '#invocation-mldsa44', roles: ['CapabilityInvocation'], ...invocation },
      { suffixText: '#assertion-ed25519-jwk', roles: ['AssertionMethod'], ...assertion },
      {
        suffixText: '#agreement-p256-jwk',
        roles: ['KeyAgreement', 'CapabilityDelegation'],
        ...agreement,
      },
    ];
  }

  const assertion = generateEd25519MultikeyKey();
  const agreement = generateP256MultikeyKey();
  return [
    { suffixText: '#auth-mldsa44', roles: ['Authentication'], ...auth },
    { suffixText: '#invocation-mldsa44', roles: ['CapabilityInvocation'], ...invocation },
    { suffixText: '#assertion-ed25519', roles: ['AssertionMethod'], ...assertion },
    {
      suffixText: '#agreement-p256',
      roles: ['KeyAgreement', 'CapabilityDelegation'],
      ...agreement,
    },
  ];
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

function ensureExtrinsicSuccess(result, label) {
  if (result.dispatchError) {
    throw new Error(`${label} failed: ${result.dispatchError.toString()}`);
  }
}

async function main() {
  dotenv.config();

  console.log(`${LOG_STEP} Step: load config`);
  const accountJsonPath = process.env.ACCOUNT_JSON;
  if (!accountJsonPath) {
    throw new Error('Set ACCOUNT_JSON in .env');
  }
  const accountPassword = process.env.ACCOUNT_PASSWORD;
  if (!accountPassword) {
    throw new Error('Set ACCOUNT_PASSWORD in .env');
  }

  console.log(`${LOG_STEP} Step: connect substrate`);
  const api = await createApi('wss://qsb.qbck.io:9945');
  const supportsKeyMaterial = didSupportsKeyMaterial(api);

  console.log(`${LOG_STEP} Step: load account`);
  const account = await loadOrCreateAccount(accountJsonPath, accountPassword);
  console.log(`${LOG_OK} Loaded account: ${account.address}`);

  console.log(`${LOG_STEP} Step: fetch balance`);
  const freeBalance = await getFreeBalance(api, account.address);
  console.log(`Free balance: ${freeBalance}`);

  console.log(`${LOG_STEP} Step: load or generate DID keys`);
  let did;
  let publicKey;
  let privateKey;
  const stored = await loadDidKeys();
  const loadedFromStore = stored != null;
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

    const createDidCall = api.tx.did.createDid(toBytesArg(toBytes(toMultikey(publicKey))), []);
    const payload = buildDidPayload(DID_CREATE_PREFIX, createDidCall);
    const signature = ml_dsa44.sign(privateKey, payload);
    const result = await createDid(api, account, toBytes(toMultikey(publicKey)), signature);
    logReceipt(result);
    if (result.dispatchError) {
      throw new Error('DID create failed; not saving DID keys');
    }
    await storeDidKeys(did, publicKey, privateKey);
  }

  console.log(`${LOG_STEP} Step: resolve DID document`);
  const didResolution = await resolveDid(api, did);
  const resolutionError = didResolution.didResolutionMetadata.error;
  if (resolutionError === 'runtimeApiDecodeError' && loadedFromStore) {
    throw new Error(
      'Stored DID cannot be decoded by the current node runtime API. This usually means the ' +
        'local did_store.json points to a DID created with an older pallet storage layout. ' +
        'Remove the local DID store or set DID_STORE_PATH to a new file and run again. ' +
        `Current DID_STORE_PATH: ${process.env.DID_STORE_PATH || 'did_store.json'}`
    );
  }
  if (resolutionError === 'runtimeApiDecodeError') {
    throw new Error(
      'Newly created DID cannot be decoded by did_getByString. The connected RPC node likely ' +
        'does not match the runtime/API expected by this example.'
    );
  }
  console.log(`${LOG_DID} DID resolution:`);
  console.log(JSON.stringify(didResolution, null, 2));

  const didId = toBytes(did);
  const didIdArg = toBytesArg(didId);

  console.log(`${LOG_STEP} Step: add DID keys for different roles`);
  if (!supportsKeyMaterial) {
    console.log(
      `${LOG_WARN} Connected runtime does not expose KeyMaterialInput; ` +
        'JWK demo keys are skipped and Multikey is used for all added keys.'
    );
  }
  const keysToAdd = buildDemoKeyPlan(supportsKeyMaterial);
  for (const keyEntry of keysToAdd) {
    const suffix = toBytes(keyEntry.suffixText);
    const addKeyCall = api.tx.did.addKey(
      didIdArg,
      toBytesArg(suffix),
      materialForRuntime(api, keyEntry.material),
      keyEntry.roles,
      null,
      []
    );
    const addKeySignature = signDidCall(privateKey, DID_ADD_KEY_PREFIX, addKeyCall);
    const result = await addKey(
      api,
      account,
      didIdArg,
      suffix,
      keyEntry.material,
      keyEntry.roles,
      null,
      addKeySignature
    );
    logReceipt(result);
    ensureExtrinsicSuccess(result, 'addKey');
    console.log(`${LOG_DID} Added key ${did}${keyEntry.suffixText} roles=${JSON.stringify(keyEntry.roles)}`);
    await storeKey(did, keyEntry.suffixText, keyEntry.publicKey, keyEntry.privateKey);
  }

  console.log(`${LOG_STEP} Step: add DID metadata`);
  const metadataEntries = [
    ['profile', 'https://profiles.example.org/alice'],
    ['organization', 'QSB Labs'],
    ['environment', 'demo'],
    ['keySuite', 'ML-DSA-44,Ed25519,P-256'],
  ];
  for (const [keyText, valueText] of metadataEntries) {
    const metadataKey = toBytes(keyText);
    const metadataValue = toBytes(valueText);
    const setMetadataCall = api.tx.did.setMetadata(
      didIdArg,
      { key: toBytesArg(metadataKey), value: toBytesArg(metadataValue) },
      []
    );
    const setMetadataSignature = signDidCall(privateKey, DID_SET_METADATA_PREFIX, setMetadataCall);
    const result = await setMetadata(
      api,
      account,
      didIdArg,
      metadataKey,
      metadataValue,
      setMetadataSignature
    );
    logReceipt(result);
    ensureExtrinsicSuccess(result, 'setMetadata');
    console.log(`${LOG_OK} Metadata set: ${keyText}`);
  }

  console.log(`${LOG_STEP} Step: add multiple DID services with DID URL id + full URI endpoint`);
  const servicesToAdd = [
    [`${did}#messaging`, 'MessagingService', 'https://resolver.example.org/api/v1/messages'],
    [
      `${did}#credentials`,
      'CredentialRegistry',
      'https://wallet.example.org/credentials/status/2026',
    ],
    [`${did}#profile`, 'ProfileService', 'https://profiles.example.org/alice'],
  ];
  for (const [serviceIdText, serviceTypeText, serviceEndpointText] of servicesToAdd) {
    const serviceId = toBytes(serviceIdText);
    const serviceType = toBytes(serviceTypeText);
    const serviceEndpoint = toBytes(serviceEndpointText);
    const addServiceCall = api.tx.did.addService(
      didIdArg,
      {
        id: toBytesArg(serviceId),
        service_type: toBytesArg(serviceType),
        endpoint: toBytesArg(serviceEndpoint),
      },
      []
    );
    const addServiceSignature = ml_dsa44.sign(
      privateKey,
      buildDidPayload(DID_ADD_SERVICE_PREFIX, addServiceCall)
    );
    const result = await addService(
      api,
      account,
      didIdArg,
      serviceId,
      serviceType,
      serviceEndpoint,
      addServiceSignature
    );
    logReceipt(result);
    ensureExtrinsicSuccess(result, 'addService');
    console.log(`${LOG_OK} Service added: ${serviceIdText}`);
  }

  console.log(`${LOG_STEP} Step: resolve final DID document`);
  const finalResolution = await resolveDid(api, did);
  console.log(`${LOG_DID} Final DID resolution:`);
  console.log(JSON.stringify(finalResolution, null, 2));
  console.log(`${LOG_OK} Done. DID document above is ready to present.`);

  await api.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
