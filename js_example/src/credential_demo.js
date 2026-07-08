import fs from 'node:fs/promises';
import path from 'node:path';
import dotenv from 'dotenv';
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa';
import { randomBytes } from '@noble/post-quantum/utils';

import { deriveDidId, concatBytes } from './did_utils.js';
import { resolveDid, decodeMultikey } from './did_resolver.js';
import { loadDidKeys, storeDidKeys, loadKey, storeKey } from './did_store.js';
import {
  addKey,
  createApi,
  createDid,
  didSupportsKeyMaterial,
  materialForRuntime,
} from './substrate_client.js';
import { logReceipt } from './tx_logger.js';

const LOG_OK = '✅';
const LOG_WARN = '⚠️';
const LOG_STEP = '➡️';
const DID_CREATE_PREFIX = 'QSB_DID_CREATE';
const DID_ADD_KEY_PREFIX = 'QSB_DID_ADD_KEY';
const MULTICODEC_ML_DSA_44 = 0x1210;
const ASSERTION_KEY_SUFFIX_TEXT = '#assertion-mldsa44';

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

function buildDidPayload(prefix, call) {
  const encodedArgs = call.method.args
    .slice(0, Math.max(0, call.method.args.length - 1))
    .map((arg) => arg.toU8a());
  return concatBytes(toBytes(prefix), ...encodedArgs);
}

function signDidCall(privateKey, prefix, call) {
  return ml_dsa44.sign(privateKey, buildDidPayload(prefix, call));
}

async function loadOrCreateAccount(jsonPath, password) {
  try {
    await fs.access(jsonPath);
  } catch {
    console.log(`${LOG_WARN} Account file not found. Creating new account at: ${jsonPath}`);
    await cryptoWaitReady();
    const keyring = new Keyring({ type: 'sr25519' });
    const { mnemonicGenerate } = await import('@polkadot/util-crypto');
    const pair = keyring.addFromUri(mnemonicGenerate());
    await fs.mkdir(path.dirname(jsonPath), { recursive: true });
    await fs.writeFile(jsonPath, JSON.stringify(pair.toJson(password), null, 2), 'utf-8');
    return pair;
  }
  const raw = await fs.readFile(jsonPath, 'utf-8');
  const accountJson = JSON.parse(raw);
  await cryptoWaitReady();
  const keyring = new Keyring({ type: accountJson.type || 'sr25519' });
  const pair = keyring.addFromJson(accountJson);
  pair.decodePkcs8(password);
  return pair;
}

async function loadOrCreateDid(api, account) {
  const stored = await loadDidKeys();
  if (stored) {
    const resolution = await resolveDid(api, stored.did);
    if (resolution.didDocument && !resolution.didDocumentMetadata.deactivated) {
      console.log(`${LOG_OK} Reusing existing DID: ${stored.did}`);
      return stored;
    }
    console.log(`${LOG_WARN} Stored DID is deactivated or unresolvable; creating a new one`);
  }

  const keys = ml_dsa44.keygen(randomBytes(32));
  const publicKey = keys.publicKey ?? keys[0];
  const privateKey = keys.secretKey ?? keys[1];
  const genesisHash = (await api.rpc.chain.getBlockHash(0)).toHex();
  const did = `did:qsb:${deriveDidId(genesisHash, publicKey)}`;

  const createDidCall = api.tx.did.createDid(toBytesArg(toBytes(toMultikey(publicKey))), []);
  const signature = ml_dsa44.sign(privateKey, buildDidPayload(DID_CREATE_PREFIX, createDidCall));
  const result = await createDid(api, account, toBytes(toMultikey(publicKey)), signature);
  logReceipt(result);
  if (result.dispatchError) {
    throw new Error('DID create failed; not saving DID keys');
  }
  await storeDidKeys(did, publicKey, privateKey);
  console.log(`${LOG_OK} Created DID: ${did}`);
  return { did, publicKey, privateKey };
}

async function getOrCreateAssertionKey(api, account, did, rootPrivateKey) {
  const verificationMethodId = `${did}${ASSERTION_KEY_SUFFIX_TEXT}`;
  const stored = await loadKey(ASSERTION_KEY_SUFFIX_TEXT);
  let didResolution = await resolveDid(api, did);
  let didDocument = didResolution.didDocument || {};

  if (stored) {
    const existingVm = (didDocument.verificationMethod || []).find(
      (vm) => vm.id === verificationMethodId
    );
    if (existingVm) {
      const { publicKey: chainPublicKey } = decodeMultikey(existingVm.publicKeyMultibase);
      if (Buffer.from(chainPublicKey).equals(Buffer.from(stored.publicKey))) {
        console.log(`${LOG_OK} Reusing persisted assertion key ${verificationMethodId}`);
        return { publicKey: stored.publicKey, privateKey: stored.privateKey, didDocument };
      }
    }
    console.log(`${LOG_WARN} Persisted assertion key not found on-chain; adding a new one`);
  }

  const assertionKeys = ml_dsa44.keygen(randomBytes(32));
  const publicKey = assertionKeys.publicKey ?? assertionKeys[0];
  const privateKey = assertionKeys.secretKey ?? assertionKeys[1];
  const keyMaterial = toMultikeyMaterial(toBytes(toMultikey(publicKey)));
  const didIdArg = toBytesArg(toBytes(did));
  const keySuffix = toBytes(ASSERTION_KEY_SUFFIX_TEXT);
  const addKeyCall = api.tx.did.addKey(
    didIdArg,
    toBytesArg(keySuffix),
    materialForRuntime(api, keyMaterial),
    ['AssertionMethod'],
    null,
    []
  );
  const addKeySignature = signDidCall(rootPrivateKey, DID_ADD_KEY_PREFIX, addKeyCall);
  const addKeyResult = await addKey(
    api,
    account,
    didIdArg,
    keySuffix,
    keyMaterial,
    ['AssertionMethod'],
    null,
    addKeySignature
  );
  logReceipt(addKeyResult);
  if (addKeyResult.dispatchError) {
    throw new Error(`addKey failed: ${addKeyResult.dispatchError.toString()}`);
  }
  console.log(`${LOG_OK} Added key ${verificationMethodId} roles=['AssertionMethod']`);
  await storeKey(did, ASSERTION_KEY_SUFFIX_TEXT, publicKey, privateKey);
  didResolution = await resolveDid(api, did);
  didDocument = didResolution.didDocument;
  return { publicKey, privateKey, didDocument };
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, key) => {
        acc[key] = canonicalize(value[key]);
        return acc;
      }, {});
  }
  return value;
}

function canonicalJsonBytes(payload) {
  return toBytes(JSON.stringify(canonicalize(payload)));
}

function signCredential(privateKey, verificationMethod, credential) {
  const message = canonicalJsonBytes(credential);
  const signature = ml_dsa44.sign(privateKey, message);
  return {
    ...credential,
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'mldsa44-demo',
      created: new Date().toISOString(),
      verificationMethod,
      proofPurpose: 'assertionMethod',
      proofValue: Buffer.from(signature).toString('base64url'),
    },
  };
}

function verifyCredential(publicKey, signedCredential) {
  const { proof, ...credential } = signedCredential;
  const message = canonicalJsonBytes(credential);
  const signature = Buffer.from(proof.proofValue, 'base64url');
  return ml_dsa44.verify(publicKey, message, signature);
}

function findVerificationMethod(didDocument, verificationMethodId) {
  const vm = (didDocument.verificationMethod || []).find((v) => v.id === verificationMethodId);
  if (!vm) {
    throw new Error(`verificationMethod ${verificationMethodId} not found in DID document`);
  }
  return vm;
}

async function main() {
  dotenv.config();

  console.log(`${LOG_STEP} Step: load config`);
  const accountJsonPath = process.env.ACCOUNT_JSON;
  if (!accountJsonPath) throw new Error('Set ACCOUNT_JSON in .env');
  const accountPassword = process.env.ACCOUNT_PASSWORD;
  if (!accountPassword) throw new Error('Set ACCOUNT_PASSWORD in .env');

  console.log(`${LOG_STEP} Step: connect substrate`);
  const api = await createApi('wss://qsb.qbck.io:9945');

  console.log(`${LOG_STEP} Step: load account`);
  const account = await loadOrCreateAccount(accountJsonPath, accountPassword);
  console.log(`${LOG_OK} Loaded account: ${account.address}`);

  console.log(`${LOG_STEP} Step: load or create DID`);
  const { did, privateKey: rootPrivateKey } = await loadOrCreateDid(api, account);

  console.log(`${LOG_STEP} Step: get or create assertion key (ML-DSA-44, persisted in did_store)`);
  const { privateKey: assertionPrivateKey, didDocument } = await getOrCreateAssertionKey(
    api,
    account,
    did,
    rootPrivateKey
  );
  if (!didDocument) {
    throw new Error('Could not resolve DID document to verify credential');
  }

  console.log(`${LOG_STEP} Step: display resolved DID document`);
  console.log(JSON.stringify(didDocument, null, 2));

  const verificationMethodId = `${did}${ASSERTION_KEY_SUFFIX_TEXT}`;

  console.log(`${LOG_STEP} Step: sign a demo credential with the assertion key`);
  const credential = {
    issuer: did,
    subject: did,
    claim: { role: 'demo-tester', level: 'gold' },
    issuanceDate: new Date().toISOString(),
  };
  const signedCredential = signCredential(assertionPrivateKey, verificationMethodId, credential);
  console.log(JSON.stringify(signedCredential, null, 2));

  console.log(`${LOG_STEP} Step: extract verification method ${verificationMethodId} from DID document`);
  const verificationMethod = findVerificationMethod(didDocument, verificationMethodId);
  console.log(JSON.stringify(verificationMethod, null, 2));

  console.log(`${LOG_STEP} Step: verify credential against the resolved DID document`);
  const { publicKey: resolvedPublicKey } = decodeMultikey(verificationMethod.publicKeyMultibase);
  const isValid = verifyCredential(resolvedPublicKey, signedCredential);
  console.log(`${isValid ? LOG_OK : LOG_WARN} Signature valid: ${isValid}`);

  console.log(`${LOG_STEP} Step: verify a tampered credential (expected to fail)`);
  const tamperedCredential = JSON.parse(JSON.stringify(signedCredential));
  tamperedCredential.claim.level = 'platinum';
  const isTamperedValid = verifyCredential(resolvedPublicKey, tamperedCredential);
  console.log(`${!isTamperedValid ? LOG_OK : LOG_WARN} Tampered signature valid: ${isTamperedValid}`);

  await api.disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
