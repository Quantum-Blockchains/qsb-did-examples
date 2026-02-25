# DID Pallet Integration in JavaScript (Consistent Demo Flow)

This document describes exactly what the current `js_example/src/index.js` does:
https://github.com/Quantum-Blockchains/qsb-did-examples

## 1. What You Need in `.env`

In `js_example/.env`, provide:

```env
ACCOUNT_JSON=./storage/account.json
ACCOUNT_PASSWORD=your_account_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=./storage/did_store.json
```

Field meanings:

1. `ACCOUNT_JSON`: path to the Polkadot.js account export (`account.json`).
2. `ACCOUNT_PASSWORD`: password used to decrypt that account.
3. `DID_STORE_PASSWORD`: password used to encrypt/decrypt local DID private key storage.
4. `DID_STORE_PATH`: path to the local DID store file.

## 2. Run

Requirements:

1. `Node.js` 18 or newer.
2. `npm` (included with Node.js).
3. Network access to `wss://qsb.qbck.io:9945`.
4. A Substrate account exported as `account.json`.

```bash
cd js_example
npm install
npm start
```

## 3. Core DID Signature Rule

For each DID operation, the signature is calculated from:

`PREFIX + SCALE-encoded call arguments (without did_signature)`

Main prefixes used:

1. `QSB_DID_CREATE`
2. `QSB_DID_ADD_KEY`
3. `QSB_DID_UPDATE_ROLES`
4. `QSB_DID_ROTATE_KEY`
5. `QSB_DID_SET_METADATA`
6. `QSB_DID_ADD_SERVICE`
7. `QSB_DID_REMOVE_SERVICE`
8. `QSB_DID_REMOVE_METADATA`
9. `QSB_DID_REVOKE_KEY`
10. `QSB_DID_DEACTIVATE`

## 4. Chain Connection (QSB-Poseidon)

Endpoint:

1. Name: `QSB-Poseidon`
2. URL: `wss://qsb.qbck.io:9945`

Connection example:

```js
import { ApiPromise, WsProvider } from '@polkadot/api';

const provider = new WsProvider('wss://qsb.qbck.io:9945');
const api = await ApiPromise.create({ provider });
// api is now connected and ready
```

## 5. Loading the Substrate Account

Goal: prepare the blockchain account that signs and pays for extrinsics.

What happens:

1. Read `account.json`.
2. Decrypt private key with `ACCOUNT_PASSWORD`.
3. Return `pair`, used by `signAndSend(...)`.

Important distinction:

1. This account signs at Substrate transaction level.
2. This is not the DID signature (`did_signature`) verified by the DID pallet.

```js
import fs from 'node:fs/promises';
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';

async function loadAccount(jsonPath) {
  // 1) Read account.json
  const raw = await fs.readFile(jsonPath, 'utf-8');
  // 2) Parse Polkadot.js JSON export
  const accountJson = JSON.parse(raw);
  // 3) Read password from .env
  const password = process.env.ACCOUNT_PASSWORD;
  if (!password) {
    throw new Error('ACCOUNT_PASSWORD is required');
  }
  // 4) Initialize polkadot-js crypto utils
  await cryptoWaitReady();
  // 5) Build keyring with key type from export (e.g. sr25519)
  const keyring = new Keyring({ type: accountJson.type || 'sr25519' });
  // 6) Load account into keyring
  const pair = keyring.addFromJson(accountJson);
  // 7) Decrypt private key
  pair.decodePkcs8(password);
  // 8) Return ready-to-use signer
  return pair;
}
```

## 6. Load/Generate DID Keys

Goal: reuse existing DID keys from local storage or generate a new DID keypair.

Flow:

1. Try `loadDidKeys()`.
2. If keys exist, reuse stored `did`, `publicKey`, `privateKey`.
3. If keys do not exist, generate a new ML-DSA-44 keypair and create DID on-chain.
4. After successful `createDid`, persist keys using `storeDidKeys(...)`.

```js
let did;
let publicKey;
let privateKey;
const stored = await loadDidKeys();

if (stored) {
  did = stored.did;
  publicKey = stored.publicKey;
  privateKey = stored.privateKey;
} else {
  const keys = ml_dsa44.keygen(randomBytes(32));
  publicKey = keys.publicKey;
  privateKey = keys.secretKey;

  // Derive DID from genesis hash + public key
  const genesisHash = (await api.rpc.chain.getBlockHash(0)).toHex();
  const didId = deriveDidId(genesisHash, publicKey);
  did = `did:qsb:${didId}`;

  // createDid + save keys in local DID store
  const createDidCall = api.tx.did.createDid(toBytesArg(publicKey), []);
  const createSig = signDidCall(privateKey, 'QSB_DID_CREATE', createDidCall);
  const result = await createDid(api, account, publicKey, createSig);
  if (result.dispatchError) throw new Error('DID create failed');
  await storeDidKeys(did, publicKey, privateKey);
}
```

## 7. Shared DID Signing Helpers

These helpers are used by all DID operations:

1. Convert inputs to `Bytes`.
2. Build the pallet-compatible DID payload.
3. Sign payload with DID private key.

```js
function toBytes(value) {
  // Convert string to UTF-8 bytes
  return new TextEncoder().encode(value);
}

function toBytesArg(value) {
  // For `Bytes`, Polkadot API works safely with Array<number>
  return Array.isArray(value) ? value : Array.from(value);
}

function buildDidPayload(prefix, call) {
  // Exclude the final argument (did_signature)
  const encodedArgs = call.method.args
    .slice(0, Math.max(0, call.method.args.length - 1))
    // Encode exactly like runtime SCALE encoding
    .map((arg) => arg.toU8a());
  // Payload = PREFIX + SCALE(args without did_signature)
  return concatBytes(toBytes(prefix), ...encodedArgs);
}

function signDidCall(privateKey, prefix, call) {
  // ML-DSA-44 signature over DID payload
  return ml_dsa44.sign(privateKey, buildDidPayload(prefix, call));
}
```

## 8. DID Functions (One Subsection Per Function)

### 8.1 `createDid`

Purpose: create a new DID record and initial `Authentication` key on-chain.

Parameters:

1. `publicKey`: ML-DSA-44 public key.
2. `did_signature`: DID signature for `QSB_DID_CREATE + encode(public_key)`.

```js
// 1) Build a dummy call to construct DID payload
const createDidCall = api.tx.did.createDid(toBytesArg(publicKey), []);
// 2) Sign payload
const createSig = signDidCall(privateKey, 'QSB_DID_CREATE', createDidCall);
// 3) Send real extrinsic
await createDid(api, account, publicKey, createSig);
```

### 8.2 `addKey`

Purpose: add a new DID key with selected roles.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `secondaryPublicKey`: new key to add.
3. `roles`: key roles, e.g. `['AssertionMethod']`.
4. `did_signature`: signature for `QSB_DID_ADD_KEY + encode(did_id) + encode(public_key) + encode(roles)`.

```js
// 1) Generate secondary DID key
const secondary = ml_dsa44.keygen(randomBytes(32));
const secondaryPublicKey = secondary.publicKey;
// 2) Define roles
const roles = ['AssertionMethod'];
// 3) Build call for payload
const call = api.tx.did.addKey(didIdArg, toBytesArg(secondaryPublicKey), roles, []);
// 4) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_ADD_KEY', call);
// 5) Send extrinsic
await addKey(api, account, didIdArg, secondaryPublicKey, roles, sig);
```

### 8.3 `updateRoles`

Purpose: change roles of an existing active DID key.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `secondaryPublicKey`: key whose roles are updated.
3. `roles`: new role set, e.g. `['CapabilityInvocation']`.
4. `did_signature`: signature for `QSB_DID_UPDATE_ROLES + encode(did_id) + encode(public_key) + encode(roles)`.

```js
// 1) New roles for existing key
const roles = ['CapabilityInvocation'];
// 2) Build call for payload
const call = api.tx.did.updateRoles(didIdArg, toBytesArg(secondaryPublicKey), roles, []);
// 3) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_UPDATE_ROLES', call);
// 4) Send extrinsic
await updateRoles(api, account, didIdArg, secondaryPublicKey, roles, sig);
```

### 8.4 `rotateKey`

Purpose: revoke old key and add new key in one operation.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `secondaryPublicKey`: old key.
3. `rotatedPublicKey`: new key.
4. `roles`: roles for new key.
5. `did_signature`: signature for `QSB_DID_ROTATE_KEY + encode(did_id) + encode(old_pk) + encode(new_pk) + encode(roles)`.

```js
// 1) Generate replacement key
const rotated = ml_dsa44.keygen(randomBytes(32));
const rotatedPublicKey = rotated.publicKey;
// 2) Define roles for new key
const roles = ['CapabilityDelegation'];
// 3) Build call for payload
const call = api.tx.did.rotateKey(
  didIdArg,
  toBytesArg(secondaryPublicKey),
  toBytesArg(rotatedPublicKey),
  roles,
  []
);
// 4) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_ROTATE_KEY', call);
// 5) Send extrinsic
await rotateKey(api, account, didIdArg, secondaryPublicKey, rotatedPublicKey, roles, sig);
```

### 8.5 `setMetadata`

Purpose: add or update DID metadata entry (`key`, `value`).

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `metadataKey`: metadata key.
3. `metadataValue`: metadata value.
4. `did_signature`: signature for `QSB_DID_SET_METADATA + encode(did_id) + encode(entry)`.

```js
// 1) Metadata key and value
const metadataKey = toBytes('profile');
const metadataValue = toBytes('https://example.com/profile');
// 2) Build call for payload
const call = api.tx.did.setMetadata(
  didIdArg,
  { key: toBytesArg(metadataKey), value: toBytesArg(metadataValue) },
  []
);
// 3) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_SET_METADATA', call);
// 4) Send extrinsic
await setMetadata(api, account, didIdArg, metadataKey, metadataValue, sig);
```

### 8.6 `addService`

Purpose: add a service endpoint to DID document.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `serviceId`, `serviceType`, `serviceEndpoint`: `ServiceEndpoint` fields.
3. `did_signature`: signature for `QSB_DID_ADD_SERVICE + encode(did_id) + encode(service)`.

```js
// 1) Demo service endpoint constants
const serviceId = toBytes('service-1');
const serviceType = toBytes('ExampleService');
const serviceEndpoint = toBytes('https://example.com');
// 2) Build call for payload
const call = api.tx.did.addService(
  didIdArg,
  {
    id: toBytesArg(serviceId),
    service_type: toBytesArg(serviceType),
    endpoint: toBytesArg(serviceEndpoint),
  },
  []
);
// 3) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_ADD_SERVICE', call);
// 4) Send extrinsic
await addService(api, account, didIdArg, serviceId, serviceType, serviceEndpoint, sig);
```

### 8.7 `removeService`

Purpose: remove service by `service_id`.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `serviceIdArg`: service ID as `Bytes`.
3. `did_signature`: signature for `QSB_DID_REMOVE_SERVICE + encode(did_id) + encode(service_id)`.

```js
// 1) serviceId as Bytes
const serviceIdArg = toBytesArg(serviceId);
// 2) Build call for payload
const call = api.tx.did.removeService(didIdArg, serviceIdArg, []);
// 3) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_REMOVE_SERVICE', call);
// 4) Send extrinsic
await removeService(api, account, didIdArg, serviceIdArg, sig);
```

### 8.8 `removeMetadata`

Purpose: remove metadata entry by key.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `metadataKey`: metadata key.
3. `did_signature`: signature for `QSB_DID_REMOVE_METADATA + encode(did_id) + encode(key)`.

```js
// 1) Build call for payload
const call = api.tx.did.removeMetadata(didIdArg, toBytesArg(metadataKey), []);
// 2) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_REMOVE_METADATA', call);
// 3) Send extrinsic
await removeMetadata(api, account, didIdArg, metadataKey, sig);
```

### 8.9 `revokeKey`

Purpose: mark selected DID key as revoked.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `rotatedPublicKey`: key to revoke.
3. `did_signature`: signature for `QSB_DID_REVOKE_KEY + encode(did_id) + encode(public_key)`.

```js
// 1) Build call for payload
const call = api.tx.did.revokeKey(didIdArg, toBytesArg(rotatedPublicKey), []);
// 2) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_REVOKE_KEY', call);
// 3) Send extrinsic
await revokeKey(api, account, didIdArg, rotatedPublicKey, sig);
```

### 8.10 `deactivateDid`

Purpose: deactivate DID.

Parameters:

1. `didIdArg`: DID as `Bytes`.
2. `did_signature`: signature for `QSB_DID_DEACTIVATE + encode(did_id)`.

```js
// 1) Build call for payload
const call = api.tx.did.deactivateDid(didIdArg, []);
// 2) Sign DID payload
const sig = signDidCall(privateKey, 'QSB_DID_DEACTIVATE', call);
// 3) Send extrinsic
await deactivateDid(api, account, didIdArg, sig);
```

## 9. Schema Operations Executed by the Program

After the DID demo flow, the script also runs two Schema pallet operations:

1. `schema.registerSchema`
2. `schema.deprecateSchema`

Schema JSON is built locally (with random `_nonce`), and schema signature is calculated as:

`QSB_SCHEMA + schema_json`

```js
const schemaJsonRaw = buildSchemaJson();
const schemaJson = toBytes(schemaJsonRaw);
const schemaUri = toBytes(DEFAULT_SCHEMA_URI);
const schemaSignature = ml_dsa44.sign(privateKey, concatBytes(toBytes('QSB_SCHEMA'), schemaJson));

await registerSchema(api, account, schemaJson, schemaUri, toBytes(did), schemaSignature);
await deprecateSchema(api, account, toBytes(schemaId), toBytes(did), schemaSignature);
```

## 10. Two Different Signatures (Important)

Each DID operation involves two signatures:

1. Substrate account signature:
`tx.signAndSend(account, ...)`
2. DID signature:
`did_signature` (ML-DSA-44) over DID payload

Both must be valid.

## 11. Common Errors

1. `ENOENT ... account.json`
: wrong `ACCOUNT_JSON` path
2. `InvalidSignature`
: wrong DID payload (prefix/encoding/argument order)
3. `Compact input is > Number.MAX_SAFE_INTEGER`
: wrong format for `Bytes` argument (use `Array<number>`)
4. `API-WS ... 1006 Abnormal Closure`
: network/TLS/endpoint issue, not DID logic
