# QSB DID JavaScript Example Guide

This guide describes the current `js_example` flow for the DID pallet in
`qsb-node` main at commit `2bdb50360fc21ed4ece841b122f7d9368bd5b15c`.

## Runtime Contract

Current `qsb-node` main exposes these key material inputs:

```js
{ Multikey: Array.from(multikeyBytes) }
{ Jwk: Array.from(publicKeyJwkBytes) }
```

Important rules:

- `createDid(public_key, did_signature)` receives a Multikey ML-DSA-44 byte
  string, not raw public key bytes.
- `addKey(..., key_material, ...)` receives `KeyMaterialInput`.
- `rotateKey(..., new_key_material, ...)` receives `KeyMaterialInput`.
- JWK keys are stored opaquely and must not receive `CapabilityInvocation`.
- The active `did:qsb:<id>#update` key is the only key that authorizes DID
  mutations.

The example detects the runtime metadata at startup. If the connected node still
uses legacy `public_key` arguments instead of `KeyMaterialInput`, it switches to
Multikey-only key operations and skips JWK additions.

## Signature Payloads

Each DID operation signs:

```text
PREFIX || SCALE(args without did_signature)
```

The JS example builds a temporary `api.tx.did.*` call with an empty final
signature argument and signs the SCALE-encoded call arguments:

```js
function buildDidPayload(prefix, call) {
  const encodedArgs = call.method.args
    .slice(0, Math.max(0, call.method.args.length - 1))
    .map((arg) => arg.toU8a());

  return concatBytes(toBytes(prefix), ...encodedArgs);
}
```

This keeps payload encoding aligned with the runtime metadata, including enum
encoding for `KeyMaterialInput` when that API is available.

## DID Creation

The example generates an ML-DSA-44 keypair, derives the DID from the raw public
key, then sends a Multikey ML-DSA-44 value to the runtime:

```js
const publicKey = keys.publicKey;
const multikeyBytes = toBytes(toMultikey(publicKey));
const call = api.tx.did.createDid(toBytesArg(multikeyBytes), []);
const signature = ml_dsa44.sign(privateKey, buildDidPayload('QSB_DID_CREATE', call));
await createDid(api, account, multikeyBytes, signature);
```

The runtime creates `did:qsb:<id>#update` with role `CapabilityInvocation`.

## Mixed Key Material

When `KeyMaterialInput` is available, the demo intentionally adds a mixed set of
DID keys:

- Multikey ML-DSA-44 keys for roles that may include `CapabilityInvocation`,
- JWK keys for roles such as `Authentication`, `AssertionMethod`, and
  `KeyAgreement`.

Examples:

```js
const multikeyMaterial = { Multikey: Array.from(multikeyBytes) };
const jwkMaterial = { Jwk: Array.from(jwkBytes) };
```

JWK keys are never assigned `CapabilityInvocation`. On legacy runtimes the same
flow uses Multikey for all added keys.

## Services

The demo service id is `#service-1`, which is a DID URL fragment. The service
endpoint is `https://example.com`, an absolute URI. Those formats match the
current pallet validation rules.

## Resolution

The JS resolver first calls `did_getByString`. If that RPC returns a runtime
decode error for the connected node, the resolver falls back to direct
`Did.DidRecords` storage lookup and maps raw `DidDetails` into a DID Resolution
result:

- `DidKeyMaterial::Multikey` maps to `type: "Multikey"` and
  `publicKeyMultibase`.
- `DidKeyMaterial::Jwk` maps to `type: "JsonWebKey2020"` and `publicKeyJwk`.
- Revoked keys are excluded from active verification relationships.

The full demo deactivates the DID near the end. If the configured
`DID_STORE_PATH` points to a deactivated DID, remove that file or use a new path
before running the lifecycle again.

## Run

```bash
cd qsb-did-examples/js_example
npm install
npm start
```

Required `.env`:

```env
ACCOUNT_JSON=./storage/account.json
ACCOUNT_PASSWORD=your_account_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=./storage/did_store.json
```
