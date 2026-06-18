# JS Example

Example client for QSB DID + Schema pallets (Node.js).

Current demo flow includes:
- DID create
- key operations with current `KeyMaterialInput` calls, or legacy
  Multikey-only calls when the connected runtime still exposes `public_key`
  arguments (`addKey`, `updateRoles`, `rotateKey`, `revokeKey`)
- metadata operations (`setMetadata`, `removeMetadata`)
- service operations (`addService`, `removeService`)
- DID deactivation
- schema register/deprecate

## Requirements

- Node.js 18+
- Access to QSB-Poseidon RPC: `wss://qsb.qbck.io:9945`
- Polkadot-js account JSON (encrypted)

On the https://qsb.qbck.io/poseidon/
 page, you can obtain funds for performing transactions by clicking the “Receive funds” button and providing your account address.

## Install

```bash
cd js_example
npm install
```

## Run

```bash
npm start
```

## Configuration (.env)

Create `js_example/.env`:

```
ACCOUNT_JSON=./storage/account.json
ACCOUNT_PASSWORD=your_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=./storage/did_store.json
```

Notes:
- `ACCOUNT_JSON` and `ACCOUNT_PASSWORD` are required in `.env`.
- If `ACCOUNT_JSON` does not exist, the app creates a new encrypted account JSON at that path.
- `DID_STORE_PASSWORD` encrypts the DID private key stored on disk.
- DID creation sends a Multikey ML-DSA-44 value, as required by the current pallet.
- Added DID keys are mixed on runtimes that expose `KeyMaterialInput`: part of
  the demo-added key material is JWK and part is Multikey. If the connected
  runtime still exposes legacy `public_key` arguments, the demo skips JWK and
  uses Multikey for added keys.
- JWK verification methods are emitted as `JsonWebKey2020` with
  `publicKeyJwk`; Multikey methods are emitted as `Multikey` with
  `publicKeyMultibase`.
- If the stored DID is already deactivated, remove `storage/did_store.json` or
  point `DID_STORE_PATH` to a new file before running the full lifecycle again.
- DID resolution first tries `did_getByString`; if that RPC cannot decode the
  current runtime return type, the example falls back to `Did.DidRecords`.
- Schema and service demo values are hardcoded in `src/index.js` (`DEFAULT_SCHEMA_URI`, `DEFAULT_SERVICE_*`).
- `DEFAULT_SERVICE_ID` is a DID URL fragment (`#service-1`) and
  `DEFAULT_SERVICE_ENDPOINT` is an absolute URI, matching pallet validation.
- TLS verification is hardcoded as insecure in `src/substrate_client.js` for demo compatibility.

## Main libraries

- `@polkadot/api` (Substrate RPC + extrinsics)
- `@polkadot/keyring` (load polkadot-js JSON)
- `@noble/post-quantum` (ML-DSA-44 keypair/signatures)
- `@noble/hashes` (blake2b-256)
- `bs58` (DID/Schema IDs)
- `dotenv` (load `.env`)

## Detailed Guide

- Full step-by-step guide with code snippets: `../docs/js-did-guide.md`
