# JS Example

Example client for QSB DID + Schema pallets (Node.js).

Current demo flow includes:
- DID create
- key operations (`addKey`, `updateRoles`, `rotateKey`, `revokeKey`)
- metadata operations (`setMetadata`, `removeMetadata`)
- service operations (`addService`, `removeService`)
- DID deactivation
- schema register/deprecate

## Requirements

- Node.js 18+
- Access to QSB-Poseidon RPC: `wss://qsb.qbck.io:9945`
- Polkadot-js account JSON (encrypted)

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
- `ACCOUNT_JSON` can be passed as `--account-json` instead of `.env`.
- `DID_STORE_PASSWORD` encrypts the DID private key stored on disk.
- Schema and service demo values are hardcoded in `src/index.js` (`DEFAULT_SCHEMA_URI`, `DEFAULT_SERVICE_*`).
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
