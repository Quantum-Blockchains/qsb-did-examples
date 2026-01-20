# JS Example

Example client for QSB DID + Schema pallets (Node.js).

## Requirements

- Node.js 18+
- Access to `wss://qsb.qbck.io:9945`
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
ACCOUNT_JSON=/path/to/account.json
ACCOUNT_PASSWORD=your_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=/path/to/did_store.json
SCHEMA_JSON={"name":"example","version":"1.0"}
SCHEMA_URI=https://example.com/schema
SERVICE_ID=service-1
SERVICE_TYPE=ExampleService
SERVICE_ENDPOINT=https://example.com
SSL_INSECURE=0
```

Notes:
- `ACCOUNT_JSON` can be passed as `--account-json` instead of `.env`.
- `DID_STORE_PASSWORD` encrypts the DID private key stored on disk.
- `SCHEMA_JSON` gets a random `_nonce` on each run to make it unique.
- Set `SSL_INSECURE=1` to disable TLS verification if needed.

## Main libraries

- `@polkadot/api` (Substrate RPC + extrinsics)
- `@polkadot/keyring` (load polkadot-js JSON)
- `@noble/post-quantum` (ML-DSA-44 keypair/signatures)
- `@noble/hashes` (blake2b-256)
- `bs58` (DID/Schema IDs)
- `dotenv` (load `.env`)
