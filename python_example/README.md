# Python Example

Example client for QSB DID + Schema pallets.

## Requirements

- Python 3.11+
- Poetry
- Access to `wss://qsb.qbck.io:9945`
- Polkadot-js account JSON (encrypted)

## Install

```bash
cd python_example
poetry install
```

## Run

```bash
poetry run app
```

## Configuration (.env)

Create `python_example/.env`:

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
```

Notes:
- `ACCOUNT_JSON` can be passed as `--account-json` instead of `.env`.
- `DID_STORE_PASSWORD` is used to encrypt the DID private key stored on disk.
- `SCHEMA_JSON` gets a random `_nonce` on each run to make it unique.

## Main libraries

- `substrate-interface` (Substrate RPC + extrinsics)
- `pqcrypto` (ML-DSA-44 keypair/signatures)
- `cryptography` (encrypt DID private key)
- `python-dotenv` (load `.env`)
- `base58` (DID/Schema IDs)

## Tests

```bash
poetry run pytest
```
