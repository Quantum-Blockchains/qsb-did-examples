# Python Example

Example client for QSB DID + Schema pallets.

Current demo flow includes:
- DID create
- key operations (`add_key`, `update_roles`, `rotate_key`, `revoke_key`)
- metadata operations (`set_metadata`, `remove_metadata`)
- service operations (`add_service`, `remove_service`)
- DID deactivation
- schema register/deprecate

## Requirements

- Python 3.11+
- Poetry
- Access to QSB-Poseidon RPC: `wss://qsb.qbck.io:9945`
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
ACCOUNT_JSON=./storage/account.json
ACCOUNT_PASSWORD=your_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=./storage/did_store.json
```

Notes:
- `ACCOUNT_JSON` can be passed as `--account-json` instead of `.env`.
- `DID_STORE_PASSWORD` is used to encrypt the DID private key stored on disk.
- Schema and service demo values are hardcoded in `src/app/main.py` (`DEFAULT_SCHEMA_URI`, `DEFAULT_SERVICE_*`).
- TLS verification is hardcoded as insecure in `src/app/substrate_client.py` for demo compatibility.

## Main libraries

- `substrate-interface` (Substrate RPC + extrinsics)
- `pqcrypto` (ML-DSA-44 keypair/signatures)
- `cryptography` (encrypt DID private key)
- `python-dotenv` (load `.env`)
- `base58` (DID/Schema IDs)


## Detailed Guide

- Full step-by-step guide with code snippets: `../docs/python-did-guide.md`
