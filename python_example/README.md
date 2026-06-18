# Python Example

Example client for QSB DID + Schema pallets.

Current demo flow includes:
- DID create
- key operations with current `KeyMaterialInput` calls, or legacy
  Multikey-only calls when the connected runtime still exposes `public_key`
  arguments (`add_key`, `update_roles`, `rotate_key`, `revoke_key`)
- metadata operations (`set_metadata`, `remove_metadata`)
- service operations (`add_service`, `remove_service`)
- DID deactivation
- schema register/deprecate

## Requirements

- Python 3.11+
- Poetry
- Access to QSB-Poseidon RPC: `wss://qsb.qbck.io:9945`
- Polkadot-js account JSON (encrypted)

On the https://qsb.qbck.io/poseidon/
 page, you can obtain funds for performing transactions by clicking the “Receive funds” button and providing your account address.

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
- `ACCOUNT_JSON` and `ACCOUNT_PASSWORD` are required in `.env`.
- If `ACCOUNT_JSON` does not exist, the app creates a new encrypted account JSON at that path.
- `DID_STORE_PASSWORD` is used to encrypt the DID private key stored on disk.
- DID creation sends a Multikey ML-DSA-44 value, as required by the current pallet.
- Added DID keys are mixed on runtimes that expose `KeyMaterialInput`: half of
  the demo-added key material is JWK and half is Multikey. If the connected
  runtime still exposes legacy `public_key` arguments, the demo skips JWK and
  uses Multikey for added keys.
- JWK verification methods are emitted as `JsonWebKey2020` with
  `publicKeyJwk`; Multikey methods are emitted as `Multikey` with
  `publicKeyMultibase`.
- If `did_getByString` reports a runtime decode error for an existing DID, remove
  `storage/did_store.json` or point `DID_STORE_PATH` to a new file. That local
  store may reference a DID created before the current pallet storage layout.
- If the stored DID is already deactivated, also remove `storage/did_store.json`
  or point `DID_STORE_PATH` to a new file before running the full lifecycle again.
- DID resolution first tries `did_getByString`; if that RPC cannot decode the
  current runtime return type, the example falls back to `Did.DidRecords`.
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
