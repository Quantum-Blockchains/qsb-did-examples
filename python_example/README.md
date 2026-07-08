# Python Example

Example client for QSB DID + Schema pallets.

## What's here

Two independent scripts, run separately:

1. **`poetry run app`** (`app.main`) — creates (or reuses) a DID, adds 4 keys with different roles, sets metadata, adds services, and prints the resolved DID Document. **Does not deactivate the DID** — it stays usable for later runs, including the credential demo below.
2. **`poetry run credential-demo`** (`app.credential_demo`) — signs a small JSON "credential" with a dedicated DID key, resolves the DID Document, and verifies the signature purely from what's published on-chain. Also demonstrates that a tampered credential fails verification.

You don't have to run them in order — `credential-demo` will create a DID itself if one doesn't exist yet.

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

## Configuration (.env)

Create `python_example/.env`:

```
ACCOUNT_JSON=./storage/account.json
ACCOUNT_PASSWORD=your_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=./storage/did_store.json
```

- `ACCOUNT_JSON` / `ACCOUNT_PASSWORD` are required. If `ACCOUNT_JSON` doesn't exist yet, it's created automatically (a new encrypted account JSON).
- `DID_STORE_PASSWORD` encrypts every private key written to `DID_STORE_PATH` (see below).

## Run: full DID lifecycle demo

```bash
poetry run app
```

What it does, in order:
1. Load/create the Substrate account and the DID (reusing it from `did_store.json` if present and still active on-chain; otherwise creates a new one).
2. Resolve and print the DID Document.
3. Add 4 keys with different roles:
   - `#auth-mldsa44` — `Authentication` — ML-DSA-44
   - `#invocation-mldsa44` — `CapabilityInvocation` — ML-DSA-44
   - `#assertion-ed25519-jwk` (or `#assertion-ed25519`) — `AssertionMethod` — Ed25519
   - `#agreement-p256-jwk` (or `#agreement-p256`) — `KeyAgreement`, `CapabilityDelegation` — P-256

   The `-jwk` suffix/JWK encoding is used when the connected runtime exposes `KeyMaterialInput`; otherwise these fall back to `Multikey` encoding (legacy `public_key`-only runtimes).
4. Set 4 metadata entries (`profile`, `organization`, `environment`, `keySuite`).
5. Add 3 services (`#messaging`, `#credentials`, `#profile`).
6. Resolve and print the final DID Document.

Every key added here is persisted (encrypted) to `did_store.json` — see "DID key storage" below.

## Run: credential signing demo

```bash
poetry run credential-demo
```

What it does, in order:
1. Load or create the DID (same as above).
2. Add a dedicated `#assertion-mldsa44` key with the `AssertionMethod` role — **reused** on later runs instead of minting a new one every time (it checks the persisted key against what's actually published on-chain, not just what's in the local file, and only adds a new one if they don't match).
3. Display the resolved DID Document.
4. Sign a small demo credential (`issuer`, `subject`, `claim`, `issuanceDate`) with that key, producing a `proof` block (`type: DataIntegrityProof`, `cryptosuite: mldsa44-demo` — an illustrative label, not a registered W3C cryptosuite).
5. Extract the matching `verificationMethod` from the DID Document and verify the signature against it — proving that anyone who only has the DID (not the private key) can independently verify the credential.
6. Tamper with a copy of the credential and verify again, to show the signature check actually catches it (`False`/fails, as expected).

## DID key storage (`storage/did_store.json`)

- The root/genesis key is always persisted at the top level (`public_key_hex` / `private_key_enc`).
- Every other demo-added key (from either script) is also persisted, in a `keys: []` array — each entry has its own `key_id` (e.g. `#auth-mldsa44`), its own random salt, and its own encrypted private key. Adding a key with an id that's already in the store replaces that entry rather than duplicating it.
- Encryption: PBKDF2-HMAC-SHA256 (390 000 iterations) derives a key from `DID_STORE_PASSWORD` + a random salt; that derived key encrypts the raw private key with `Fernet` (AES-128-CBC + HMAC-SHA256). Without `DID_STORE_PASSWORD`, decrypting is computationally infeasible.

## Notes

- DID creation sends a Multikey ML-DSA-44 value, as required by the current pallet.
- JWK verification methods are emitted as `JsonWebKey2020` with `publicKeyJwk`; Multikey methods are emitted as `Multikey` with `publicKeyMultibase`.
- If `did_getByString` reports a runtime decode error for an existing DID, remove `storage/did_store.json` or point `DID_STORE_PATH` to a new file. That local store may reference a DID created before the current pallet storage layout.
- DID resolution first tries `did_getByString`; if that RPC can't decode the current runtime's return type, the example falls back to `Did.DidRecords`.
- Metadata/service demo values are hardcoded in `src/app/main.py`.
- TLS verification is hardcoded as insecure in `src/app/substrate_client.py`, for demo compatibility only.

## Main libraries

- `substrate-interface` (Substrate RPC + extrinsics)
- `pqcrypto` (ML-DSA-44 keypair/signatures)
- `cryptography` (Ed25519/P-256 keys, encrypting the DID private key)
- `python-dotenv` (load `.env`)
- `base58` (DID/Schema IDs)

## Tests

```bash
poetry run pytest
```
Pure-logic unit tests only (no network) — SCALE encoding helpers, JWK shapes, credential sign/verify round-trips, and the `did_store` key persistence.

## Detailed Guide

- Full step-by-step guide with code snippets: `../docs/python-did-guide.md`
