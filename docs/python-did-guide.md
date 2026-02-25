# DID Pallet Integration in Python (Consistent Demo Flow)

This document describes exactly what the current `python_example/src/app/main.py` does:
https://github.com/Quantum-Blockchains/qsb-did-examples

## 1. What You Need in `.env`

In `python_example/.env`, provide:

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

1. `Python` 3.11 or newer.
2. `Poetry`.
3. Network access to `wss://qsb.qbck.io:9945`.
4. A Substrate account exported as `account.json`.

```bash
cd python_example
poetry install
poetry run app
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

```python
import ssl
from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(
    url="wss://qsb.qbck.io:9945",
    ws_options={"sslopt": {"cert_reqs": ssl.CERT_NONE}},
)
# substrate client is now connected and ready
```

## 5. Loading the Substrate Account

Goal: prepare the blockchain account that signs and pays for extrinsics.

What happens:

1. Read `account.json`.
2. Decrypt private key with `ACCOUNT_PASSWORD`.
3. Return `account`, used by `create_signed_extrinsic(...)`.

Important distinction:

1. This account signs at Substrate transaction level.
2. This is not the DID signature (`did_signature`) verified by the DID pallet.

```python
import json
import os
from getpass import getpass
from substrateinterface import Keypair


def load_account(json_path: str) -> Keypair:
    # 1) Read account.json
    with open(json_path, "r", encoding="utf-8") as f:
        account_json = json.load(f)
    # 2) Read password from .env or interactive prompt
    password = os.getenv("ACCOUNT_PASSWORD")
    if not password:
        password = getpass("Account password: ")
    # 3) Decrypt and return signer
    return Keypair.create_from_encrypted_json(account_json, password)
```

## 6. Load/Generate DID Keys

Goal: reuse existing DID keys from local storage or generate a new DID keypair.

Flow:

1. Try `load_did_keys()`.
2. If keys exist, reuse stored `did`, `public_key`, `private_key`.
3. If keys do not exist, generate a new ML-DSA-44 keypair and create DID on-chain.
4. After successful `create_did`, persist keys using `store_did_keys(...)`.

```python
from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign

stored = load_did_keys()
if stored:
    did, public_key, private_key = stored
else:
    # 1) Generate ML-DSA-44 keypair
    public_key, private_key = generate_keypair()

    # 2) Derive DID from genesis hash + public key
    genesis_hash = substrate.get_block_hash(0)
    did_id = derive_did_id(genesis_hash, public_key)
    did = f"did:qsb:{did_id}"

    # 3) Build createDid payload, sign it, send extrinsic
    payload = build_create_did_payload(public_key)
    did_signature = sign(private_key, payload)
    receipt = create_did(substrate, account, public_key, did_signature)
    if not getattr(receipt, "is_success", False):
        raise SystemExit("DID create failed")

    # 4) Save DID keys in local encrypted store
    store_did_keys(did, public_key, private_key)
```

## 7. Shared DID Signing Helpers

These helpers are used by all DID operations:

1. Encode SCALE `Compact<u32>`.
2. Encode `Vec<u8>`.
3. Build the pallet-compatible DID payload.

```python
DID_ADD_KEY_PREFIX = b"QSB_DID_ADD_KEY"
DID_SET_METADATA_PREFIX = b"QSB_DID_SET_METADATA"

KEY_ROLE_INDEX = {
    "Authentication": 0,
    "AssertionMethod": 1,
    "KeyAgreement": 2,
    "CapabilityInvocation": 3,
    "CapabilityDelegation": 4,
}


def _scale_compact_u32(value: int) -> bytes:
    # Compact SCALE for list/bytes lengths
    if value < 1 << 6:
        return bytes([(value << 2) & 0xFF])
    if value < 1 << 14:
        return ((value << 2) | 0b01).to_bytes(2, "little")
    if value < 1 << 30:
        return ((value << 2) | 0b10).to_bytes(4, "little")
    raise ValueError("Compact SCALE length too large")


def _scale_vec_u8(data: bytes) -> bytes:
    # Vec<u8> encoding = compact length + raw bytes
    return _scale_compact_u32(len(data)) + data


def _scale_roles(roles: list[str]) -> bytes:
    # Vec<KeyRole> encoded as compact length + role indexes
    encoded = bytearray(_scale_compact_u32(len(roles)))
    for role in roles:
        encoded.append(KEY_ROLE_INDEX[role])
    return bytes(encoded)


def build_add_key_payload(did_id: bytes, public_key: bytes, roles: list[str]) -> bytes:
    # Prefix + encode(did_id) + encode(public_key) + encode(roles)
    return DID_ADD_KEY_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(public_key) + _scale_roles(roles)


def build_set_metadata_payload(did_id: bytes, key: bytes, value: bytes) -> bytes:
    # Prefix + encode(did_id) + encode(entry)
    return DID_SET_METADATA_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(key) + _scale_vec_u8(value)
```

## 8. DID Functions (One Subsection Per Function)

### 8.1 `create_did`

Purpose: create a new DID record and initial `Authentication` key on-chain.

Parameters:

1. `public_key`: ML-DSA-44 public key.
2. `did_signature`: DID signature for `QSB_DID_CREATE + encode(public_key)`.

```python
# 1) Build DID payload
payload = build_create_did_payload(public_key)
# 2) Sign payload with DID private key
did_signature = sign(private_key, payload)
# 3) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="create_did",
    call_params={
        "public_key": public_key,
        "did_signature": did_signature,
    },
)
# 4) Build signed extrinsic with Substrate account
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
# 5) Submit and wait for inclusion
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
# 6) Print events/status
log_receipt(receipt)
```

### 8.2 `add_key`

Purpose: add a new DID key with selected roles.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `secondary_public_key`: new key to add.
3. `roles`: key roles, e.g. `['AssertionMethod']`.
4. `did_signature`: signature for `QSB_DID_ADD_KEY + encode(did_id) + encode(public_key) + encode(roles)`.

```python
# 1) Generate secondary DID key
secondary_public_key, _ = generate_keypair()
# 2) Define roles
roles = ["AssertionMethod"]
# 3) Build DID payload and sign
payload = build_add_key_payload(did_bytes, secondary_public_key, roles)
did_signature = sign(private_key, payload)
# 4) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="add_key",
    call_params={
        "did_id": did_bytes,
        "public_key": secondary_public_key,
        "roles": roles,
        "did_signature": did_signature,
    },
)
# 5) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.3 `update_roles`

Purpose: change roles of an existing active DID key.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `secondary_public_key`: key whose roles are updated.
3. `roles`: new role set, e.g. `['CapabilityInvocation']`.
4. `did_signature`: signature for `QSB_DID_UPDATE_ROLES + encode(did_id) + encode(public_key) + encode(roles)`.

```python
# 1) New roles for existing key
roles = ["CapabilityInvocation"]
# 2) Build DID payload and sign
payload = build_update_roles_payload(did_bytes, secondary_public_key, roles)
did_signature = sign(private_key, payload)
# 3) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="update_roles",
    call_params={
        "did_id": did_bytes,
        "public_key": secondary_public_key,
        "roles": roles,
        "did_signature": did_signature,
    },
)
# 4) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.4 `rotate_key`

Purpose: revoke old key and add new key in one operation.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `secondary_public_key`: old key.
3. `rotated_public_key`: new key.
4. `roles`: roles for new key.
5. `did_signature`: signature for `QSB_DID_ROTATE_KEY + encode(did_id) + encode(old_pk) + encode(new_pk) + encode(roles)`.

```python
# 1) Generate replacement key
rotated_public_key, _ = generate_keypair()
# 2) Define roles for new key
roles = ["CapabilityDelegation"]
# 3) Build DID payload and sign
payload = build_rotate_key_payload(
    did_bytes,
    secondary_public_key,
    rotated_public_key,
    roles,
)
did_signature = sign(private_key, payload)
# 4) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="rotate_key",
    call_params={
        "did_id": did_bytes,
        "old_public_key": secondary_public_key,
        "new_public_key": rotated_public_key,
        "roles": roles,
        "did_signature": did_signature,
    },
)
# 5) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.5 `set_metadata`

Purpose: add or update DID metadata entry (`key`, `value`).

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `metadata_key`: metadata key.
3. `metadata_value`: metadata value.
4. `did_signature`: signature for `QSB_DID_SET_METADATA + encode(did_id) + encode(entry)`.

```python
# 1) Metadata key and value
metadata_key = b"profile"
metadata_value = b"https://example.com/profile"
# 2) Build DID payload and sign
payload = build_set_metadata_payload(did_bytes, metadata_key, metadata_value)
did_signature = sign(private_key, payload)
# 3) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="set_metadata",
    call_params={
        "did_id": did_bytes,
        "entry": {
            "key": metadata_key,
            "value": metadata_value,
        },
        "did_signature": did_signature,
    },
)
# 4) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.6 `add_service`

Purpose: add a service endpoint to DID document.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `service_id`, `service_type`, `service_endpoint`: `ServiceEndpoint` fields.
3. `did_signature`: signature for `QSB_DID_ADD_SERVICE + encode(did_id) + encode(service)`.

```python
# 1) Demo service endpoint constants
service_id = b"service-1"
service_type = b"ExampleService"
service_endpoint = b"https://example.com"
# 2) Build DID payload and sign
payload = build_add_service_payload(did_bytes, service_id, service_type, service_endpoint)
did_signature = sign(private_key, payload)
# 3) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="add_service",
    call_params={
        "did_id": did_bytes,
        "service": {
            "id": service_id,
            "service_type": service_type,
            "endpoint": service_endpoint,
        },
        "did_signature": did_signature,
    },
)
# 4) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.7 `remove_service`

Purpose: remove service by `service_id`.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `service_id`: service ID as `Bytes`.
3. `did_signature`: signature for `QSB_DID_REMOVE_SERVICE + encode(did_id) + encode(service_id)`.

```python
# 1) Build DID payload and sign
payload = build_remove_service_payload(did_bytes, service_id)
did_signature = sign(private_key, payload)
# 2) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="remove_service",
    call_params={
        "did_id": did_bytes,
        "service_id": service_id,
        "did_signature": did_signature,
    },
)
# 3) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.8 `remove_metadata`

Purpose: remove metadata entry by key.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `metadata_key`: metadata key.
3. `did_signature`: signature for `QSB_DID_REMOVE_METADATA + encode(did_id) + encode(key)`.

```python
# 1) Build DID payload and sign
payload = build_remove_metadata_payload(did_bytes, metadata_key)
did_signature = sign(private_key, payload)
# 2) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="remove_metadata",
    call_params={
        "did_id": did_bytes,
        "key": metadata_key,
        "did_signature": did_signature,
    },
)
# 3) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.9 `revoke_key`

Purpose: mark selected DID key as revoked.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `rotated_public_key`: key to revoke.
3. `did_signature`: signature for `QSB_DID_REVOKE_KEY + encode(did_id) + encode(public_key)`.

```python
# 1) Build DID payload and sign
payload = build_revoke_key_payload(did_bytes, rotated_public_key)
did_signature = sign(private_key, payload)
# 2) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="revoke_key",
    call_params={
        "did_id": did_bytes,
        "public_key": rotated_public_key,
        "did_signature": did_signature,
    },
)
# 3) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

### 8.10 `deactivate_did`

Purpose: deactivate DID.

Parameters:

1. `did_bytes`: DID as `Bytes`.
2. `did_signature`: signature for `QSB_DID_DEACTIVATE + encode(did_id)`.

```python
# 1) Build DID payload and sign
payload = build_deactivate_did_payload(did_bytes)
did_signature = sign(private_key, payload)
# 2) Build runtime call
call = substrate.compose_call(
    call_module="Did",
    call_function="deactivate_did",
    call_params={
        "did_id": did_bytes,
        "did_signature": did_signature,
    },
)
# 3) Sign and submit
extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
log_receipt(receipt)
```

## 9. Schema Operations Executed by the Program

After the DID demo flow, the script also runs two Schema pallet operations:

1. `schema.register_schema`
2. `schema.deprecate_schema`

Schema JSON is built locally (with random `_nonce`), and schema signature is calculated as:

`QSB_SCHEMA + schema_json`

```python
schema_json = build_schema_json()
schema_uri = b"https://example.com/schema"
schema_signature = sign(private_key, b"QSB_SCHEMA" + schema_json)

register_schema(substrate, account, schema_json, schema_uri, did.encode("utf-8"), schema_signature)
deprecate_schema(substrate, account, schema_id.encode("utf-8"), did.encode("utf-8"), schema_signature)
```

## 10. Two Different Signatures (Important)

Each DID operation involves two signatures:

1. Substrate account signature:
`create_signed_extrinsic(..., keypair=account)`
2. DID signature:
`did_signature` (ML-DSA-44) over DID payload

Both must be valid.

## 11. Common Errors

1. `ENOENT ... account.json`
: wrong `ACCOUNT_JSON` path
2. `InvalidToken` (from `cryptography.fernet`)
: wrong `DID_STORE_PASSWORD` for the existing `did_store.json`
3. `InvalidSignature`
: wrong DID payload (prefix/encoding/argument order)
4. TLS/certificate verification errors
: endpoint certificate chain issue; this demo disables cert verification in Python client
