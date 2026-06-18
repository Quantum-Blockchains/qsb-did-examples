# QSB DID Python Example Guide

This guide describes the current `python_example` flow for the DID pallet in
`qsb-node` main at commit `2bdb50360fc21ed4ece841b122f7d9368bd5b15c`.

## Runtime Contract

Current `qsb-node` main exposes these key material inputs:

```python
{"Multikey": multikey_bytes}
{"Jwk": public_key_jwk_bytes}
```

Important rules:

- `create_did(public_key, did_signature)` receives a Multikey ML-DSA-44 byte
  string, not raw public key bytes.
- `add_key(..., key_material, ...)` receives `KeyMaterialInput`.
- `rotate_key(..., new_key_material, ...)` receives `KeyMaterialInput`.
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

The Python example manually encodes the payload. For runtimes with
`KeyMaterialInput`, enum variant indexes are:

```text
0 = Multikey(Vec<u8>)
1 = Jwk(Vec<u8>)
```

The helper therefore encodes key material as:

```python
def _scale_key_material(key_material: dict) -> bytes:
    if "Multikey" in key_material:
        return b"\x00" + _scale_vec_u8(key_material["Multikey"])
    if "Jwk" in key_material:
        return b"\x01" + _scale_vec_u8(key_material["Jwk"])
    raise ValueError("Unsupported KeyMaterialInput")
```

## DID Creation

The example generates an ML-DSA-44 keypair, derives the DID from the raw public
key, then sends a Multikey ML-DSA-44 value to the runtime:

```python
public_key, private_key = generate_keypair()
did_multikey = to_multikey(public_key)
payload = build_create_did_payload(did_multikey)
did_signature = sign(private_key, payload)
receipt = create_did(substrate, account, did_multikey, did_signature)
```

The runtime creates `did:qsb:<id>#update` with role `CapabilityInvocation`.

## Mixed Key Material

When `KeyMaterialInput` is available, the demo intentionally adds four extra DID
keys:

- two Multikey keys,
- two JWK keys.

Example material values:

```python
multikey = {"Multikey": to_multikey(public_key)}
jwk = {"Jwk": public_key_jwk_bytes}
```

JWK keys are used only for roles that do not require `CapabilityInvocation`. On
legacy runtimes the same flow uses Multikey for all added keys.

## Services

The service endpoint is `https://example.com`, an absolute URI. Keep service ids
compatible with the connected runtime validation rules.

## Resolution

The Python resolver first calls `did_getByString`. If that RPC returns a runtime
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
cd qsb-did-examples/python_example
poetry install
poetry run app
```

Required `.env`:

```env
ACCOUNT_JSON=./storage/account.json
ACCOUNT_PASSWORD=your_account_password
DID_STORE_PASSWORD=your_did_store_password
DID_STORE_PATH=./storage/did_store.json
```

Use Python 3.11 or newer for this example.
