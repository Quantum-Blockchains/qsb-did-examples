import argparse
import json
import os
from getpass import getpass
from uuid import uuid4

from dotenv import load_dotenv
from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign
from substrateinterface import Keypair

from app.did_resolver import resolve_did
from app.did_store import load_did_keys, store_did_keys
from app.substrate_client import (
    add_key,
    add_service,
    create_did,
    create_substrate,
    deactivate_did,
    deprecate_schema,
    get_free_balance,
    register_schema,
    remove_metadata,
    remove_service,
    revoke_key,
    rotate_key,
    set_metadata,
    update_roles,
)
from app.did_utils import derive_did_id, derive_schema_id
from app.tx_logger import log_receipt

LOG_OK = "✅"
LOG_WARN = "⚠️"
LOG_DID = "🪪"
LOG_SCHEMA = "📜"
LOG_STEP = "➡️"
RPC_URL = "wss://qsb.qbck.io:9945"
SCHEMA_PREFIX = b"QSB_SCHEMA"
DID_CREATE_PREFIX = b"QSB_DID_CREATE"
DID_ADD_KEY_PREFIX = b"QSB_DID_ADD_KEY"
DID_REVOKE_KEY_PREFIX = b"QSB_DID_REVOKE_KEY"
DID_DEACTIVATE_PREFIX = b"QSB_DID_DEACTIVATE"
DID_ADD_SERVICE_PREFIX = b"QSB_DID_ADD_SERVICE"
DID_REMOVE_SERVICE_PREFIX = b"QSB_DID_REMOVE_SERVICE"
DID_SET_METADATA_PREFIX = b"QSB_DID_SET_METADATA"
DID_REMOVE_METADATA_PREFIX = b"QSB_DID_REMOVE_METADATA"
DID_ROTATE_KEY_PREFIX = b"QSB_DID_ROTATE_KEY"
DID_UPDATE_ROLES_PREFIX = b"QSB_DID_UPDATE_ROLES"
DEFAULT_SERVICE_ID = b"service-1"
DEFAULT_SERVICE_TYPE = b"ExampleService"
DEFAULT_SERVICE_ENDPOINT = b"https://example.com"
DEFAULT_SCHEMA_URI = b"https://example.com/schema"
DEFAULT_SCHEMA_BASE = {"name": "example", "version": "1.0"}

KEY_ROLE_INDEX = {
    "Authentication": 0,
    "AssertionMethod": 1,
    "KeyAgreement": 2,
    "CapabilityInvocation": 3,
    "CapabilityDelegation": 4,
}


def _scale_compact_u32(value: int) -> bytes:
    if value < 1 << 6:
        return bytes([(value << 2) & 0xFF])
    if value < 1 << 14:
        encoded = (value << 2) | 0b01
        return encoded.to_bytes(2, "little")
    if value < 1 << 30:
        encoded = (value << 2) | 0b10
        return encoded.to_bytes(4, "little")
    raise ValueError("Compact SCALE length too large")


def _scale_vec_u8(data: bytes) -> bytes:
    return _scale_compact_u32(len(data)) + data


def build_create_did_payload(public_key: bytes) -> bytes:
    return DID_CREATE_PREFIX + _scale_vec_u8(public_key)


def build_add_service_payload(
    did_id: bytes,
    service_id: bytes,
    service_type: bytes,
    endpoint: bytes,
) -> bytes:
    service_encoded = (
        _scale_vec_u8(service_id) + _scale_vec_u8(service_type) + _scale_vec_u8(endpoint)
    )
    return DID_ADD_SERVICE_PREFIX + _scale_vec_u8(did_id) + service_encoded


def build_remove_service_payload(did_id: bytes, service_id: bytes) -> bytes:
    return DID_REMOVE_SERVICE_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(service_id)


def _scale_roles(roles: list[str]) -> bytes:
    encoded = bytearray(_scale_compact_u32(len(roles)))
    for role in roles:
        index = KEY_ROLE_INDEX[role]
        encoded.append(index)
    return bytes(encoded)


def build_add_key_payload(did_id: bytes, public_key: bytes, roles: list[str]) -> bytes:
    return (
        DID_ADD_KEY_PREFIX
        + _scale_vec_u8(did_id)
        + _scale_vec_u8(public_key)
        + _scale_roles(roles)
    )


def build_revoke_key_payload(did_id: bytes, public_key: bytes) -> bytes:
    return DID_REVOKE_KEY_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(public_key)


def build_set_metadata_payload(did_id: bytes, key: bytes, value: bytes) -> bytes:
    return DID_SET_METADATA_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(key) + _scale_vec_u8(value)


def build_remove_metadata_payload(did_id: bytes, key: bytes) -> bytes:
    return DID_REMOVE_METADATA_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(key)


def build_rotate_key_payload(
    did_id: bytes,
    old_public_key: bytes,
    new_public_key: bytes,
    roles: list[str],
) -> bytes:
    return (
        DID_ROTATE_KEY_PREFIX
        + _scale_vec_u8(did_id)
        + _scale_vec_u8(old_public_key)
        + _scale_vec_u8(new_public_key)
        + _scale_roles(roles)
    )


def build_update_roles_payload(did_id: bytes, public_key: bytes, roles: list[str]) -> bytes:
    return DID_UPDATE_ROLES_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(public_key) + _scale_roles(roles)


def build_deactivate_did_payload(did_id: bytes) -> bytes:
    return DID_DEACTIVATE_PREFIX + _scale_vec_u8(did_id)


def build_schema_json() -> bytes:
    schema_obj = dict(DEFAULT_SCHEMA_BASE)
    schema_obj["_nonce"] = uuid4().hex
    return json.dumps(schema_obj, separators=(",", ":")).encode("utf-8")


def load_account(json_path: str) -> Keypair:
    with open(json_path, "r", encoding="utf-8") as f:
        account_json = json.load(f)

    password = os.getenv("ACCOUNT_PASSWORD")
    if not password:
        password = getpass("Account password: ")

    try:
        return Keypair.create_from_encrypted_json(account_json, password)
    except Exception as exc:
        raise RuntimeError("Failed to load account from JSON") from exc


def main() -> None:
    load_dotenv()
    print(f"{LOG_STEP} Step: load config")
    parser = argparse.ArgumentParser(description="QSB DID + Schema demo client")
    parser.add_argument(
        "--account-json",
        required=False,
        help="Path to polkadot-js account JSON file",
    )
    args = parser.parse_args()
    account_json_path = args.account_json or os.getenv("ACCOUNT_JSON")
    if not account_json_path:
        raise SystemExit("Provide --account-json or set ACCOUNT_JSON in .env")

    print(f"{LOG_STEP} Step: connect substrate")
    substrate = create_substrate(RPC_URL)
    print(f"{LOG_STEP} Step: load account")
    account = load_account(account_json_path)
    print(f"{LOG_OK} Loaded account: {account.ss58_address}")
    print(f"{LOG_STEP} Step: fetch balance")
    free_balance = get_free_balance(substrate, account.ss58_address)
    print(f"Free balance: {free_balance}")

    print(f"{LOG_STEP} Step: load or generate DID keys")
    stored = load_did_keys()
    if stored:
        did, public_key, private_key = stored
        print(f"{LOG_DID} DID: {did}")
    else:
        public_key, private_key = generate_keypair()
        print(f"{LOG_OK} ML-DSA-44 public key: {public_key.hex()}")
        genesis_hash = substrate.get_block_hash(0)
        did_id = derive_did_id(genesis_hash, public_key)
        did = f"did:qsb:{did_id}"
        print(f"{LOG_DID} DID: {did}")

        payload = build_create_did_payload(public_key)
        did_signature = sign(private_key, payload)
        receipt = create_did(substrate, account, public_key, did_signature)
        log_receipt(receipt)
        is_success = getattr(receipt, "is_success", None)
        if is_success is None:
            is_success = getattr(receipt, "success", False)
        if not is_success:
            raise SystemExit("DID create failed; not saving DID keys")
        store_did_keys(did, public_key, private_key)

    if "genesis_hash" not in locals():
        genesis_hash = substrate.get_block_hash(0)
    print(f"{LOG_STEP} Step: resolve DID document")
    did_doc = resolve_did(substrate, did)
    if did_doc:
        print(f"{LOG_DID} DID document:")
        print(json.dumps(did_doc, indent=2))
    else:
        print(f"{LOG_WARN} DID not found or invalid response")

    did_bytes = did.encode("utf-8")

    print(f"{LOG_STEP} Step: add DID key (assertion method)")
    secondary_public_key, _ = generate_keypair()
    add_key_roles = ["AssertionMethod"]
    add_key_signature = sign(
        private_key,
        build_add_key_payload(did_bytes, secondary_public_key, add_key_roles),
    )
    receipt = add_key(
        substrate,
        account,
        did_bytes,
        secondary_public_key,
        add_key_roles,
        add_key_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: update DID key roles")
    updated_roles = ["CapabilityInvocation"]
    update_roles_signature = sign(
        private_key,
        build_update_roles_payload(did_bytes, secondary_public_key, updated_roles),
    )
    receipt = update_roles(
        substrate,
        account,
        did_bytes,
        secondary_public_key,
        updated_roles,
        update_roles_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: rotate DID key")
    rotated_public_key, _ = generate_keypair()
    rotate_roles = ["CapabilityDelegation"]
    rotate_signature = sign(
        private_key,
        build_rotate_key_payload(
            did_bytes,
            secondary_public_key,
            rotated_public_key,
            rotate_roles,
        ),
    )
    receipt = rotate_key(
        substrate,
        account,
        did_bytes,
        secondary_public_key,
        rotated_public_key,
        rotate_roles,
        rotate_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: set DID metadata")
    metadata_key = b"profile"
    metadata_value = b"https://example.com/profile"
    set_metadata_signature = sign(
        private_key,
        build_set_metadata_payload(did_bytes, metadata_key, metadata_value),
    )
    receipt = set_metadata(
        substrate,
        account,
        did_bytes,
        metadata_key,
        metadata_value,
        set_metadata_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: add DID service")
    service_id = DEFAULT_SERVICE_ID
    service_type = DEFAULT_SERVICE_TYPE
    service_endpoint = DEFAULT_SERVICE_ENDPOINT
    add_service_signature = sign(
        private_key,
        build_add_service_payload(did_bytes, service_id, service_type, service_endpoint),
    )
    receipt = add_service(
        substrate,
        account,
        did_bytes,
        service_id,
        service_type,
        service_endpoint,
        add_service_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: resolve DID document (after add service)")
    did_doc = resolve_did(substrate, did)
    if did_doc:
        print(f"{LOG_DID} DID document:")
        print(json.dumps(did_doc, indent=2))
    else:
        print(f"{LOG_WARN} DID not found or invalid response")

    print(f"{LOG_STEP} Step: remove DID service")
    receipt = remove_service(
        substrate,
        account,
        did_bytes,
        service_id,
        sign(private_key, build_remove_service_payload(did_bytes, service_id)),
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: remove DID metadata")
    remove_metadata_signature = sign(
        private_key,
        build_remove_metadata_payload(did_bytes, metadata_key),
    )
    receipt = remove_metadata(
        substrate,
        account,
        did_bytes,
        metadata_key,
        remove_metadata_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: revoke rotated DID key")
    revoke_key_signature = sign(
        private_key,
        build_revoke_key_payload(did_bytes, rotated_public_key),
    )
    receipt = revoke_key(
        substrate,
        account,
        did_bytes,
        rotated_public_key,
        revoke_key_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: register schema")
    schema_json = build_schema_json()
    schema_uri = DEFAULT_SCHEMA_URI
    schema_id = derive_schema_id(genesis_hash, schema_json)
    print(f"{LOG_SCHEMA} Schema ID: {schema_id}")
    schema_signature = sign(private_key, SCHEMA_PREFIX + schema_json)
    receipt = register_schema(
        substrate,
        account,
        schema_json,
        schema_uri,
        did.encode("utf-8"),
        schema_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: deprecate schema")
    receipt = deprecate_schema(
        substrate,
        account,
        schema_id.encode("utf-8"),
        did.encode("utf-8"),
        schema_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: deactivate DID")
    deactivate_signature = sign(private_key, build_deactivate_did_payload(did_bytes))
    receipt = deactivate_did(
        substrate,
        account,
        did_bytes,
        deactivate_signature,
    )
    log_receipt(receipt)

    print(f"{LOG_OK} Done.")


if __name__ == "__main__":
    main()
