import argparse
import base64
import json
import os

from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign
from substrateinterface import Keypair

from app.did_resolver import resolve_did
from app.did_store import load_did_keys, store_did_keys, store_key
from app.substrate_client import (
    add_key,
    add_service,
    create_did,
    create_substrate,
    did_supports_key_material,
    get_free_balance,
    set_metadata,
)
from app.did_utils import derive_did_id
from app.tx_logger import log_receipt

LOG_OK = "✅"
LOG_WARN = "⚠️"
LOG_DID = "🪪"
LOG_STEP = "➡️"
RPC_URL = "wss://qsb.qbck.io:9945"
DID_CREATE_PREFIX = b"QSB_DID_CREATE"
DID_ADD_KEY_PREFIX = b"QSB_DID_ADD_KEY"
DID_ADD_SERVICE_PREFIX = b"QSB_DID_ADD_SERVICE"
DID_SET_METADATA_PREFIX = b"QSB_DID_SET_METADATA"
DEFAULT_SERVICE_ID = b"service-1"
DEFAULT_SERVICE_TYPE = b"ExampleService"
DEFAULT_SERVICE_ENDPOINT = b"https://example.com"
MULTICODEC_ML_DSA_44 = 0x1210
MULTICODEC_ED25519_PUB = 0xED
MULTICODEC_P256_PUB = 0x1201

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


def _scale_option_vec_u8(data: bytes | None) -> bytes:
    if data is None:
        return b"\x00"
    return b"\x01" + _scale_vec_u8(data)


def _encode_uvarint(value: int) -> bytes:
    out = bytearray()
    v = value
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            b |= 0x80
        out.append(b)
        if not v:
            break
    return bytes(out)


def to_multikey(public_key: bytes, codec: int = MULTICODEC_ML_DSA_44) -> bytes:
    prefixed = _encode_uvarint(codec) + public_key
    encoded = base64.urlsafe_b64encode(prefixed).decode("ascii").rstrip("=")
    return f"u{encoded}".encode("utf-8")


def multikey_material(multikey: bytes) -> dict:
    return {"Multikey": multikey}


def jwk_material(public_key_jwk: bytes) -> dict:
    return {"Jwk": public_key_jwk}


def _scale_key_material(key_material: dict) -> bytes:
    if "Multikey" in key_material:
        return b"\x00" + _scale_vec_u8(key_material["Multikey"])
    if "Jwk" in key_material:
        return b"\x01" + _scale_vec_u8(key_material["Jwk"])
    raise ValueError("Unsupported KeyMaterialInput")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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


def _scale_roles(roles: list[str]) -> bytes:
    encoded = bytearray(_scale_compact_u32(len(roles)))
    for role in roles:
        index = KEY_ROLE_INDEX[role]
        encoded.append(index)
    return bytes(encoded)


def build_add_key_payload(
    did_id: bytes,
    key_id_suffix: bytes | None,
    key_material: dict,
    roles: list[str],
    controller: bytes | None,
) -> bytes:
    return (
        DID_ADD_KEY_PREFIX
        + _scale_vec_u8(did_id)
        + _scale_option_vec_u8(key_id_suffix)
        + _scale_key_material(key_material)
        + _scale_roles(roles)
        + _scale_option_vec_u8(controller)
    )


def build_add_key_payload_for_runtime(
    supports_key_material: bool,
    did_id: bytes,
    key_id_suffix: bytes | None,
    key_material: dict,
    roles: list[str],
    controller: bytes | None,
) -> bytes:
    if supports_key_material:
        return build_add_key_payload(did_id, key_id_suffix, key_material, roles, controller)
    if "Multikey" not in key_material:
        raise ValueError("Connected runtime does not support JWK key material")
    return (
        DID_ADD_KEY_PREFIX
        + _scale_vec_u8(did_id)
        + _scale_option_vec_u8(key_id_suffix)
        + _scale_vec_u8(key_material["Multikey"])
        + _scale_roles(roles)
        + _scale_option_vec_u8(controller)
    )


def build_set_metadata_payload(did_id: bytes, key: bytes, value: bytes) -> bytes:
    return DID_SET_METADATA_PREFIX + _scale_vec_u8(did_id) + _scale_vec_u8(key) + _scale_vec_u8(value)


def _create_and_store_account(json_path: str, password: str) -> Keypair:
    account = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    account_json = account.export_to_encrypted_json(password, name="qsb-demo-account")
    directory = os.path.dirname(json_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(account_json, f, indent=2)
    return account


def load_or_create_account(json_path: str, password: str) -> Keypair:
    if not os.path.exists(json_path):
        print(f"{LOG_WARN} Account file not found. Creating new account at: {json_path}")
        return _create_and_store_account(json_path, password)

    with open(json_path, "r", encoding="utf-8") as f:
        account_json = json.load(f)

    try:
        return Keypair.create_from_encrypted_json(account_json, password)
    except Exception as exc:
        raise RuntimeError("Failed to load account from JSON") from exc


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_key_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return public_key_raw, private_key_raw


def generate_p256_keypair() -> tuple[ec.EllipticCurvePublicKey, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_raw = private_key.private_numbers().private_value.to_bytes(32, "big")
    return private_key.public_key(), private_key_raw


def generate_ed25519_multikey() -> bytes:
    public_key_raw, _private_key_raw = generate_ed25519_keypair()
    return to_multikey(public_key_raw, MULTICODEC_ED25519_PUB)


def generate_ed25519_jwk() -> bytes:
    public_key_raw, _private_key_raw = generate_ed25519_keypair()
    return json.dumps(
        {"kty": "OKP", "crv": "Ed25519", "x": _b64url(public_key_raw)},
        separators=(",", ":"),
    ).encode("utf-8")


def generate_p256_multikey() -> bytes:
    public_key, _private_key_raw = generate_p256_keypair()
    public_key_compressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return to_multikey(public_key_compressed, MULTICODEC_P256_PUB)


def generate_p256_jwk() -> bytes:
    public_key, _private_key_raw = generate_p256_keypair()
    numbers = public_key.public_numbers()
    return json.dumps(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def build_demo_key_plan(
    supports_key_material: bool,
) -> list[tuple[bytes, list[str], dict, bytes, bytes]]:
    auth_public, auth_private = generate_keypair()
    invocation_public, invocation_private = generate_keypair()

    if supports_key_material:
        assertion_public, assertion_private = generate_ed25519_keypair()
        assertion_jwk = json.dumps(
            {"kty": "OKP", "crv": "Ed25519", "x": _b64url(assertion_public)},
            separators=(",", ":"),
        ).encode("utf-8")

        agreement_public_key, agreement_private = generate_p256_keypair()
        agreement_numbers = agreement_public_key.public_numbers()
        agreement_public = agreement_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        agreement_jwk = json.dumps(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64url(agreement_numbers.x.to_bytes(32, "big")),
                "y": _b64url(agreement_numbers.y.to_bytes(32, "big")),
            },
            separators=(",", ":"),
        ).encode("utf-8")

        return [
            (
                b"#auth-mldsa44",
                ["Authentication"],
                multikey_material(to_multikey(auth_public)),
                auth_public,
                auth_private,
            ),
            (
                b"#invocation-mldsa44",
                ["CapabilityInvocation"],
                multikey_material(to_multikey(invocation_public)),
                invocation_public,
                invocation_private,
            ),
            (
                b"#assertion-ed25519-jwk",
                ["AssertionMethod"],
                jwk_material(assertion_jwk),
                assertion_public,
                assertion_private,
            ),
            (
                b"#agreement-p256-jwk",
                ["KeyAgreement", "CapabilityDelegation"],
                jwk_material(agreement_jwk),
                agreement_public,
                agreement_private,
            ),
        ]

    assertion_public, assertion_private = generate_ed25519_keypair()
    agreement_public_key, agreement_private = generate_p256_keypair()
    agreement_public = agreement_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    return [
        (
            b"#auth-mldsa44",
            ["Authentication"],
            multikey_material(to_multikey(auth_public)),
            auth_public,
            auth_private,
        ),
        (
            b"#invocation-mldsa44",
            ["CapabilityInvocation"],
            multikey_material(to_multikey(invocation_public)),
            invocation_public,
            invocation_private,
        ),
        (
            b"#assertion-ed25519",
            ["AssertionMethod"],
            multikey_material(to_multikey(assertion_public, MULTICODEC_ED25519_PUB)),
            assertion_public,
            assertion_private,
        ),
        (
            b"#agreement-p256",
            ["KeyAgreement", "CapabilityDelegation"],
            multikey_material(to_multikey(agreement_public, MULTICODEC_P256_PUB)),
            agreement_public,
            agreement_private,
        ),
    ]


def main() -> None:
    load_dotenv()
    print(f"{LOG_STEP} Step: load config")
    parser = argparse.ArgumentParser(description="QSB DID + Schema demo client")
    parser.parse_args()
    account_json_path = os.getenv("ACCOUNT_JSON")
    if not account_json_path:
        raise SystemExit("Set ACCOUNT_JSON in .env")
    account_password = os.getenv("ACCOUNT_PASSWORD")
    if not account_password:
        raise SystemExit("Set ACCOUNT_PASSWORD in .env")

    print(f"{LOG_STEP} Step: connect substrate")
    substrate = create_substrate(RPC_URL)
    print(f"{LOG_STEP} Step: load account")
    account = load_or_create_account(account_json_path, account_password)
    print(f"{LOG_OK} Loaded account: {account.ss58_address}")
    print(f"{LOG_STEP} Step: fetch balance")
    free_balance = get_free_balance(substrate, account.ss58_address)
    print(f"Free balance: {free_balance}")

    print(f"{LOG_STEP} Step: load or generate DID keys")
    stored = load_did_keys()
    loaded_from_store = stored is not None
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

        did_multikey = to_multikey(public_key)
        payload = build_create_did_payload(did_multikey)
        did_signature = sign(private_key, payload)
        receipt = create_did(substrate, account, did_multikey, did_signature)
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
    did_resolution = resolve_did(substrate, did)
    resolution_error = did_resolution["didResolutionMetadata"].get("error")
    if resolution_error == "runtimeApiDecodeError" and loaded_from_store:
        store_path = os.getenv("DID_STORE_PATH", "did_store.json")
        raise SystemExit(
            "Stored DID cannot be decoded by the current node runtime API. "
            "This usually means the local did_store.json points to a DID created "
            "with an older pallet storage layout. Remove the local DID store or set "
            f"DID_STORE_PATH to a new file and run again. Current DID_STORE_PATH: {store_path}"
        )
    if resolution_error == "runtimeApiDecodeError":
        raise SystemExit(
            "Newly created DID cannot be decoded by did_getByString. "
            "The connected RPC node likely does not match the runtime/API expected "
            "by this example."
        )
    print(f"{LOG_DID} DID resolution:")
    print(json.dumps(did_resolution, indent=2))

    did_bytes = did.encode("utf-8")
    supports_key_material = did_supports_key_material(substrate)

    print(f"{LOG_STEP} Step: add DID keys for different roles")
    if not supports_key_material:
        print(
            f"{LOG_WARN} Connected runtime does not expose KeyMaterialInput; "
            "JWK demo keys are skipped and Multikey is used for all added keys."
        )
    keys_to_add = build_demo_key_plan(supports_key_material)
    for key_suffix, roles, key_material, public_key_raw, private_key_raw in keys_to_add:
        add_key_signature = sign(
            private_key,
            build_add_key_payload_for_runtime(
                supports_key_material,
                did_bytes,
                key_suffix,
                key_material,
                roles,
                None,
            ),
        )
        receipt = add_key(
            substrate,
            account,
            did_bytes,
            key_suffix,
            key_material,
            roles,
            None,
            add_key_signature,
        )
        log_receipt(receipt)
        is_success = getattr(receipt, "is_success", None)
        if is_success is None:
            is_success = getattr(receipt, "success", False)
        if not is_success:
            print(f"{LOG_WARN} add_key failed for {key_suffix.decode('utf-8')}; not saving to did_store")
            continue
        print(f"{LOG_DID} Added key {did}{key_suffix.decode('utf-8')} roles={roles}")
        store_key(did, key_suffix.decode("utf-8"), public_key_raw, private_key_raw)

    print(f"{LOG_STEP} Step: add DID metadata")
    metadata_entries = [
        (b"profile", b"https://profiles.example.org/alice"),
        (b"organization", b"QSB Labs"),
        (b"environment", b"demo"),
        (b"keySuite", b"ML-DSA-44,Ed25519,P-256"),
    ]
    for metadata_key, metadata_value in metadata_entries:
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
        print(f"{LOG_OK} Metadata set: {metadata_key.decode('utf-8')}")
        log_receipt(receipt)

    print(f"{LOG_STEP} Step: add multiple DID services with DID URL id + full URI endpoint")
    services_to_add = [
        (
            f"{did}#messaging".encode("utf-8"),
            b"MessagingService",
            b"https://resolver.example.org/api/v1/messages",
        ),
        (
            f"{did}#credentials".encode("utf-8"),
            b"CredentialRegistry",
            b"https://wallet.example.org/credentials/status/2026",
        ),
        (
            f"{did}#profile".encode("utf-8"),
            b"ProfileService",
            b"https://profiles.example.org/alice",
        ),
    ]
    for service_id, service_type, service_endpoint in services_to_add:
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
        print(f"{LOG_OK} Service added: {service_id.decode('utf-8')}")
        log_receipt(receipt)

    print(f"{LOG_STEP} Step: resolve final DID document")
    did_resolution = resolve_did(substrate, did)
    print(f"{LOG_DID} Final DID resolution:")
    print(json.dumps(did_resolution, indent=2))
    print(f"{LOG_OK} Done. DID document above is ready to present.")


if __name__ == "__main__":
    main()
