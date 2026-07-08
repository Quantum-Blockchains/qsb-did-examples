import base64
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign, verify

from app.did_resolver import from_multikey, resolve_did
from app.did_store import load_did_keys, load_key, store_did_keys, store_key
from app.did_utils import derive_did_id
from app.main import (
    MULTICODEC_ML_DSA_44,
    RPC_URL,
    build_add_key_payload_for_runtime,
    build_create_did_payload,
    load_or_create_account,
    multikey_material,
    to_multikey,
)
from app.substrate_client import add_key, create_did, create_substrate, did_supports_key_material
from app.tx_logger import log_receipt

LOG_OK = "✅"
LOG_WARN = "⚠️"
LOG_STEP = "➡️"
ASSERTION_KEY_SUFFIX = b"#assertion-mldsa44"
ASSERTION_KEY_SUFFIX_TEXT = ASSERTION_KEY_SUFFIX.decode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_credential(private_key: bytes, verification_method: str, credential: dict) -> dict:
    message = canonical_json_bytes(credential)
    signature = sign(private_key, message)
    signed = dict(credential)
    signed["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "mldsa44-demo",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "proofValue": _b64url(signature),
    }
    return signed


def verify_credential(public_key: bytes, signed_credential: dict) -> bool:
    proof = signed_credential["proof"]
    credential = {k: v for k, v in signed_credential.items() if k != "proof"}
    message = canonical_json_bytes(credential)
    signature = _b64url_decode(proof["proofValue"])
    return verify(public_key, message, signature)


def find_verification_method(did_document: dict, verification_method_id: str) -> dict:
    for vm in did_document.get("verificationMethod", []):
        if vm["id"] == verification_method_id:
            return vm
    raise ValueError(f"verificationMethod {verification_method_id} not found in DID document")


def load_or_create_did(substrate, account) -> tuple[str, bytes, bytes]:
    stored = load_did_keys()
    if stored:
        did, public_key, private_key = stored
        resolution = resolve_did(substrate, did)
        if resolution["didDocument"] and not resolution["didDocumentMetadata"].get("deactivated", False):
            print(f"{LOG_OK} Reusing existing DID: {did}")
            return did, public_key, private_key
        print(f"{LOG_WARN} Stored DID is deactivated or unresolvable; creating a new one")

    public_key, private_key = generate_keypair()
    genesis_hash = substrate.get_block_hash(0)
    did_id = derive_did_id(genesis_hash, public_key)
    did = f"did:qsb:{did_id}"
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
    print(f"{LOG_OK} Created DID: {did}")
    return did, public_key, private_key


def get_or_create_assertion_key(
    substrate,
    account,
    did: str,
    root_private_key: bytes,
    supports_key_material: bool,
) -> tuple[bytes, bytes, dict]:
    verification_method_id = f"{did}{ASSERTION_KEY_SUFFIX_TEXT}"
    stored = load_key(ASSERTION_KEY_SUFFIX_TEXT)
    did_document = resolve_did(substrate, did)["didDocument"] or {}

    if stored:
        public_key, private_key = stored
        existing_vm = next(
            (vm for vm in did_document.get("verificationMethod", []) if vm["id"] == verification_method_id),
            None,
        )
        if existing_vm:
            _codec, chain_public_key = from_multikey(existing_vm["publicKeyMultibase"])
            if chain_public_key == public_key:
                print(f"{LOG_OK} Reusing persisted assertion key {verification_method_id}")
                return public_key, private_key, did_document
        print(f"{LOG_WARN} Persisted assertion key not found on-chain; adding a new one")

    public_key, private_key = generate_keypair()
    multikey = to_multikey(public_key, MULTICODEC_ML_DSA_44)
    did_bytes = did.encode("utf-8")
    add_key_signature = sign(
        root_private_key,
        build_add_key_payload_for_runtime(
            supports_key_material,
            did_bytes,
            ASSERTION_KEY_SUFFIX,
            multikey_material(multikey),
            ["AssertionMethod"],
            None,
        ),
    )
    receipt = add_key(
        substrate,
        account,
        did_bytes,
        ASSERTION_KEY_SUFFIX,
        multikey_material(multikey),
        ["AssertionMethod"],
        None,
        add_key_signature,
    )
    log_receipt(receipt)
    is_success = getattr(receipt, "is_success", None)
    if is_success is None:
        is_success = getattr(receipt, "success", False)
    if not is_success:
        raise SystemExit("add_key failed for assertion key; not saving to did_store")
    print(f"{LOG_OK} Added key {verification_method_id} roles=['AssertionMethod']")
    store_key(did, ASSERTION_KEY_SUFFIX_TEXT, public_key, private_key)
    did_document = resolve_did(substrate, did)["didDocument"]
    return public_key, private_key, did_document


def main() -> None:
    load_dotenv()
    print(f"{LOG_STEP} Step: load config")
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

    print(f"{LOG_STEP} Step: load or create DID")
    did, _root_public_key, root_private_key = load_or_create_did(substrate, account)

    print(f"{LOG_STEP} Step: get or create assertion key (ML-DSA-44, persisted in did_store)")
    supports_key_material = did_supports_key_material(substrate)
    _assertion_public_key, assertion_private_key, did_document = get_or_create_assertion_key(
        substrate, account, did, root_private_key, supports_key_material
    )
    if not did_document:
        raise SystemExit("Could not resolve DID document to verify credential")

    print(f"{LOG_STEP} Step: display resolved DID document")
    print(json.dumps(did_document, indent=2))

    verification_method_id = f"{did}{ASSERTION_KEY_SUFFIX_TEXT}"

    print(f"{LOG_STEP} Step: sign a demo credential with the assertion key")
    credential = {
        "issuer": did,
        "subject": did,
        "claim": {"role": "demo-tester", "level": "gold"},
        "issuanceDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed_credential = sign_credential(assertion_private_key, verification_method_id, credential)
    print(json.dumps(signed_credential, indent=2))

    print(f"{LOG_STEP} Step: extract verification method {verification_method_id} from DID document")
    verification_method = find_verification_method(did_document, verification_method_id)
    print(json.dumps(verification_method, indent=2))

    print(f"{LOG_STEP} Step: verify credential against the resolved DID document")
    _codec, resolved_public_key = from_multikey(verification_method["publicKeyMultibase"])
    is_valid = verify_credential(resolved_public_key, signed_credential)
    print(f"{LOG_OK if is_valid else LOG_WARN} Signature valid: {is_valid}")

    print(f"{LOG_STEP} Step: verify a tampered credential (expected to fail)")
    tampered_credential = json.loads(json.dumps(signed_credential))
    tampered_credential["claim"]["level"] = "platinum"
    is_tampered_valid = verify_credential(resolved_public_key, tampered_credential)
    print(f"{LOG_OK if not is_tampered_valid else LOG_WARN} Tampered signature valid: {is_tampered_valid}")


if __name__ == "__main__":
    main()
