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
    add_service,
    create_did,
    create_substrate,
    deprecate_schema,
    get_free_balance,
    register_schema,
    remove_service,
)
from app.did_utils import derive_did_id, derive_schema_id
from app.tx_logger import log_receipt

LOG_OK = "✅"
LOG_WARN = "⚠️"
LOG_DID = "🪪"
LOG_SCHEMA = "📜"
LOG_STEP = "➡️"


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
    parser = argparse.ArgumentParser(description="Subscribe to new blocks")
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
    substrate = create_substrate("wss://qsb.qbck.io:9945")
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

        payload = b"QSB_DID_CREATE" + public_key
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

    print(f"{LOG_STEP} Step: add DID service")
    service_id = os.getenv("SERVICE_ID", "service-1").encode("utf-8")
    service_type = os.getenv("SERVICE_TYPE", "ExampleService").encode("utf-8")
    service_endpoint = os.getenv("SERVICE_ENDPOINT", "https://example.com").encode("utf-8")
    receipt = add_service(
        substrate,
        account,
        did.encode("utf-8"),
        service_id,
        service_type,
        service_endpoint,
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
        did.encode("utf-8"),
        service_id,
    )
    log_receipt(receipt)

    print(f"{LOG_STEP} Step: register schema")
    schema_json_raw = os.getenv("SCHEMA_JSON", "{\"name\":\"example\",\"version\":\"1.0\"}")
    try:
        schema_obj = json.loads(schema_json_raw)
        if isinstance(schema_obj, dict):
            schema_obj["_nonce"] = uuid4().hex
            schema_json_raw = json.dumps(schema_obj, separators=(",", ":"))
    except json.JSONDecodeError:
        schema_json_raw = f"{schema_json_raw}|nonce={uuid4().hex}"
    schema_json = schema_json_raw.encode("utf-8")
    schema_uri = os.getenv("SCHEMA_URI", "https://example.com/schema").encode("utf-8")
    schema_id = derive_schema_id(genesis_hash, schema_json)
    print(f"{LOG_SCHEMA} Schema ID: {schema_id}")
    schema_signature = sign(private_key, b"QSB_SCHEMA" + schema_json)
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

    print(f"{LOG_OK} Connected.")


if __name__ == "__main__":
    main()
