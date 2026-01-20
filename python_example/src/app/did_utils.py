import base58
import hashlib


def derive_did_id(genesis_hash_hex: str, public_key: bytes) -> str:
    genesis_bytes = bytes.fromhex(genesis_hash_hex.removeprefix("0x"))
    material = b"QSB_DID" + genesis_bytes + public_key
    did_id_bytes = hashlib.blake2b(material, digest_size=32).digest()
    return base58.b58encode(did_id_bytes).decode("ascii")


def derive_schema_id(genesis_hash_hex: str, schema_json: bytes) -> str:
    genesis_bytes = bytes.fromhex(genesis_hash_hex.removeprefix("0x"))
    material = b"QSB_SCHEMA" + genesis_bytes + schema_json
    schema_id_bytes = hashlib.blake2b(material, digest_size=32).digest()
    schema_id_b58 = base58.b58encode(schema_id_bytes).decode("ascii")
    return f"did:qsb:schema:{schema_id_b58}"
