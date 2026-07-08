import base64
import json
import os
from getpass import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LOG_OK = "✅"


def encrypt_private_key(private_key: bytes, password: str, salt: bytes) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    fernet = Fernet(key)
    return fernet.encrypt(private_key).decode("ascii")


def decrypt_private_key(encrypted_private_key: str, password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_private_key.encode("ascii"))


def _store_path() -> str:
    return os.getenv("DID_STORE_PATH", "did_store.json")


def _password() -> str:
    password = os.getenv("DID_STORE_PASSWORD")
    if not password:
        password = getpass("DID store password: ")
    return password


def _read_record(store_path: str) -> dict:
    with open(store_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_record(store_path: str, record: dict) -> None:
    with open(store_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)


def store_did_keys(did: str, public_key: bytes, private_key: bytes) -> None:
    store_path = _store_path()
    password = _password()
    salt = os.urandom(16)
    encrypted_private_key = encrypt_private_key(private_key, password, salt)
    record = {
        "did": did,
        "public_key_hex": public_key.hex(),
        "private_key_enc": encrypted_private_key,
        "salt_hex": salt.hex(),
        "kdf": "pbkdf2_sha256_390000",
    }
    _write_record(store_path, record)
    print(f"{LOG_OK} DID keypair saved to {store_path}")


def load_did_keys() -> tuple[str, bytes, bytes] | None:
    store_path = _store_path()
    if not os.path.exists(store_path):
        return None
    password = _password()
    record = _read_record(store_path)
    salt = bytes.fromhex(record["salt_hex"])
    private_key = decrypt_private_key(record["private_key_enc"], password, salt)
    public_key = bytes.fromhex(record["public_key_hex"])
    did = record["did"]
    print(f"{LOG_OK} DID keypair loaded from {store_path}")
    return did, public_key, private_key


def store_key(did: str, key_id: str, public_key: bytes, private_key: bytes) -> None:
    store_path = _store_path()
    password = _password()
    record = _read_record(store_path) if os.path.exists(store_path) else {"did": did}
    salt = os.urandom(16)
    entry = {
        "key_id": key_id,
        "public_key_hex": public_key.hex(),
        "private_key_enc": encrypt_private_key(private_key, password, salt),
        "salt_hex": salt.hex(),
        "kdf": "pbkdf2_sha256_390000",
    }
    keys = [k for k in record.get("keys", []) if k.get("key_id") != key_id]
    keys.append(entry)
    record["keys"] = keys
    _write_record(store_path, record)
    print(f"{LOG_OK} Key {key_id} saved to {store_path}")


def load_key(key_id: str) -> tuple[bytes, bytes] | None:
    store_path = _store_path()
    if not os.path.exists(store_path):
        return None
    record = _read_record(store_path)
    entry = next((k for k in record.get("keys", []) if k.get("key_id") == key_id), None)
    if not entry:
        return None
    password = _password()
    salt = bytes.fromhex(entry["salt_hex"])
    private_key = decrypt_private_key(entry["private_key_enc"], password, salt)
    public_key = bytes.fromhex(entry["public_key_hex"])
    print(f"{LOG_OK} Key {key_id} loaded from {store_path}")
    return public_key, private_key
