import base58
import base64
import json
from substrateinterface.exceptions import SubstrateRequestException


def encode_uvarint(value: int) -> bytes:
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


def to_multikey(public_key: bytes, codec: int | None) -> str:
    if codec is None:
        return "z" + base58.b58encode(public_key).decode("ascii")
    prefixed = encode_uvarint(codec) + public_key
    encoded = base64.urlsafe_b64encode(prefixed).decode("ascii").rstrip("=")
    return f"u{encoded}"


def _bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        if value.startswith("0x"):
            return bytes.fromhex(value[2:])
        return value.encode("utf-8")
    return bytes(value)


def _decode_text(value) -> str:
    return _bytes(value).decode("utf-8", errors="replace")


def _parse_json_bytes(value):
    text = _decode_text(value)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _normalize_key_material(key: dict) -> dict:
    material = key.get("key_material") or key.get("keyMaterial") or {}
    multikey = material.get("Multikey") or material.get("multikey")
    if multikey:
        return {
            "type": "Multikey",
            "multicodec": multikey.get("multicodec"),
            "public_key": _bytes(multikey.get("public_key") or multikey.get("publicKey")),
        }

    jwk = material.get("Jwk") or material.get("jwk")
    if jwk:
        return {
            "type": "Jwk",
            "public_key_jwk": _bytes(jwk.get("public_key_jwk") or jwk.get("publicKeyJwk")),
        }

    return {
        "type": "Multikey",
        "multicodec": key.get("multicodec"),
        "public_key": _bytes(key.get("public_key") or key.get("publicKey")),
    }


def _did_id_bytes(did: str) -> bytes:
    prefix = "did:qsb:"
    if not did.startswith(prefix):
        raise ValueError("DID must start with did:qsb:")
    did_id = base58.b58decode(did[len(prefix) :])
    if len(did_id) != 32:
        raise ValueError("DID id must decode to 32 bytes")
    return did_id


def _success(did: str, result: dict) -> dict:
    return {
        "didDocument": did_to_document(did, result),
        "didDocumentMetadata": {
            "deactivated": result.get("deactivated", False),
            "versionId": result.get("version", 0),
        },
        "didResolutionMetadata": {
            "contentType": "application/did+ld+json",
            "error": None,
        },
    }


def _not_found() -> dict:
    return {
        "didDocument": None,
        "didDocumentMetadata": {
            "deactivated": False,
            "versionId": 0,
        },
        "didResolutionMetadata": {
            "contentType": None,
            "error": "notFound",
        },
    }


def _query_did_records(substrate, did: str) -> dict | None:
    record = substrate.query("Did", "DidRecords", [_did_id_bytes(did)])
    return getattr(record, "value", None)


def did_to_document(did: str, details: dict) -> dict:
    role_map = {
        "Authentication": "authentication",
        "AssertionMethod": "assertionMethod",
        "KeyAgreement": "keyAgreement",
        "CapabilityInvocation": "capabilityInvocation",
        "CapabilityDelegation": "capabilityDelegation",
    }
    services = []
    for service in details.get("services", []):
        service_type = service.get("service_type", service.get("type", b""))
        service_endpoint = service.get("endpoint", service.get("serviceEndpoint", b""))
        services.append(
            {
                "id": bytes(service["id"]).decode("utf-8", errors="replace"),
                "type": bytes(service_type).decode("utf-8", errors="replace"),
                "serviceEndpoint": bytes(service_endpoint).decode("utf-8", errors="replace"),
            }
        )

    metadata = []
    for item in details.get("metadata", []):
        metadata.append(
            {
                "key": bytes(item["key"]).decode("utf-8", errors="replace"),
                "value": bytes(item["value"]).decode("utf-8", errors="replace"),
            }
        )

    doc = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": did,
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": [],
        "keyAgreement": [],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
        "service": services,
        "metadata": metadata,
    }
    for key in details.get("keys", []):
        if key.get("revoked", False):
            continue
        key_id = _decode_text(key["key_id"])
        material = _normalize_key_material(key)
        controller = _decode_text(key.get("controller") or did.encode("utf-8"))
        vm = {
            "id": key_id,
            "controller": controller,
        }
        if material["type"] == "Jwk":
            vm["type"] = "JsonWebKey2020"
            vm["publicKeyJwk"] = _parse_json_bytes(material["public_key_jwk"])
        else:
            vm["type"] = "Multikey"
            vm["publicKeyMultibase"] = to_multikey(
                material["public_key"],
                material.get("multicodec"),
            )
        doc["verificationMethod"].append(vm)
        for role in key.get("roles", []):
            field = role_map.get(role)
            if field:
                doc[field].append(key_id)
    return doc


def resolve_did(substrate, did: str) -> dict:
    try:
        response = substrate.rpc_request("did_getByString", [did])
    except SubstrateRequestException as exc:
        try:
            result = _query_did_records(substrate, did)
            if result:
                resolved = _success(did, result)
                resolved["didResolutionMetadata"]["warning"] = (
                    "did_getByString failed; resolved through Did.DidRecords storage query"
                )
                return resolved
        except Exception:
            pass
        return {
            "didDocument": None,
            "didDocumentMetadata": {
                "deactivated": False,
                "versionId": 0,
            },
            "didResolutionMetadata": {
                "contentType": None,
                "error": "runtimeApiDecodeError",
                "message": str(exc),
            },
        }

    if isinstance(response, dict):
        result = response.get("result")
        if result:
            return _success(did, result)

    return _not_found()
