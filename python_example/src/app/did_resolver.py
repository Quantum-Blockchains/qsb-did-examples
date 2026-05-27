import base58
import base64


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
        key_id = bytes(key["key_id"]).decode("utf-8", errors="replace")
        public_key_bytes = bytes(key["public_key"])
        public_key_multibase = to_multikey(public_key_bytes, key.get("multicodec"))
        controller = bytes(key.get("controller") or did.encode("utf-8")).decode("utf-8", errors="replace")
        vm = {
            "id": key_id,
            "type": "Multikey",
            "controller": controller,
            "publicKeyMultibase": public_key_multibase,
        }
        doc["verificationMethod"].append(vm)
        for role in key.get("roles", []):
            field = role_map.get(role)
            if field:
                doc[field].append(key_id)
    return doc


def resolve_did(substrate, did: str) -> dict:
    response = substrate.rpc_request("did_getByString", [did])
    if isinstance(response, dict):
        result = response.get("result")
        if result:
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
