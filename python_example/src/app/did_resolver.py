import base58


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
        services.append(
            {
                "id": bytes(service["id"]).decode("utf-8", errors="replace"),
                "service_type": bytes(service["service_type"]).decode("utf-8", errors="replace"),
                "endpoint": bytes(service["endpoint"]).decode("utf-8", errors="replace"),
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
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "version": details.get("version"),
        "deactivated": details.get("deactivated"),
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": [],
        "keyAgreement": [],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
        "service": services,
        "metadata": metadata,
    }
    for index, key in enumerate(details.get("keys", []), start=1):
        key_id = f"{did}#keys-{index}"
        public_key_bytes = bytes(key["public_key"])
        public_key_multibase = "z" + base58.b58encode(public_key_bytes).decode("ascii")
        vm = {
            "id": key_id,
            "type": "ML-DSA-44",
            "controller": did,
            "publicKeyMultibase": public_key_multibase,
            "revoked": key.get("revoked", False),
            "roles": key.get("roles", []),
        }
        doc["verificationMethod"].append(vm)
        for role in key.get("roles", []):
            field = role_map.get(role)
            if field:
                doc[field].append(key_id)
    return doc


def resolve_did(substrate, did: str) -> dict | None:
    response = substrate.rpc_request("did_getByString", [did])
    if not isinstance(response, dict):
        return None
    result = response.get("result")
    if not result:
        return None
    return did_to_document(did, result)
