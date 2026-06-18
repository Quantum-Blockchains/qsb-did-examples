import ssl

from substrateinterface import SubstrateInterface


def create_substrate(url: str) -> SubstrateInterface:
    return SubstrateInterface(
        url=url,
        ws_options={"sslopt": {"cert_reqs": ssl.CERT_NONE}},
    )


def get_free_balance(substrate: SubstrateInterface, address: str) -> int:
    account_info = substrate.query("System", "Account", [address])
    return account_info.value["data"]["free"]


def _call_field_names(substrate: SubstrateInterface, call_function: str) -> list[str]:
    metadata = substrate.get_metadata_call_function("Did", call_function)
    return [field["name"] for field in metadata["fields"]]


def did_supports_key_material(substrate: SubstrateInterface) -> bool:
    return "key_material" in _call_field_names(substrate, "add_key")


def _material_to_legacy_public_key(key_material: dict) -> bytes:
    if "Multikey" in key_material:
        return key_material["Multikey"]
    raise ValueError("Connected runtime does not support JWK key material")


def create_did(substrate: SubstrateInterface, account, public_key: bytes, did_signature: bytes):
    call = substrate.compose_call(
        call_module="Did",
        call_function="create_did",
        call_params={
            "public_key": public_key,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def add_key(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    key_id_suffix: bytes | None,
    key_material: dict,
    roles: list[str],
    controller: bytes | None,
    did_signature: bytes,
):
    supports_key_material = did_supports_key_material(substrate)
    material_param = (
        {"key_material": key_material}
        if supports_key_material
        else {"public_key": _material_to_legacy_public_key(key_material)}
    )
    call = substrate.compose_call(
        call_module="Did",
        call_function="add_key",
        call_params={
            "did_id": did_id,
            "key_id_suffix": key_id_suffix,
            **material_param,
            "roles": roles,
            "controller": controller,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def revoke_key(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    key_id: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="revoke_key",
        call_params={
            "did_id": did_id,
            "key_id": key_id,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def deactivate_did(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="deactivate_did",
        call_params={
            "did_id": did_id,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def register_schema(
    substrate: SubstrateInterface,
    account,
    schema_json: bytes,
    schema_uri: bytes,
    issuer_did: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Schema",
        call_function="register_schema",
        call_params={
            "schema_json": schema_json,
            "schema_uri": schema_uri,
            "issuer_did": issuer_did,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def deprecate_schema(
    substrate: SubstrateInterface,
    account,
    schema_id: bytes,
    issuer_did: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Schema",
        call_function="deprecate_schema",
        call_params={
            "schema_id": schema_id,
            "issuer_did": issuer_did,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def add_service(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    service_id: bytes,
    service_type: bytes,
    endpoint: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="add_service",
        call_params={
            "did_id": did_id,
            "service": {
                "id": service_id,
                "service_type": service_type,
                "endpoint": endpoint,
            },
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def remove_service(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    service_id: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="remove_service",
        call_params={
            "did_id": did_id,
            "service_id": service_id,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def set_metadata(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    key: bytes,
    value: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="set_metadata",
        call_params={
            "did_id": did_id,
            "entry": {
                "key": key,
                "value": value,
            },
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def remove_metadata(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    key: bytes,
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="remove_metadata",
        call_params={
            "did_id": did_id,
            "key": key,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def rotate_key(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    old_key_id: bytes,
    new_key_material: dict,
    new_key_id_suffix: bytes | None,
    new_controller: bytes | None,
    roles: list[str],
    did_signature: bytes,
):
    supports_key_material = did_supports_key_material(substrate)
    material_param = (
        {"new_key_material": new_key_material}
        if supports_key_material
        else {"new_public_key": _material_to_legacy_public_key(new_key_material)}
    )
    call = substrate.compose_call(
        call_module="Did",
        call_function="rotate_key",
        call_params={
            "did_id": did_id,
            "old_key_id": old_key_id,
            **material_param,
            "new_key_id_suffix": new_key_id_suffix,
            "new_controller": new_controller,
            "roles": roles,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)


def update_roles(
    substrate: SubstrateInterface,
    account,
    did_id: bytes,
    key_id: bytes,
    roles: list[str],
    did_signature: bytes,
):
    call = substrate.compose_call(
        call_module="Did",
        call_function="update_roles",
        call_params={
            "did_id": did_id,
            "key_id": key_id,
            "roles": roles,
            "did_signature": did_signature,
        },
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=account)
    return substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
