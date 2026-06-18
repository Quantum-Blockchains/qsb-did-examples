import json

from app.main import (
    _scale_key_material,
    _scale_vec_u8,
    generate_ed25519_jwk,
    generate_p256_jwk,
    jwk_material,
    multikey_material,
)


def test_scale_key_material_multikey():
    multikey = b"uExampleMultikey"

    assert _scale_key_material(multikey_material(multikey)) == b"\x00" + _scale_vec_u8(multikey)


def test_scale_key_material_jwk():
    jwk = b'{"kty":"OKP","crv":"Ed25519","x":"abc"}'

    assert _scale_key_material(jwk_material(jwk)) == b"\x01" + _scale_vec_u8(jwk)


def test_generated_jwk_shapes():
    ed25519 = json.loads(generate_ed25519_jwk().decode("utf-8"))
    p256 = json.loads(generate_p256_jwk().decode("utf-8"))

    assert ed25519["kty"] == "OKP"
    assert ed25519["crv"] == "Ed25519"
    assert p256["kty"] == "EC"
    assert p256["crv"] == "P-256"
