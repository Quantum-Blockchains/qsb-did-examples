from app.credential_demo import sign_credential, verify_credential
from app.did_resolver import from_multikey, to_multikey
from pqcrypto.sign.ml_dsa_44 import generate_keypair

MULTICODEC_ML_DSA_44 = 0x1210


def test_sign_and_verify_round_trip():
    public_key, private_key = generate_keypair()
    credential = {"issuer": "did:qsb:example", "subject": "did:qsb:example", "claim": {"role": "tester"}}

    signed = sign_credential(private_key, "did:qsb:example#assertion-mldsa44", credential)

    assert verify_credential(public_key, signed) is True


def test_tampered_credential_fails_verification():
    public_key, private_key = generate_keypair()
    credential = {"issuer": "did:qsb:example", "subject": "did:qsb:example", "claim": {"role": "tester"}}

    signed = sign_credential(private_key, "did:qsb:example#assertion-mldsa44", credential)
    signed["claim"]["role"] = "admin"

    assert verify_credential(public_key, signed) is False


def test_multikey_round_trip():
    public_key, _private_key = generate_keypair()

    multikey = to_multikey(public_key, MULTICODEC_ML_DSA_44)
    codec, decoded = from_multikey(multikey)

    assert codec == MULTICODEC_ML_DSA_44
    assert decoded == public_key
