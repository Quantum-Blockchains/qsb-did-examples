from app.did_store import load_key, store_did_keys, store_key


def test_store_and_load_key_round_trip(tmp_path, monkeypatch):
    store_path = tmp_path / "did_store.json"
    monkeypatch.setenv("DID_STORE_PATH", str(store_path))
    monkeypatch.setenv("DID_STORE_PASSWORD", "test-password")

    public_key = b"public-key-bytes"
    private_key = b"private-key-bytes"
    store_key("did:qsb:example", "#assertion-mldsa44", public_key, private_key)

    loaded = load_key("#assertion-mldsa44")

    assert loaded == (public_key, private_key)


def test_load_key_missing_entry_returns_none(tmp_path, monkeypatch):
    store_path = tmp_path / "did_store.json"
    monkeypatch.setenv("DID_STORE_PATH", str(store_path))
    monkeypatch.setenv("DID_STORE_PASSWORD", "test-password")

    store_key("did:qsb:example", "#assertion-mldsa44", b"pub", b"priv")

    assert load_key("#does-not-exist") is None


def test_load_key_missing_store_returns_none(tmp_path, monkeypatch):
    store_path = tmp_path / "did_store.json"
    monkeypatch.setenv("DID_STORE_PATH", str(store_path))
    monkeypatch.setenv("DID_STORE_PASSWORD", "test-password")

    assert load_key("#assertion-mldsa44") is None


def test_store_key_preserves_root_key_fields(tmp_path, monkeypatch):
    store_path = tmp_path / "did_store.json"
    monkeypatch.setenv("DID_STORE_PATH", str(store_path))
    monkeypatch.setenv("DID_STORE_PASSWORD", "test-password")

    store_did_keys("did:qsb:example", b"root-public", b"root-private")
    store_key("did:qsb:example", "#assertion-mldsa44", b"assertion-public", b"assertion-private")

    from app.did_store import load_did_keys

    did, root_public, root_private = load_did_keys()
    assertion_public, assertion_private = load_key("#assertion-mldsa44")

    assert (did, root_public, root_private) == ("did:qsb:example", b"root-public", b"root-private")
    assert (assertion_public, assertion_private) == (b"assertion-public", b"assertion-private")
