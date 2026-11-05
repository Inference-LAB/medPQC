"""
tests.unit.test_trust
=====================
Comprehensive unit tests for medpqc.security.trust.TrustStore.
Validates registration, multi-key rotation, expiration, revocation,
reinstatement, export/import, and file persistence.
"""

import os
import tempfile
import pytest
from medpqc.security.trust import TrustStore
from medpqc.kem.auth import IdentityKeyPair


def test_trust_store_initial_peers():
    k1 = IdentityKeyPair()
    k2 = IdentityKeyPair()
    store = TrustStore(initial_peers={"node-1": k1.public_bytes, "node-2": k2.public_bytes})

    assert store.is_trusted("node-1", k1.public_bytes) is True
    assert store.is_trusted("node-2", k2.public_bytes) is True
    assert store.list_peers() == ["node-1", "node-2"]


def test_trust_store_invalid_parameters():
    store = TrustStore()
    with pytest.raises(ValueError, match="node_id must be a non-empty string"):
        store.register_peer("", b"x" * 32)
    with pytest.raises(ValueError, match="node_id must be a non-empty string"):
        store.register_peer(123, b"x" * 32)  # type: ignore
    with pytest.raises(ValueError, match="Invalid Ed25519 public key length"):
        store.register_peer("node-1", b"short")
    with pytest.raises(ValueError, match="Invalid Ed25519 public key length"):
        store.register_peer("node-1", b"x" * 33)
    with pytest.raises(ValueError, match="node_id must be a string"):
        store.revoke_peer(123)  # type: ignore


def test_trust_store_verification_and_revocation():
    store = TrustStore()
    k1 = IdentityKeyPair()
    k2 = IdentityKeyPair()

    store.register_peer("hospital-alpha", k1.public_bytes)
    assert store.is_trusted("hospital-alpha", k1.public_bytes) is True
    assert store.is_trusted("hospital-alpha", k2.public_bytes) is False
    assert store.is_trusted("hospital-beta", k1.public_bytes) is False

    store.verify_peer("hospital-alpha", k1.public_bytes)

    with pytest.raises(PermissionError, match="UNTRUSTED_PEER"):
        store.verify_peer("hospital-beta", k1.public_bytes)

    with pytest.raises(PermissionError, match="IDENTITY_MISMATCH"):
        store.verify_peer("hospital-alpha", k2.public_bytes)

    store.revoke_peer("hospital-alpha")
    assert store.is_trusted("hospital-alpha", k1.public_bytes) is False
    with pytest.raises(PermissionError, match="REVOKED_PEER"):
        store.verify_peer("hospital-alpha", k1.public_bytes)

    # Reinstating node allows re-registration
    store.reinstate_node("hospital-alpha")
    store.register_peer("hospital-alpha", k1.public_bytes)
    assert store.is_trusted("hospital-alpha", k1.public_bytes) is True


def test_trust_store_key_rotation_and_expiration():
    store = TrustStore()
    k_old = IdentityKeyPair()
    k_new = IdentityKeyPair()

    # Register old key expiring at t=2000
    store.register_peer("node-x", k_old.public_bytes, key_id="key-old", not_before=1000, not_after=2000)
    # Register new key valid from t=1500 to t=3000 (overlapping transition)
    store.register_peer("node-x", k_new.public_bytes, key_id="key-new", not_before=1500, not_after=3000)

    # At t=1200: only k_old is valid
    assert store.is_trusted("node-x", k_old.public_bytes, current_time=1200) is True
    assert store.is_trusted("node-x", k_new.public_bytes, current_time=1200) is False

    # At t=1800: both keys valid (rotation window)
    assert store.is_trusted("node-x", k_old.public_bytes, current_time=1800) is True
    assert store.is_trusted("node-x", k_new.public_bytes, current_time=1800) is True

    # At t=2500: k_old expired, only k_new valid
    assert store.is_trusted("node-x", k_old.public_bytes, current_time=2500) is False
    assert store.is_trusted("node-x", k_new.public_bytes, current_time=2500) is True

    # Revoking key-new
    store.revoke_key("key-new")
    assert store.is_trusted("node-x", k_new.public_bytes, current_time=1800) is False


def test_trust_store_export_import_and_file_persistence():
    k1 = IdentityKeyPair()
    k2 = IdentityKeyPair()
    store = TrustStore()
    store.register_peer("node-a", k1.public_bytes)
    store.register_peer("node-b", k2.public_bytes)
    store.revoke_peer("node-b")

    exported = store.export_registry()
    assert "nodes" in exported
    assert "node-a" in exported["nodes"]
    assert "node-b" in exported["revoked_nodes"]

    store2 = TrustStore()
    store2.import_registry(exported)
    assert store2.is_trusted("node-a", k1.public_bytes) is True
    assert store2.is_trusted("node-b", k2.public_bytes) is False

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "truststore.json")
        store.save_to_file(path)
        assert os.path.exists(path)

        store3 = TrustStore()
        store3.load_from_file(path)
        assert store3.is_trusted("node-a", k1.public_bytes) is True
        assert store3.is_trusted("node-b", k2.public_bytes) is False

        with pytest.raises(FileNotFoundError, match="Trust store file not found"):
            store3.load_from_file(os.path.join(tmpdir, "missing.json"))
