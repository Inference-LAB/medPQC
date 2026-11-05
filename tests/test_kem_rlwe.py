"""
tests.test_kem_rlwe
===================
Unit tests for medpqc.kem.rlwe module.
Validates NIST FIPS 203 ML-KEM-768 parameters, length invariants, and error handling.
"""

import pytest
from medpqc.kem.rlwe import (
    PostQuantumKEM,
    KEMError,
    MLKEM768_EK_LEN,
    MLKEM768_CT_LEN,
    MLKEM768_SS_LEN,
    MLKEM768_DK_LEN,
)
import medpqc.kem


def test_fips_203_mlkem768_key_lengths_and_roundtrip():
    alice = PostQuantumKEM(alg_name="ML-KEM-768")
    bob = PostQuantumKEM(alg_name="ML-KEM-768")

    assert alice.backend in ("fips-203-mlkem", "liboqs")
    assert len(alice.public_key_bytes) == MLKEM768_EK_LEN

    # Bob encapsulates to Alice
    ct, bob_secret = bob.encapsulate(alice.public_key_bytes)
    assert len(ct) == MLKEM768_CT_LEN
    assert len(bob_secret) == MLKEM768_SS_LEN

    # Alice decapsulates
    alice_secret = alice.decapsulate(ct)
    assert len(alice_secret) == MLKEM768_SS_LEN
    assert alice_secret == bob_secret


def test_encapsulate_to_peer_classmethod():
    """Validates encapsulation without instantiating full throwaway keypair."""
    alice = PostQuantumKEM(alg_name="ML-KEM-768")
    ct, bob_secret = PostQuantumKEM.encapsulate_to_peer(alice.public_key_bytes)
    assert len(ct) == MLKEM768_CT_LEN
    assert len(bob_secret) == MLKEM768_SS_LEN

    alice_secret = alice.decapsulate(ct)
    assert alice_secret == bob_secret


def test_mlkem_invalid_inputs_rejected():
    kem = PostQuantumKEM()

    # Invalid public key length
    with pytest.raises(KEMError):
        kem.encapsulate(b"short_key")
    with pytest.raises(TypeError):
        kem.encapsulate(12345)  # type: ignore

    # Invalid ciphertext length
    with pytest.raises(KEMError):
        kem.decapsulate(b"short_ciphertext")
    with pytest.raises(TypeError):
        kem.decapsulate(None)  # type: ignore


def test_mlkem_unsupported_algorithm_raises():
    with pytest.raises(KEMError):
        PostQuantumKEM(alg_name="NonExistentKEM")


def test_provider_info_structure():
    kem = PostQuantumKEM()
    info = kem.provider_info
    assert info["algorithm"] == "ML-KEM-768"
    assert info["public_key_len"] == str(MLKEM768_EK_LEN)
    assert info["ciphertext_len"] == str(MLKEM768_CT_LEN)
    assert info["shared_secret_len"] == str(MLKEM768_SS_LEN)


def test_no_toy_kem_in_production_exports():
    """F-KAT-01: NativeRLWEKEM and ExperimentalToyRLWE must not be in production exports."""
    import medpqc
    assert not hasattr(medpqc, "NativeRLWEKEM")
    assert not hasattr(medpqc, "ExperimentalToyRLWE")
    assert not hasattr(medpqc.kem, "NativeRLWEKEM")
    assert not hasattr(medpqc.kem, "ExperimentalToyRLWE")
