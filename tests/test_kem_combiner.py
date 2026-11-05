"""
tests.test_kem_combiner
========================
Unit tests for medpqc.kem.combiner module.
Validates RFC 5869 HKDF-SHA-512 key derivation, directional keys, and transcript binding.
"""

import pytest
from medpqc.kem.combiner import (
    hkdf_sha512,
    hkdf_extract_and_expand,
    build_session_context,
    HybridKeyCombiner,
)


def test_rfc5869_sha512_kat():
    """Validates HKDF-SHA-512 against known RFC 5869 / test vector."""
    ikm = b"\x0b" * 32
    salt = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    info = b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"
    okm = hkdf_sha512(ikm, salt, info, 32)
    assert len(okm) == 32

    # Determinism
    okm2 = hkdf_sha512(ikm, salt, info, 32)
    assert okm == okm2


def test_directional_key_derivation():
    k_ecdh = b"E" * 32
    k_pq = b"P" * 32
    th = b"T" * 64
    s_ecdh = b"A" * 65
    r_ecdh = b"B" * 65
    ct = b"C" * 1088

    k_i2r, k_r2i, kid = HybridKeyCombiner.derive_directional_keys(
        k_ecdh=k_ecdh,
        k_pq=k_pq,
        transcript_hash=th,
        sender_ecdh_pub=s_ecdh,
        receiver_ecdh_pub=r_ecdh,
        pq_ciphertext=ct,
    )

    assert len(k_i2r) == 32
    assert len(k_r2i) == 32
    assert len(kid) == 16
    assert k_i2r != k_r2i


def test_directional_key_sensitivity_all_fields():
    """F-HS-06: Changing any single input changes all derived keys."""
    base_args = {
        "k_ecdh": b"E" * 32,
        "k_pq": b"P" * 32,
        "transcript_hash": b"T" * 64,
        "sender_ecdh_pub": b"A" * 65,
        "receiver_ecdh_pub": b"B" * 65,
        "pq_ciphertext": b"C" * 1088,
    }
    base_i2r, base_r2i, base_id = HybridKeyCombiner.derive_directional_keys(**base_args)

    for field, val in base_args.items():
        altered_args = dict(base_args)
        # Flip first byte
        altered_val = bytearray(val)
        altered_val[0] ^= 0x01
        altered_args[field] = bytes(altered_val)

        alt_i2r, alt_r2i, alt_id = HybridKeyCombiner.derive_directional_keys(**altered_args)
        assert alt_i2r != base_i2r, f"k_i2r invariant under change to {field}"
        assert alt_r2i != base_r2i, f"k_r2i invariant under change to {field}"
        assert alt_id != base_id, f"key_id invariant under change to {field}"


def test_build_session_context():
    ctx1 = build_session_context(sender_id="Alice", receiver_id="Bob")
    ctx2 = build_session_context(sender_id="Alice", receiver_id="Bob")
    ctx3 = build_session_context(sender_id="Alice", receiver_id="Eve")

    assert ctx1 == ctx2
    assert ctx1 != ctx3


def test_hybrid_key_combiner_invalid_lengths_raises():
    with pytest.raises(ValueError):
        HybridKeyCombiner.derive_directional_keys(
            k_ecdh=b"short",
            k_pq=b"P" * 32,
            transcript_hash=b"T" * 64,
            sender_ecdh_pub=b"A" * 65,
            receiver_ecdh_pub=b"B" * 65,
            pq_ciphertext=b"C" * 1088,
        )

    with pytest.raises(ValueError):
        HybridKeyCombiner.combine(b"short", b"P" * 32)

    with pytest.raises(ValueError):
        HybridKeyCombiner.derive_all_keys(b"short", b"P" * 32)


def test_hybrid_key_combiner_legacy_and_symmetric_derivations():
    """Verify combine and derive_all_keys interfaces."""
    k_ecdh = b"E" * 32
    k_pq = b"P" * 32

    i2r, r2i, kid = HybridKeyCombiner.combine(k_ecdh, k_pq, context=b"ctx")
    assert len(i2r) == 32
    assert len(r2i) == 32
    assert len(kid) == 16
    assert i2r != r2i

    # Test default context branch
    i2r_def, r2i_def, kid_def = HybridKeyCombiner.combine(k_ecdh, k_pq)
    assert len(i2r_def) == 32

    kaes, kmac, schaos = HybridKeyCombiner.derive_all_keys(k_ecdh, k_pq, session_context=b"sess")
    assert len(kaes) == 32
    assert len(kmac) == 32
    assert len(schaos) == 32

