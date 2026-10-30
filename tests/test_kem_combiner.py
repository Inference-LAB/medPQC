"""
tests.test_kem_combiner
========================
Unit tests for medpqc.kem.combiner module.
"""

import pytest
from medpqc.kem.combiner import hkdf_extract_and_expand, HybridKeyCombiner

def test_hkdf_extract_and_expand():
    ikm = b"test_input_key_material_32bytes!"
    salt = b"test_salt"
    info = b"test_info"
    okm = hkdf_extract_and_expand(ikm, salt=salt, info=info, length=64)
    assert len(okm) == 64
    assert isinstance(okm, bytes)

def test_hkdf_determinism():
    ikm = b"identical_key_material_12345678"
    okm1 = hkdf_extract_and_expand(ikm, length=64)
    okm2 = hkdf_extract_and_expand(ikm, length=64)
    assert okm1 == okm2

def test_hybrid_key_combiner_lengths():
    k_ecdh = b"\x01" * 32
    k_pq   = b"\x02" * 32
    k_aes, k_mac, okm = HybridKeyCombiner.combine(k_ecdh, k_pq)

    assert len(k_aes) == 32
    assert len(k_mac) == 32
    assert len(okm) == 64
    assert k_aes != k_mac
    assert okm[:32] == k_aes
    assert okm[32:] == k_mac

def test_hybrid_key_combiner_sensitivity():
    k_ecdh1 = b"\x01" * 32
    k_ecdh2 = b"\x01" * 31 + b"\x02"  # 1-byte difference
    k_pq    = b"\x03" * 32

    aes1, _, _ = HybridKeyCombiner.combine(k_ecdh1, k_pq)
    aes2, _, _ = HybridKeyCombiner.combine(k_ecdh2, k_pq)

    assert aes1 != aes2
