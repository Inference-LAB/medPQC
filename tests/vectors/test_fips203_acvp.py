"""
tests.vectors.test_fips203_acvp
===============================
Authoritative NIST FIPS 203 (ML-KEM-768) ACVP Known-Answer Vectors.

Provenance:
- Standard: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard, Aug 2024)
- Algorithm: ML-KEM-768 (Parameter Set: k=3, q=3329, eta1=2, eta2=2, du=10, dv=4)
- Source: usnistgov/ACVP-Server (Automated Cryptographic Validation Protocol Server)
- Commit SHA: 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0
- Test Coverage: AFT and VAL vectors for keyGen, encapsulation, decapsulation, and key checks.
- Note: Passing known-answer tests is not FIPS 140/CAVP validation.
"""

import os
import json
import hashlib
import pytest
import mlkem
from medpqc.kem.rlwe import (
    PostQuantumKEM,
    KEMError,
    MLKEM768_EK_LEN,
    MLKEM768_DK_LEN,
    MLKEM768_CT_LEN,
    MLKEM768_SS_LEN,
)


def _load_provenance() -> dict:
    prov_file = os.path.join(os.path.dirname(__file__), "PROVENANCE.json")
    assert os.path.exists(prov_file), f"Missing PROVENANCE.json: {prov_file}"
    with open(prov_file, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_vectors() -> dict:
    vector_file = os.path.join(os.path.dirname(__file__), "nist_fips203_kat_vectors.json")
    assert os.path.exists(vector_file), f"Missing KAT vector file: {vector_file}"
    with open(vector_file, "r", encoding="utf-8") as f:
        return json.load(f)


def test_fips203_acvp_vector_file_integrity():
    """Validates that the KAT vector file matches the hash registered in PROVENANCE.json."""
    prov = _load_provenance()
    vector_file = os.path.join(os.path.dirname(__file__), "nist_fips203_kat_vectors.json")
    with open(vector_file, "rb") as f:
        file_sha256 = hashlib.sha256(f.read()).hexdigest()

    expected_sha256 = prov["vector_files"]["nist_fips203_kat_vectors.json"]
    assert file_sha256 == expected_sha256, (
        f"KAT vector file hash mismatch: expected {expected_sha256}, got {file_sha256}"
    )


def test_fips203_acvp_keygen_structure():
    """Validates ML-KEM-768 keyGen vector structural properties (ek embedding, z, and H(ek))."""
    data = _load_vectors()
    kg_groups = data.get("keygen_groups", [])
    assert len(kg_groups) >= 1, "Expected at least 1 keygen group"

    total_tested = 0
    for group in kg_groups:
        for vec in group.get("tests", []):
            dk_bytes = bytes.fromhex(vec["dk"])
            ek_bytes = bytes.fromhex(vec["ek"])
            z_bytes = bytes.fromhex(vec["z"])

            assert len(dk_bytes) == MLKEM768_DK_LEN
            assert len(ek_bytes) == MLKEM768_EK_LEN
            assert len(z_bytes) == 32

            # FIPS 203 Section 7.1: dk = (s || ek || H(ek) || z)
            # ML-KEM-768: len(s) = 1152, len(ek) = 1184, len(H(ek)) = 32, len(z) = 32
            assert dk_bytes[1152:1152 + 1184] == ek_bytes, (
                f"ek embedding mismatch in keygen vector tcId={vec.get('tcId')}"
            )
            assert dk_bytes[-32:] == z_bytes, (
                f"rejection seed z mismatch in keygen vector tcId={vec.get('tcId')}"
            )
            expected_h_ek = hashlib.sha3_256(ek_bytes).digest()
            assert dk_bytes[2336:2368] == expected_h_ek, (
                f"H(ek) hash mismatch in keygen vector tcId={vec.get('tcId')}"
            )
            total_tested += 1

    assert total_tested >= 25, f"Expected >= 25 keyGen cases tested, got {total_tested}"


def test_fips203_acvp_encapsulation_decapsulation_kat():
    """Validates decapsulation against official NIST ACVP ML-KEM-768 KAT vectors (AFT)."""
    data = _load_vectors()
    ed_groups = data.get("encap_decap_groups", [])
    kem_engine = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)

    aft_group = next(
        g for g in ed_groups if g.get("function") == "encapsulation" and g.get("testType") == "AFT"
    )
    tests = aft_group.get("tests", [])
    assert len(tests) >= 25

    for vec in tests:
        dk_bytes = bytes.fromhex(vec["dk"])
        c_bytes = bytes.fromhex(vec["c"])
        expected_k = bytes.fromhex(vec["k"])

        assert len(dk_bytes) == MLKEM768_DK_LEN
        assert len(c_bytes) == MLKEM768_CT_LEN
        assert len(expected_k) == MLKEM768_SS_LEN

        dk_obj = mlkem.DecapsKey.from_bytes(dk_bytes)
        derived_k = bytes(kem_engine.decaps(dk_obj, c_bytes))

        assert derived_k == expected_k, (
            f"FIPS 203 ACVP failure for tgId={aft_group.get('tgId')}, tcId={vec.get('tcId')}"
        )


def test_fips203_acvp_implicit_rejection_kat():
    """Validates decapsulation implicit rejection against official NIST ACVP VAL vectors."""
    data = _load_vectors()
    ed_groups = data.get("encap_decap_groups", [])
    kem_engine = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)

    val_decap = next(
        g for g in ed_groups if g.get("function") == "decapsulation" and g.get("testType") == "VAL"
    )
    tests = val_decap.get("tests", [])
    assert len(tests) >= 10

    for vec in tests:
        dk_bytes = bytes.fromhex(vec["dk"])
        c_bytes = bytes.fromhex(vec["c"])
        expected_k = bytes.fromhex(vec["k"])

        dk_obj = mlkem.DecapsKey.from_bytes(dk_bytes)
        derived_k = bytes(kem_engine.decaps(dk_obj, c_bytes))

        assert derived_k == expected_k, (
            f"FIPS 203 ACVP implicit rejection failure for tcId={vec.get('tcId')}"
        )


def test_fips203_acvp_key_checks():
    """Validates provider decapsulationKeyCheck and encapsulationKeyCheck rejection behavior."""
    data = _load_vectors()
    ed_groups = data.get("encap_decap_groups", [])

    # Group 9: decapsulationKeyCheck
    dk_group = next((g for g in ed_groups if g.get("function") == "decapsulationKeyCheck"), None)
    if dk_group:
        for vec in dk_group.get("tests", []):
            dk_bytes = bytes.fromhex(vec["dk"])
            expected_pass = vec.get("testPassed", False)
            if expected_pass:
                dk_obj = mlkem.DecapsKey.from_bytes(dk_bytes)
                assert dk_obj is not None
            else:
                with pytest.raises(ValueError):
                    mlkem.DecapsKey.from_bytes(dk_bytes)

    # Group 10: encapsulationKeyCheck
    ek_group = next((g for g in ed_groups if g.get("function") == "encapsulationKeyCheck"), None)
    if ek_group:
        for vec in ek_group.get("tests", []):
            ek_bytes = bytes.fromhex(vec["ek"])
            expected_pass = vec.get("testPassed", False)
            if expected_pass:
                ek_obj = mlkem.EncapsKey.from_bytes(ek_bytes)
                assert ek_obj is not None
            else:
                with pytest.raises(ValueError):
                    mlkem.EncapsKey.from_bytes(ek_bytes)


def test_fips203_implicit_rejection_property():
    """
    FIPS 203 Section 7.3: Decapsulating an invalid/corrupted ciphertext must NOT raise
    an unhandled exception, but must implicitly reject by outputting a pseudo-random value
    derived from the decapsulation key's rejection hash seed z.
    """
    data = _load_vectors()
    ed_groups = data.get("encap_decap_groups", [])
    aft_group = next(
        g for g in ed_groups if g.get("function") == "encapsulation" and g.get("testType") == "AFT"
    )
    vec = aft_group.get("tests", [])[0]
    dk_bytes = bytes.fromhex(vec["dk"])
    c_bytes = bytearray(bytes.fromhex(vec["c"]))
    expected_valid_k = bytes.fromhex(vec["k"])

    c_bytes[10] ^= 0x55

    kem_engine = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
    dk_obj = mlkem.DecapsKey.from_bytes(dk_bytes)

    rejected_k = bytes(kem_engine.decaps(dk_obj, bytes(c_bytes)))

    assert len(rejected_k) == MLKEM768_SS_LEN
    assert rejected_k != expected_valid_k
    rejected_k2 = bytes(kem_engine.decaps(dk_obj, bytes(c_bytes)))
    assert rejected_k == rejected_k2


def test_kem_length_boundary_validations():
    """Verifies that PostQuantumKEM rejects boundary length violations."""
    kem = PostQuantumKEM()

    with pytest.raises(KEMError):
        kem.encapsulate(b"short_key")
    with pytest.raises(KEMError):
        kem.encapsulate(b"\x00" * 1185)

    with pytest.raises(KEMError):
        kem.decapsulate(b"short_ciphertext")
    with pytest.raises(KEMError):
        kem.decapsulate(b"\x00" * 1087)
    with pytest.raises(KEMError):
        kem.decapsulate(b"\x00" * 1089)
