"""
tests.test_cipher_engine
========================
Unit tests for medpqc.cipher.engine module (MedPQCCipher & validate_metadata).
Validates lossless roundtrips across all bit-depths, strict metadata range/type validation,
and AAD metadata tampering rejection (including retained DICOM headers).
"""

import numpy as np
import pytest
from medpqc.cipher.engine import MedPQCCipher, validate_metadata

def test_cipher_uint8_lossless_roundtrip():
    cipher = MedPQCCipher(k_aes=b"A" * 32, k_mac=b"B" * 32)
    img = np.random.randint(0, 256, size=(64, 64), dtype=np.uint8)

    enc = cipher.encrypt(img, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.dtype == np.uint8
    assert dec.shape == (64, 64)
    assert np.array_equal(img, dec)

def test_cipher_uint16_lossless_roundtrip():
    cipher = MedPQCCipher(k_aes=b"A" * 32, k_mac=b"B" * 32)
    img16 = np.random.randint(0, 4096, size=(32, 32), dtype=np.uint16)

    enc = cipher.encrypt(img16, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.dtype == np.uint16
    assert dec.shape == (32, 32)
    assert np.array_equal(img16, dec)

def test_cipher_int16_dicom_hounsfield_lossless():
    cipher = MedPQCCipher(k_aes=b"K" * 32, k_mac=b"M" * 32)
    ct_data = np.random.randint(-1000, 2000, size=(32, 32), dtype=np.int16)

    enc = cipher.encrypt(ct_data, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.dtype == np.int16
    assert dec.shape == (32, 32)
    assert np.array_equal(ct_data, dec)

def test_cipher_rgb_3channel_lossless():
    cipher = MedPQCCipher(k_aes=b"R" * 32, k_mac=b"G" * 32)
    rgb = np.random.randint(0, 256, size=(32, 32, 3), dtype=np.uint8)

    enc = cipher.encrypt(rgb, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.shape == (32, 32, 3)
    assert np.array_equal(rgb, dec)

def test_cipher_initialization_with_okm_none():
    cipher = MedPQCCipher(k_aes=b"1" * 32, k_mac=b"2" * 32, okm=None)
    assert cipher.okm == (b"1" * 32 + b"2" * 32)

def test_cipher_s_chaos_and_okm_initializations():
    k32_a = b"1" * 32
    k32_m = b"2" * 32

    # Positional 96-byte OKM
    c96 = MedPQCCipher(k32_a, k32_m, b"X" * 96)
    assert len(c96.okm) == 96
    assert c96.s_chaos == b"X" * 32

    # Explicit 32-byte s_chaos
    c32 = MedPQCCipher(k32_a, k32_m, s_chaos=b"S" * 32)
    assert c32.s_chaos == b"S" * 32

    # Invalid length s_chaos
    with pytest.raises(ValueError, match="Invalid s_chaos length"):
        MedPQCCipher(k32_a, k32_m, s_chaos=b"bad_len")

    # Explicit okm of 96 bytes
    c_okm96 = MedPQCCipher(k32_a, k32_m, okm=b"O" * 96)
    assert c_okm96.s_chaos == b"O" * 32

    # Explicit okm of <96 bytes
    c_okm64 = MedPQCCipher(k32_a, k32_m, okm=b"O" * 64)
    assert len(c_okm64.s_chaos) == 32

def test_cipher_invalid_key_lengths_raises():
    with pytest.raises(ValueError, match="Invalid AES key length"):
        MedPQCCipher(k_aes=b"short", k_mac=b"B" * 32)
    with pytest.raises(ValueError, match="Invalid MAC key length"):
        MedPQCCipher(k_aes=b"A" * 32, k_mac=b"short")

def test_cipher_from_shared_secrets():
    cipher = MedPQCCipher.from_shared_secrets(k_ecdh=b"E" * 32, k_pq=b"P" * 32)
    assert len(cipher.k_aes) == 32
    assert len(cipher.k_mac) == 32
    assert len(cipher.okm) == 96

def test_cipher_without_scrambling():
    cipher = MedPQCCipher(k_aes=b"X" * 32, k_mac=b"Y" * 32)
    img = np.random.randint(0, 256, size=(32, 32), dtype=np.uint8)
    enc = cipher.encrypt(img, enable_scrambling=False)
    dec = cipher.decrypt(enc)
    assert np.array_equal(img, dec)

def test_cipher_retained_headers_roundtrip_and_tamper():
    cipher = MedPQCCipher(k_aes=b"H" * 32, k_mac=b"R" * 32)
    img = np.zeros((32, 32), dtype=np.uint8)
    retained = {'Modality': 'CT', 'Rows': 32, 'Columns': 32}

    enc = cipher.encrypt(img, retained_headers=retained)
    dec = cipher.decrypt(enc)
    assert np.array_equal(img, dec)

    # Tamper with retained header in metadata
    tampered_bundle = dict(enc)
    tampered_headers = dict(retained)
    tampered_headers['Modality'] = 'MR'
    tampered_bundle['retained_headers'] = tampered_headers
    with pytest.raises(ValueError):
        cipher.decrypt(tampered_bundle)

def test_cipher_ciphertext_tamper_rejection():
    cipher = MedPQCCipher(k_aes=b"T" * 32, k_mac=b"A" * 32)
    img = np.zeros((32, 32), dtype=np.uint8)
    enc = cipher.encrypt(img)

    ct = bytearray(enc['aead']['ciphertext'])
    ct[10] ^= 0x01
    enc['aead']['ciphertext'] = bytes(ct)

    with pytest.raises(ValueError):
        cipher.decrypt(enc)

def test_validate_metadata_edges():
    # 1D not allowed
    with pytest.raises(ValueError, match="Expected 2D or 3D"):
        validate_metadata((100,), "uint8", 100, "2.1.0")

    # 4D not allowed
    with pytest.raises(ValueError, match="Expected 2D or 3D"):
        validate_metadata((2, 2, 2, 2), "uint8", 16, "2.1.0")

    # Zero or negative dim
    with pytest.raises(ValueError, match="outside permitted range"):
        validate_metadata((-5, 10), "uint8", 50, "2.1.0")
    with pytest.raises(ValueError, match="outside permitted range"):
        validate_metadata((100000, 10), "uint8", 1000000, "2.1.0")

    # Unsupported dtype
    with pytest.raises(ValueError, match="Unsupported dtype"):
        validate_metadata((10, 10), "complex128", 1600, "2.1.0")
    with pytest.raises(ValueError, match="Unsupported dtype"):
        validate_metadata((10, 10), "invalid_dtype_str", 100, "2.1.0")

    # Byte count mismatch
    with pytest.raises(ValueError, match="Byte count mismatch"):
        validate_metadata((10, 10), "uint8", 99, "2.1.0")

    # Unsupported version
    with pytest.raises(ValueError, match="Unsupported protocol version"):
        validate_metadata((10, 10), "uint8", 100, "0.1.0")
