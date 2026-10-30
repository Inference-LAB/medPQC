"""
tests.test_cipher_engine
========================
Unit tests for medpqc.cipher.engine module (MedPQCCipher).
"""

import numpy as np
import pytest
from medpqc.cipher.engine import MedPQCCipher

def test_cipher_uint8_lossless_roundtrip():
    cipher = MedPQCCipher(k_aes=b"A" * 32, k_mac=b"B" * 32)
    img = np.random.randint(0, 256, size=(128, 128), dtype=np.uint8)

    enc = cipher.encrypt(img, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.dtype == np.uint8
    assert dec.shape == (128, 128)
    assert np.array_equal(img, dec)

def test_cipher_uint16_lossless_roundtrip():
    cipher = MedPQCCipher(k_aes=b"A" * 32, k_mac=b"B" * 32)
    img16 = np.random.randint(0, 4096, size=(64, 64), dtype=np.uint16)

    enc = cipher.encrypt(img16, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.dtype == np.uint16
    assert dec.shape == (64, 64)
    assert np.array_equal(img16, dec)

def test_cipher_int16_dicom_hounsfield_lossless():
    # Signed 16-bit CT image with negative Hounsfield values (-1000 air to +2000 bone)
    cipher = MedPQCCipher(k_aes=b"K" * 32, k_mac=b"M" * 32)
    ct_data = np.random.randint(-1000, 2000, size=(64, 64), dtype=np.int16)

    enc = cipher.encrypt(ct_data, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.dtype == np.int16
    assert dec.shape == (64, 64)
    assert np.array_equal(ct_data, dec)

def test_cipher_rgb_3channel_lossless():
    cipher = MedPQCCipher(k_aes=b"R" * 32, k_mac=b"G" * 32)
    rgb = np.random.randint(0, 256, size=(64, 64, 3), dtype=np.uint8)

    enc = cipher.encrypt(rgb, enable_scrambling=True)
    dec = cipher.decrypt(enc)

    assert dec.shape == (64, 64, 3)
    assert np.array_equal(rgb, dec)

def test_cipher_initialization_with_okm_none():
    cipher = MedPQCCipher(k_aes=b"1" * 32, k_mac=b"2" * 32, okm=None)
    assert cipher.okm == b"1" * 32 + b"2" * 32

def test_cipher_from_shared_secrets():
    cipher = MedPQCCipher.from_shared_secrets(k_ecdh=b"E" * 32, k_pq=b"P" * 32)
    assert len(cipher.k_aes) == 32
    assert len(cipher.k_mac) == 32
    assert len(cipher.okm) == 64

def test_cipher_without_scrambling():
    cipher = MedPQCCipher(k_aes=b"X" * 32, k_mac=b"Y" * 32)
    img = np.random.randint(0, 256, size=(32, 32), dtype=np.uint8)
    enc = cipher.encrypt(img, enable_scrambling=False)
    dec = cipher.decrypt(enc)
    assert np.array_equal(img, dec)

def test_cipher_tamper_rejection():
    cipher = MedPQCCipher(k_aes=b"T" * 32, k_mac=b"A" * 32)
    img = np.zeros((32, 32), dtype=np.uint8)
    enc = cipher.encrypt(img)

    # Flip 1 bit in ciphertext
    ct = bytearray(enc['aead']['ciphertext'])
    ct[10] ^= 0x01
    enc['aead']['ciphertext'] = bytes(ct)

    with pytest.raises(ValueError):
        cipher.decrypt(enc)
