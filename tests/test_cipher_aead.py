"""
tests.test_cipher_aead
======================
Unit tests for medpqc.cipher.aead module.
"""

import secrets
import pytest
from medpqc.cipher.aead import AuthenticatedCipher

def test_aead_encrypt_decrypt_roundtrip():
    aes_key = secrets.token_bytes(32)
    mac_key = secrets.token_bytes(32)
    plaintext = b"Highly confidential clinical medical DICOM payload"

    bundle = AuthenticatedCipher.encrypt(plaintext, aes_key, mac_key)
    assert 'nonce' in bundle and len(bundle['nonce']) == 12
    assert 'ciphertext' in bundle
    assert 'gcm_tag' in bundle and len(bundle['gcm_tag']) == 16
    assert 'outer_mac' in bundle and len(bundle['outer_mac']) == 32

    recovered = AuthenticatedCipher.decrypt(bundle, aes_key, mac_key)
    assert recovered == plaintext

def test_aead_tamper_detection_ciphertext():
    aes_key = secrets.token_bytes(32)
    mac_key = secrets.token_bytes(32)
    plaintext = b"Radiology report CT chest scan"

    bundle = AuthenticatedCipher.encrypt(plaintext, aes_key, mac_key)
    # Tamper with 1 bit in ciphertext
    ct_tampered = bytearray(bundle['ciphertext'])
    ct_tampered[0] ^= 0x01
    bundle['ciphertext'] = bytes(ct_tampered)

    with pytest.raises(ValueError, match="OUTER_HMAC_FAIL"):
        AuthenticatedCipher.decrypt(bundle, aes_key, mac_key)

def test_aead_tamper_detection_tag():
    aes_key = secrets.token_bytes(32)
    mac_key = secrets.token_bytes(32)
    plaintext = b"Radiology report CT chest scan"

    bundle = AuthenticatedCipher.encrypt(plaintext, aes_key, mac_key)
    # Tamper with GCM tag
    tag_tampered = bytearray(bundle['gcm_tag'])
    tag_tampered[0] ^= 0x01
    bundle['gcm_tag'] = bytes(tag_tampered)

    with pytest.raises(ValueError, match="OUTER_HMAC_FAIL"):
        AuthenticatedCipher.decrypt(bundle, aes_key, mac_key)

def test_aead_wrong_aes_key_rejection():
    aes_key = secrets.token_bytes(32)
    wrong_aes = secrets.token_bytes(32)
    mac_key = secrets.token_bytes(32)
    plaintext = b"Payload with valid MAC key but wrong AES key"

    bundle = AuthenticatedCipher.encrypt(plaintext, aes_key, mac_key)

    with pytest.raises(ValueError, match="GCM_TAG_FAIL"):
        AuthenticatedCipher.decrypt(bundle, wrong_aes, mac_key)
