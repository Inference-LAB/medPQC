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

def test_aead_with_aad_roundtrip_and_tamper():
    aes_key = secrets.token_bytes(32)
    mac_key = secrets.token_bytes(32)
    plaintext = b"DICOM image payload"
    aad = b"Metadata: Rows=512, Columns=512, BitsAllocated=16"

    bundle = AuthenticatedCipher.encrypt(plaintext, aes_key, mac_key, aad=aad)
    recovered = AuthenticatedCipher.decrypt(bundle, aes_key, mac_key, aad=aad)
    assert recovered == plaintext

    # Tamper with AAD
    tampered_aad = b"Metadata: Rows=512, Columns=512, BitsAllocated=08"
    with pytest.raises(ValueError, match="OUTER_HMAC_FAIL"):
        AuthenticatedCipher.decrypt(bundle, aes_key, mac_key, aad=tampered_aad)

def test_aead_validation_errors():
    k32 = b"K" * 32
    pt = b"test payload"

    # Encrypt invalid keys/nonce
    with pytest.raises(ValueError, match="Invalid AES key length"):
        AuthenticatedCipher.encrypt(pt, b"short", k32)
    with pytest.raises(ValueError, match="Invalid MAC key length"):
        AuthenticatedCipher.encrypt(pt, k32, b"short")
    with pytest.raises(ValueError, match="Invalid nonce length"):
        AuthenticatedCipher.encrypt(pt, k32, k32, nonce=b"bad_nonce")

    # Encrypt valid custom nonce
    custom_nonce = b"\x01" * 12
    bundle = AuthenticatedCipher.encrypt(pt, k32, k32, nonce=custom_nonce)
    assert bundle['nonce'] == custom_nonce

    # Decrypt invalid keys/bundle
    with pytest.raises(ValueError, match="Invalid AES key length"):
        AuthenticatedCipher.decrypt(bundle, b"bad", k32)
    with pytest.raises(ValueError, match="Invalid MAC key length"):
        AuthenticatedCipher.decrypt(bundle, k32, b"bad")
    with pytest.raises(ValueError, match="AEAD bundle must be a dictionary"):
        AuthenticatedCipher.decrypt("not-a-dict", k32, k32)

    # Corrupt bundle components
    b_bad_nonce = dict(bundle, nonce=b"short")
    with pytest.raises(ValueError, match="Invalid nonce in AEAD bundle"):
        AuthenticatedCipher.decrypt(b_bad_nonce, k32, k32)

    b_bad_ct = dict(bundle, ciphertext="not_bytes")
    with pytest.raises(ValueError, match="Missing or invalid ciphertext in AEAD bundle"):
        AuthenticatedCipher.decrypt(b_bad_ct, k32, k32)

    b_bad_tag = dict(bundle, gcm_tag=b"short")
    with pytest.raises(ValueError, match="Invalid GCM tag in AEAD bundle"):
        AuthenticatedCipher.decrypt(b_bad_tag, k32, k32)

    b_bad_mac = dict(bundle, outer_mac=b"short")
    with pytest.raises(ValueError, match="Invalid outer MAC in AEAD bundle"):
        AuthenticatedCipher.decrypt(b_bad_mac, k32, k32)
