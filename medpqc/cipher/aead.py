"""
medpqc.cipher.aead
==================
Authenticated Encryption with Associated Data (AEAD).
Combines AES-256-GCM (NIST SP 800-38D) with outer HMAC-SHA3-256 for key commitment.
"""

import hmac
import hashlib
import secrets
from typing import Dict, Any
from Crypto.Cipher import AES

class AuthenticatedCipher:
    """Provides IND-CCA2 and INT-CTXT authenticated encryption."""

    @staticmethod
    def encrypt(data_bytes: bytes, aes_key: bytes, mac_key: bytes) -> Dict[str, bytes]:
        """
        Encrypts plaintext bytes with AES-256-GCM and computes outer HMAC key commitment.
        Returns: {
            'nonce': 12 bytes,
            'ciphertext': bytes,
            'gcm_tag': 16 bytes,
            'outer_mac': 32 bytes
        }
        """
        nonce = secrets.token_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, gcm_tag = cipher.encrypt_and_digest(data_bytes)

        # Outer HMAC: authenticates the full bundle (nonce || ciphertext || tag)
        mac_input = nonce + ciphertext + gcm_tag
        outer_mac = hmac.new(mac_key, mac_input, hashlib.sha3_256).digest()

        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'gcm_tag': gcm_tag,
            'outer_mac': outer_mac
        }

    @staticmethod
    def decrypt(bundle: Dict[str, bytes], aes_key: bytes, mac_key: bytes) -> bytes:
        """
        Verifies outer HMAC and GCM tag before decrypting (Verify-then-Decrypt).
        Raises ValueError on any authentication or tampering failure.
        """
        nonce = bundle['nonce']
        ciphertext = bundle['ciphertext']
        gcm_tag = bundle['gcm_tag']
        outer_mac = bundle['outer_mac']

        # 1. Fast outer HMAC verification (protects against oracle attacks)
        expected_mac = hmac.new(mac_key, nonce + ciphertext + gcm_tag, hashlib.sha3_256).digest()
        if not hmac.compare_digest(expected_mac, outer_mac):
            raise ValueError("OUTER_HMAC_FAIL: Tampering detected or invalid MAC key.")

        # 2. AES-256-GCM tag verification & decryption
        try:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, gcm_tag)
            return plaintext
        except ValueError:
            raise ValueError("GCM_TAG_FAIL: Ciphertext corrupted or wrong AES key.")
