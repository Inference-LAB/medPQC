"""
medpqc.cipher.aead
==================
Authenticated Encryption with Associated Data (AEAD) via AES-256-GCM (NIST SP 800-38D).

Employs the standardized, hardware-accelerated AESGCM primitive from the
`cryptography` library. Cryptographically binds Associated Authenticated Data (AAD)
to prevent any envelope reconstruction metadata tampering.
"""

import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..utils.limits import DecryptionError


class AuthenticatedCipher:
    """Provides authenticated encryption with strict AAD binding via AES-256-GCM."""

    NONCE_LEN: int = 12
    KEY_LEN: int = 32
    TAG_LEN: int = 16

    @classmethod
    def encrypt(
        cls,
        data_bytes: bytes,
        aes_key: bytes,
        mac_key: bytes | None = None,
        aad: bytes = b"",
        nonce: bytes | None = None,
    ) -> dict[str, bytes]:
        """
        Encrypts plaintext bytes with AES-256-GCM and binds Associated Authenticated Data (AAD).
        Enforces a 96-bit (12-byte) random nonce per NIST SP 800-38D.
        """
        if not isinstance(aes_key, (bytes, bytearray)) or len(aes_key) != cls.KEY_LEN:
            raise ValueError(f"Invalid AES key length: {len(aes_key) if aes_key else 0}. Expected {cls.KEY_LEN} bytes.")
        if mac_key is not None and (not isinstance(mac_key, (bytes, bytearray)) or len(mac_key) != cls.KEY_LEN):
            raise ValueError(f"Invalid MAC key length: {len(mac_key)}. Expected {cls.KEY_LEN} bytes.")

        if nonce is None:
            nonce = secrets.token_bytes(cls.NONCE_LEN)
        elif not isinstance(nonce, (bytes, bytearray)) or len(nonce) != cls.NONCE_LEN:
            raise ValueError(f"Invalid nonce length: {len(nonce)}. Expected exactly {cls.NONCE_LEN} bytes.")

        if not isinstance(data_bytes, (bytes, bytearray)):
            raise TypeError("data_bytes must be bytes or bytearray")

        aesgcm = AESGCM(bytes(aes_key))
        ct_with_tag = aesgcm.encrypt(bytes(nonce), bytes(data_bytes), bytes(aad) if aad else None)

        ciphertext = ct_with_tag[: -cls.TAG_LEN]
        gcm_tag = ct_with_tag[-cls.TAG_LEN :]

        bundle: dict[str, bytes] = {
            "nonce": bytes(nonce),
            "ciphertext": ciphertext,
            "gcm_tag": gcm_tag,
        }

        if mac_key is not None:
            mac_input = bytes(nonce) + len(aad).to_bytes(4, "big") + bytes(aad) + ciphertext + gcm_tag
            bundle["outer_mac"] = hmac.new(bytes(mac_key), mac_input, hashlib.sha3_256).digest()

        return bundle

    @classmethod
    def decrypt(
        cls,
        bundle: dict[str, bytes],
        aes_key: bytes,
        mac_key: bytes | None = None,
        aad: bytes = b"",
    ) -> bytes:
        """
        Verifies GCM authentication tag and decrypts ciphertext with bound AAD.
        Raises AuthenticationError / ValueError on any authentication or ciphertext tampering.
        """
        if not isinstance(aes_key, (bytes, bytearray)) or len(aes_key) != cls.KEY_LEN:
            raise ValueError(f"Invalid AES key length: {len(aes_key) if aes_key else 0}. Expected {cls.KEY_LEN} bytes.")
        if mac_key is not None and (not isinstance(mac_key, (bytes, bytearray)) or len(mac_key) != cls.KEY_LEN):
            raise ValueError(f"Invalid MAC key length: {len(mac_key)}. Expected {cls.KEY_LEN} bytes.")

        if not isinstance(bundle, dict):
            raise ValueError("AEAD bundle must be a dictionary.")

        nonce = bundle.get("nonce")
        ciphertext = bundle.get("ciphertext")
        gcm_tag = bundle.get("gcm_tag")
        outer_mac = bundle.get("outer_mac")

        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != cls.NONCE_LEN:
            raise ValueError(f"Invalid nonce in AEAD bundle: expected {cls.NONCE_LEN} bytes.")
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise ValueError("Missing or invalid ciphertext in AEAD bundle.")
        if not isinstance(gcm_tag, (bytes, bytearray)) or len(gcm_tag) != cls.TAG_LEN:
            raise ValueError(f"Invalid GCM tag in AEAD bundle: expected {cls.TAG_LEN} bytes.")

        # Verify outer HMAC if present
        if outer_mac is not None and mac_key is not None:
            if not isinstance(outer_mac, (bytes, bytearray)) or len(outer_mac) != 32:
                raise ValueError("Invalid outer MAC in AEAD bundle.")
            mac_input = bytes(nonce) + len(aad).to_bytes(4, "big") + bytes(aad) + bytes(ciphertext) + bytes(gcm_tag)
            expected_mac = hmac.new(bytes(mac_key), mac_input, hashlib.sha3_256).digest()
            if not hmac.compare_digest(expected_mac, bytes(outer_mac)):
                raise ValueError("OUTER_HMAC_FAIL: Tampering detected or invalid MAC key.")

        ct_with_tag = bytes(ciphertext) + bytes(gcm_tag)
        aesgcm = AESGCM(bytes(aes_key))

        try:
            return aesgcm.decrypt(bytes(nonce), ct_with_tag, bytes(aad) if aad else None)
        except InvalidTag:
            raise ValueError("GCM_TAG_FAIL: Ciphertext or AAD tag mismatch.")
        except (TypeError, ValueError) as e:
            raise DecryptionError(f"DECRYPTION_FAIL: Failed to decrypt payload: {e}") from e
