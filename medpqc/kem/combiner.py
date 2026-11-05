"""
medpqc.kem.combiner
===================
Hybrid Classical/Post-Quantum Key Derivation.

Combines Classical (ECDH P-256) and Post-Quantum (NIST FIPS 203 ML-KEM-768)
shared secrets using RFC 5869 HKDF-SHA-512 with strict dual-transcript binding
and per-direction key separation:
  - k_enc_i2r (32 bytes): Initiator -> Responder AES-256-GCM encryption key
  - k_enc_r2i (32 bytes): Responder -> Initiator AES-256-GCM encryption key
  - session_key_id (16 bytes): Canonical Key Identifier for envelope binding

Guarantees:
  - Hybrid Defense: Protection is maintained if either classical or post-quantum hardness assumption holds.
  - Direction Separation: Independent cryptographic keys for each transmission direction.
  - Strict Transcript Binding: Canonical length-prefixed framing preventing key substitution.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..utils.canonical import length_prefix_encode

KDF_SALT_CONSTANT = b"MedPQC-v2.4-KeyDerivation-Salt"


def hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Standard RFC 5869 HKDF using SHA-512 via cryptography.hazmat.
    Fails hard if unavailable; never performs silent algorithm fallbacks.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt if salt else bytes(64),
        info=info,
    )
    return hkdf.derive(ikm)


# RFC 5869 compatibility alias
def hkdf_extract_and_expand(
    ikm: bytes,
    salt: bytes = b"",
    info: bytes = b"HybridImageKEM-v2.4",
    length: int = 64,
) -> bytes:
    return hkdf_sha512(ikm, salt, info, length)


def build_session_context(
    protocol_version: str = "MedPQC-v2.4",
    suite_id: str = "ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",
    sender_id: str = "client-pacs",
    receiver_id: str = "server-pacs",
    sender_ecdh_pub: bytes = b"",
    receiver_ecdh_pub: bytes = b"",
    pq_ciphertext: bytes = b"",
    session_id: bytes = b"",
    sender_id_pub: bytes = b"",
    receiver_id_pub: bytes = b"",
    transcript_hash: bytes | None = None,
) -> bytes:
    """
    Constructs a length-prefixed canonical session context string binding all protocol entities.
    """
    elements = [
        b"MedPQC-SessionContext-v2.4",
        protocol_version.encode("utf-8"),
        suite_id.encode("utf-8"),
        sender_id.encode("utf-8"),
        receiver_id.encode("utf-8"),
        session_id,
        sender_id_pub,
        receiver_id_pub,
        sender_ecdh_pub,
        receiver_ecdh_pub,
        pq_ciphertext,
        transcript_hash if transcript_hash is not None else b"",
    ]
    return length_prefix_encode(elements)


class HybridKeyCombiner:
    """
    Domain-separated hybrid key combiner.
    Derives directional encryption keys and session identifiers from combined secrets.
    """

    @classmethod
    def derive_session_keys_strict(
        cls,
        k_ecdh: bytes,
        k_pq: bytes,
        sender_ecdh_pub: bytes,
        receiver_ecdh_pub: bytes,
        pq_ciphertext: bytes,
        sender_id: str,
        receiver_id: str,
        session_id: bytes,
        transcript_hash: bytes,
        suite_id: str = "ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",
        protocol_version: str = "MedPQC-v2.4",
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """
        Strict RFC 5869 HKDF-SHA-512 derivation binding all session and transcript components.
        Returns:
          (k_enc_i2r [32B], k_enc_r2i [32B], session_key_id [16B])
        """
        if len(k_ecdh) != 32 or len(k_pq) != 32:
            raise ValueError(
                f"Invalid shared secret lengths: ECDH={len(k_ecdh)}, PQ={len(k_pq)}. "
                "Expected exactly 32 bytes for each shared secret."
            )

        ikm = length_prefix_encode(
            [
                b"MedPQC-StrictIKM-v2.4",
                k_ecdh,
                k_pq,
                sender_ecdh_pub,
                receiver_ecdh_pub,
                pq_ciphertext,
                sender_id.encode("utf-8"),
                receiver_id.encode("utf-8"),
                session_id,
                transcript_hash,
                suite_id.encode("utf-8"),
                protocol_version.encode("utf-8"),
            ]
        )

        effective_salt = salt if salt is not None else KDF_SALT_CONSTANT

        k_enc_i2r = hkdf_sha512(
            ikm,
            effective_salt,
            info=b"MedPQC-v2.4|initiator-to-responder-aes256gcm",
            length=32,
        )
        k_enc_r2i = hkdf_sha512(
            ikm,
            effective_salt,
            info=b"MedPQC-v2.4|responder-to-initiator-aes256gcm",
            length=32,
        )
        session_key_id = hkdf_sha512(
            ikm,
            effective_salt,
            info=b"MedPQC-v2.4|session-key-identifier",
            length=16,
        )

        return k_enc_i2r, k_enc_r2i, session_key_id

    derive_transcript_bound_keys = derive_session_keys_strict

    @staticmethod
    def derive_directional_keys(
        k_ecdh: bytes,
        k_pq: bytes,
        transcript_hash: bytes,
        sender_ecdh_pub: bytes,
        receiver_ecdh_pub: bytes,
        pq_ciphertext: bytes,
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """
        Derives per-direction keys using length-prefixed canonical IKM.
        Returns:
          (k_enc_i2r [32B], k_enc_r2i [32B], session_key_id [16B])
        """
        return HybridKeyCombiner.derive_session_keys_strict(
            k_ecdh=k_ecdh,
            k_pq=k_pq,
            sender_ecdh_pub=sender_ecdh_pub,
            receiver_ecdh_pub=receiver_ecdh_pub,
            pq_ciphertext=pq_ciphertext,
            sender_id="",
            receiver_id="",
            session_id=b"",
            transcript_hash=transcript_hash,
            salt=salt,
        )

    @staticmethod
    def combine(
        k_ecdh: bytes,
        k_pq: bytes,
        salt: bytes | None = None,
        context: bytes | None = None,
        info: bytes = b"HybridImageKEM-v2.4",
    ) -> tuple[bytes, bytes, bytes]:
        """
        Backwards-compatible interface returning directional keys:
        Returns: (k_enc_i2r [32 bytes], k_enc_r2i [32 bytes], session_key_id [16 bytes])
        """
        if len(k_ecdh) != 32 or len(k_pq) != 32:
            raise ValueError("Expected exactly 32 bytes for each shared secret.")

        ikm = length_prefix_encode([k_ecdh, k_pq])
        effective_salt = salt if salt is not None else KDF_SALT_CONSTANT
        ctx = context if context is not None else info

        k_i2r = hkdf_sha512(ikm, effective_salt, ctx + b"|i2r", 32)
        k_r2i = hkdf_sha512(ikm, effective_salt, ctx + b"|r2i", 32)
        k_id = hkdf_sha512(ikm, effective_salt, ctx + b"|id", 16)

        return k_i2r, k_r2i, k_id

    @staticmethod
    def derive_all_keys(
        k_ecdh: bytes,
        k_pq: bytes,
        session_context: bytes = b"",
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """
        Derives (k_aes [32B], k_mac [32B], s_chaos [32B]) for symmetric engine.
        Total length of combined key material (okm) is 96 bytes.
        """
        if len(k_ecdh) != 32 or len(k_pq) != 32:
            raise ValueError("Expected exactly 32 bytes for each shared secret.")

        ikm = length_prefix_encode([k_ecdh, k_pq])
        effective_salt = salt if salt is not None else KDF_SALT_CONSTANT
        ctx = session_context if session_context else b"MedPQC-v2.4|engine-keys"

        okm = hkdf_sha512(ikm, effective_salt, ctx, 96)
        k_aes = okm[:32]
        k_mac = okm[32:64]
        s_chaos = okm[64:96]
        return k_aes, k_mac, s_chaos
