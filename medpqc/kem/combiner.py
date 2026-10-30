"""
medpqc.kem.combiner
====================
Hybrid KEM Key Combiner using HKDF-SHA3-512 / HKDF-SHA512.
Combines Classical (ECDH) and Post-Quantum (RLWE / ML-KEM) shared secrets
to produce a 64-byte Output Keying Material (OKM).
"""

import hashlib
import hmac
from typing import Tuple

def hkdf_extract_and_expand(
    ikm: bytes,
    salt: bytes = b"",
    info: bytes = b"HybridImageKEM-v1",
    length: int = 64
) -> bytes:
    """
    RFC 5869 HKDF using SHA3-512 (fallback to SHA-512).
    """
    hash_fn = hashlib.sha3_512 if hasattr(hashlib, 'sha3_512') else hashlib.sha512
    hash_len = 64

    if not salt:
        salt = bytes(hash_len)

    # Step 1: Extract (PRK = HMAC-Hash(salt, IKM))
    prk = hmac.new(salt, ikm, hash_fn).digest()

    # Step 2: Expand (OKM = T(1) || T(2) || ...)
    t_prev = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t_curr = hmac.new(prk, t_prev + info + bytes([counter]), hash_fn).digest()
        okm += t_curr
        t_prev = t_curr
        counter += 1

    return okm[:length]

class HybridKeyCombiner:
    """Combines classical and post-quantum keys into AES & MAC keys."""

    @staticmethod
    def combine(
        k_ecdh: bytes,
        k_pq: bytes,
        salt: bytes = b"MedPQC-Salt-2026",
        info: bytes = b"HybridImageKEM-v1"
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Derives 64-byte OKM from concatenation k_ecdh || k_pq.
        Returns: (k_aes [32 bytes], k_mac [32 bytes], okm [64 bytes])
        """
        ikm = k_ecdh + k_pq
        okm = hkdf_extract_and_expand(ikm, salt=salt, info=info, length=64)
        k_aes = okm[0:32]
        k_mac = okm[32:64]
        return k_aes, k_mac, okm
