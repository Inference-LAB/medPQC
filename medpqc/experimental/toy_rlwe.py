"""
medpqc.experimental.toy_rlwe
============================
Custom non-standard Ring-LWE demonstration for educational and comparative research only.

WARNING:
THIS IS A TOY IMPLEMENTATION. It does NOT implement NIST FIPS 203 Module-LWE
(rank k=3) and must NOT be used for production clinical workflows or claimed
as standard post-quantum cryptography.
"""

import hashlib
import secrets
from typing import cast

import numpy as np


class ExperimentalToyRLWE:
    """
    Experimental educational Ring-LWE construction.
    NOT FIPS 203 ML-KEM.
    """

    Q_PRIME = 3329
    N_DEG = 256

    def __init__(self) -> None:
        self.seed_a = secrets.token_bytes(32)
        rng = np.random.default_rng(int.from_bytes(hashlib.sha3_256(self.seed_a).digest()[:8], "big"))
        self.a = rng.integers(0, self.Q_PRIME, size=self.N_DEG, dtype=np.int32)
        self.s = self._sample_cbd(eta=2)
        self.e = self._sample_cbd(eta=2)
        self.b = (self._poly_mul(self.a, self.s) + self.e) % self.Q_PRIME

    @classmethod
    def _poly_mul(cls, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        conv = np.convolve(a, b)
        res = np.zeros(cls.N_DEG, dtype=np.int64)
        for i in range(len(conv)):
            deg = i % cls.N_DEG
            sign = -1 if (i // cls.N_DEG) % 2 == 1 else 1
            res[deg] = (res[deg] + sign * conv[i]) % cls.Q_PRIME
        return (res % cls.Q_PRIME).astype(np.int32)

    @classmethod
    def _sample_cbd(cls, eta: int = 2) -> np.ndarray:
        b_len = (cls.N_DEG * 2 * eta) // 8
        rand_bytes = secrets.token_bytes(b_len)
        bits = np.unpackbits(np.frombuffer(rand_bytes, dtype=np.uint8))[: cls.N_DEG * 2 * eta]
        bits = bits.reshape(cls.N_DEG, 2 * eta)
        a = bits[:, :eta].sum(axis=1)
        b = bits[:, eta:].sum(axis=1)
        return cast(np.ndarray, (a.astype(np.int32) - b.astype(np.int32)) % cls.Q_PRIME)

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self.seed_a + self.b.astype("<u2").tobytes())

    @classmethod
    def encapsulate(cls, peer_pub_bytes: bytes) -> tuple[bytes, bytes]:
        seed_a = peer_pub_bytes[:32]
        b_peer = np.frombuffer(peer_pub_bytes[32:], dtype="<u2").astype(np.int32)
        rng = np.random.default_rng(int.from_bytes(hashlib.sha3_256(seed_a).digest()[:8], "big"))
        a = rng.integers(0, cls.Q_PRIME, size=cls.N_DEG, dtype=np.int32)
        r = cls._sample_cbd(eta=2)
        e1 = cls._sample_cbd(eta=2)
        e2 = cls._sample_cbd(eta=2)
        m_bytes = secrets.token_bytes(32)
        m_bits = np.unpackbits(np.frombuffer(m_bytes, dtype=np.uint8))
        m_poly = m_bits.astype(np.int32) * ((cls.Q_PRIME + 1) // 2)
        u = (cls._poly_mul(a, r) + e1) % cls.Q_PRIME
        v = (cls._poly_mul(b_peer, r) + e2 + m_poly) % cls.Q_PRIME
        ct = u.astype("<u2").tobytes() + v.astype("<u2").tobytes()
        ss = hashlib.sha3_256(m_bytes + ct).digest()
        return ct, ss

    def decapsulate(self, ct_bytes: bytes) -> bytes:
        half = self.N_DEG * 2
        u = np.frombuffer(ct_bytes[:half], dtype="<u2").astype(np.int32)
        v = np.frombuffer(ct_bytes[half : 2 * half], dtype="<u2").astype(np.int32)
        noisy_m = (v - self._poly_mul(u, self.s)) % self.Q_PRIME
        q_half = self.Q_PRIME / 2.0
        recovered_bits = np.zeros(self.N_DEG, dtype=np.uint8)
        for i in range(self.N_DEG):
            val = float(noisy_m[i])
            dist_zero = min(val, self.Q_PRIME - val)
            dist_half = abs(val - q_half)
            recovered_bits[i] = 1 if dist_half < dist_zero else 0
        m_bytes = np.packbits(recovered_bits).tobytes()
        return hashlib.sha3_256(m_bytes + ct_bytes).digest()
