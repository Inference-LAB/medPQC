"""
medpqc.kem.rlwe
================
Post-Quantum Key Encapsulation Mechanism (KEM).
Supports:
  1. Standard FIPS 203 ML-KEM-768 (via liboqs if available)
  2. Native Ring-LWE KEM over Z_3329[x]/(x^256 + 1) aligned with ML-KEM-512 parameters
Generates 32-byte shared secret and ciphertext encapsulation.
"""

import os
import hashlib
import secrets
import numpy as np
from typing import Tuple

# Ring parameters matching the paper (q=3329, n=256, x^256 + 1)
Q_PRIME = 3329
N_DEG = 256

def _poly_mul_negacyclic(a: np.ndarray, b: np.ndarray, q: int = Q_PRIME) -> np.ndarray:
    """Multiplication in Z_q[x]/(x^n + 1)."""
    # Polynomial multiplication with reduction modulo x^n + 1
    conv = np.convolve(a, b)
    res = np.zeros(N_DEG, dtype=np.int64)
    for i in range(len(conv)):
        coeff = conv[i]
        deg = i % N_DEG
        sign = -1 if (i // N_DEG) % 2 == 1 else 1
        res[deg] = (res[deg] + sign * coeff) % q
    return (res % q).astype(np.int32)

def _sample_cbd(eta: int = 2) -> np.ndarray:
    """Centered Binomial Distribution sample with parameter eta=2."""
    b_len = (N_DEG * 2 * eta) // 8
    rand_bytes = secrets.token_bytes(b_len)
    bits = np.unpackbits(np.frombuffer(rand_bytes, dtype=np.uint8))[:N_DEG * 2 * eta]
    bits = bits.reshape(N_DEG, 2 * eta)
    a = bits[:, :eta].sum(axis=1)
    b = bits[:, eta:].sum(axis=1)
    return (a.astype(np.int32) - b.astype(np.int32)) % Q_PRIME

class NativeRLWEKEM:
    """
    Self-contained Ring-LWE Key Encapsulation Mechanism.
    Ring: Z_3329[x]/(x^256 + 1)
    Public Key: (a, b = a*s + e)
    Ciphertext: (u = a*r + e1, v = b*r + e2 + Encode(m))
    Shared Secret: 32 bytes derived from m via SHA3-256
    """

    def __init__(self):
        # Generate global / instance ring parameter a from seed
        self.seed_a = secrets.token_bytes(32)
        rng = np.random.default_rng(int.from_bytes(hashlib.sha3_256(self.seed_a).digest()[:8], 'big'))
        self.a = rng.integers(0, Q_PRIME, size=N_DEG, dtype=np.int32)

        # Secret key s and error e
        self.s = _sample_cbd(eta=2)
        self.e = _sample_cbd(eta=2)

        # b = a*s + e mod q
        self.b = (_poly_mul_negacyclic(self.a, self.s) + self.e) % Q_PRIME

    @property
    def public_key_bytes(self) -> bytes:
        """Export serialized public key (seed_a || b)."""
        return self.seed_a + self.b.astype('<u2').tobytes()

    @classmethod
    def encapsulate(cls, peer_pub_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a random 32-byte shared secret to peer public key.
        Returns: (ciphertext_bytes, shared_secret_32_bytes)
        """
        seed_a = peer_pub_bytes[:32]
        b_peer = np.frombuffer(peer_pub_bytes[32:], dtype='<u2').astype(np.int32)

        rng = np.random.default_rng(int.from_bytes(hashlib.sha3_256(seed_a).digest()[:8], 'big'))
        a = rng.integers(0, Q_PRIME, size=N_DEG, dtype=np.int32)

        # Random ephemeral secret r, e1, e2
        r = _sample_cbd(eta=2)
        e1 = _sample_cbd(eta=2)
        e2 = _sample_cbd(eta=2)

        # Message m in {0, 1}^256 (32 bytes)
        m_bytes = secrets.token_bytes(32)
        m_bits = np.unpackbits(np.frombuffer(m_bytes, dtype=np.uint8))
        # Encode message to ring elements (0 -> 0, 1 -> round(q/2))
        m_poly = (m_bits.astype(np.int32) * ((Q_PRIME + 1) // 2))

        # u = a*r + e1
        u = (_poly_mul_negacyclic(a, r) + e1) % Q_PRIME
        # v = b*r + e2 + m_poly
        v = (_poly_mul_negacyclic(b_peer, r) + e2 + m_poly) % Q_PRIME

        ct_bytes = u.astype('<u2').tobytes() + v.astype('<u2').tobytes()
        shared_secret = hashlib.sha3_256(m_bytes + ct_bytes).digest()
        return ct_bytes, shared_secret

    def decapsulate(self, ct_bytes: bytes) -> bytes:
        """
        Decapsulate ciphertext to recover the 32-byte shared secret.
        """
        half = N_DEG * 2
        u = np.frombuffer(ct_bytes[:half], dtype='<u2').astype(np.int32)
        v = np.frombuffer(ct_bytes[half:2*half], dtype='<u2').astype(np.int32)

        # Decrypt noisy message: v - s*u mod q
        noisy_m = (v - _poly_mul_negacyclic(u, self.s)) % Q_PRIME

        # Decode noisy coefficients to nearest bit (closer to q/2 -> 1, closer to 0/q -> 0)
        # Distance to 0 is min(x, q-x), distance to q/2 is abs(x - q/2)
        q_half = Q_PRIME / 2.0
        recovered_bits = np.zeros(N_DEG, dtype=np.uint8)
        for i in range(N_DEG):
            val = float(noisy_m[i])
            dist_zero = min(val, Q_PRIME - val)
            dist_half = abs(val - q_half)
            recovered_bits[i] = 1 if dist_half < dist_zero else 0

        m_bytes = np.packbits(recovered_bits).tobytes()
        shared_secret = hashlib.sha3_256(m_bytes + ct_bytes).digest()
        return shared_secret


class PostQuantumKEM:
    """Unified wrapper supporting liboqs ML-KEM-768 with fallback to Native RLWE."""

    def __init__(self, alg_name: str = "ML-KEM-768"):
        self.alg_name = alg_name
        self._liboqs_kem = None
        self._native_kem = None

        try:
            import oqs  # pragma: no cover
            if alg_name in oqs.get_enabled_KEM_mechanisms():  # pragma: no cover
                self._liboqs_kem = oqs.KeyEncapsulation(alg_name)
                self.public_key_bytes = self._liboqs_kem.generate_keypair()
                return
        except ImportError:
            pass

        # Fallback to Native RLWE KEM
        self._native_kem = NativeRLWEKEM()
        self.public_key_bytes = self._native_kem.public_key_bytes

    def encapsulate(self, peer_pub_bytes: bytes) -> Tuple[bytes, bytes]:
        if self._liboqs_kem is not None:  # pragma: no cover
            import oqs
            client = oqs.KeyEncapsulation(self.alg_name)
            return client.encap_secret(peer_pub_bytes)
        return NativeRLWEKEM.encapsulate(peer_pub_bytes)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if self._liboqs_kem is not None:  # pragma: no cover
            return self._liboqs_kem.decap_secret(ciphertext)
        return self._native_kem.decapsulate(ciphertext)
