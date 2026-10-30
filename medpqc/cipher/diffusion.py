"""
medpqc.cipher.diffusion
=======================
Bit-plane XOR and 3-round CBC-chained chaotic diffusion.
Accelerated using Numba JIT for sub-millisecond execution.
"""

import numpy as np

try:
    from numba import njit
except ImportError:  # pragma: no cover
    def njit(*args, **kwargs):  # pragma: no cover
        def decorator(fn):
            return fn
        return decorator

@njit(fastmath=True)
def _cbc_forward_rounds(out: np.ndarray, fs: np.ndarray, iv: int, n: int, rounds: int = 3) -> np.ndarray:
    """Fast JIT CBC forward diffusion."""
    for rnd in range(rounds):
        seg = fs[rnd * n : (rnd + 1) * n]
        out[0] = out[0] ^ iv
        for i in range(1, n):
            out[i] = out[i] ^ seg[i] ^ out[i - 1]
    return out

@njit(fastmath=True)
def _cbc_inverse_rounds(out: np.ndarray, fs: np.ndarray, iv: int, n: int, rounds: int = 3) -> np.ndarray:
    """Fast JIT CBC inverse diffusion."""
    for rnd in range(rounds - 1, -1, -1):
        seg = fs[rnd * n : (rnd + 1) * n]
        prev = out.copy()
        out[0] = prev[0] ^ iv
        for i in range(1, n):
            out[i] = prev[i] ^ seg[i] ^ prev[i - 1]
    return out

class ChaoticDiffusion:
    """Performs bit-plane XOR and multi-round CBC-chained diffusion."""

    @staticmethod
    def bitplane_diffuse(flat_bytes: np.ndarray, keystream_bytes: np.ndarray) -> np.ndarray:
        """
        Bit-plane XOR diffusion: unpacks to 8 bit-planes, applies XOR with chaotic bits,
        and repacks to bytes.
        """
        n = flat_bytes.size
        unpacked_data = np.unpackbits(flat_bytes)
        unpacked_key = np.unpackbits(keystream_bytes[:n])
        xor_bits = np.bitwise_xor(unpacked_data, unpacked_key)
        return np.packbits(xor_bits)

    @staticmethod
    def bitplane_undiffuse(diffused_bytes: np.ndarray, keystream_bytes: np.ndarray) -> np.ndarray:
        """Inverse of bitplane_diffuse (symmetric operation)."""
        return ChaoticDiffusion.bitplane_diffuse(diffused_bytes, keystream_bytes)

    @staticmethod
    def cbc_mix(flat_bytes: np.ndarray, keystream_bytes: np.ndarray, rounds: int = 3) -> np.ndarray:
        """
        3-round CBC-mode chaotic mixing.
        """
        n = flat_bytes.size
        # Resize keystream to cover all rounds
        fs = np.resize(keystream_bytes, rounds * n)
        iv = int(keystream_bytes[0])
        out = flat_bytes.copy()
        return _cbc_forward_rounds(out, fs, iv, n, rounds=rounds)

    @staticmethod
    def cbc_unmix(mixed_bytes: np.ndarray, keystream_bytes: np.ndarray, rounds: int = 3) -> np.ndarray:
        """
        Inverse of 3-round CBC-mode chaotic mixing.
        """
        n = mixed_bytes.size
        fs = np.resize(keystream_bytes, rounds * n)
        iv = int(keystream_bytes[0])
        out = mixed_bytes.copy()
        return _cbc_inverse_rounds(out, fs, iv, n, rounds=rounds)
