"""
medpqc.cipher.diffusion
=======================
Bit-plane XOR and 3-round Chaotic Chained Diffusion (CCD).

Image-space pre-whitening and avalanche propagation layer designed to destroy
pixel structure before standard AEAD encryption.
Accelerated using Numba JIT with NumPy fallback.

Note: This is an image-domain chained XOR transformation (CCD), distinct from
the standard NIST SP 800-38A block cipher CBC encryption mode.
"""

from typing import Any, Callable

import numpy as np

try:
    from numba import njit
except ImportError:

    def njit(*args: Any, **kwargs: Any) -> Callable[[Any], Any]:  # type: ignore[no-redef]
        def decorator(fn: Any) -> Any:
            return fn

        return decorator


@njit(fastmath=True)
def _cbc_forward_rounds(out: np.ndarray, fs: np.ndarray, iv: int, n: int, rounds: int = 3) -> np.ndarray:
    """Fast JIT CCD forward diffusion."""
    for rnd in range(rounds):
        seg = fs[rnd * n : (rnd + 1) * n]
        out[0] = out[0] ^ iv
        for i in range(1, n):
            out[i] = out[i] ^ seg[i] ^ out[i - 1]
    return out


@njit(fastmath=True)
def _cbc_inverse_rounds(out: np.ndarray, fs: np.ndarray, iv: int, n: int, rounds: int = 3) -> np.ndarray:
    """Fast JIT CCD inverse diffusion."""
    for rnd in range(rounds - 1, -1, -1):
        seg = fs[rnd * n : (rnd + 1) * n]
        prev = out.copy()
        out[0] = prev[0] ^ iv
        for i in range(1, n):
            out[i] = prev[i] ^ seg[i] ^ prev[i - 1]
    return out


class ChaoticDiffusion:
    """Performs bit-plane XOR and multi-round Chaotic Chained Diffusion (CCD)."""

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
        """Inverse of bitplane_diffuse (symmetric bitwise XOR)."""
        return ChaoticDiffusion.bitplane_diffuse(diffused_bytes, keystream_bytes)

    @staticmethod
    def ccd_mix(flat_bytes: np.ndarray, keystream_bytes: np.ndarray, rounds: int = 3) -> np.ndarray:
        """
        Chaotic Chained Diffusion (CCD): multi-round forward XOR chaining.
        """
        n = flat_bytes.size
        required_len = rounds * n
        if keystream_bytes.size < required_len:
            raise ValueError(f"Keystream too short: {keystream_bytes.size} < {required_len}")

        fs = keystream_bytes[:required_len]
        iv = int(fs[0]) if fs.size > 0 else 0x5A
        out = flat_bytes.copy()
        return _cbc_forward_rounds(out, fs, iv, n, rounds)

    @staticmethod
    def ccd_unmix(mixed_bytes: np.ndarray, keystream_bytes: np.ndarray, rounds: int = 3) -> np.ndarray:
        """
        Exact inverse of Chaotic Chained Diffusion (CCD).
        """
        n = mixed_bytes.size
        required_len = rounds * n
        if keystream_bytes.size < required_len:
            raise ValueError(f"Keystream too short: {keystream_bytes.size} < {required_len}")

        fs = keystream_bytes[:required_len]
        iv = int(fs[0]) if fs.size > 0 else 0x5A
        out = mixed_bytes.copy()
        return _cbc_inverse_rounds(out, fs, iv, n, rounds)

    # Aliases for backward compatibility
    cbc_mix = ccd_mix
    cbc_unmix = ccd_unmix
