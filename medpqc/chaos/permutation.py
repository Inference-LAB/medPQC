"""
medpqc.chaos.permutation
=========================
Chaotic Pixel Permutation / Scrambling.

Eliminates adjacent-pixel correlation in structured medical images.
Driven deterministically by the Lorenz chaotic attractor via entropy distillation.
Lossless round-trip guaranteed: InversePermute(Permute(X)) == X.
"""

from typing import Tuple
import hashlib
import numpy as np
from .lorenz import LorenzChaosEngine

class ChaoticPermuter:
    """Chaotic permutation engine to break spatial adjacent-pixel correlation."""

    @staticmethod
    def generate_permutation_indices(seed_bytes: bytes, n_elements: int) -> np.ndarray:
        """
        Derive bijective permutation indices of length `n_elements` using argsort
        over decoupled chaotic trajectory states.
        """
        # Step stride and chaotic float extraction to decouple adjacent steps
        n_needed = n_elements
        # Generate trajectory with stride
        raw_stream = LorenzChaosEngine.generate_keystream(seed_bytes, n_needed * 2, warmup=1500)
        # Decouple adjacent values using stride sampling and hash mixing
        stride = 2
        decoupled = raw_stream[:n_needed * stride:stride].copy()
        
        # Salt with SHA3 to break any residual low-frequency phase correlations
        salt = hashlib.sha3_256(seed_bytes + b"perm-salt").digest()
        salt_ints = np.frombuffer(salt * ((n_needed // 32) + 1), dtype=np.uint8)[:n_needed]
        mixed = decoupled + (salt_ints.astype(np.float64) / 256.0)

        perm_indices = np.argsort(mixed)
        return perm_indices

    @staticmethod
    def permute(data_1d: np.ndarray, seed_bytes: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """
        Permute a 1D array using chaotic index mapping.
        Returns: (permuted_array, perm_indices)
        """
        n = data_1d.size
        idx = ChaoticPermuter.generate_permutation_indices(seed_bytes, n)
        return data_1d[idx], idx

    @staticmethod
    def inverse_permute(permuted_1d: np.ndarray, seed_bytes: bytes) -> np.ndarray:
        """
        Invert the chaotic permutation to restore original order.
        """
        n = permuted_1d.size
        idx = ChaoticPermuter.generate_permutation_indices(seed_bytes, n)
        inv_idx = np.empty_like(idx)
        inv_idx[idx] = np.arange(n)
        return permuted_1d[inv_idx]
