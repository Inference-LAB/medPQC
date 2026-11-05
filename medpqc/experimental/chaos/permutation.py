"""
medpqc.chaos.permutation
=========================
Bijective Chaotic Coordinate Sorting and Fisher-Yates Permutations.

Eliminates spatial adjacent-pixel correlation in structured medical images.
Provides two distinct bijective permutation algorithms:
  1. Coordinate Sorting Permutation:
     Sorts double-precision keystream floats derived from the Lorenz continuous
     dynamical attractor, perturbed with SHA3-256 salt to decouple periodicities.
  2. Unbiased Chaotic Fisher-Yates Shuffle:
     Performs an unbiased permutation shuffle using chaotic entropy stream,
     eliminating cycle bias on large medical image buffers.

Both constructions guarantee exact lossless inversion (MSE = 0.0):
  InversePermute(Permute(X)) == X
"""

import hashlib

import numpy as np

from .sponge import ChaoticEntropySponge


class ChaoticPermuter:
    """
    Chaotic spatial coordinate permuter to break spatial adjacent-pixel correlation.
    Supports both sorting permutation and unbiased Fisher-Yates shuffling.
    """

    @staticmethod
    def generate_permutation_indices(seed_bytes: bytes, n_elements: int) -> np.ndarray:
        """
        Derives a bijective coordinate permutation of length `n_elements`.
        Sorts continuous chaotic sponge floats perturbed with SHA3-256 salt.
        """
        if n_elements <= 0:
            raise ValueError(f"n_elements must be positive, got {n_elements}")

        # Extract chaotic uniform keystream from sponge
        raw_bytes = ChaoticEntropySponge.extract_uint8_stream(seed_bytes, n_elements * 2)
        u16 = np.frombuffer(raw_bytes, dtype="<u2")[:n_elements].astype(np.float64)

        # Salt with SHA3 to decouple any residual periodicities
        salt_seed = hashlib.sha3_256(seed_bytes + b"perm-salt-v2.2").digest()
        salt_stream = np.frombuffer(ChaoticEntropySponge.extract_uint8_stream(salt_seed, n_elements * 2), dtype="<u2")[
            :n_elements
        ].astype(np.float64)

        mixed = u16 + (salt_stream / 65536.0)
        return np.argsort(mixed)

    @staticmethod
    def generate_fisher_yates_indices(seed_bytes: bytes, n_elements: int) -> np.ndarray:
        """
        Derives an unbiased permutation of length `n_elements` using chaotic Fisher-Yates shuffle
        with rejection sampling to eliminate modulo bias.
        """
        if n_elements <= 0:
            raise ValueError(f"n_elements must be positive, got {n_elements}")
        if n_elements == 1:
            return np.zeros(1, dtype=np.int64)

        chunk_size = max(1024, n_elements * 2)
        counter = 0
        buffer = np.empty(0, dtype=np.uint32)
        buf_idx = 0

        def get_next_u32() -> int:
            nonlocal buffer, buf_idx, counter
            if buf_idx >= len(buffer):
                subseed = hashlib.sha3_256(seed_bytes + b"fisher-yates-v2.3:" + counter.to_bytes(4, "big")).digest()
                raw_bytes = ChaoticEntropySponge.extract_uint8_stream(subseed, chunk_size * 4)
                buffer = np.frombuffer(raw_bytes, dtype="<u4")
                buf_idx = 0
                counter += 1
            val = int(buffer[buf_idx])
            buf_idx += 1
            return val

        indices = np.arange(n_elements, dtype=np.int64)
        for i in range(n_elements - 1, 0, -1):
            m = i + 1
            limit = (0x100000000 // m) * m
            while True:
                sample = get_next_u32()
                if sample < limit:
                    j = sample % m
                    break
            indices[i], indices[j] = indices[j], indices[i]

        return indices

    @staticmethod
    def permute(data_1d: np.ndarray, seed_bytes: bytes) -> tuple[np.ndarray, np.ndarray]:
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
        Losslessly inverts the chaotic sorting permutation.
        """
        n = permuted_1d.size
        idx = ChaoticPermuter.generate_permutation_indices(seed_bytes, n)
        recovered = np.empty_like(permuted_1d)
        recovered[idx] = permuted_1d
        return recovered

    @staticmethod
    def fisher_yates_shuffle(data_1d: np.ndarray, seed_bytes: bytes) -> tuple[np.ndarray, np.ndarray]:
        """
        Permute a 1D array using unbiased chaotic Fisher-Yates shuffle.
        Returns: (shuffled_array, perm_indices)
        """
        n = data_1d.size
        idx = ChaoticPermuter.generate_fisher_yates_indices(seed_bytes, n)
        return data_1d[idx], idx

    @staticmethod
    def fisher_yates_unshuffle(shuffled_1d: np.ndarray, seed_bytes: bytes) -> np.ndarray:
        """
        Losslessly inverts the chaotic Fisher-Yates shuffle.
        """
        n = shuffled_1d.size
        idx = ChaoticPermuter.generate_fisher_yates_indices(seed_bytes, n)
        recovered = np.empty_like(shuffled_1d)
        recovered[idx] = shuffled_1d
        return recovered
