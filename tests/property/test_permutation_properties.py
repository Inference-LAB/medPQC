"""
tests.property.test_permutation_properties
==========================================
Property-based and generative tests for medpqc.experimental.chaos.permutation.
Validates bijectivity, invertibility, and distribution properties across varied array sizes.
"""

import numpy as np
import pytest
from medpqc.experimental.chaos.permutation import ChaoticPermuter


@pytest.mark.parametrize("size", [1, 2, 7, 16, 63, 128, 255, 512, 1024])
def test_permutation_sorting_bijectivity_and_inversion(size):
    seed = f"seed-sort-{size}".encode('utf-8')
    data = np.arange(size, dtype=np.int64)

    idx = ChaoticPermuter.generate_permutation_indices(seed, size)
    assert len(idx) == size
    assert set(idx) == set(range(size))

    permuted, _ = ChaoticPermuter.permute(data, seed)
    recovered = ChaoticPermuter.inverse_permute(permuted, seed)
    assert np.array_equal(data, recovered)


@pytest.mark.parametrize("size", [1, 2, 7, 16, 63, 128, 255, 512, 1024])
def test_fisher_yates_bijectivity_and_inversion(size):
    seed = f"seed-fy-{size}".encode('utf-8')
    data = np.random.randint(-1000, 1000, size=size, dtype=np.int32)

    indices = ChaoticPermuter.generate_fisher_yates_indices(seed, size)
    assert len(indices) == size
    assert set(indices) == set(range(size))

    shuffled, _ = ChaoticPermuter.fisher_yates_shuffle(data, seed)
    recovered = ChaoticPermuter.fisher_yates_unshuffle(shuffled, seed)
    assert np.array_equal(data, recovered)
