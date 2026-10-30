"""
tests.test_chaos_permutation
============================
Unit tests for medpqc.chaos.permutation module.
"""

import numpy as np
import pytest
from medpqc.chaos.permutation import ChaoticPermuter

def test_permutation_indices_bijective():
    seed = b"test_perm_seed"
    n = 256
    idx = ChaoticPermuter.generate_permutation_indices(seed, n)
    assert len(idx) == n
    # Verify bijection: every index from 0 to n-1 appears exactly once
    assert np.array_equal(np.sort(idx), np.arange(n))

def test_permutation_and_inverse():
    seed = b"test_perm_inv_seed"
    original = np.arange(1000, dtype=np.uint8)
    permuted, _ = ChaoticPermuter.permute(original, seed)
    recovered = ChaoticPermuter.inverse_permute(permuted, seed)

    # Permuted array should not be in identical order
    assert not np.array_equal(original, permuted)
    # Inverse must match original exactly
    assert np.array_equal(original, recovered)

def test_permutation_scrambling_destroys_correlation():
    seed = b"scramble_seed"
    # Create linearly correlated ramp
    ramp = np.arange(1024, dtype=np.float64)
    corr_orig = float(np.corrcoef(ramp[:-1], ramp[1:])[0, 1])
    assert corr_orig > 0.99

    scrambled, _ = ChaoticPermuter.permute(ramp, seed)
    corr_scrambled = float(np.corrcoef(scrambled[:-1], scrambled[1:])[0, 1])
    # Correlation after scrambling should drop near zero (< 0.1)
    assert abs(corr_scrambled) < 0.1
