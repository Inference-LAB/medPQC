"""
tests.test_chaos_sponge
========================
Unit tests for medpqc.chaos.sponge module.
"""

import numpy as np
import pytest
from medpqc.chaos.sponge import ChaoticEntropySponge

def test_sponge_bit_extraction_shape():
    seed = b"test_sponge_seed_123"
    n_bits = 1000
    bits = ChaoticEntropySponge.extract_bits(seed, n_bits, warmup=50)
    assert len(bits) == n_bits
    assert set(np.unique(bits)).issubset({0, 1})

def test_sponge_bit_balance():
    seed = b"test_balance_seed"
    n_bits = 10000
    bits = ChaoticEntropySponge.extract_bits(seed, n_bits, warmup=50)
    # Check that proportion of ones is balanced close to 0.50 (+- 0.05)
    mean_val = float(bits.mean())
    assert 0.45 <= mean_val <= 0.55

def test_sponge_uint8_stream():
    seed = b"test_uint8_sponge"
    u8 = ChaoticEntropySponge.extract_uint8_stream(seed, length=256, warmup=50)
    assert len(u8) == 256
    assert u8.dtype == np.uint8
