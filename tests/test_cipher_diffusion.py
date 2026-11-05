"""
tests.test_cipher_diffusion
===========================
Unit tests for medpqc.cipher.diffusion module.
"""

import numpy as np
import pytest
from medpqc.experimental.diffusion import ChaoticDiffusion

def test_bitplane_diffusion_roundtrip():
    data = np.random.randint(0, 256, size=1024, dtype=np.uint8)
    key = np.random.randint(0, 256, size=1024, dtype=np.uint8)

    diffused = ChaoticDiffusion.bitplane_diffuse(data, key)
    undiffused = ChaoticDiffusion.bitplane_undiffuse(diffused, key)

    assert not np.array_equal(data, diffused)
    assert np.array_equal(data, undiffused)

def test_cbc_mixing_roundtrip():
    data = np.random.randint(0, 256, size=512, dtype=np.uint8)
    key = np.random.randint(0, 256, size=512 * 3, dtype=np.uint8)

    mixed = ChaoticDiffusion.cbc_mix(data, key, rounds=3)
    unmixed = ChaoticDiffusion.cbc_unmix(mixed, key, rounds=3)

    assert not np.array_equal(data, mixed)
    assert np.array_equal(data, unmixed)

def test_cbc_avalanche_propagation():
    # 1-byte change should propagate across the block
    data1 = np.zeros(256, dtype=np.uint8)
    data2 = np.zeros(256, dtype=np.uint8)
    data2[0] = 1  # 1 bit change at head
    key = np.ones(256 * 3, dtype=np.uint8) * 42

    m1 = ChaoticDiffusion.cbc_mix(data1, key, rounds=3)
    m2 = ChaoticDiffusion.cbc_mix(data2, key, rounds=3)

    diff_count = np.count_nonzero(m1 != m2)
    assert diff_count >= 100  # Wide avalanche spread (approaching ~50% of block)

def test_ccd_short_keystream_raises():
    data = np.zeros(64, dtype=np.uint8)
    short_key = np.zeros(10, dtype=np.uint8)
    with pytest.raises(ValueError, match="Keystream too short"):
        ChaoticDiffusion.ccd_mix(data, short_key, rounds=3)
    with pytest.raises(ValueError, match="Keystream too short"):
        ChaoticDiffusion.ccd_unmix(data, short_key, rounds=3)
