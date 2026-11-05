"""
tests.test_chaos_lorenz
========================
Unit tests for medpqc.experimental.chaos.lorenz module.
"""

import numpy as np
import pytest
from medpqc.experimental.chaos.lorenz import LorenzChaosEngine, _rk4_step

def test_lorenz_seed_to_state_determinism():
    seed = b"test_seed_12345"
    s1 = LorenzChaosEngine.seed_to_state(seed)
    s2 = LorenzChaosEngine.seed_to_state(seed)

    assert np.array_equal(s1, s2)
    assert s1.shape == (3,)
    assert np.all(s1 >= -2.0) and np.all(s1 <= 2.0)

def test_rk4_step_propagation():
    s0 = np.array([1.0, 1.0, 1.0], dtype=np.float64)
    s1 = _rk4_step(s0, dt=0.01)
    assert s1.shape == (3,)
    assert not np.array_equal(s0, s1)
    # Check bounded Lorenz expansion
    assert np.all(np.isfinite(s1))

def test_lorenz_trajectory_shape():
    seed = b"test_trajectory_seed"
    n_steps = 100
    traj = LorenzChaosEngine.generate_trajectory(seed, n_steps=n_steps, warmup=50)
    assert traj.shape == (n_steps, 3)
    assert np.all(np.isfinite(traj))

def test_lorenz_keystream_normalization():
    seed = b"test_keystream_seed"
    stream = LorenzChaosEngine.generate_keystream(seed, length=1000, warmup=100)
    assert len(stream) == 1000
    assert stream.min() >= 0.0
    assert stream.max() <= 1.0

def test_lorenz_uint8_stream():
    seed = b"test_uint8_seed"
    u8 = LorenzChaosEngine.generate_uint8_stream(seed, length=500, warmup=100)
    assert len(u8) == 500
    assert u8.dtype == np.uint8
