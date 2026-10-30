"""
medpqc.chaos.lorenz
===================
High-performance Lorenz 3D Chaotic Attractor.
Solves the classical Lorenz ODEs via 4th-order Runge-Kutta (RK4):
  dx/dt = sigma * (y - x)
  dy/dt = x * (rho - z) - y
  dz/dt = x * y - beta * z
Parameters: sigma=10.0, rho=28.0, beta=8/3, dt=0.01.
Accelerated using Numba JIT with NumPy fallback.
"""

import hashlib
import numpy as np
from typing import Tuple

SIGMA = 10.0
RHO   = 28.0
BETA  = 8.0 / 3.0
DT    = 0.01

try:
    from numba import njit
    HAS_NUMBA = True
except ImportError:  # pragma: no cover
    HAS_NUMBA = False
    def njit(*args, **kwargs):  # pragma: no cover
        def decorator(fn):
            return fn
        return decorator

@njit(fastmath=True)
def _rk4_step(s: np.ndarray, dt: float = DT) -> np.ndarray:
    """Compute single RK4 step on Lorenz state [x, y, z]."""
    x, y, z = s[0], s[1], s[2]
    
    # k1
    dx1 = SIGMA * (y - x)
    dy1 = x * (RHO - z) - y
    dz1 = x * y - BETA * z

    # k2
    x2 = x + 0.5 * dt * dx1
    y2 = y + 0.5 * dt * dy1
    z2 = z + 0.5 * dt * dz1
    dx2 = SIGMA * (y2 - x2)
    dy2 = x2 * (RHO - z2) - y2
    dz2 = x2 * y2 - BETA * z2

    # k3
    x3 = x + 0.5 * dt * dx2
    y3 = y + 0.5 * dt * dy2
    z3 = z + 0.5 * dt * dz2
    dx3 = SIGMA * (y3 - x3)
    dy3 = x3 * (RHO - z3) - y3
    dz3 = x3 * y3 - BETA * z3

    # k4
    x4 = x + dt * dx3
    y4 = y + dt * dy3
    z4 = z + dt * dz3
    dx4 = SIGMA * (y4 - x4)
    dy4 = x4 * (RHO - z4) - y4
    dz4 = x4 * y4 - BETA * z4

    res = np.empty(3, dtype=np.float64)
    res[0] = x + (dt / 6.0) * (dx1 + 2.0 * dx2 + 2.0 * dx3 + dx4)
    res[1] = y + (dt / 6.0) * (dy1 + 2.0 * dy2 + 2.0 * dy3 + dy4)
    res[2] = z + (dt / 6.0) * (dz1 + 2.0 * dz2 + 2.0 * dz3 + dz4)
    return res

@njit(fastmath=True)
def _integrate_lorenz_loop(s_init: np.ndarray, warmup: int, n_steps: int) -> np.ndarray:
    """Numba-accelerated integration loop."""
    s = s_init.copy()
    for _ in range(warmup):
        s = _rk4_step(s)
    
    out = np.empty((n_steps, 3), dtype=np.float64)
    for i in range(n_steps):
        s = _rk4_step(s)
        out[i, 0] = s[0]
        out[i, 1] = s[1]
        out[i, 2] = s[2]
    return out

class LorenzChaosEngine:
    """Generates chaotic trajectories and keystreams seeded from OKM."""

    @staticmethod
    def seed_to_state(seed_bytes: bytes) -> np.ndarray:
        """Deterministically map seed bytes to initial condition [x0, y0, z0] in [-2, 2]^3."""
        d = hashlib.sha3_512(seed_bytes).digest()
        state = np.array([
            int.from_bytes(d[i*6 : i*6+6], 'big') / (2**48 - 1) * 4.0 - 2.0
            for i in range(3)
        ], dtype=np.float64)
        return state

    @classmethod
    def generate_trajectory(
        cls,
        seed_bytes: bytes,
        n_steps: int,
        warmup: int = 2000
    ) -> np.ndarray:
        """
        Integrate Lorenz system for `n_steps` after `warmup`.
        Returns array of shape (n_steps, 3).
        """
        s0 = cls.seed_to_state(seed_bytes)
        return _integrate_lorenz_loop(s0, warmup, n_steps)

    @classmethod
    def generate_keystream(
        cls,
        seed_bytes: bytes,
        length: int,
        warmup: int = 2000
    ) -> np.ndarray:
        """
        Generate 1D chaotic float stream in [0, 1] of specified length.
        """
        n_steps = (length // 3) + 5
        traj = cls.generate_trajectory(seed_bytes, n_steps, warmup=warmup)
        flat = traj.flatten()[:length]
        lo, hi = flat.min(), flat.max()
        return (flat - lo) / (hi - lo + 1e-15)

    @classmethod
    def generate_uint8_stream(
        cls,
        seed_bytes: bytes,
        length: int,
        warmup: int = 2000
    ) -> np.ndarray:
        """Generate chaotic byte stream in [0, 255]."""
        f = cls.generate_keystream(seed_bytes, length, warmup=warmup)
        return (f * 255.0).astype(np.uint8)
