"""
medpqc.chaos
============
Chaotic attractor engines, permutation, and entropy extractors.
"""

from .lorenz import LorenzChaosEngine
from .permutation import ChaoticPermuter
from .sponge import ChaoticEntropySponge

__all__ = [
    "ChaoticEntropySponge",
    "ChaoticPermuter",
    "LorenzChaosEngine",
]
