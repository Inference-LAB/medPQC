"""
medpqc.chaos.sponge
===================
Cryptographic Sponge & Entropy Distillation Extractor for Chaotic Orbits.

Absorbs non-linear continuous ODE trajectories into a SHA3-512 cryptographic sponge
to distill dynamical entropy and eliminate temporal auto-correlation.
"""

import hashlib

import numpy as np

from .lorenz import LorenzChaosEngine


class ChaoticEntropySponge:
    """
    Distills chaotic dynamical states into uniform, cryptographically sound bitstreams.
    Maintains and continuously advances dynamical state.
    """

    @staticmethod
    def extract_bits(seed_bytes: bytes, n_bits: int, block_states: int = 1, warmup: int = 100) -> np.ndarray:
        """
        Extract `n_bits` binary values {0, 1} from Lorenz trajectory via SHA3 sponge.
        """
        n_bytes = (n_bits + 7) // 8
        stream_bytes = ChaoticEntropySponge.extract_uint8_stream(
            seed_bytes, n_bytes, block_states=block_states, warmup=warmup
        )
        bits = np.unpackbits(stream_bytes)[:n_bits]
        return bits

    @staticmethod
    def extract_uint8_stream(
        seed_bytes: bytes,
        n_bytes: int | None = None,
        block_states: int = 1,
        warmup: int = 100,
        length: int | None = None,
    ) -> np.ndarray:
        """
        Extract pseudorandom bytes by absorbing advancing Lorenz states into SHA3-512.
        Accepts either n_bytes or length for backward compatibility.
        """
        total_bytes = n_bytes if n_bytes is not None else length
        if total_bytes is None:
            raise ValueError("Must specify n_bytes or length.")

        out_bytes = bytearray()

        # 1. Initialize state from seed
        current_state = LorenzChaosEngine.seed_to_state(seed_bytes)

        # 2. Advance Lorenz dynamical state across warmup steps
        for _ in range(warmup):
            current_state = LorenzChaosEngine.step_state(current_state)

        sponge_state = hashlib.sha3_512(seed_bytes + current_state.tobytes()).digest()
        counter = 0

        # 3. Absorb and squeeze loop
        while len(out_bytes) < total_bytes:
            current_state = LorenzChaosEngine.step_state(current_state)
            absorb_data = current_state.tobytes() + sponge_state + counter.to_bytes(4, "big")
            sponge_state = hashlib.sha3_512(absorb_data).digest()

            # Squeeze all 64 bytes of SHA3-512 per iteration
            out_bytes.extend(sponge_state)
            counter += 1

        return np.frombuffer(bytes(out_bytes[:total_bytes]), dtype=np.uint8)
