"""
medpqc.cipher.engine
====================
Unified Medical Image Encryption & Decryption Engine.
Integrates Hybrid KEM + Chaotic Permutation + Diffusion + AES-256-GCM.
Preserves 8-bit and 16-bit medical data with zero loss (MSE = 0.0).
"""

import hashlib
import numpy as np
from typing import Tuple, Dict, Any

from ..kem.combiner import HybridKeyCombiner
from ..chaos.lorenz import LorenzChaosEngine
from ..chaos.permutation import ChaoticPermuter
from .diffusion import ChaoticDiffusion
from .aead import AuthenticatedCipher

class MedPQCCipher:
    """
    High-Performance Medical Image Encryption Engine.
    Coordinates:
      1. Chaotic Permutation (Scrambling) -> crushes spatial correlation
      2. Bit-plane XOR diffusion
      3. 3-round CBC-chained chaotic mixing
      4. AES-256-GCM AEAD authenticated encryption
      5. Outer HMAC-SHA3-256 key commitment
    """

    def __init__(self, k_aes: bytes, k_mac: bytes, okm: bytes = None):
        self.k_aes = k_aes
        self.k_mac = k_mac
        self.okm = okm if okm is not None else (k_aes + k_mac)

    @classmethod
    def from_shared_secrets(cls, k_ecdh: bytes, k_pq: bytes) -> "MedPQCCipher":
        """Instantiate cipher directly from classical and post-quantum shared secrets."""
        k_aes, k_mac, okm = HybridKeyCombiner.combine(k_ecdh, k_pq)
        return cls(k_aes, k_mac, okm)

    def encrypt(
        self,
        image_array: np.ndarray,
        enable_scrambling: bool = True
    ) -> Dict[str, Any]:
        """
        Encrypt a NumPy image array (uint8 or uint16, 2D or 3D).
        Returns a dictionary containing the authenticated ciphertext bundle and metadata.
        """
        orig_shape = image_array.shape
        orig_dtype = str(image_array.dtype)

        # Convert to raw bytes view preserving exact native multi-byte representations (uint8, uint16, int16, etc.)
        flat_bytes = np.frombuffer(image_array.tobytes(), dtype=np.uint8).copy()
        n_bytes = flat_bytes.size

        # 1. Derive sub-seeds from OKM
        chaos_seed = hashlib.sha3_512(self.okm + b"chaos-seed-v1").digest()
        perm_seed  = hashlib.sha3_512(self.okm + b"perm-seed-v1").digest()

        # 2. Chaotic Permutation (Pixel Scrambling)
        if enable_scrambling:
            scrambled, _ = ChaoticPermuter.permute(flat_bytes, perm_seed)
        else:
            scrambled = flat_bytes.copy()

        # 3. Generate chaotic keystream bytes
        keystream = LorenzChaosEngine.generate_uint8_stream(chaos_seed, n_bytes * 3)

        # 4. Bit-plane XOR diffusion
        bp_diffused = ChaoticDiffusion.bitplane_diffuse(scrambled, keystream[:n_bytes])

        # 5. 3-round CBC-chained mixing
        cbc_mixed = ChaoticDiffusion.cbc_mix(bp_diffused, keystream, rounds=3)

        # 6. AES-256-GCM + Outer HMAC AEAD
        aead_bundle = AuthenticatedCipher.encrypt(cbc_mixed.tobytes(), self.k_aes, self.k_mac)

        return {
            'aead': aead_bundle,
            'shape': orig_shape,
            'dtype': orig_dtype,
            'enable_scrambling': enable_scrambling,
            'n_bytes': n_bytes
        }

    def decrypt(self, encrypted_bundle: Dict[str, Any]) -> np.ndarray:
        """
        Decrypt the ciphertext bundle and reconstruct the original image losslessly.
        """
        aead_bundle = encrypted_bundle['aead']
        orig_shape = encrypted_bundle['shape']
        orig_dtype = np.dtype(encrypted_bundle['dtype'])
        enable_scrambling = encrypted_bundle.get('enable_scrambling', True)
        n_bytes = encrypted_bundle['n_bytes']

        # 1. Verify AEAD and decrypt AES ciphertext
        cbc_mixed_bytes = AuthenticatedCipher.decrypt(aead_bundle, self.k_aes, self.k_mac)
        cbc_mixed = np.frombuffer(cbc_mixed_bytes, dtype=np.uint8)

        # 2. Derive chaotic seeds
        chaos_seed = hashlib.sha3_512(self.okm + b"chaos-seed-v1").digest()
        perm_seed  = hashlib.sha3_512(self.okm + b"perm-seed-v1").digest()

        keystream = LorenzChaosEngine.generate_uint8_stream(chaos_seed, n_bytes * 3)

        # 3. Inverse 3-round CBC unmixing
        bp_diffused = ChaoticDiffusion.cbc_unmix(cbc_mixed, keystream, rounds=3)

        # 4. Inverse Bit-plane XOR undiffusion
        scrambled = ChaoticDiffusion.bitplane_undiffuse(bp_diffused, keystream[:n_bytes])

        # 5. Inverse Chaotic Permutation
        if enable_scrambling:
            recovered_bytes = ChaoticPermuter.inverse_permute(scrambled, perm_seed)
        else:
            recovered_bytes = scrambled

        # 6. Reconstruct original typed array and shape universally
        reconstructed = np.frombuffer(recovered_bytes.tobytes(), dtype=orig_dtype).reshape(orig_shape)
        return reconstructed
