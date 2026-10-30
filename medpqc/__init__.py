"""
MedPQC: High-Performance Post-Quantum Medical Image Encryption Library
======================================================================
Combines Hybrid KEM (ECDH P-256 + FIPS 203 ML-KEM / RLWE) with
JIT-Accelerated Lorenz Chaotic Permutation & Diffusion and
AES-256-GCM Authenticated Encryption for PACS DICOM systems.
"""

__version__ = "1.0.0"
__author__ = "Inference Lab"

from .kem.ecdh import ECDHKeyExchange, generate_ecdh_keypair
from .kem.rlwe import NativeRLWEKEM, PostQuantumKEM
from .kem.combiner import HybridKeyCombiner
from .chaos.lorenz import LorenzChaosEngine
from .chaos.sponge import ChaoticEntropySponge
from .chaos.permutation import ChaoticPermuter
from .cipher.diffusion import ChaoticDiffusion
from .cipher.aead import AuthenticatedCipher
from .cipher.engine import MedPQCCipher
from .dicom.handler import MedicalImageIO
from .dicom.pacs import DICOMPACSEnvelope

__all__ = [
    "__version__",
    "ECDHKeyExchange",
    "generate_ecdh_keypair",
    "NativeRLWEKEM",
    "PostQuantumKEM",
    "HybridKeyCombiner",
    "LorenzChaosEngine",
    "ChaoticEntropySponge",
    "ChaoticPermuter",
    "ChaoticDiffusion",
    "AuthenticatedCipher",
    "MedPQCCipher",
    "MedicalImageIO",
    "DICOMPACSEnvelope",
]
