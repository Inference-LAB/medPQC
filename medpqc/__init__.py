"""
MedPQC: Hybrid Post-Quantum Medical Image Cryptographic Protection Framework
=============================================================================
Research implementation of hybrid post-quantum cryptographic protection for
medical imaging workflows and DICOM/PACS data management.

Standards & Primitives:
  - Key Encapsulation: Ephemeral ECDH P-256 + NIST FIPS 203 ML-KEM-768
  - Authentication: Ed25519 digital signatures with mandatory TrustStore verification
  - Key Derivation: RFC 5869 HKDF-SHA-512 with domain separation
  - Authenticated Encryption: AES-256-GCM AEAD with canonical context-bound AAD
  - Replay Defense: Atomic SQLite and memory-backed session tracking
"""

from typing import Any

__version__ = "1.1.0"
__author__ = "Inference Lab"

from .cipher.aead import AuthenticatedCipher
from .cipher.engine import MedPQCCipher, serialize_metadata_aad
from .kem.auth import (
    AuthenticatedHybridKEM,
    IdentityKeyPair,
    InitiatorContext,
    NonDurableReplayStoreWarning,
    RemovedAPIError,
    ResponderContext,
)
from .kem.combiner import (
    HybridKeyCombiner,
    build_session_context,
    hkdf_extract_and_expand,
)
from .kem.ecdh import ECDHKeyExchange, generate_ecdh_keypair
from .kem.rlwe import KEMError, PostQuantumKEM
from .security.replay import (
    MemoryReplayStore,
    ReplayProtector,
    ReplayStoreBase,
    SqliteReplayStore,
)
from .security.trust import TrustStore
from .utils.canonical import (
    canonical_json_dumps,
    canonical_json_loads,
    length_prefix_decode,
    length_prefix_encode,
)
from .utils.validation import (
    validate_image_array,
    validate_key_length,
    validate_site_salt,
)


def __getattr__(name: str) -> Any:
    """Lazy loader for optional DICOM subsystem components."""
    if name == "MedicalImageIO":
        from .dicom.handler import MedicalImageIO

        return MedicalImageIO
    if name in ("PROTECTED_PHI_TAGS", "DICOMPACSEnvelope", "DICOMPACSSession"):
        from .dicom import pacs

        return getattr(pacs, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "PROTECTED_PHI_TAGS",
    "AuthenticatedCipher",
    "AuthenticatedHybridKEM",
    "DICOMPACSEnvelope",
    "DICOMPACSSession",
    "ECDHKeyExchange",
    "HybridKeyCombiner",
    "IdentityKeyPair",
    "InitiatorContext",
    "KEMError",
    "MedPQCCipher",
    "MedicalImageIO",
    "MemoryReplayStore",
    "NonDurableReplayStoreWarning",
    "PostQuantumKEM",
    "RemovedAPIError",
    "ReplayProtector",
    "ReplayStoreBase",
    "ResponderContext",
    "SqliteReplayStore",
    "TrustStore",
    "__author__",
    "__version__",
    "build_session_context",
    "canonical_json_dumps",
    "canonical_json_loads",
    "generate_ecdh_keypair",
    "hkdf_extract_and_expand",
    "length_prefix_decode",
    "length_prefix_encode",
    "serialize_metadata_aad",
    "validate_image_array",
    "validate_key_length",
    "validate_site_salt",
]
