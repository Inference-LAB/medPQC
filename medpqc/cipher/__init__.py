"""
medpqc.cipher
=============
Authenticated AEAD ciphers and unified encryption engine.
"""

from typing import Any

from .aead import AuthenticatedCipher
from .engine import MedPQCCipher, serialize_metadata_aad, validate_metadata


def __getattr__(name: str) -> Any:
    """Backward-compatibility shim for relocated experimental diffusion."""
    if name == "ChaoticDiffusion":
        import warnings

        warnings.warn(
            "ChaoticDiffusion has moved to medpqc.experimental.diffusion.",
            DeprecationWarning,
            stacklevel=2,
        )
        from ..experimental.diffusion import ChaoticDiffusion

        return ChaoticDiffusion
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AuthenticatedCipher",
    "MedPQCCipher",
    "serialize_metadata_aad",
    "validate_metadata",
]
