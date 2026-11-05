"""
medpqc.utils.limits
===================
Security bounds, operational thresholds, and resource limits for MedPQC v2.3.

Defines strictly enforced ceilings for memory allocations, dimensions,
manifest sizes, nesting depths, and cryptographic key usage limits
to prevent denial-of-service, decompression bombs, and memory exhaustion.
"""

# Operational and memory allocation limits
MAX_PAYLOAD_BYTES: int = 256 * 1024 * 1024  # 256 MiB maximum payload
MAX_MANIFEST_BYTES: int = 64 * 1024  # 64 KiB maximum manifest/header
MAX_IMAGE_DIM: int = 65536  # 64K maximum per single dimension
MAX_FRAMES: int = 2048  # 2048 maximum volumetric/time frames
MAX_CHANNELS: int = 4  # 4 maximum colour/spectral channels
MAX_JSON_DEPTH: int = 10  # 10 maximum recursion depth for canonical JSON
MAX_CIPHERTEXTS_PER_KEY: int = 65536  # 2^16 invocations before mandatory rekeying


class LimitExceededError(ValueError):
    """Base exception raised when a security bound or threshold is breached."""


class PayloadLimitExceededError(LimitExceededError):
    """Raised when payload size exceeds MAX_PAYLOAD_BYTES."""


class ManifestLimitExceededError(LimitExceededError):
    """Raised when manifest size exceeds MAX_MANIFEST_BYTES."""


class DimensionLimitExceededError(LimitExceededError):
    """Raised when image dimensions exceed MAX_IMAGE_DIM or MAX_FRAMES."""


class KeyExhaustionError(LimitExceededError):
    """Raised when invocation counter exceeds MAX_CIPHERTEXTS_PER_KEY."""


class MissingOptionalDependencyError(ImportError):
    """Raised when an optional subsystem is used without required dependencies."""


class EnvelopeFormatError(ValueError):
    """Raised when envelope formatting or serialization is malformed."""


class CanonicalizationError(ValueError):
    """Raised when canonical JSON serialization or deserialization fails."""


class AuthenticationError(ValueError):
    """Raised on authentication or integrity tag mismatch."""


class DecryptionError(ValueError):
    """Raised on AEAD decryption or padding failure."""


def check_manifest_size(size_in_bytes: int) -> None:
    """Validates that serialized manifest does not exceed MAX_MANIFEST_BYTES."""
    if size_in_bytes > MAX_MANIFEST_BYTES:
        raise ManifestLimitExceededError(
            f"Manifest size {size_in_bytes} bytes exceeds maximum permitted {MAX_MANIFEST_BYTES} bytes."
        )


def check_payload_size(size_in_bytes: int) -> None:
    """Validates that declared or actual payload does not exceed MAX_PAYLOAD_BYTES."""
    if size_in_bytes < 0:
        raise ValueError(f"Payload size cannot be negative: {size_in_bytes}")
    if size_in_bytes > MAX_PAYLOAD_BYTES:
        raise PayloadLimitExceededError(
            f"Payload size {size_in_bytes} bytes exceeds maximum permitted {MAX_PAYLOAD_BYTES} bytes."
        )


def check_dimensions(shape: tuple[int, ...] | list[int]) -> None:
    """Validates individual and composite dimension bounds before buffer allocation."""
    if not isinstance(shape, (tuple, list)) or len(shape) not in (2, 3):
        raise ValueError(f"MALFORMED_METADATA: Invalid image dimensions {shape}. Expected 2D or 3D.")

    if len(shape) == 3 and shape[0] > MAX_FRAMES:
        raise DimensionLimitExceededError(
            f"MALFORMED_METADATA: Volumetric frame count {shape[0]} exceeds MAX_FRAMES {MAX_FRAMES}."
        )

    for dim in shape:
        if not isinstance(dim, int) or dim <= 0 or dim > MAX_IMAGE_DIM:
            raise DimensionLimitExceededError(
                f"MALFORMED_METADATA: Dimension {dim} outside permitted range [1, {MAX_IMAGE_DIM}]."
            )
