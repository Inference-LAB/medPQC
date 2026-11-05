"""
medpqc.utils.validation
=======================
Input validation, parameter bounds checking, and integrity assertions.

Prevents buffer overflows, denial-of-service, and memory exhaustion attacks
by enforcing strict limits on shapes, data types, key lengths, and salts.
"""

from typing import Any

import numpy as np

from .limits import (
    check_dimensions,
    check_payload_size,
)

ALLOWED_DTYPES: set[str] = {"uint8", "int8", "uint16", "int16", "uint32", "int32", "float32", "float64"}

SUPPORTED_VERSIONS: set[str] = {"2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "MedPQC-v2.3", "MedPQC-v2.4"}


def validate_metadata(shape: tuple[int, ...] | list[int], dtype: str, n_bytes: int, version: str = "2.3.0") -> None:
    """
    Rigorously validates metadata types, ranges, and consistency before any allocations.
    Rejects hostile or corrupted parameters to prevent buffer-overflow or DoS attacks.
    """
    check_dimensions(shape)
    check_payload_size(n_bytes)

    dt_str = str(dtype)
    if dt_str not in ALLOWED_DTYPES:
        raise ValueError(f"MALFORMED_METADATA: Unsupported dtype '{dt_str}'. Must be in {sorted(ALLOWED_DTYPES)}.")

    np_dt = np.dtype(dt_str)
    expected_bytes = int(np.prod(shape) * np_dt.itemsize)
    if int(n_bytes) != expected_bytes:
        raise ValueError(f"MALFORMED_METADATA: Byte count mismatch. Declared {n_bytes}, calculated {expected_bytes}.")

    if str(version) not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"MALFORMED_METADATA: Unsupported protocol version '{version}'. Supported: {sorted(SUPPORTED_VERSIONS)}."
        )


def validate_key_length(key: bytes, expected_length: int, key_name: str = "key") -> bytes:
    """
    Validates that a cryptographic key has the exact expected byte length.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"Invalid type for {key_name}: expected bytes or bytearray, got {type(key).__name__}")
    if len(key) != expected_length:
        raise ValueError(f"Invalid {key_name} length: {len(key)} bytes. Expected {expected_length} bytes.")
    return bytes(key)


def validate_site_salt(salt: Any, min_length: int = 16) -> bytes:
    """
    Validates that a site salt is of adequate length and byte type for keyed pseudonymization.
    """
    if hasattr(salt, "key_bytes"):
        salt = salt.key_bytes
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"Invalid type for site_salt: expected bytes or bytearray, got {type(salt).__name__}")
    if len(salt) < min_length:
        raise ValueError(f"Invalid site_salt: length {len(salt)} < minimum required {min_length} bytes.")
    return bytes(salt)


def validate_image_array(arr: Any) -> None:
    """
    Validates that input array is a valid numpy array with supported dimensions and dtype.
    """
    if not isinstance(arr, np.ndarray):
        raise TypeError(f"Expected numpy.ndarray, got {type(arr).__name__}")
    if arr.ndim not in (2, 3):
        raise ValueError(f"Invalid array dimensions: {arr.ndim}. Expected 2D or 3D.")
    if str(arr.dtype) not in ALLOWED_DTYPES:
        raise ValueError(f"Unsupported array dtype '{arr.dtype}'. Must be in {sorted(ALLOWED_DTYPES)}.")
