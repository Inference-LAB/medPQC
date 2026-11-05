"""
tests.unit.test_validation
==========================
Unit tests for medpqc.utils.validation.
Validates bounds checking, type assertions, and metadata validation routines.
"""

import numpy as np
import pytest
from medpqc.utils.validation import (
    validate_metadata,
    validate_key_length,
    validate_site_salt,
    validate_image_array
)


def test_validate_metadata_success_and_errors():
    # Valid
    validate_metadata((64, 64), "uint8", 4096, "2.2.0")
    validate_metadata((16, 16, 3), "uint16", 16 * 16 * 3 * 2, "2.1.0")

    # Shape errors
    with pytest.raises(ValueError, match="Invalid image dimensions"):
        validate_metadata((64,), "uint8", 64, "2.2.0")
    with pytest.raises(ValueError, match="Invalid image dimensions"):
        validate_metadata("bad_shape", "uint8", 64, "2.2.0")  # type: ignore

    # Dim value errors
    with pytest.raises(ValueError, match="outside permitted range"):
        validate_metadata((0, 64), "uint8", 0, "2.2.0")
    with pytest.raises(ValueError, match="outside permitted range"):
        validate_metadata((70000, 64), "uint8", 70000 * 64, "2.2.0")
    with pytest.raises(ValueError, match="outside permitted range"):
        validate_metadata(("64", 64), "uint8", 4096, "2.2.0")  # type: ignore

    # Dtype error
    with pytest.raises(ValueError, match="Unsupported dtype"):
        validate_metadata((64, 64), "complex128", 4096, "2.2.0")

    # Byte count mismatch
    with pytest.raises(ValueError, match="Byte count mismatch"):
        validate_metadata((64, 64), "uint8", 5000, "2.2.0")

    # Version error
    with pytest.raises(ValueError, match="Unsupported protocol version"):
        validate_metadata((64, 64), "uint8", 4096, "1.0.0")


def test_validate_key_length():
    valid = validate_key_length(b"A" * 32, 32, "test_key")
    assert valid == b"A" * 32

    with pytest.raises(TypeError, match="Invalid type for test_key"):
        validate_key_length("not_bytes", 32, "test_key")  # type: ignore

    with pytest.raises(ValueError, match="Invalid test_key length: 16 bytes"):
        validate_key_length(b"A" * 16, 32, "test_key")


def test_validate_site_salt():
    salt = validate_site_salt(b"S" * 16)
    assert salt == b"S" * 16

    with pytest.raises(TypeError, match="Invalid type for site_salt"):
        validate_site_salt("not_bytes")  # type: ignore

    with pytest.raises(ValueError, match="Invalid site_salt: length 15 < minimum required 16 bytes"):
        validate_site_salt(b"S" * 15)


def test_validate_image_array():
    arr = np.zeros((32, 32), dtype=np.uint16)
    validate_image_array(arr)

    arr3d = np.zeros((16, 16, 3), dtype=np.uint8)
    validate_image_array(arr3d)

    with pytest.raises(TypeError, match="Expected numpy.ndarray"):
        validate_image_array([1, 2, 3])  # type: ignore

    with pytest.raises(ValueError, match="Invalid array dimensions: 1"):
        validate_image_array(np.zeros((100,), dtype=np.uint8))

    with pytest.raises(ValueError, match="Unsupported array dtype"):
        validate_image_array(np.zeros((10, 10), dtype=np.complex64))
