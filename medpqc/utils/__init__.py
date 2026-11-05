"""
medpqc.utils
============
Utility subpackage providing canonical serialization and input validation.
"""

from .canonical import (
    canonical_json_dumps,
    canonical_json_loads,
    length_prefix_decode,
    length_prefix_encode,
)
from .validation import (
    ALLOWED_DTYPES,
    SUPPORTED_VERSIONS,
    validate_image_array,
    validate_key_length,
    validate_metadata,
    validate_site_salt,
)

__all__ = [
    "ALLOWED_DTYPES",
    "SUPPORTED_VERSIONS",
    "canonical_json_dumps",
    "canonical_json_loads",
    "length_prefix_decode",
    "length_prefix_encode",
    "validate_image_array",
    "validate_key_length",
    "validate_metadata",
    "validate_site_salt",
]
