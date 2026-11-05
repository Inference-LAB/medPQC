"""
tests.unit.test_canonical
=========================
Unit tests for medpqc.utils.canonical.
Validates canonical JSON encoding/decoding and length-prefixed framing.
"""

import pytest
from medpqc.utils.canonical import (
    canonical_json_dumps,
    canonical_json_loads,
    length_prefix_encode,
    length_prefix_decode
)


def test_canonical_json_dumps_and_loads():
    data = {"b": 2, "a": 1, "z": [3, 2, 1]}
    encoded = canonical_json_dumps(data)
    # Check sorted keys and no space after separators
    assert encoded == b'{"a":1,"b":2,"z":[3,2,1]}'

    # Loads from bytes
    decoded_bytes = canonical_json_loads(encoded)
    assert decoded_bytes == data

    # Loads from bytearray
    decoded_ba = canonical_json_loads(bytearray(encoded))
    assert decoded_ba == data

    # Loads from string
    decoded_str = canonical_json_loads('{"a":1,"b":2}')
    assert decoded_str == {"a": 1, "b": 2}


def test_length_prefix_encode_and_decode():
    items = [b"Alice", b"", b"PACS_IMAGE_DATA_12345", b"\x00\xff\xfe"]
    encoded = length_prefix_encode(items)

    decoded = length_prefix_decode(encoded)
    assert decoded == items

    # Bytearray input
    decoded_ba = length_prefix_decode(bytearray(encoded))
    assert decoded_ba == items

    # Invalid items type to encode
    with pytest.raises(TypeError, match="Expected bytes or bytearray"):
        length_prefix_encode(["not_bytes"])  # type: ignore

    # Invalid input type to decode
    with pytest.raises(TypeError, match="Expected bytes or bytearray"):
        length_prefix_decode("not_bytes")  # type: ignore


def test_length_prefix_decode_corrupted_data():
    # Truncated length prefix (less than 4 bytes remaining)
    with pytest.raises(ValueError, match="Truncated length prefix"):
        length_prefix_decode(b"\x00\x00")

    # Declared length exceeds stream
    with pytest.raises(ValueError, match="Truncated item"):
        length_prefix_decode(b"\x00\x00\x00\x10abc")  # Declared 16 bytes, only 3 present
