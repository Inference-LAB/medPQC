"""
medpqc.utils.canonical
======================
Canonical serialization and framing primitives for MedPQC v2.3.

Ensures deterministic, platform-independent byte representations for
cryptographic transcripts, Associated Authenticated Data (AAD), and
replay-protected metadata.

Strict JSON parsing enforces:
  - No duplicate object keys (RFC 8259 compliance)
  - Rejection of non-standard IEEE 754 constants (NaN, Infinity)
  - Recursion depth bounding (maximum MAX_JSON_DEPTH = 10)
  - Maximum size limits (MAX_MANIFEST_BYTES = 64 KiB)
"""

import json
from typing import Any

from .limits import (
    MAX_JSON_DEPTH,
    MAX_MANIFEST_BYTES,
    ManifestLimitExceededError,
)


def _check_depth(obj: Any, current_depth: int = 0) -> None:
    if current_depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON recursion depth exceeds maximum permitted limit {MAX_JSON_DEPTH}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"JSON object key must be a string, got {type(k).__name__}")
            _check_depth(v, current_depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_depth(item, current_depth + 1)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    res: dict[str, Any] = {}
    for k, v in pairs:
        if k in res:
            raise ValueError(f"DUPLICATE_KEY: JSON object contains duplicate key: {k!r}")
        res[k] = v
    return res


def _reject_constant(val: str) -> Any:
    raise ValueError(f"INVALID_JSON_CONSTANT: Disallowed IEEE-754 constant {val!r}")


def canonical_json_dumps(obj: Any) -> bytes:
    """
    Serializes a Python object to canonical JSON bytes.
    Enforces sorted keys, compact separators, no NaN/Infinity, UTF-8 encoding.
    Guarantees bit-for-bit determinism across all platforms.
    """
    _check_depth(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_loads(data: bytes | bytearray | str) -> Any:
    """
    Parses canonical JSON bytes or string with strict schema and security enforcement.
    Rejects duplicate keys, NaN/Infinity, and excessive nesting depth.
    """
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_MANIFEST_BYTES:
            raise ManifestLimitExceededError(
                f"JSON payload size {len(data)} exceeds MAX_MANIFEST_BYTES {MAX_MANIFEST_BYTES}"
            )
        text = data.decode("utf-8")
    else:
        if len(data.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise ManifestLimitExceededError(f"JSON string size exceeds MAX_MANIFEST_BYTES {MAX_MANIFEST_BYTES}")
        text = data

    parsed = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    _check_depth(parsed)
    return parsed


def length_prefix_encode(items: list[bytes]) -> bytes:
    """
    Encodes a list of byte sequences with 4-byte big-endian length prefixes.
    Prevents ambiguity and length-extension in cryptographic transcript hashing.
    """
    out = bytearray()
    for item in items:
        if not isinstance(item, (bytes, bytearray)):
            raise TypeError(f"Expected bytes or bytearray, got {type(item).__name__}")
        out.extend(len(item).to_bytes(4, "big"))
        out.extend(item)
    return bytes(out)


def length_prefix_decode(data: bytes) -> list[bytes]:
    """
    Decodes length-prefixed byte sequences produced by length_prefix_encode.
    Raises ValueError on truncated or malformed data.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")

    items: list[bytes] = []
    idx = 0
    total_len = len(data)

    while idx < total_len:
        if idx + 4 > total_len:
            raise ValueError(f"Truncated length prefix at offset {idx}: remaining bytes {total_len - idx} < 4")
        item_len = int.from_bytes(data[idx : idx + 4], "big")
        idx += 4
        if idx + item_len > total_len:
            raise ValueError(f"Truncated item at offset {idx}: declared length {item_len}, available {total_len - idx}")
        items.append(bytes(data[idx : idx + item_len]))
        idx += item_len

    return items
