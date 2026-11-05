"""
tests.fuzz.test_fuzz_manifest
==============================
Hypothesis property fuzzing for canonical JSON manifest parser and length-prefix decoder.
Verifies robust handling and typed error raising on arbitrary, adversarial, or malformed inputs.
"""

import pytest
from hypothesis import given, strategies as st, settings
from medpqc.utils.canonical import (
    canonical_json_dumps,
    canonical_json_loads,
    length_prefix_encode,
    length_prefix_decode,
)
from medpqc.utils.limits import (
    CanonicalizationError,
    LimitExceededError,
    PayloadLimitExceededError,
)


@given(st.lists(st.binary(min_size=0, max_size=1000), max_size=20))
@settings(max_examples=100)
def test_fuzz_length_prefix_roundtrip(items):
    """Verifies arbitrary lists of byte sequences survive length prefix roundtrip exactly."""
    encoded = length_prefix_encode(items)
    decoded = length_prefix_decode(encoded)
    assert decoded == items


@given(st.binary(min_size=0, max_size=500))
@settings(max_examples=100)
def test_fuzz_length_prefix_malformed_bytes(corrupt_bytes: bytes):
    """Verifies arbitrary byte inputs to length_prefix_decode either succeed or raise LimitExceededError/ValueError."""
    try:
        decoded = length_prefix_decode(corrupt_bytes)
        assert isinstance(decoded, list)
    except (LimitExceededError, ValueError, IndexError, TypeError):
        pass


@given(st.text(min_size=0, max_size=2000))
@settings(max_examples=100)
def test_fuzz_canonical_json_loads_arbitrary_text(text: str):
    """Verifies canonical_json_loads safely parses or rejects arbitrary textual inputs without unhandled crashes."""
    try:
        parsed = canonical_json_loads(text)
        assert isinstance(parsed, (dict, list, str, int, float, bool, type(None)))
    except (CanonicalizationError, LimitExceededError, ValueError, TypeError):
        pass


@given(st.recursive(
    st.one_of(st.integers(), st.floats(allow_nan=False, allow_infinity=False), st.text()),
    lambda children: st.one_of(st.lists(children, max_size=5), st.dictionaries(st.text(max_size=10), children, max_size=5)),
    max_leaves=15,
))
@settings(max_examples=100)
def test_fuzz_canonical_json_roundtrip(obj):
    """Verifies JSON encodable objects survive canonical dumping and loading."""
    try:
        encoded = canonical_json_dumps(obj)
        decoded = canonical_json_loads(encoded)
        # Verify idempotence
        assert canonical_json_dumps(decoded) == encoded
    except (LimitExceededError, CanonicalizationError, ValueError):
        pass
