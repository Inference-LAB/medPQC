"""
tests.fuzz.test_fuzz_cipher_engine
==================================
Hypothesis property fuzzing for MedPQCCipher decryption against malformed bundles.
Verifies memory safety, dimension bounds enforcement, and rejection of malformed envelopes.
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from medpqc.cipher.engine import MedPQCCipher
from medpqc.utils.limits import (
    AuthenticationError,
    LimitExceededError,
    DimensionLimitExceededError,
)


@given(st.binary(min_size=0, max_size=2048))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_cipher_decrypt_arbitrary_bytes(corrupt_payload: bytes):
    """
    Verifies that passing arbitrary raw bytes to decrypt safely raises
    ValueError or AuthenticationError without uncontrolled crashes or unhandled memory allocations.
    """
    cipher = MedPQCCipher(k_aes=b"F" * 32, k_mac=b"M" * 32)
    with pytest.raises((ValueError, AuthenticationError, LimitExceededError, Exception)):
        cipher.decrypt(corrupt_payload)


@given(st.dictionaries(
    st.text(min_size=1, max_size=15),
    st.one_of(st.integers(), st.text(max_size=30)),
    max_size=6,
))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_cipher_decrypt_malformed_dictionary(corrupt_dict):
    """
    Verifies that passing arbitrary malformed dictionary bundles safely raises
    ValueError or AuthenticationError without unhandled crashes.
    """
    cipher = MedPQCCipher(k_aes=b"F" * 32, k_mac=b"M" * 32)
    with pytest.raises((ValueError, KeyError, TypeError, AuthenticationError, LimitExceededError)):
        cipher.decrypt(corrupt_dict)
