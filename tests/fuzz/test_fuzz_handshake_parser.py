"""
tests.fuzz.test_fuzz_handshake_parser
=====================================
Hypothesis property fuzzing for handshake message parsing.
Verifies rejection of mutated handshake payloads, type confusion, and invalid signatures.
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.trust import TrustStore
from medpqc.security.replay import MemoryReplayStore
from medpqc.utils.limits import AuthenticationError


@given(st.dictionaries(
    st.text(min_size=1, max_size=15),
    st.one_of(st.text(max_size=50), st.binary(max_size=50), st.integers()),
    max_size=8,
))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_handshake_respond_malformed_init_dict(malformed_dict):
    """
    Verifies that malformed init_message dictionaries are rejected safely by respond().
    """
    trust_store = TrustStore()
    replay_store = MemoryReplayStore()
    bob_id = IdentityKeyPair()
    trust_store.register_peer("bob", bob_id.public_bytes)

    responder = ResponderContext(
        "bob",
        bob_id,
        trust_store=trust_store,
        replay_store=replay_store,
        allow_non_durable_replay_store=True,
    )

    with pytest.raises((ValueError, KeyError, TypeError, PermissionError, AuthenticationError)):
        responder.respond(init_message=malformed_dict)


@given(st.dictionaries(
    st.text(min_size=1, max_size=15),
    st.one_of(st.text(max_size=50), st.binary(max_size=50), st.integers()),
    max_size=8,
))
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_fuzz_handshake_finalize_malformed_resp_dict(malformed_dict):
    """
    Verifies that malformed response_message dictionaries are rejected safely by finalize().
    """
    trust_store = TrustStore()
    alice_id = IdentityKeyPair()
    trust_store.register_peer("alice", alice_id.public_bytes)

    initiator = InitiatorContext("alice", alice_id, trust_store=trust_store)
    _ = initiator.initiate(
        receiver_id="bob",
        session_id=b"1234567890123456",
    )

    with pytest.raises((ValueError, KeyError, TypeError, PermissionError, AuthenticationError)):
        initiator.finalize(response_message=malformed_dict)
