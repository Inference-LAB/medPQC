"""
tests.test_kem_auth
===================
Unit tests for medpqc.kem.auth module (InitiatorContext, ResponderContext, IdentityKeyPair, Session).
Validates mutual peer authentication, resistance against MITM key-substitution,
canonical transcript binding, identity-misbinding defenses, and replay protection.
"""

import time
import secrets
import pytest
from medpqc.kem.auth import (
    IdentityKeyPair,
    InitiatorContext,
    ResponderContext,
    TrustStore,
    Session,
    SessionState,
    AuthenticationError,
    UnsupportedSuiteError,
    WrongRecipientError,
    serialize_canonical_init_transcript,
    serialize_canonical_resp_transcript,
    encode_initiation,
    encode_response,
    parse_initiation,
    parse_response,
    ParseError,
)
from medpqc.security.replay import (
    MemoryReplayStore,
    ReplayProtector,
    ReplayDetectedError,
    StaleSessionError,
)


def test_identity_keypair_sign_verify():
    id_key = IdentityKeyPair()
    msg = b"Clinical PACS Transmission Record"
    sig = id_key.sign(msg)

    assert IdentityKeyPair.verify(id_key.public_bytes, sig, msg) is True
    # Tampered message
    assert IdentityKeyPair.verify(id_key.public_bytes, sig, msg + b"!") is False
    # Tampered signature
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01
    assert IdentityKeyPair.verify(id_key.public_bytes, bytes(bad_sig), msg) is False
    # Invalid public key format
    assert IdentityKeyPair.verify(b"bad_key", sig, msg) is False
    assert IdentityKeyPair.verify(b"\x00" * 31, sig, msg) is False


def test_identity_keypair_pem_export_import():
    """F-HS-08: Verifies PKCS8 PEM serialization and encrypted export/import."""
    id_key = IdentityKeyPair()
    passphrase = b"Correct-Horse-Battery-Staple"

    pem_encrypted = id_key.export_private_key(passphrase=passphrase)
    assert b"ENCRYPTED" in pem_encrypted

    imported_key = IdentityKeyPair.import_private_key(pem_encrypted, passphrase=passphrase)
    assert imported_key.public_bytes == id_key.public_bytes

    # Unencrypted export
    pem_plain = id_key.export_private_key(passphrase=None)
    imported_plain = IdentityKeyPair.import_private_key(pem_plain, passphrase=None)
    assert imported_plain.public_bytes == id_key.public_bytes


def test_authenticated_handshake_with_truststore_and_replay():
    alice_id = IdentityKeyPair.generate("hospital-a")
    bob_id = IdentityKeyPair.generate("hospital-b")
    session_id = secrets.token_bytes(16)

    trust_store = TrustStore()
    trust_store.register_peer("hospital-a", alice_id.public_bytes)
    trust_store.register_peer("hospital-b", bob_id.public_bytes)

    replay_store = MemoryReplayStore()

    # Step 1: Alice initiates
    alice_ctx = InitiatorContext("hospital-a", alice_id, trust_store)
    init_msg = alice_ctx.initiate(receiver_id="hospital-b", session_id=session_id)

    # Step 2: Bob responds
    bob_ctx = ResponderContext("hospital-b", bob_id, trust_store, replay_store, allow_non_durable_replay_store=True)
    resp_msg, bob_session = bob_ctx.respond(init_msg)

    # Step 3: Alice finalizes
    alice_session = alice_ctx.finalize(resp_msg)

    # Directional key verification:
    # Alice send key == Bob recv key
    assert alice_session.get_send_key() == bob_session.get_recv_key()
    # Bob send key == Alice recv key
    assert bob_session.get_send_key() == alice_session.get_recv_key()
    # Send and recv keys are independent
    assert alice_session.get_send_key() != alice_session.get_recv_key()

    assert alice_session.is_active is True
    assert bob_session.is_active is True
    assert alice_session.session_key_id == bob_session.session_key_id


def test_mitm_alter_sender_id_fails_signature():
    alice_id = IdentityKeyPair.generate("hospital-a")
    bob_id = IdentityKeyPair.generate("hospital-b")
    session_id = secrets.token_bytes(16)

    trust = TrustStore()
    trust.register_peer("hospital-a", alice_id.public_bytes)
    trust.register_peer("hospital-b", bob_id.public_bytes)
    trust.register_peer("hospital-c", alice_id.public_bytes)

    replay_store = MemoryReplayStore()

    alice_ctx = InitiatorContext("hospital-a", alice_id, trust)
    init_msg = alice_ctx.initiate(receiver_id="hospital-b", session_id=session_id)

    # Attacker alters sender_id
    init_msg["sender_id"] = "hospital-c"

    bob_ctx = ResponderContext("hospital-b", bob_id, trust, replay_store, allow_non_durable_replay_store=True)
    with pytest.raises(AuthenticationError):
        bob_ctx.respond(init_msg)


def test_mitm_alter_receiver_id_fails_signature():
    alice_id = IdentityKeyPair.generate("hospital-a")
    bob_id = IdentityKeyPair.generate("hospital-b")
    session_id = secrets.token_bytes(16)

    trust = TrustStore()
    trust.register_peer("hospital-a", alice_id.public_bytes)
    trust.register_peer("hospital-b", bob_id.public_bytes)
    trust.register_peer("rogue-pacs-node", bob_id.public_bytes)

    replay_store = MemoryReplayStore()

    alice_ctx = InitiatorContext("hospital-a", alice_id, trust)
    init_msg = alice_ctx.initiate(receiver_id="hospital-b", session_id=session_id)

    # Attacker alters receiver_id
    init_msg["receiver_id"] = "rogue-pacs-node"

    bob_ctx = ResponderContext("hospital-b", bob_id, trust, replay_store, allow_non_durable_replay_store=True)
    with pytest.raises(WrongRecipientError):
        bob_ctx.respond(init_msg)


def test_forged_init_signature_does_not_poison_replay_cache():
    alice_id = IdentityKeyPair.generate("hospital-a")
    bob_id = IdentityKeyPair.generate("hospital-b")
    session_id = secrets.token_bytes(16)

    trust = TrustStore()
    trust.register_peer("hospital-a", alice_id.public_bytes)
    trust.register_peer("hospital-b", bob_id.public_bytes)

    replay_store = MemoryReplayStore()

    alice_ctx = InitiatorContext("hospital-a", alice_id, trust)
    init_msg = alice_ctx.initiate(receiver_id="hospital-b", session_id=session_id)

    # Forged signature
    corrupt_msg = dict(init_msg)
    corrupt_msg["signature"] = b"\x00" * 64

    # Bob rejects due to invalid signature
    bob_ctx = ResponderContext("hospital-b", bob_id, trust, replay_store, allow_non_durable_replay_store=True)
    with pytest.raises(AuthenticationError):
        bob_ctx.respond(corrupt_msg)

    # The session_id must NOT have been consumed in replay_store
    cache_key = f"hospital-a:{session_id.hex()}"
    assert not replay_store.has_seen(cache_key)

    # Legitimate transmission now succeeds and consumes session
    resp_msg, _ = bob_ctx.respond(init_msg)
    assert resp_msg is not None
    assert replay_store.has_seen(cache_key)


def test_session_lifecycle_and_closure():
    k_send = b"1" * 32
    k_recv = b"2" * 32
    sess = Session(
        session_id=b"sess-1234",
        session_key_id=b"keyid-1234",
        role="initiator",
        k_send=k_send,
        k_recv=k_recv,
        local_node_id="alice",
        peer_node_id="bob",
    )

    assert sess.is_active is True
    assert sess.get_send_key() == k_send
    assert sess.get_recv_key() == k_recv
    assert sess.increment_send_counter() == 0
    assert sess.increment_send_counter() == 1

    sess.close()
    assert sess.is_active is False
    assert sess.state == SessionState.CLOSED

    with pytest.raises(PermissionError):
        sess.get_send_key()
    with pytest.raises(PermissionError):
        sess.get_recv_key()


def test_wire_framing_initiation_and_response_roundtrip():
    alice_id = IdentityKeyPair.generate("hospital-a")
    bob_id = IdentityKeyPair.generate("hospital-b")
    session_id = secrets.token_bytes(16)
    trust_store = TrustStore()
    trust_store.register_peer("hospital-a", alice_id.public_bytes)
    trust_store.register_peer("hospital-b", bob_id.public_bytes)
    replay_store = MemoryReplayStore()

    alice_ctx = InitiatorContext("hospital-a", alice_id, trust_store)
    init_msg = alice_ctx.initiate(receiver_id="hospital-b", session_id=session_id)

    # Encode initiation to wire bytes and parse back
    init_wire = encode_initiation(init_msg)
    parsed_init = parse_initiation(init_wire)
    assert parsed_init["sender_id"] == "hospital-a"
    assert parsed_init["receiver_id"] == "hospital-b"
    assert parsed_init["session_id"] == session_id

    # Respond with parsed initiation
    bob_ctx = ResponderContext("hospital-b", bob_id, trust_store, replay_store, allow_non_durable_replay_store=True)
    resp_msg, bob_sess = bob_ctx.respond(parsed_init)

    # Encode response to wire bytes and parse back
    resp_wire = encode_response(resp_msg)
    parsed_resp = parse_response(resp_wire)
    assert parsed_resp["selected_suite"] == resp_msg["selected_suite"]
    assert parsed_resp["sender_id"] == "hospital-b"

    alice_sess = alice_ctx.finalize(parsed_resp)

    # Test DirectionalCipher encrypt/decrypt between Alice and Bob
    send_cipher = alice_sess.sender_cipher()
    recv_cipher = bob_sess.receiver_cipher()
    plain = b"Hospital CT scan header payload"
    aad = b"associated-data-binding"
    encrypted = send_cipher.encrypt(plain, aad=aad)
    decrypted = recv_cipher.decrypt(encrypted, aad=aad)
    assert decrypted == plain

    # Bob sends to Alice
    bob_send = bob_sess.sender_cipher()
    alice_recv = alice_sess.receiver_cipher()
    response_plain = b"PACS Ack OK"
    encrypted2 = bob_send.encrypt(response_plain)
    decrypted2 = alice_recv.decrypt(encrypted2)
    assert decrypted2 == response_plain


def test_wire_framing_invalid_inputs():
    with pytest.raises(ParseError):
        parse_initiation(b"short")
    with pytest.raises(ParseError):
        parse_initiation(12345)  # type: ignore[arg-type]
    with pytest.raises(ParseError):
        parse_response(b"short")
    with pytest.raises(ParseError):
        parse_response(12345)  # type: ignore[arg-type]


def test_pq_kem_properties_and_methods():
    from medpqc.kem.rlwe import (
        MLKEM768_CT_LEN,
        MLKEM768_EK_LEN,
        PostQuantumKEM,
    )

    kem = PostQuantumKEM()
    assert kem.backend in ("fips-203-mlkem", "liboqs")
    info = kem.provider_info
    assert info["algorithm"] == "ML-KEM-768"
    assert info["public_key_len"] == str(MLKEM768_EK_LEN)

    ct, ss = kem.encapsulate(kem.public_key_bytes)
    assert len(ct) == MLKEM768_CT_LEN
    assert len(ss) == 32

    ss_recovered = kem.decapsulate(ct)
    assert ss_recovered == ss

    # Decapsulate with explicit dk
    ss_explicit = kem.decapsulate(ct, dk=bytes(kem._dk))
    assert ss_explicit == ss
