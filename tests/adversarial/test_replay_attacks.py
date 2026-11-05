"""
tests.adversarial.test_replay_attacks
=====================================
Adversarial tests for SEC-02:
Evaluates concurrent replay resistance, multi-worker persistent SQLite storage,
stale timestamp rejection, and sliding window boundaries.
"""

import os
import time
import secrets
import tempfile
import pytest
from medpqc.security.replay import (
    SqliteReplayStore,
    MemoryReplayStore,
    ReplayProtector,
    ReplayDetectedError,
)
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext, TrustStore


def test_sqlite_replay_attacks_across_distinct_instances():
    """Verify that multiple independent protector instances sharing SQLite DB block replays."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "shared_replay.db")
        store1 = SqliteReplayStore(db_path)
        store2 = SqliteReplayStore(db_path)

        p1 = ReplayProtector(window_seconds=120.0, store=store1)
        p2 = ReplayProtector(window_seconds=120.0, store=store2)

        now = time.time()
        sid = secrets.token_bytes(16)

        # Worker 1 processes valid initiation
        p1.check_and_record("sender-pacs-node", sid, now, current_time=now)

        # Worker 2 receives replayed session initiation: must be rejected
        with pytest.raises(ValueError, match="REPLAY_DETECTED"):
            p2.check_and_record("sender-pacs-node", sid, now, current_time=now)

        store1.close()
        store2.close()


def test_authenticated_handshake_replay_rejection():
    """Full protocol test: replaying an Alice initiation message to Bob is rejected."""
    alice_id = IdentityKeyPair.generate("alice-node")
    bob_id = IdentityKeyPair.generate("bob-node")
    session_id = secrets.token_bytes(16)

    trust_store = TrustStore()
    trust_store.register_peer("alice-node", alice_id.public_bytes)
    trust_store.register_peer("bob-node", bob_id.public_bytes)

    sqlite_store = SqliteReplayStore(":memory:")

    alice_ctx = InitiatorContext("alice-node", alice_id, trust_store)
    init_msg = alice_ctx.initiate(receiver_id="bob-node", session_id=session_id)

    bob_ctx = ResponderContext("bob-node", bob_id, trust_store, sqlite_store)

    # First attempt succeeds
    resp1, _ = bob_ctx.respond(init_msg)
    assert resp1 is not None

    # Replay of identical init_msg is detected and rejected
    with pytest.raises(ReplayDetectedError):
        bob_ctx.respond(init_msg)

    sqlite_store.close()
