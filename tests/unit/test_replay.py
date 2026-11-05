"""
tests.unit.test_replay
======================
Unit tests for medpqc.security.replay.
Covers MemoryReplayStore, SqliteReplayStore, and ReplayProtector.
"""

import os
import time
import tempfile
import pytest
from medpqc.security.replay import (
    MemoryReplayStore,
    SqliteReplayStore,
    ReplayProtector,
    ReplayDetectedError,
    StaleSessionError,
)


def test_memory_replay_store():
    store = MemoryReplayStore()
    assert store.has_seen("key-1") is False

    # First consume succeeds
    assert store.consume("key-1", 100000) is True
    assert store.has_seen("key-1") is True
    assert store.has_seen("key-2") is False

    # Second consume for same key returns False (atomic replay detection)
    assert store.consume("key-1", 100000) is False

    store.consume("key-2", 200000)
    store.prune(150000)
    assert store.has_seen("key-1") is False
    assert store.has_seen("key-2") is True

    store.close()
    with pytest.raises(RuntimeError, match="ReplayStore is closed"):
        store.has_seen("key-2")


def test_sqlite_replay_store_memory_and_file():
    # In-memory SQLite
    store = SqliteReplayStore(":memory:")
    assert store.has_seen("k1") is False
    assert store.consume("k1", 1000000) is True
    assert store.has_seen("k1") is True
    assert store.consume("k1", 1000000) is False

    store.consume("k2", 2000000)
    store.prune(1500000)
    assert store.has_seen("k1") is False
    assert store.has_seen("k2") is True
    store.close()

    # Disk-backed SQLite
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "replay.db")
        store_disk = SqliteReplayStore(db_path)
        assert store_disk.consume("sess-alpha", 500000) is True
        assert store_disk.has_seen("sess-alpha") is True
        store_disk.close()

        # Reopen to test persistence
        store_disk2 = SqliteReplayStore(db_path)
        assert store_disk2.has_seen("sess-alpha") is True
        assert store_disk2.consume("sess-alpha", 500000) is False
        store_disk2.close()


def test_replay_protector_validation_and_backends():
    with pytest.raises(ValueError, match="window_seconds must be positive"):
        ReplayProtector(window_seconds=0)
    with pytest.raises(ValueError, match="window_seconds must be positive"):
        ReplayProtector(window_seconds=-10.0)

    # Memory backend protector
    mem_store = MemoryReplayStore()
    p_mem = ReplayProtector(window_seconds=100.0, store=mem_store)
    now = 10000.0
    sid = b"\x01" * 16

    p_mem.check_and_record("sender-1", sid, now, current_time=now)
    assert p_mem.has_seen(f"sender-1:{sid.hex()}") is True

    with pytest.raises(ReplayDetectedError, match="REPLAY_DETECTED"):
        p_mem.check_and_record("sender-1", sid, now, current_time=now)

    with pytest.raises(StaleSessionError, match="STALE_SESSION"):
        p_mem.check_and_record("sender-1", b"\x02" * 16, now - 200.0, current_time=now)

    # SQLite backend protector
    sqlite_store = SqliteReplayStore(":memory:")
    p_sql = ReplayProtector(window_seconds=100.0, store=sqlite_store)

    p_sql.check_and_record("sender-sql", sid, now, current_time=now)
    assert p_sql.store.has_seen(f"sender-sql:{sid.hex()}") is True

    with pytest.raises(ReplayDetectedError, match="REPLAY_DETECTED"):
        p_sql.check_and_record("sender-sql", sid, now, current_time=now)
    sqlite_store.close()
