"""
Contract Test Suite for ReplayStore backends (D-02)
"""
import pytest
from medpqc.security.replay import (
    ReplayStore,
    InMemoryReplayStoreForTestsAndDevelopment,
    SqliteReplayStore,
)


@pytest.fixture(params=["memory", "sqlite"])
def replay_store(request, tmp_path):
    if request.param == "memory":
        store = InMemoryReplayStoreForTestsAndDevelopment()
        yield store
        store.close()
    else:
        db_path = str(tmp_path / "contract_replay.db")
        store = SqliteReplayStore(db_path)
        yield store
        store.close()


def test_replay_store_satisfies_protocol(replay_store):
    assert isinstance(replay_store, ReplayStore)


def test_atomic_consume_and_replay_rejection(replay_store):
    # First consume succeeds
    assert replay_store.consume("peerA", b"nonce123", 1000, 4000) is True
    assert replay_store.size() == 1
    assert replay_store.has_seen("peerA:6e6f6e6365313233") is True
    
    # Second consume with exact same key fails
    assert replay_store.consume("peerA", b"nonce123", 1000, 4000) is False
    assert replay_store.size() == 1
    
    # Different nonce succeeds
    assert replay_store.consume("peerA", b"nonce456", 1000, 4000) is True
    assert replay_store.size() == 2


def test_closed_store_fails_closed(replay_store):
    replay_store.close()
    with pytest.raises(RuntimeError):
        replay_store.consume("peerA", b"nonce123", 1000, 4000)
    with pytest.raises(RuntimeError):
        replay_store.has_seen("peerA:6e6f6e6365313233")
