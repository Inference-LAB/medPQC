"""
medpqc.security.replay
======================
Session Replay and Stale Transmission Protection.

Enforces timestamp sliding-window validity and tracks active session identifiers
across thread-safe memory and ACID-persistent SQLite backends.
Defends against session replay and packet injection attacks.
"""

import contextlib
import sqlite3
import threading
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable


class ReplayDetectedError(ValueError):
    """Raised when a replayed session identifier is detected."""


class StaleSessionError(ValueError):
    """Raised when a session timestamp is outside the permitted sliding window."""


@runtime_checkable
class ReplayStore(Protocol):
    """Protocol defining the mandatory atomic replay consumption contract."""

    def consume(
        self,
        cache_key_or_peer: str,
        timestamp_or_nonce: int | bytes | str,
        timestamp_ms_or_expires: int | None = None,
        expires_at_ms: int | None = None,
    ) -> bool:
        """
        Atomically records a session key or peer/nonce pair.
        Returns True if newly recorded, False if already consumed.
        """
        ...

    def size(self) -> int:
        """Returns the number of currently active session entries."""
        ...

    def close(self) -> None:
        """Releases underlying resources."""
        ...


class ReplayStoreBase(ABC):
    """Abstract base class for session replay storage backends."""

    def __init__(self) -> None:
        self._is_closed: bool = False

    @abstractmethod
    def consume(
        self,
        cache_key_or_peer: str,
        timestamp_or_nonce: int | bytes | str,
        timestamp_ms_or_expires: int | None = None,
        expires_at_ms: int | None = None,
    ) -> bool:
        """
        Atomically records the session entry.
        Returns True if newly recorded.
        Returns False if already recorded.
        """

    @abstractmethod
    def has_seen(self, cache_key: str) -> bool:
        """Returns True if the cache key has already been recorded."""

    @abstractmethod
    def record(self, cache_key: str, timestamp_ms: int) -> None:
        """Records a session cache key with its timestamp."""

    @abstractmethod
    def prune(self, cutoff_ms: int) -> None:
        """Removes entries older than the cutoff timestamp."""

    @abstractmethod
    def size(self) -> int:
        """Returns current count of recorded sessions."""

    def close(self) -> None:
        """Releases underlying resources (connections, handles)."""
        self._is_closed = True


class InMemoryReplayStoreForTestsAndDevelopment(ReplayStoreBase):
    """
    Thread-safe in-memory replay store.
    Strictly intended for development, testing, and single-process demonstrations.
    NOT intended for multi-process production deployments.
    """

    def __init__(self) -> None:
        super().__init__()
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def _normalize_args(
        self,
        cache_key_or_peer: str,
        timestamp_or_nonce: int | bytes | str,
        timestamp_ms_or_expires: int | None = None,
        expires_at_ms: int | None = None,
    ) -> tuple[str, int, int]:
        if isinstance(timestamp_or_nonce, int):
            cache_key = str(cache_key_or_peer)
            ts = timestamp_or_nonce
            exp = timestamp_ms_or_expires if timestamp_ms_or_expires is not None else ts + 300_000
        else:
            nonce_bytes = (
                timestamp_or_nonce.hex()
                if isinstance(timestamp_or_nonce, (bytes, bytearray))
                else str(timestamp_or_nonce)
            )
            cache_key = f"{cache_key_or_peer}:{nonce_bytes}"
            ts = int(timestamp_ms_or_expires) if timestamp_ms_or_expires is not None else 0
            exp = int(expires_at_ms) if expires_at_ms is not None else ts + 300_000
        return cache_key, ts, exp

    def consume(
        self,
        cache_key_or_peer: str,
        timestamp_or_nonce: int | bytes | str,
        timestamp_ms_or_expires: int | None = None,
        expires_at_ms: int | None = None,
    ) -> bool:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        cache_key, ts, exp = self._normalize_args(
            cache_key_or_peer, timestamp_or_nonce, timestamp_ms_or_expires, expires_at_ms
        )
        with self._lock:
            # Prune expired entries
            cutoff = ts - (exp - ts)
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
            if cache_key in self._seen:
                return False
            self._seen[cache_key] = ts
            return True

    def has_seen(self, cache_key: str) -> bool:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        with self._lock:
            return cache_key in self._seen

    def record(self, cache_key: str, timestamp_ms: int) -> None:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        with self._lock:
            self._seen[cache_key] = timestamp_ms

    def prune(self, cutoff_ms: int) -> None:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff_ms}

    def size(self) -> int:
        with self._lock:
            return len(self._seen)

    def close(self) -> None:
        with self._lock:
            super().close()
            self._seen.clear()


# Testing and backward-compatibility alias
MemoryReplayStore = InMemoryReplayStoreForTestsAndDevelopment


class SqliteReplayStore(ReplayStoreBase):
    """
    ACID-compliant, thread-safe, multi-process persistent replay store backed by SQLite.
    Employs Write-Ahead Logging (WAL) and atomic INSERT OR IGNORE rowcount assertions.
    """

    def __init__(self, db_path: str = ":memory:", timeout: float = 30.0) -> None:
        super().__init__()
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            db_path,
            timeout=timeout,
            check_same_thread=False,
            isolation_level=None,
        )
        if db_path != ":memory:":
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)};")
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_sessions (
                    cache_key TEXT PRIMARY KEY,
                    timestamp_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_seen_sessions_exp
                ON seen_sessions(expires_at_ms)
                """
            )

    def _normalize_args(
        self,
        cache_key_or_peer: str,
        timestamp_or_nonce: int | bytes | str,
        timestamp_ms_or_expires: int | None = None,
        expires_at_ms: int | None = None,
    ) -> tuple[str, int, int]:
        if isinstance(timestamp_or_nonce, int):
            cache_key = str(cache_key_or_peer)
            ts = timestamp_or_nonce
            exp = timestamp_ms_or_expires if timestamp_ms_or_expires is not None else ts + 300_000
        else:
            nonce_bytes = (
                timestamp_or_nonce.hex()
                if isinstance(timestamp_or_nonce, (bytes, bytearray))
                else str(timestamp_or_nonce)
            )
            cache_key = f"{cache_key_or_peer}:{nonce_bytes}"
            ts = int(timestamp_ms_or_expires) if timestamp_ms_or_expires is not None else 0
            exp = int(expires_at_ms) if expires_at_ms is not None else ts + 300_000
        return cache_key, ts, exp

    def consume(
        self,
        cache_key_or_peer: str,
        timestamp_or_nonce: int | bytes | str,
        timestamp_ms_or_expires: int | None = None,
        expires_at_ms: int | None = None,
    ) -> bool:
        """Atomically prunes expired sessions and consumes the session key."""
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        cache_key, ts, exp = self._normalize_args(
            cache_key_or_peer, timestamp_or_nonce, timestamp_ms_or_expires, expires_at_ms
        )
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM seen_sessions WHERE expires_at_ms < ?", (ts,))
            cur.execute(
                "INSERT OR IGNORE INTO seen_sessions (cache_key, timestamp_ms, expires_at_ms) VALUES (?, ?, ?)",
                (cache_key, int(ts), int(exp)),
            )
            return cur.rowcount > 0

    def has_seen(self, cache_key: str) -> bool:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT 1 FROM seen_sessions WHERE cache_key = ?", (cache_key,))
            return cur.fetchone() is not None

    def record(self, cache_key: str, timestamp_ms: int) -> None:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        expires_at_ms = int(timestamp_ms) + 300_000
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO seen_sessions (cache_key, timestamp_ms, expires_at_ms) VALUES (?, ?, ?)",
                (cache_key, int(timestamp_ms), expires_at_ms),
            )

    def prune(self, cutoff_ms: int) -> None:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        with self._lock:
            self._conn.execute("DELETE FROM seen_sessions WHERE timestamp_ms < ?", (int(cutoff_ms),))

    def size(self) -> int:
        if self._is_closed:
            raise RuntimeError("ReplayStore is closed; failing closed.")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM seen_sessions")
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            super().close()
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()


class ReplayProtector:
    """
    Session Replay and Stale Transmission Filter.
    Enforces timestamp sliding-window validity and tracks active session identifiers
    using a pluggable, atomic storage backend.
    """

    def __init__(
        self,
        window_seconds: float = 300.0,
        store: ReplayStoreBase | None = None,
    ) -> None:
        self.window_seconds = float(window_seconds)
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_ms = int(self.window_seconds * 1000)
        if store is None:
            raise TypeError("A ReplayStoreBase instance is mandatory for ReplayProtector.")
        self.store = store

    def validate_and_record(
        self,
        session_id: str,
        timestamp: float,
        current_time: float | None = None,
    ) -> bool:
        """Validates timestamp freshness and atomically records the session ID."""
        now_sec = current_time if current_time is not None else 0.0
        now_ms = int(now_sec * 1000) if now_sec < 1e11 else int(now_sec)
        ts_ms = int(timestamp * 1000) if timestamp < 1e11 else int(timestamp)

        if current_time is not None:
            skew = abs(now_ms - ts_ms)
            if skew > self.window_ms:
                raise StaleSessionError(
                    f"Timestamp {ts_ms}ms differs from current time {now_ms}ms by {skew}ms (limit: {self.window_ms}ms)"
                )

        expires_at = ts_ms + self.window_ms
        return self.store.consume(session_id, ts_ms, expires_at)

    def check_and_record(
        self,
        sender_id: str,
        session_id: bytes | str,
        timestamp: float,
        current_time: float | None = None,
    ) -> bool:
        """Legacy helper for session replay validation and recording."""
        sid_str = session_id.hex() if isinstance(session_id, (bytes, bytearray)) else str(session_id)
        cache_key = f"{sender_id}:{sid_str}"
        now_sec = current_time if current_time is not None else 0.0
        now_ms = int(now_sec * 1000) if now_sec < 1e11 else int(now_sec)
        ts_ms = int(timestamp * 1000) if timestamp < 1e11 else int(timestamp)

        if current_time is not None:
            skew = abs(now_ms - ts_ms)
            if skew > self.window_ms:
                raise StaleSessionError(
                    f"STALE_SESSION: Timestamp {ts_ms}ms differs from current time {now_ms}ms by {skew}ms"
                )

        expires_at = ts_ms + self.window_ms
        if not self.store.consume(cache_key, ts_ms, expires_at):
            raise ReplayDetectedError(f"REPLAY_DETECTED: Session key {cache_key} has already been consumed.")
        return True

    def has_seen(self, cache_key: str) -> bool:
        """Delegates has_seen to underlying replay store."""
        return self.store.has_seen(cache_key)
