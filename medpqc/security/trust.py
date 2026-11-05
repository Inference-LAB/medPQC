"""
medpqc.security.trust
=====================
Healthcare Node Trust Store & Public Key Registry.

Maps hospital, PACS archive, and clinical workstation node identifiers
to authorized Ed25519 identity public keys. Enforces mutual peer identity
verification, rotation, validity windows, and explicit revocation state.
"""

import contextlib
import os
import tempfile
import threading
from typing import Any

from ..utils.canonical import canonical_json_dumps, canonical_json_loads


class TrustStore:
    """
    Healthcare Node Trust Store & Public Key Registry.
    Supports key rotation, validity windows, explicit revocation, and atomic file persistence.
    """

    ED25519_KEY_LEN = 32

    def __init__(self, initial_peers: dict[str, bytes] | None = None):
        self._lock = threading.RLock()
        # Maps node_id -> dict of key_id -> dict(public_key, not_before, not_after, status)
        self._nodes: dict[str, dict[str, dict[str, Any]]] = {}
        self._revoked_nodes: set[str] = set()
        self._revoked_keys: set[str] = set()

        if initial_peers:
            for node_id, key_bytes in initial_peers.items():
                self.register_peer(node_id, key_bytes)

    def register_peer(
        self,
        node_id: str,
        public_key_bytes: bytes,
        key_id: str | None = None,
        not_before: int = 0,
        not_after: int | None = None,
    ) -> str:
        """
        Registers an authorized public key for a node.
        Supports key rotation by registering multiple concurrent keys per node under distinct key_ids.
        Raises PermissionError if the node has been revoked (requires explicit reinstate_node).
        """
        if not isinstance(node_id, str) or not node_id.strip():
            raise ValueError("node_id must be a non-empty string.")
        if not isinstance(public_key_bytes, (bytes, bytearray)):
            raise TypeError(f"public_key_bytes must be bytes, got {type(public_key_bytes).__name__}")
        if len(public_key_bytes) != self.ED25519_KEY_LEN:
            raise ValueError(
                f"Invalid Ed25519 public key length: {len(public_key_bytes)} bytes. "
                f"Expected exactly {self.ED25519_KEY_LEN} bytes."
            )

        kid = key_id or public_key_bytes.hex()[:16]

        with self._lock:
            if node_id in self._revoked_nodes:
                raise PermissionError(
                    f"REVOKED_NODE: Node '{node_id}' is revoked. Explicit reinstate_node() required before registering new keys."
                )

            if kid in self._revoked_keys:
                raise PermissionError(f"REVOKED_KEY: Key ID '{kid}' is revoked and cannot be registered.")

            if node_id not in self._nodes:
                self._nodes[node_id] = {}

            self._nodes[node_id][kid] = {
                "public_key": bytes(public_key_bytes),
                "key_id": kid,
                "not_before": int(not_before),
                "not_after": int(not_after) if not_after is not None else None,
                "status": "active",
            }
        return kid

    add_trusted_peer = register_peer

    def revoke_node(self, node_id: str) -> None:
        """Revokes all trust for a peer node. Existing keys are disabled."""
        if not isinstance(node_id, str):
            raise ValueError("node_id must be a string.")
        with self._lock:
            self._revoked_nodes.add(node_id)
            if node_id in self._nodes:
                for kid in self._nodes[node_id]:
                    self._revoked_keys.add(kid)

    def revoke_peer(self, node_id: str) -> None:
        """Alias for revoke_node for backward compatibility."""
        self.revoke_node(node_id)

    def revoke_key(self, key_id: str) -> None:
        """Revokes a specific key ID (e.g. for key retirement or rotation)."""
        if not isinstance(key_id, str):
            raise ValueError("key_id must be a string.")
        with self._lock:
            self._revoked_keys.add(key_id)
            for node_id, keys in self._nodes.items():
                if key_id in keys:
                    keys[key_id]["status"] = "revoked"

    def reinstate_node(self, node_id: str) -> None:
        """Explicitly reinstates a previously revoked node."""
        with self._lock:
            self._revoked_nodes.discard(node_id)
            if node_id in self._nodes:
                for kid in self._nodes[node_id]:
                    self._revoked_keys.discard(kid)
                    self._nodes[node_id][kid]["status"] = "active"

    def is_trusted(
        self,
        node_id: str,
        public_key_bytes: bytes,
        current_time: int | None = None,
    ) -> bool:
        """Returns True if the peer ID and public key match an active, unrevoked key."""
        try:
            self.verify_peer(node_id, public_key_bytes, current_time=current_time)
            return True
        except (PermissionError, ValueError):
            return False

    def verify_peer(
        self,
        node_id: str,
        public_key_bytes: bytes,
        current_time: int | None = None,
    ) -> None:
        """
        Validates peer authorization, key validity window, and revocation state.
        Raises PermissionError on untrusted, revoked, or expired identity.
        """
        if not isinstance(node_id, str):
            raise TypeError("node_id must be a string.")
        if not isinstance(public_key_bytes, (bytes, bytearray)):
            raise TypeError("public_key_bytes must be bytes.")
        if len(public_key_bytes) != self.ED25519_KEY_LEN:
            raise ValueError(f"Invalid Ed25519 key length: {len(public_key_bytes)} bytes.")

        now = int(current_time) if current_time is not None else 0

        with self._lock:
            if node_id in self._revoked_nodes:
                raise PermissionError(f"REVOKED_PEER: Node '{node_id}' has been revoked from trust store.")

            node_keys = self._nodes.get(node_id)
            if not node_keys:
                raise PermissionError(f"UNTRUSTED_PEER: Node '{node_id}' is not registered in trust store.")

            # Search active keys for matching public key bytes
            match_found = False
            for kid, cred in node_keys.items():
                if cred["public_key"] == bytes(public_key_bytes):
                    if kid in self._revoked_keys or cred["status"] == "revoked":
                        raise PermissionError(f"REVOKED_KEY: Key ID '{kid}' for node '{node_id}' has been revoked.")
                    if current_time is not None:
                        if now < cred["not_before"]:
                            raise PermissionError(f"KEY_NOT_YET_VALID: Key ID '{kid}' is not active yet.")
                        if cred["not_after"] is not None and now > cred["not_after"]:
                            raise PermissionError(f"EXPIRED_KEY: Key ID '{kid}' expired at {cred['not_after']}.")
                    match_found = True
                    break

            if not match_found:
                raise PermissionError(f"IDENTITY_MISMATCH: Key for '{node_id}' does not match registered keys.")

    def list_peers(self) -> list[str]:
        """Returns sorted list of active registered peer node IDs."""
        with self._lock:
            return sorted([n for n in self._nodes.keys() if n not in self._revoked_nodes])

    def export_registry(self) -> dict[str, Any]:
        """Exports full credentials structure as hex-encoded dictionary."""
        with self._lock:
            export_data: dict[str, Any] = {
                "nodes": {},
                "revoked_nodes": sorted(list(self._revoked_nodes)),
                "revoked_keys": sorted(list(self._revoked_keys)),
            }
            for node_id, keys in sorted(self._nodes.items()):
                export_data["nodes"][node_id] = {}
                for kid, cred in sorted(keys.items()):
                    export_data["nodes"][node_id][kid] = {
                        "public_key": cred["public_key"].hex(),
                        "not_before": cred["not_before"],
                        "not_after": cred["not_after"],
                        "status": cred["status"],
                    }
            return export_data

    def import_registry(self, data: dict[str, Any]) -> None:
        """Imports credentials structure with strict validation."""
        with self._lock:
            if "nodes" in data:
                # v2.3 credentials schema
                for node_id in data.get("revoked_nodes", []):
                    self._revoked_nodes.add(str(node_id))
                for kid in data.get("revoked_keys", []):
                    self._revoked_keys.add(str(kid))
                for node_id, keys in data.get("nodes", {}).items():
                    for kid, cred in keys.items():
                        key_bytes = bytes.fromhex(cred["public_key"])
                        if len(key_bytes) != self.ED25519_KEY_LEN:
                            raise ValueError(f"Malformed key in import for node {node_id}")
                        if node_id not in self._nodes:
                            self._nodes[node_id] = {}
                        self._nodes[node_id][kid] = {
                            "public_key": key_bytes,
                            "key_id": kid,
                            "not_before": int(cred.get("not_before", 0)),
                            "not_after": int(cred["not_after"]) if cred.get("not_after") is not None else None,
                            "status": cred.get("status", "active"),
                        }
            else:
                # Legacy simple dict mapping
                for node_id, hex_key in data.items():
                    self.register_peer(node_id, bytes.fromhex(hex_key))

    def save_to_file(self, filepath: str) -> None:
        """
        Atomically saves the trust store state using temp file and rename.
        Enforces restrictive permissions (mode 0600) where supported.
        """
        data = self.export_registry()
        raw_bytes = canonical_json_dumps(data)
        dirname = os.path.dirname(os.path.abspath(filepath)) or "."
        os.makedirs(dirname, exist_ok=True)

        with tempfile.NamedTemporaryFile(dir=dirname, delete=False, mode="wb") as tf:
            tf.write(raw_bytes)
            tf.flush()
            os.fsync(tf.fileno())
            tmp_path = tf.name

        with contextlib.suppress(AttributeError, OSError):
            os.chmod(tmp_path, 0o600)

        os.replace(tmp_path, filepath)

    def load_from_file(self, filepath: str) -> None:
        """Loads trust store state from a JSON file with integrity and length validation."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Trust store file not found: {filepath}")

        with open(filepath, "rb") as f:
            raw = f.read()

        state = canonical_json_loads(raw)
        with self._lock:
            self._nodes.clear()
            self._revoked_nodes.clear()
            self._revoked_keys.clear()
            self.import_registry(state)
