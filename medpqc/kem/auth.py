"""
medpqc.kem.auth
===============
Authenticated Hybrid Post-Quantum Key Exchange Protocol.

Provides mutual peer authentication, full canonical transcript integrity,
downgrade protection, mandatory recipient binding, and persistent atomic replay defense.

Guarantees:
  - Mutual Authentication: Both Initiator and Responder are authenticated via Ed25519 signatures.
  - Trust Store Enforcement: Peer identities must be registered and unrevoked in a TrustStore.
  - Strict Wire Framing: Strict length-prefixed canonical encoding rejecting malformed or trailing bytes.
  - Recipient Binding: Mandatory recipient verification preventing misrouted or cross-recipient attacks.
  - Atomic Replay Defense: Consumption occurs only after signature and trust validation succeed.
  - Directional Key Derivation: Independent keys for initiator-to-responder and responder-to-initiator.
"""

import hashlib
import secrets
import threading
import time
import warnings
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..security.replay import (
    InMemoryReplayStoreForTestsAndDevelopment,
    ReplayDetectedError,
    ReplayStoreBase,
    StaleSessionError,
)
from ..security.trust import TrustStore
from ..utils.canonical import length_prefix_decode, length_prefix_encode
from .combiner import HybridKeyCombiner
from .ecdh import ECDHKeyExchange, generate_ecdh_keypair
from .rlwe import PostQuantumKEM

MEDPQC_PROTOCOL_VERSION = "MedPQC-v2.4"
DEFAULT_SUITE_ID = "ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM"
SUPPORTED_SUITES = ("ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",)
SUPPORTED_VERSIONS = (
    "MedPQC-v2.4",
    "MedPQC-v2.3",
)


class RemovedAPIError(RuntimeError):
    """Raised when an obsolete or removed API is accessed."""


class NonDurableReplayStoreWarning(UserWarning):
    """Warning emitted when a non-durable in-memory replay store is used."""


class UnsupportedSuiteError(ValueError):
    """Raised when an unapproved or weak cryptographic suite is proposed."""


class UnsupportedVersionError(UnsupportedSuiteError):
    """Raised when an unsupported protocol version is negotiated."""


class AuthenticationError(PermissionError):
    """Raised when digital signature or identity verification fails."""


class WrongRecipientError(AuthenticationError):
    """Raised when a handshake message is addressed to a different recipient node ID."""


class ParseError(ValueError):
    """Raised when a wire payload cannot be parsed or violates canonical constraints."""


class KeyUsageLimitExceeded(OverflowError):
    """Raised when a session key invocation counter exceeds safety bounds."""


class SessionState(Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLOSED = "CLOSED"


class IdentityKeyPair:
    """Ed25519 Long-Term Identity Key for Peer Authentication."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | None = None,
        node_id: str = "",
    ) -> None:
        if private_key is None:
            self._priv = ed25519.Ed25519PrivateKey.generate()
        else:
            self._priv = private_key
        self._pub = self._priv.public_key()
        self.node_id = str(node_id)

    @classmethod
    def generate(cls, node_id: str = "") -> "IdentityKeyPair":
        """Factory method to generate a fresh Ed25519 identity keypair with an optional node_id."""
        return cls(private_key=None, node_id=node_id)

    @property
    def public_identity(self) -> bytes:
        """Alias returning raw public key bytes for trust store registration."""
        return self.public_bytes

    @property
    def public_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        return self._pub.public_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        """Generates 64-byte Ed25519 signature."""
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("Message must be bytes.")
        return self._priv.sign(bytes(message))

    def verify(
        self_or_cls: Any,
        arg1: bytes,
        arg2: bytes,
    ) -> bool:
        """
        Verifies Ed25519 signature against public key.
        Supports:
          - keypair.verify(message, signature)
          - IdentityKeyPair.verify(pub_bytes, signature, message)
        Catches ONLY InvalidSignature and ValueError; never masks system errors.
        """
        if isinstance(self_or_cls, IdentityKeyPair):
            pub_bytes = self_or_cls.public_bytes
            message = arg1
            signature = arg2
        else:
            pub_bytes = self_or_cls
            if (
                isinstance(arg2, (bytes, bytearray))
                and len(arg2) == 64
                and (not isinstance(arg1, (bytes, bytearray)) or len(arg1) != 64)
            ):
                message = arg1
                signature = arg2
            else:
                signature = arg1
                message = arg2

        if not isinstance(pub_bytes, (bytes, bytearray)) or len(pub_bytes) != 32:
            return False

        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            return False

        if not isinstance(message, (bytes, bytearray)):
            return False

        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(pub_bytes))
            pub.verify(bytes(signature), bytes(message))
            return True
        except (InvalidSignature, ValueError):
            return False

    def export_private_key(self, passphrase: bytes | None = None) -> bytes:
        """Exports private key as PKCS8 PEM bytes (optionally encrypted with passphrase)."""
        enc: serialization.KeySerializationEncryption
        if passphrase is not None:
            enc = serialization.BestAvailableEncryption(passphrase)
        else:
            enc = serialization.NoEncryption()
        return self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    @classmethod
    def import_private_key(
        cls,
        pem_bytes: bytes,
        passphrase: bytes | None = None,
        node_id: str = "",
    ) -> "IdentityKeyPair":
        """Imports an Ed25519 private key from PKCS8 PEM bytes."""
        priv = serialization.load_pem_private_key(pem_bytes, password=passphrase)
        if not isinstance(priv, ed25519.Ed25519PrivateKey):
            raise ValueError("Loaded key is not an Ed25519 private key.")
        return cls(private_key=priv, node_id=node_id)

    def to_encrypted_pkcs8(self, passphrase: bytes) -> bytes:
        """Exports private key as passphrase-encrypted PKCS8 PEM bytes with embedded node_id header."""
        if not isinstance(passphrase, (bytes, bytearray)) or len(passphrase) == 0:
            raise ValueError("Passphrase must be non-empty bytes.")
        pem = self.export_private_key(passphrase=bytes(passphrase))
        if self.node_id:
            return f"# Node-ID: {self.node_id}\n".encode("utf-8") + pem
        return pem

    @classmethod
    def from_encrypted_pkcs8(
        cls,
        pem_bytes: bytes,
        passphrase: bytes,
        node_id: str = "",
    ) -> "IdentityKeyPair":
        """Imports keypair from passphrase-encrypted PKCS8 PEM bytes."""
        node_id_found = node_id
        if pem_bytes.startswith(b"# Node-ID: "):
            first_line, rest = pem_bytes.split(b"\n", 1)
            node_id_found = first_line.decode("utf-8")[11:].strip()
            pem_bytes = rest
        return cls.import_private_key(pem_bytes, passphrase=passphrase, node_id=node_id_found)


def validate_uint64_timestamp(ts: Any) -> int:
    """Strictly validates that timestamp is an integer representing uint64 milliseconds."""
    if isinstance(ts, bool):
        raise ParseError(f"Timestamp cannot be a boolean: {ts}")
    if not isinstance(ts, int):
        raise ParseError(f"Timestamp must be an integer millisecond value, got {type(ts).__name__}: {ts}")
    if ts < 0:
        raise ParseError(f"Negative timestamp rejected: {ts}")
    if ts >= 2**64:
        raise ParseError(f"Timestamp exceeds uint64 bounds: {ts}")
    # Enforce millisecond scale: values below 1e11 represent seconds and are rejected
    if ts < 100_000_000_000:
        raise ParseError(f"Seconds-encoded timestamp rejected (must be uint64 milliseconds): {ts}")
    return ts


def serialize_canonical_init_transcript(
    protocol_version: str,
    offered_suites: tuple[str, ...],
    sender_id: str,
    receiver_id: str,
    session_id: bytes,
    timestamp_ms: int,
    alice_id_pub: bytes,
    ecdh_alice_pub: bytes,
    pq_alice_pub: bytes,
) -> bytes:
    """Canonical length-prefixed serialization of the Initiation Transcript."""
    elements = [
        b"MedPQC-Canonical-Init-v2.4",
        b"role:initiator",
        protocol_version.encode("utf-8"),
        ":".join(offered_suites).encode("utf-8"),
        sender_id.encode("utf-8"),
        receiver_id.encode("utf-8"),
        session_id,
        timestamp_ms.to_bytes(8, "big"),
        alice_id_pub,
        ecdh_alice_pub,
        pq_alice_pub,
    ]
    return length_prefix_encode(elements)


def serialize_canonical_resp_transcript(
    protocol_version: str,
    selected_suite: str,
    sender_id: str,
    receiver_id: str,
    session_id: bytes,
    timestamp_ms: int,
    init_transcript_hash: bytes,
    responder_nonce: bytes,
    bob_id_pub: bytes,
    ecdh_bob_pub: bytes,
    pq_ciphertext: bytes,
) -> bytes:
    """Canonical length-prefixed serialization of the Response Transcript."""
    elements = [
        b"MedPQC-Canonical-Resp-v2.4",
        b"role:responder",
        protocol_version.encode("utf-8"),
        selected_suite.encode("utf-8"),
        sender_id.encode("utf-8"),
        receiver_id.encode("utf-8"),
        session_id,
        timestamp_ms.to_bytes(8, "big"),
        init_transcript_hash,
        responder_nonce,
        bob_id_pub,
        ecdh_bob_pub,
        pq_ciphertext,
    ]
    return length_prefix_encode(elements)


def encode_initiation(msg: dict[str, Any]) -> bytes:
    """Serializes initiation message dictionary into canonical binary wire framing."""
    ts_ms = validate_uint64_timestamp(msg["timestamp"])
    elements = [
        b"MEDPQCIN",
        msg["protocol_version"].encode("utf-8"),
        msg["suite_id"].encode("utf-8"),
        ":".join(msg.get("offered_suites", [msg["suite_id"]])).encode("utf-8"),
        msg["sender_id"].encode("utf-8"),
        msg["receiver_id"].encode("utf-8"),
        msg["session_id"],
        ts_ms.to_bytes(8, "big"),
        msg["alice_id_pub"],
        msg["ecdh_pub"],
        msg["pq_pub"],
        msg["signature"],
    ]
    return length_prefix_encode(elements)


def parse_initiation(raw: bytes | dict[str, Any] | tuple[Any, ...]) -> dict[str, Any]:
    """Strictly parses and validates an initiation wire message."""
    if isinstance(raw, tuple):
        raw = raw[0]

    if isinstance(raw, dict):
        if "offered_suites" not in raw and "suite_id" not in raw:
            raise ParseError("Missing required initiation suite fields.")
        ts_ms = validate_uint64_timestamp(raw["timestamp"])
        res = dict(raw)
        res["timestamp"] = ts_ms
        return res

    if not isinstance(raw, (bytes, bytearray)):
        raise ParseError(f"Expected bytes for wire message, got {type(raw).__name__}")

    try:
        elements = length_prefix_decode(bytes(raw))
    except (ValueError, TypeError) as e:
        raise ParseError(f"Malformed length-prefixed framing: {e}") from e

    if len(elements) != 12:
        raise ParseError(f"Invalid initiation element count: expected 12, got {len(elements)}")

    if elements[0] != b"MEDPQCIN":
        raise ParseError(f"Invalid initiation magic bytes: {elements[0]!r}")

    try:
        protocol_version = elements[1].decode("utf-8")
        suite_id = elements[2].decode("utf-8")
        offered_str = elements[3].decode("utf-8")
        offered_suites = offered_str.split(":") if offered_str else [suite_id]
        sender_id = elements[4].decode("utf-8")
        receiver_id = elements[5].decode("utf-8")
        session_id = elements[6]
        ts_ms = int.from_bytes(elements[7], "big")
        validate_uint64_timestamp(ts_ms)
        alice_id_pub = elements[8]
        ecdh_pub = elements[9]
        pq_pub = elements[10]
        signature = elements[11]
    except UnicodeDecodeError as e:
        raise ParseError(f"Invalid UTF-8 encoding in initiation field: {e}") from e

    return {
        "protocol_version": protocol_version,
        "suite_id": suite_id,
        "offered_suites": offered_suites,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "session_id": session_id,
        "timestamp": ts_ms,
        "alice_id_pub": alice_id_pub,
        "ecdh_pub": ecdh_pub,
        "pq_pub": pq_pub,
        "signature": signature,
    }


def encode_response(msg: dict[str, Any]) -> bytes:
    """Serializes response message dictionary into canonical binary wire framing."""
    ts_ms = validate_uint64_timestamp(msg["timestamp"])
    elements = [
        b"MEDPQCRP",
        msg["protocol_version"].encode("utf-8"),
        msg["selected_suite"].encode("utf-8"),
        msg["sender_id"].encode("utf-8"),
        msg["receiver_id"].encode("utf-8"),
        msg["session_id"],
        ts_ms.to_bytes(8, "big"),
        msg["init_transcript_hash"],
        msg["responder_nonce"],
        msg["bob_id_pub"],
        msg["ecdh_pub"],
        msg["pq_ciphertext"],
        msg["signature"],
    ]
    return length_prefix_encode(elements)


def parse_response(raw: bytes | dict[str, Any] | tuple[Any, ...]) -> dict[str, Any]:
    """Strictly parses and validates a response wire message."""
    if isinstance(raw, tuple):
        raw = raw[0]

    if isinstance(raw, dict):
        selected_suite = raw.get("selected_suite") or raw.get("suite_id")
        if not selected_suite:
            raise ParseError("Missing suite field in response message.")
        if "init_transcript_hash" not in raw and "responder_nonce" not in raw:
            raise ParseError("Missing required response fields or initiation message passed as response.")
        ts_ms = validate_uint64_timestamp(raw["timestamp"])
        res = dict(raw)
        res["timestamp"] = ts_ms
        res["selected_suite"] = selected_suite
        return res

    if not isinstance(raw, (bytes, bytearray)):
        raise ParseError(f"Expected bytes for wire message, got {type(raw).__name__}")

    try:
        elements = length_prefix_decode(bytes(raw))
    except (ValueError, TypeError) as e:
        raise ParseError(f"Malformed length-prefixed framing: {e}") from e

    if len(elements) != 13:
        raise ParseError(f"Invalid response element count: expected 13, got {len(elements)}")

    if elements[0] != b"MEDPQCRP":
        raise ParseError(f"Invalid response magic bytes: {elements[0]!r}")

    try:
        protocol_version = elements[1].decode("utf-8")
        selected_suite = elements[2].decode("utf-8")
        sender_id = elements[3].decode("utf-8")
        receiver_id = elements[4].decode("utf-8")
        session_id = elements[5]
        ts_ms = int.from_bytes(elements[6], "big")
        validate_uint64_timestamp(ts_ms)
        init_transcript_hash = elements[7]
        responder_nonce = elements[8]
        bob_id_pub = elements[9]
        ecdh_pub = elements[10]
        pq_ciphertext = elements[11]
        signature = elements[12]
    except UnicodeDecodeError as e:
        raise ParseError(f"Invalid UTF-8 encoding in response field: {e}") from e

    return {
        "protocol_version": protocol_version,
        "selected_suite": selected_suite,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "session_id": session_id,
        "timestamp": ts_ms,
        "init_transcript_hash": init_transcript_hash,
        "responder_nonce": responder_nonce,
        "bob_id_pub": bob_id_pub,
        "ecdh_pub": ecdh_pub,
        "pq_ciphertext": pq_ciphertext,
        "signature": signature,
    }


class DirectionalCipher:
    """
    Direction-bound AEAD cipher produced by a Session.
    Binds encryption and decryption invocations to the Session's shared invocation counter.
    """

    def __init__(self, session: "Session", key: bytes, is_sender: bool) -> None:
        self._session = session
        self._key = key
        self._is_sender = is_sender

    def encrypt(self, data: bytes, aad: bytes = b"", nonce: bytes | None = None) -> bytes:
        """Encrypts data using session directional key and increments invocation counter."""
        if not self._session.is_active:
            raise PermissionError("Session is closed; cipher operations rejected.")

        self._session.check_and_increment_counter(self._is_sender)

        if nonce is None:
            nonce = secrets.token_bytes(12)
        elif len(nonce) != 12:
            raise ValueError(f"AES-GCM nonce must be exactly 12 bytes, got {len(nonce)}")

        aesgcm = AESGCM(self._key)
        ct_tag = aesgcm.encrypt(nonce, data, aad)
        return nonce + ct_tag

    def decrypt(self, payload: bytes, aad: bytes = b"") -> bytes:
        """Decrypts payload [nonce(12B) + ciphertext + tag(16B)] using session directional key."""
        if not self._session.is_active:
            raise PermissionError("Session is closed; cipher operations rejected.")

        if len(payload) < 28:
            raise ValueError("Payload too short for AES-GCM (nonce 12B + tag 16B required)")

        nonce = payload[:12]
        ct_tag = payload[12:]

        aesgcm = AESGCM(self._key)
        try:
            return aesgcm.decrypt(nonce, ct_tag, aad)
        except InvalidTag as e:
            raise AuthenticationError("Decryption authentication verification failed.") from e


class Session:
    """
    Stateful secure cryptographic session between two authenticated PACS nodes.
    Maintains directional encryption keys, message sequence counters, and thread-safe state.
    """

    MAX_MESSAGE_LIMIT: int = 65536  # Conservative session invocation cap

    def __init__(
        self,
        session_id: bytes,
        session_key_id: bytes,
        role: str,
        k_send: bytes,
        k_recv: bytes,
        local_node_id: str,
        peer_node_id: str,
        suite_id: str = DEFAULT_SUITE_ID,
    ) -> None:
        self.session_id = session_id
        self.session_key_id = session_key_id
        self.role = role
        self._k_send = k_send
        self._k_recv = k_recv
        self.local_node_id = local_node_id
        self.peer_node_id = peer_node_id
        self.suite_id = suite_id
        self._send_counter = 0
        self._recv_counter = 0
        self._lock = threading.Lock()
        self._state = SessionState.ESTABLISHED

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._state == SessionState.ESTABLISHED

    @property
    def state(self) -> SessionState:
        with self._lock:
            return self._state

    @property
    def k_send(self) -> bytes:
        return self.get_send_key()

    @property
    def k_recv(self) -> bytes:
        return self.get_recv_key()

    def get_send_key(self) -> bytes:
        with self._lock:
            if self._state != SessionState.ESTABLISHED:
                raise PermissionError("Session is closed.")
            return self._k_send

    def get_recv_key(self) -> bytes:
        with self._lock:
            if self._state != SessionState.ESTABLISHED:
                raise PermissionError("Session is closed.")
            return self._k_recv

    def check_and_increment_counter(self, is_sender: bool) -> int:
        with self._lock:
            if self._state != SessionState.ESTABLISHED:
                raise PermissionError("Session is closed.")
            if is_sender:
                if self._send_counter >= self.MAX_MESSAGE_LIMIT:
                    raise KeyUsageLimitExceeded(
                        f"Send key usage limit exceeded ({self.MAX_MESSAGE_LIMIT} invocations)."
                    )
                ctr = self._send_counter
                self._send_counter += 1
                return ctr
            else:
                if self._recv_counter >= self.MAX_MESSAGE_LIMIT:
                    raise KeyUsageLimitExceeded(
                        f"Recv key usage limit exceeded ({self.MAX_MESSAGE_LIMIT} invocations)."
                    )
                ctr = self._recv_counter
                self._recv_counter += 1
                return ctr

    def increment_send_counter(self) -> int:
        return self.check_and_increment_counter(is_sender=True)

    def increment_recv_counter(self) -> int:
        return self.check_and_increment_counter(is_sender=False)

    def sender_cipher(self) -> DirectionalCipher:
        """Produces a direction-bound cipher using the send key and shared counter."""
        with self._lock:
            if self._state != SessionState.ESTABLISHED:
                raise PermissionError("Session is closed.")
            return DirectionalCipher(self, self._k_send, is_sender=True)

    def receiver_cipher(self) -> DirectionalCipher:
        """Produces a direction-bound cipher using the receive key and shared counter."""
        with self._lock:
            if self._state != SessionState.ESTABLISHED:
                raise PermissionError("Session is closed.")
            return DirectionalCipher(self, self._k_recv, is_sender=False)

    def close(self) -> None:
        """Closes the session and zeroes references to symmetric key material."""
        with self._lock:
            self._state = SessionState.CLOSED
            self._k_send = b"\x00" * len(self._k_send)
            self._k_recv = b"\x00" * len(self._k_recv)


class InitiatorContext:
    """
    Context for handshake initiation and finalization.
    Holds local identity and trust store; verifies peer responses.
    """

    MAX_CLOCK_SKEW_MS: int = 300_000

    def __init__(
        self,
        node_id: str,
        identity: IdentityKeyPair,
        trust_store: TrustStore,
    ) -> None:
        if not node_id:
            raise ValueError("Initiator node_id must be non-empty.")
        if not isinstance(identity, IdentityKeyPair):
            raise TypeError("identity must be an IdentityKeyPair instance.")
        if not isinstance(trust_store, TrustStore):
            raise TypeError("trust_store must be a TrustStore instance.")

        self.node_id = str(node_id)
        self.identity = identity
        self.trust_store = trust_store
        self._pending: dict[bytes, tuple[ECDHKeyExchange, PostQuantumKEM, bytes, str, int]] = {}

    def initiate(
        self,
        receiver_id: str,
        session_id: bytes | None = None,
        timestamp: int | None = None,
        protocol_version: str = MEDPQC_PROTOCOL_VERSION,
        suite_id: str = DEFAULT_SUITE_ID,
        offered_suites: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        """Creates an initiation message for the intended peer receiver_id."""
        if not receiver_id:
            raise ValueError("receiver_id must be non-empty.")

        sid = session_id if session_id is not None else secrets.token_bytes(16)
        if len(sid) < 8:
            raise ValueError("session_id must be at least 8 bytes.")

        ts_ms = timestamp if timestamp is not None else int(time.time() * 1000)
        validate_uint64_timestamp(ts_ms)

        suites = offered_suites or (suite_id,)

        ecdh_alice, ecdh_alice_pub = generate_ecdh_keypair()
        pq_alice = PostQuantumKEM(alg_name="ML-KEM-768")

        init_transcript = serialize_canonical_init_transcript(
            protocol_version=protocol_version,
            offered_suites=suites,
            sender_id=self.node_id,
            receiver_id=receiver_id,
            session_id=sid,
            timestamp_ms=ts_ms,
            alice_id_pub=self.identity.public_bytes,
            ecdh_alice_pub=ecdh_alice_pub,
            pq_alice_pub=pq_alice.public_key_bytes,
        )
        signature = self.identity.sign(init_transcript)

        self._pending[sid] = (ecdh_alice, pq_alice, init_transcript, receiver_id, ts_ms)

        return {
            "protocol_version": protocol_version,
            "suite_id": suites[0],
            "offered_suites": list(suites),
            "sender_id": self.node_id,
            "receiver_id": receiver_id,
            "session_id": sid,
            "timestamp": ts_ms,
            "alice_id_pub": self.identity.public_bytes,
            "ecdh_pub": ecdh_alice_pub,
            "pq_pub": pq_alice.public_key_bytes,
            "signature": signature,
        }

    def finalize(
        self,
        response_message: bytes | dict[str, Any],
        ecdh_alice: ECDHKeyExchange | None = None,
        pq_alice: PostQuantumKEM | None = None,
        current_time: int | None = None,
    ) -> Session:
        """Verifies peer response and establishes the authenticated cryptographic Session."""
        resp = parse_response(response_message)
        session_id = resp["session_id"]

        if session_id in self._pending:
            stored_ecdh, stored_pq, init_transcript, expected_peer, init_ts = self._pending.pop(session_id)
            ecdh_alice = stored_ecdh
            pq_alice = stored_pq
        else:
            if ecdh_alice is None or pq_alice is None:
                raise AuthenticationError("No pending initiation state found for session ID.")
            expected_peer = resp["sender_id"]
            init_transcript = b""

        # 1. Recipient check: Message must be addressed to THIS initiator node
        if resp["receiver_id"] != self.node_id:
            raise WrongRecipientError(
                f"Response addressed to '{resp['receiver_id']}', but this node is '{self.node_id}'"
            )

        # 2. Sender check: Response must come from the peer we intended to contact
        if resp["sender_id"] != expected_peer:
            raise WrongRecipientError(f"Response received from '{resp['sender_id']}', expected '{expected_peer}'")

        # 3. Trust Store lookup: Peer public key MUST match trust store
        now_ms = current_time if current_time is not None else int(time.time() * 1000)
        validate_uint64_timestamp(now_ms)
        try:
            self.trust_store.verify_peer(expected_peer, resp["bob_id_pub"], current_time=now_ms)
        except (TypeError, ValueError, PermissionError) as e:
            raise AuthenticationError(f"Peer trust verification failed: {e}") from e

        # 4. Freshness check
        resp_ts = resp["timestamp"]
        if abs(now_ms - resp_ts) > self.MAX_CLOCK_SKEW_MS:
            raise StaleSessionError(f"Response timestamp difference {abs(now_ms - resp_ts)}ms exceeds skew window.")

        # 5. Init transcript binding check
        if init_transcript:
            expected_hash = hashlib.sha512(init_transcript).digest()
            if resp["init_transcript_hash"] != expected_hash:
                raise AuthenticationError("init_transcript_hash mismatch in response.")

        # 6. Response signature verification
        resp_transcript = serialize_canonical_resp_transcript(
            protocol_version=resp["protocol_version"],
            selected_suite=resp["selected_suite"],
            sender_id=resp["sender_id"],
            receiver_id=resp["receiver_id"],
            session_id=session_id,
            timestamp_ms=resp_ts,
            init_transcript_hash=resp["init_transcript_hash"],
            responder_nonce=resp["responder_nonce"],
            bob_id_pub=resp["bob_id_pub"],
            ecdh_bob_pub=resp["ecdh_pub"],
            pq_ciphertext=resp["pq_ciphertext"],
        )
        if not IdentityKeyPair.verify(resp["bob_id_pub"], resp["signature"], resp_transcript):
            raise AuthenticationError("Invalid signature on response transcript.")

        # 7. Shared secret computation
        ss_ecdh = ecdh_alice.exchange(resp["ecdh_pub"])
        ss_pq = pq_alice.decapsulate(resp["pq_ciphertext"])

        # 8. Directional key derivation
        k_enc_i2r, k_enc_r2i, session_key_id = HybridKeyCombiner.derive_session_keys_strict(
            k_ecdh=ss_ecdh,
            k_pq=ss_pq,
            sender_ecdh_pub=ecdh_alice.public_bytes,
            receiver_ecdh_pub=resp["ecdh_pub"],
            pq_ciphertext=resp["pq_ciphertext"],
            sender_id=self.node_id,
            receiver_id=expected_peer,
            session_id=session_id,
            transcript_hash=hashlib.sha512(resp_transcript).digest(),
            suite_id=resp["selected_suite"],
            protocol_version=resp["protocol_version"],
        )

        return Session(
            session_id=session_id,
            session_key_id=session_key_id,
            role="initiator",
            k_send=k_enc_i2r,
            k_recv=k_enc_r2i,
            local_node_id=self.node_id,
            peer_node_id=expected_peer,
            suite_id=resp["selected_suite"],
        )


class ResponderContext:
    """
    Context for handshake response handling.
    Enforces mandatory recipient binding, trust verification, and atomic replay defense.
    """

    MAX_CLOCK_SKEW_MS: int = 300_000

    def __init__(
        self,
        node_id: str,
        identity: IdentityKeyPair,
        trust_store: TrustStore,
        replay_store: ReplayStoreBase,
        allow_non_durable_replay_store: bool = False,
    ) -> None:
        if not node_id:
            raise ValueError("Responder node_id must be non-empty.")
        if not isinstance(identity, IdentityKeyPair):
            raise TypeError("identity must be an IdentityKeyPair instance.")
        if identity.node_id and identity.node_id != node_id:
            raise ValueError(
                f"ResponderContext node_id '{node_id}' does not match identity node_id '{identity.node_id}'."
            )
        if not isinstance(trust_store, TrustStore):
            raise TypeError("trust_store must be a TrustStore instance.")
        if not isinstance(replay_store, ReplayStoreBase):
            raise TypeError("replay_store must be a ReplayStoreBase instance.")

        if isinstance(replay_store, InMemoryReplayStoreForTestsAndDevelopment):
            if not allow_non_durable_replay_store:
                raise ValueError(
                    "InMemoryReplayStoreForTestsAndDevelopment cannot be used in production ResponderContext "
                    "without allow_non_durable_replay_store=True. SqliteReplayStore is the recommended default."
                )
            warnings.warn(
                "Using non-durable in-memory replay store in ResponderContext.",
                NonDurableReplayStoreWarning,
                stacklevel=2,
            )

        self.node_id = str(node_id)
        self.identity = identity
        self.trust_store = trust_store
        self.replay_store = replay_store
        self.allow_non_durable_replay_store = allow_non_durable_replay_store
        self.session: Session | None = None

    def respond(
        self,
        init_message: bytes | dict[str, Any],
        current_time: int | None = None,
    ) -> tuple[dict[str, Any], Session]:
        """
        Validates initiator message, checks recipient binding, verifies identity and freshness,
        atomically consumes session in replay store, and returns (response_message, session).
        """
        init = parse_initiation(init_message)

        # 1. Recipient Binding (D-01): Handshake MUST be addressed to THIS node
        if init["receiver_id"] != self.node_id:
            raise WrongRecipientError(
                f"Handshake addressed to '{init['receiver_id']}', but this node is '{self.node_id}'"
            )

        # 2. Version and suite negotiation
        protocol_version = init["protocol_version"]
        if protocol_version not in SUPPORTED_VERSIONS:
            raise UnsupportedVersionError(f"Unsupported protocol version: '{protocol_version}'")

        offered = tuple(init.get("offered_suites", [init.get("suite_id")]))
        selected_suite = None
        for s in offered:
            if s in SUPPORTED_SUITES:
                selected_suite = s
                break
        if selected_suite is None:
            raise UnsupportedSuiteError(f"No mutually supported cipher suite: {offered}")

        sender_id = init["sender_id"]
        alice_id_pub = init["alice_id_pub"]

        # 3. Trust Store Verification: Peer MUST be known and unrevoked
        now_ms = current_time if current_time is not None else int(time.time() * 1000)
        validate_uint64_timestamp(now_ms)
        try:
            self.trust_store.verify_peer(sender_id, alice_id_pub, current_time=now_ms)
        except (TypeError, ValueError, PermissionError) as e:
            raise AuthenticationError(f"Peer trust verification failed: {e}") from e

        # 4. Signature & Transcript Verification
        ts_ms = init["timestamp"]
        session_id = init["session_id"]
        init_transcript = serialize_canonical_init_transcript(
            protocol_version=protocol_version,
            offered_suites=offered,
            sender_id=sender_id,
            receiver_id=self.node_id,
            session_id=session_id,
            timestamp_ms=ts_ms,
            alice_id_pub=alice_id_pub,
            ecdh_alice_pub=init["ecdh_pub"],
            pq_alice_pub=init["pq_pub"],
        )
        if not IdentityKeyPair.verify(alice_id_pub, init["signature"], init_transcript):
            raise AuthenticationError("Invalid signature on initiation transcript.")

        # 5. Freshness & Atomic Replay Consumption (D-02)
        if abs(now_ms - ts_ms) > self.MAX_CLOCK_SKEW_MS:
            raise StaleSessionError(f"Session timestamp difference {abs(now_ms - ts_ms)}ms exceeds skew window.")

        cache_key = f"{sender_id}:{session_id.hex()}"
        expires_at = ts_ms + self.MAX_CLOCK_SKEW_MS
        if not self.replay_store.consume(cache_key, ts_ms, expires_at):
            raise ReplayDetectedError(
                f"REPLAY_DETECTED: Session '{session_id.hex()[:8]}' from '{sender_id}' already consumed."
            )

        # 6. Ephemeral KEM exchange & encapsulation
        ecdh_bob, ecdh_bob_pub = generate_ecdh_keypair()
        pq_ciphertext, ss_pq = PostQuantumKEM.encapsulate_to_peer(init["pq_pub"])
        ss_ecdh = ecdh_bob.exchange(init["ecdh_pub"])

        # 7. Response transcript construction & signing
        init_transcript_hash = hashlib.sha512(init_transcript).digest()
        responder_nonce = secrets.token_bytes(32)
        resp_timestamp_ms = now_ms

        resp_transcript = serialize_canonical_resp_transcript(
            protocol_version=protocol_version,
            selected_suite=selected_suite,
            sender_id=self.node_id,
            receiver_id=sender_id,
            session_id=session_id,
            timestamp_ms=resp_timestamp_ms,
            init_transcript_hash=init_transcript_hash,
            responder_nonce=responder_nonce,
            bob_id_pub=self.identity.public_bytes,
            ecdh_bob_pub=ecdh_bob_pub,
            pq_ciphertext=pq_ciphertext,
        )
        signature = self.identity.sign(resp_transcript)

        # 8. Directional key derivation
        k_enc_i2r, k_enc_r2i, session_key_id = HybridKeyCombiner.derive_session_keys_strict(
            k_ecdh=ss_ecdh,
            k_pq=ss_pq,
            sender_ecdh_pub=init["ecdh_pub"],
            receiver_ecdh_pub=ecdh_bob_pub,
            pq_ciphertext=pq_ciphertext,
            sender_id=sender_id,
            receiver_id=self.node_id,
            session_id=session_id,
            transcript_hash=hashlib.sha512(resp_transcript).digest(),
            suite_id=selected_suite,
            protocol_version=protocol_version,
        )

        session = Session(
            session_id=session_id,
            session_key_id=session_key_id,
            role="responder",
            k_send=k_enc_r2i,
            k_recv=k_enc_i2r,
            local_node_id=self.node_id,
            peer_node_id=sender_id,
            suite_id=selected_suite,
        )
        self.session = session

        response_message = {
            "protocol_version": protocol_version,
            "selected_suite": selected_suite,
            "sender_id": self.node_id,
            "receiver_id": sender_id,
            "session_id": session_id,
            "timestamp": resp_timestamp_ms,
            "init_transcript_hash": init_transcript_hash,
            "responder_nonce": responder_nonce,
            "bob_id_pub": self.identity.public_bytes,
            "ecdh_pub": ecdh_bob_pub,
            "pq_ciphertext": pq_ciphertext,
            "signature": signature,
        }

        return response_message, session


class AuthenticatedHybridKEM:
    """Removed in MedPQC v2.5.0. Callers must migrate to InitiatorContext and ResponderContext directly."""

    def __init__(self) -> None:
        raise RemovedAPIError(
            "AuthenticatedHybridKEM was removed in MedPQC v2.5.0. "
            "Please migrate to InitiatorContext and ResponderContext directly."
        )

    @classmethod
    def initiate(cls) -> Any:
        raise RemovedAPIError(
            "AuthenticatedHybridKEM.initiate was removed in MedPQC v2.5.0. Use InitiatorContext.initiate instead."
        )

    @classmethod
    def respond(cls) -> Any:
        raise RemovedAPIError(
            "AuthenticatedHybridKEM.respond was removed in MedPQC v2.5.0. Use ResponderContext.respond instead."
        )

    @classmethod
    def finalize(cls) -> Any:
        raise RemovedAPIError(
            "AuthenticatedHybridKEM.finalize was removed in MedPQC v2.5.0. Use InitiatorContext.finalize instead."
        )
