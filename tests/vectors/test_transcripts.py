"""
tests.vectors.test_transcripts
==============================
Validates bit-for-bit determinism of canonical handshake transcripts against fixed-byte vectors.
Also validates synchronization between tests/vectors/transcripts.json and docs/PROTOCOL_SPECIFICATION.md.
"""

from pathlib import Path
import json
import hashlib
from medpqc.kem.auth import serialize_canonical_init_transcript, serialize_canonical_resp_transcript


def test_fixed_byte_transcripts():
    vector_path = Path(__file__).parent / "transcripts.json"
    with open(vector_path, "r", encoding="utf-8") as f:
        vec = json.load(f)

    init_tx = serialize_canonical_init_transcript(
        protocol_version="MedPQC-v2.4",
        offered_suites=("ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",),
        sender_id="alice-pacs",
        receiver_id="bob-pacs",
        session_id=b"session-12345678",
        timestamp_ms=1700000000000,
        alice_id_pub=b"A" * 32,
        ecdh_alice_pub=b"E" * 65,
        pq_alice_pub=b"P" * 1184,
    )
    init_tx_hash = hashlib.sha512(init_tx).digest()

    assert init_tx.hex() == vec["init_transcript_hex"]
    assert init_tx_hash.hex() == vec["init_transcript_hash_hex"]

    resp_tx = serialize_canonical_resp_transcript(
        protocol_version="MedPQC-v2.4",
        selected_suite="ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",
        sender_id="alice-pacs",
        receiver_id="bob-pacs",
        session_id=b"session-12345678",
        timestamp_ms=1700000001000,
        init_transcript_hash=init_tx_hash,
        responder_nonce=b"N" * 32,
        bob_id_pub=b"B" * 32,
        ecdh_bob_pub=b"F" * 65,
        pq_ciphertext=b"C" * 1088,
    )
    resp_tx_hash = hashlib.sha512(resp_tx).digest()

    assert resp_tx.hex() == vec["resp_transcript_hex"]
    assert resp_tx_hash.hex() == vec["resp_transcript_hash_hex"]


def test_spec_vectors_sync():
    """
    D-25: Asserts that docs/PROTOCOL_SPECIFICATION.md embeds and matches
    the fixed-byte transcript hashes from transcripts.json.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    spec_path = repo_root / "docs" / "PROTOCOL_SPECIFICATION.md"
    vector_path = Path(__file__).parent / "transcripts.json"

    assert spec_path.exists(), "docs/PROTOCOL_SPECIFICATION.md must exist"
    spec_text = spec_path.read_text(encoding="utf-8")

    with open(vector_path, "r", encoding="utf-8") as f:
        vec = json.load(f)

    assert vec["init_transcript_hash_hex"] in spec_text, (
        f"PROTOCOL_SPECIFICATION.md missing init_transcript_hash_hex {vec['init_transcript_hash_hex']}"
    )
    assert vec["resp_transcript_hash_hex"] in spec_text, (
        f"PROTOCOL_SPECIFICATION.md missing resp_transcript_hash_hex {vec['resp_transcript_hash_hex']}"
    )
