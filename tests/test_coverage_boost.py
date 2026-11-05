"""
Tests to cover edge branches and error cases across core modules
(cipher, kem, security, dicom) to satisfy hardened coverage floors.
"""

import pytest
import numpy as np
import tempfile
import os
import gc
from pathlib import Path
import json
import base64

from medpqc.cipher.engine import (
    MedPQCCipher,
    serialize_metadata_aad,
    validate_metadata,
    KeyExhaustionError,
    MAX_CIPHERTEXTS_PER_KEY,
)
import medpqc.cipher
from medpqc.kem.auth import (
    IdentityKeyPair,
    InitiatorContext,
    ResponderContext,
    Session,
    validate_uint64_timestamp,
    serialize_canonical_init_transcript,
    serialize_canonical_resp_transcript,
    parse_initiation,
    parse_response,
    WrongRecipientError,
    StaleSessionError,
    AuthenticationError,
    ParseError,
    RemovedAPIError,
)
from medpqc.kem.rlwe import PostQuantumKEM, KEMError
from medpqc.security.trust import TrustStore
from medpqc.security.replay import (
    MemoryReplayStore,
    SqliteReplayStore,
    ReplayProtector,
    ReplayStore,
)
from medpqc.dicom.pacs import (
    DICOMPACSEnvelope,
    DICOMPACSSession,
    SitePseudonymizationKey,
    ManifestSource,
    serialize_binary_envelope,
    parse_binary_envelope,
    UnsupportedDICOMError,
    PRIVATE_PAYLOAD_TAG,
)
from tests.factories.dicom_factory import create_synthetic_dicom
import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage, generate_uid


# =============================================================================
# Cipher Package Coverage Boost
# =============================================================================
def test_cipher_module_getattr_and_errors():
    with pytest.deprecated_call():
        cls = medpqc.cipher.ChaoticDiffusion
        assert cls is not None

    with pytest.raises(AttributeError):
        _ = medpqc.cipher.non_existent_attribute_xyz


def test_serialize_metadata_aad_with_transfer_syntax():
    out = serialize_metadata_aad(
        shape=(64, 64),
        dtype="int16",
        enable_scrambling=True,
        n_bytes=64 * 64 * 2,
        retained_headers={"Modality": "CT"},
        transfer_syntax_uid="1.2.840.10008.1.2.1",
    )
    assert b"transfer_syntax_uid" in out
    assert b"1.2.840.10008.1.2.1" in out


def test_build_strict_aad_types():
    meta = {
        "envelope_version": "2.4",
        "suite_id": "ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",
        "session_key_id": "skid123",
        "envelope_id": "env123",
        "payload_type": "dicom-pixel-data",
        "pipeline_id": "raw-pixel-pipeline",
        "shape": [512, 512],
        "dtype": "int16",
        "endianness": "little",
        "frame_count": 1,
        "samples_per_pixel": 1,
        "planar_configuration": 0,
        "photometric_interpretation": "MONOCHROME2",
        "pixel_representation": 1,
        "transfer_syntax_uid": "1.2.840.10008.1.2.1",
        "original_byte_count": 524288,
        "dataset_hash": b"raw_bytes",
    }
    aad = MedPQCCipher.build_strict_aad(meta)
    assert isinstance(aad, bytes)
    assert b"skid123" in aad


def test_cipher_encrypt_decrypt_bytes_format_and_transfer_syntax():
    key = b"C" * 32
    cipher = MedPQCCipher(k_aes=key)
    img = np.random.randint(-100, 100, size=(16, 16), dtype=np.int16)

    # Encrypt with transfer_syntax_uid
    bundle = cipher.encrypt(
        img,
        enable_scrambling=False,
        transfer_syntax_uid="1.2.840.10008.1.2.1",
    )
    assert bundle["transfer_syntax_uid"] == "1.2.840.10008.1.2.1"

    # Decrypt with bundle dict
    restored = cipher.decrypt(bundle)
    assert np.array_equal(img, restored)

    # Invalid input type to decrypt raises TypeError
    with pytest.raises(TypeError):
        cipher.decrypt(12345)  # type: ignore[arg-type]


def test_cipher_key_exhaustion_error():
    key = b"K" * 32
    cipher = MedPQCCipher(k_aes=key)
    cipher._enc_count = MAX_CIPHERTEXTS_PER_KEY
    img = np.zeros((8, 8), dtype=np.int16)
    with pytest.raises(KeyExhaustionError):
        cipher.encrypt(img)


# =============================================================================
# Security Package Coverage Boost
# =============================================================================
def test_trust_store_edge_validations():
    ts = TrustStore()

    with pytest.raises(TypeError):
        ts.register_peer("alice", "not_bytes")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        ts.register_peer("alice", b"short")

    with pytest.raises(ValueError):
        ts.register_peer("", b"A" * 32)

    pk = b"P" * 32
    kid = ts.register_peer("bob", pk)
    ts.revoke_key(kid)
    with pytest.raises(PermissionError):
        ts.register_peer("bob", pk, key_id=kid)

    with pytest.raises(ValueError):
        ts.revoke_key(12345)  # type: ignore[arg-type]

    exported = ts.export_registry()
    ts2 = TrustStore()
    ts2.import_registry(exported)

    # Peer listing and revoke node
    assert "bob" in ts.list_peers()
    ts.revoke_node("bob")
    with pytest.raises(PermissionError):
        ts.verify_peer("bob", pk)

    ts.reinstate_node("bob")
    kid2 = ts.register_peer("bob", b"N" * 32)
    ts.verify_peer("bob", b"N" * 32)

    # Save and load registry
    with tempfile.TemporaryDirectory() as tmp_dir:
        reg_path = Path(tmp_dir) / "registry.json"
        ts.save_to_file(str(reg_path))
        ts3 = TrustStore()
        ts3.load_from_file(str(reg_path))
        assert "bob" in ts3.list_peers()


def test_replay_store_abstract_and_protector_edge_cases():
    store = MemoryReplayStore()
    assert store.has_seen("key") is False
    assert store.consume("key", 1000, 2000) is True
    assert store.has_seen("key") is True
    assert store.size() == 1

    # ReplayProtector validation
    with pytest.raises(ValueError):
        ReplayProtector(window_seconds=-1.0, store=store)
    with pytest.raises(TypeError):
        ReplayProtector(window_seconds=10.0, store=None)  # type: ignore[arg-type]

    protector = ReplayProtector(window_seconds=10.0, store=store)
    assert protector.has_seen("key") is True
    assert protector.validate_and_record("sess_fresh", timestamp=5000, current_time=5000) is True

    # Stale session check
    with pytest.raises(StaleSessionError):
        protector.validate_and_record("sess_stale", timestamp=1000, current_time=50000)

    # check_and_record helper
    assert protector.check_and_record("peer1", b"session_id_123", timestamp=6000, current_time=6000) is True


def test_sqlite_replay_store_all_methods():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_replay.db"
        store = SqliteReplayStore(db_path)
        assert store.has_seen("token1") is False
        assert store.consume("token1", 1000, 2000) is True
        assert store.has_seen("token1") is True

        store.record("token2", 1500)
        assert store.size() >= 2

        store.prune(cutoff_ms=1200)
        assert store.size() >= 1

        store.close()
        # Operations on closed store fail closed
        with pytest.raises(RuntimeError):
            store.has_seen("token1")
        with pytest.raises(RuntimeError):
            store.consume("token1", 1000, 2000)
        with pytest.raises(RuntimeError):
            store.record("token3", 2000)
        with pytest.raises(RuntimeError):
            store.prune(1000)
        with pytest.raises(RuntimeError):
            store.size()

        del store
        gc.collect()


# =============================================================================
# KEM Package Coverage Boost
# =============================================================================
def test_kem_auth_timestamp_validations():
    with pytest.raises(ParseError):
        validate_uint64_timestamp(True)
    with pytest.raises(ParseError):
        validate_uint64_timestamp(123.456)  # type: ignore[arg-type]
    with pytest.raises(ParseError):
        validate_uint64_timestamp(-10)
    with pytest.raises(ParseError):
        validate_uint64_timestamp(2**64)


def test_kem_identity_sign_and_pem():
    kp = IdentityKeyPair()
    with pytest.raises(TypeError):
        kp.sign("string_message_not_bytes")  # type: ignore[arg-type]

    # Private key bytes roundtrip
    priv = kp.export_private_key()
    loaded_kp = IdentityKeyPair.import_private_key(priv)
    assert loaded_kp.public_bytes == kp.public_bytes


def test_kem_binary_framing_parser_errors():
    with pytest.raises(ParseError):
        parse_initiation(b"too_short")

    with pytest.raises(ParseError):
        parse_response(b"too_short")


def test_kem_session_closed_and_message_limit():
    key = b"S" * 32
    sess = Session(
        session_id=b"1" * 16,
        session_key_id="skid",
        role="initiator",
        k_send=key,
        k_recv=key,
        local_node_id="local",
        peer_node_id="peer",
    )
    assert sess.is_active
    assert sess.get_send_key() == key
    assert sess.get_recv_key() == key
    sc = sess.sender_cipher()
    rc = sess.receiver_cipher()
    assert sc is not None
    assert rc is not None

    sess.check_and_increment_counter(is_sender=True)
    sess.check_and_increment_counter(is_sender=False)

    # Close session
    sess.close()
    assert not sess.is_active
    with pytest.raises(PermissionError):
        sess.sender_cipher()
    with pytest.raises(PermissionError):
        sess.receiver_cipher()
    with pytest.raises(PermissionError):
        sess.check_and_increment_counter(is_sender=True)


def test_kem_initiator_and_responder_edge_errors():
    id_a = IdentityKeyPair()
    id_b = IdentityKeyPair()
    ts = TrustStore()
    ts.register_peer("a", id_a.public_bytes)
    ts.register_peer("b", id_b.public_bytes)
    mem = MemoryReplayStore()

    with pytest.raises(ValueError):
        InitiatorContext("", id_a, ts)
    with pytest.raises(ValueError):
        ResponderContext("", id_b, ts, mem, allow_non_durable_replay_store=True)

    init_ctx = InitiatorContext("a", id_a, ts)
    with pytest.raises(ValueError):
        init_ctx.initiate("")

    with pytest.raises(TypeError):
        ResponderContext("b", id_b, "not_trust_store", mem, allow_non_durable_replay_store=True)  # type: ignore[arg-type]

    # Stale timestamp in respond
    init_msg = init_ctx.initiate("b")
    resp_ctx = ResponderContext("b", id_b, ts, mem, allow_non_durable_replay_store=True)
    with pytest.raises(StaleSessionError):
        resp_ctx.respond(init_msg, current_time=init_msg["timestamp"] + 400_000)

    # Normal respond
    resp_msg, bob_sess = resp_ctx.respond(init_msg)

    # Finalize with WrongRecipientError (wrong sender_id in response)
    corrupted_resp = dict(resp_msg)
    corrupted_resp["sender_id"] = "impostor"
    with pytest.raises(WrongRecipientError):
        init_ctx.finalize(corrupted_resp)

    # New session for StaleSessionError
    init_msg2 = init_ctx.initiate("b")
    resp_msg2, _ = resp_ctx.respond(init_msg2)
    with pytest.raises(StaleSessionError):
        init_ctx.finalize(resp_msg2, current_time=resp_msg2["timestamp"] + 400_000)

    # New session for corrupted signature
    init_msg3 = init_ctx.initiate("b")
    resp_msg3, _ = resp_ctx.respond(init_msg3)
    corrupted_sig_resp = dict(resp_msg3)
    corrupted_sig_resp["signature"] = b"X" * 64
    with pytest.raises(AuthenticationError):
        init_ctx.finalize(corrupted_sig_resp)


def test_post_quantum_kem_decapsulate_errors():
    kem = PostQuantumKEM()
    with pytest.raises(TypeError):
        kem.decapsulate("not_bytes")  # type: ignore[arg-type]

    with pytest.raises(KEMError):
        kem.decapsulate(b"short_ciphertext")

    with pytest.raises(KEMError):
        kem.decapsulate(b"C" * 1088, dk=b"short_dk")


# =============================================================================
# DICOM Package Coverage Boost
# =============================================================================
def test_dicom_binary_envelope_validation():
    with pytest.raises(TypeError):
        serialize_binary_envelope("not_a_dict", b"ciphertext")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        parse_binary_envelope(12345)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        parse_binary_envelope(b"abc")

    header_raw = b"this is not json\n"
    raw_bad = len(header_raw).to_bytes(4, "big") + header_raw + b"payload"
    with pytest.raises(ValueError):
        parse_binary_envelope(raw_bad)


def test_dicom_site_pseudonymization_key_type():
    with pytest.raises(TypeError):
        SitePseudonymizationKey(12345)  # type: ignore[arg-type]


def test_dicom_rejection_of_overlay_curve_and_burned_in():
    ds = create_synthetic_dicom(rows=16, cols=16)
    key = b"D" * 32
    site_key = SitePseudonymizationKey(b"P" * 32)
    cipher = MedPQCCipher(key)

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_path = Path(tmp_dir) / "in.dcm"
        enc_path = Path(tmp_dir) / "enc.dcm"

        # 1. Overlay plane tag (0x6000, 0x0010)
        ds.add_new((0x6000, 0x0010), "OW", b"\x00" * 32)
        ds.save_as(str(in_path))
        with pytest.raises(UnsupportedDICOMError):
            DICOMPACSEnvelope.encrypt_dicom_file(str(in_path), str(enc_path), cipher, site_key)

        # 2. Curve tag (0x5000, 0x0010)
        del ds[(0x6000, 0x0010)]
        ds.add_new((0x5000, 0x0010), "OW", b"\x00" * 32)
        ds.save_as(str(in_path))
        with pytest.raises(UnsupportedDICOMError):
            DICOMPACSEnvelope.encrypt_dicom_file(str(in_path), str(enc_path), cipher, site_key)

        # 3. BurnedInAnnotation == YES
        del ds[(0x5000, 0x0010)]
        ds.BurnedInAnnotation = "YES"
        ds.save_as(str(in_path))
        with pytest.raises(UnsupportedDICOMError):
            DICOMPACSEnvelope.encrypt_dicom_file(str(in_path), str(enc_path), cipher, site_key)


def test_dicom_pacs_session_lifecycle_and_edge_cases():
    id_a = IdentityKeyPair()
    id_b = IdentityKeyPair()
    ts = TrustStore()
    ts.register_peer("alice", id_a.public_bytes)
    ts.register_peer("bob", id_b.public_bytes)

    # 1. Client initiation
    init_msg, client_state = DICOMPACSSession.client_initiate(id_a, sender_id="alice", receiver_id="bob")
    assert "init_msg" in client_state

    # 2. Bob encrypts study
    ds = create_synthetic_dicom(rows=16, cols=16)
    ds.FrameOfReferenceUID = generate_uid()

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_dcm = Path(tmp_dir) / "orig.dcm"
        enc_dcm = Path(tmp_dir) / "enc.dcm"
        dec_dcm = Path(tmp_dir) / "dec.dcm"
        ds.save_as(str(in_dcm))

        env, resp_msg = DICOMPACSSession.encrypt_dicom_study(
            input_dcm_path=str(in_dcm),
            output_dcm_path=str(enc_dcm),
            bob_identity=id_b,
            init_message=init_msg,
            trust_store=ts,
            site_key=SitePseudonymizationKey(b"P" * 32),
        )

        # 3. Alice decrypts study
        restored_pixels = DICOMPACSSession.decrypt_dicom_study(
            encrypted_dcm_path=str(enc_dcm),
            output_dcm_path=str(dec_dcm),
            alice_identity=id_a,
            client_state=client_state,
            trust_store=ts,
        )
        assert restored_pixels.shape == (16, 16)

        # Error cases for decrypt_dicom_study
        # Missing private payload
        ds_bare = create_synthetic_dicom(rows=16, cols=16)
        bare_dcm = Path(tmp_dir) / "bare.dcm"
        ds_bare.save_as(str(bare_dcm))
        with pytest.raises(ValueError):
            DICOMPACSSession.decrypt_dicom_study(
                str(bare_dcm), str(dec_dcm), id_a, client_state, ts
            )


def test_handler_image_io_formats_and_metadata_none():
    from medpqc.dicom.handler import MedicalImageIO

    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Save DCM without metadata (8-bit)
        arr8 = np.arange(64, dtype=np.uint8).reshape((8, 8))
        dcm_8 = Path(tmp_dir) / "img8.dcm"
        MedicalImageIO.save(str(dcm_8), arr8, metadata=None)
        loaded8, ds8 = MedicalImageIO.load(str(dcm_8))
        assert loaded8.shape == (8, 8)
        assert ds8.BitsAllocated == 8

        # 2. Save DCM without metadata (16-bit)
        arr16 = np.arange(64, dtype=np.uint16).reshape((8, 8))
        dcm_16 = Path(tmp_dir) / "img16.dcm"
        MedicalImageIO.save(str(dcm_16), arr16, metadata=None)
        loaded16, ds16 = MedicalImageIO.load(str(dcm_16))
        assert loaded16.shape == (8, 8)
        assert ds16.BitsAllocated == 16

        # 3. Save and load PNG (2D and 3D)
        png_path = Path(tmp_dir) / "img.png"
        MedicalImageIO.save(str(png_path), arr8)
        loaded_png, meta_png = MedicalImageIO.load(str(png_path))
        assert loaded_png.shape == (8, 8)
        assert meta_png["format"] == ".png"

        arr_color = np.zeros((8, 8, 3), dtype=np.uint8)
        arr_color[:, :, 0] = 255
        png_col_path = Path(tmp_dir) / "color.png"
        MedicalImageIO.save(str(png_col_path), arr_color)
        loaded_col, _ = MedicalImageIO.load(str(png_col_path))
        assert loaded_col.shape == (8, 8, 3)

        # 4. Load nonexistent image
        with pytest.raises(ValueError):
            MedicalImageIO.load(str(Path(tmp_dir) / "nonexistent.png"))


def test_kem_rlwe_mock_and_error_paths(monkeypatch):
    import medpqc.kem.rlwe as rlwe_mod
    from medpqc.kem.rlwe import KEMError, PostQuantumKEM

    # 1. PostQuantumKEM with invalid algorithm name
    with pytest.raises(KEMError):
        PostQuantumKEM(alg_name="INVALID-ALGO")

    # 2. Key generation error handling
    if rlwe_mod.HAS_MLKEM:
        orig_keygen = rlwe_mod.mlkem_backend.ML_KEM.key_gen

        def fail_keygen(self):
            raise RuntimeError("forced keygen error")

        monkeypatch.setattr(rlwe_mod.mlkem_backend.ML_KEM, "key_gen", fail_keygen)
        with pytest.raises(KEMError, match="key generation failed"):
            PostQuantumKEM()
        monkeypatch.setattr(rlwe_mod.mlkem_backend.ML_KEM, "key_gen", orig_keygen)

    # 3. Encapsulation error handling
    kem = PostQuantumKEM()
    with pytest.raises(TypeError):
        kem.encapsulate(123)  # type: ignore
    with pytest.raises(KEMError):
        kem.encapsulate(b"short_pk")

    # 4. Decapsulation error handling
    with pytest.raises(TypeError):
        kem.decapsulate(123)  # type: ignore
    with pytest.raises(KEMError):
        kem.decapsulate(b"short_ct")

    # 5. Invalid decapsulation key format
    with pytest.raises(KEMError, match="decapsulation key format"):
        kem.decapsulate(b"C" * 1088, dk=b"K" * 2400)

    # 6. Mock liboqs backend
    class MockOqsKEM:
        def __init__(self, alg_name: str) -> None:
            self.alg_name = alg_name

        def generate_keypair(self) -> bytes:
            return b"OQS_PUB_KEY_" + b"P" * 1172

        def encap_secret(self, pk: bytes) -> tuple[bytes, bytes]:
            return b"C" * 1088, b"S" * 32

        def decap_secret(self, ct: bytes) -> bytes:
            return b"S" * 32

    class MockOqsModule:
        KeyEncapsulation = MockOqsKEM

        @staticmethod
        def get_enabled_KEM_mechanisms() -> list[str]:
            return ["ML-KEM-768"]

    monkeypatch.setattr(rlwe_mod, "HAS_LIBOQS", True)
    monkeypatch.setattr(rlwe_mod, "oqs", MockOqsModule, raising=False)

    oqs_kem = PostQuantumKEM(alg_name="ML-KEM-768", prefer_liboqs=True)
    assert oqs_kem.backend == "liboqs"
    ct_oqs, ss_oqs = oqs_kem.encapsulate(b"P" * 1184)
    assert len(ct_oqs) == 1088
    assert len(ss_oqs) == 32
    recovered_ss = oqs_kem.decapsulate(ct_oqs)
    assert recovered_ss == b"S" * 32

    # 7. Backend failure fallthroughs
    monkeypatch.setattr(rlwe_mod, "HAS_MLKEM", False)
    monkeypatch.setattr(rlwe_mod, "HAS_LIBOQS", False)
    with pytest.raises(KEMError, match="backend not available"):
        PostQuantumKEM()
    with pytest.raises(KEMError, match="No standard FIPS 203 ML-KEM backend available for encapsulation"):
        PostQuantumKEM.encapsulate_to_peer(b"P" * 1184)


def test_dicom_pacs_manifest_external_and_fallback_restoration():
    from medpqc.dicom.pacs import (
        DICOMPACSEnvelope,
        ManifestError,
        ManifestSource,
        parse_binary_envelope,
        restore_dicom_file,
        serialize_binary_envelope,
    )

    # 1. Binary envelope framing error paths
    with pytest.raises(TypeError):
        serialize_binary_envelope(["not", "dict"])  # type: ignore

    with pytest.raises(TypeError):
        parse_binary_envelope(12345)  # type: ignore

    with pytest.raises(ValueError, match="truncated"):
        parse_binary_envelope(b"MEDPQC")

    with pytest.raises(ValueError, match="Malformed binary envelope"):
        parse_binary_envelope(b"MEDPQC\x00\x01not-json-content")

    with pytest.raises(ValueError, match="Invalid envelope framing"):
        parse_binary_envelope(b"\xff\xfe\xfd\xfc")

    # 2. restore_dicom_file parameter errors
    with pytest.raises(ValueError):
        restore_dicom_file(None, None, None)

    # 3. External manifest source and fallback restoration
    cipher = MedPQCCipher(b"K" * 32)
    site_key = SitePseudonymizationKey(b"P" * 32)
    ds = create_synthetic_dicom(rows=16, cols=16)
    ds.FrameOfReferenceUID = generate_uid()

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_dcm = Path(tmp_dir) / "source.dcm"
        enc_ext_dcm = Path(tmp_dir) / "enc_ext.dcm"
        dec_ext_dcm = Path(tmp_dir) / "dec_ext.dcm"
        ds.save_as(str(in_dcm))

        # Encrypt with explicit sidecar path
        ext_json_path = str(enc_ext_dcm) + ".pqc.json"
        DICOMPACSEnvelope.encrypt_dicom_file(
            input_dcm_path=str(in_dcm),
            output_dcm_path=str(enc_ext_dcm),
            cipher=cipher,
            sidecar_path=ext_json_path,
            site_key=site_key,
        )

        ext_json_path = str(enc_ext_dcm) + ".pqc.json"
        assert os.path.exists(ext_json_path)

        # Decrypt with EXTERNAL manifest
        restored_arr = DICOMPACSEnvelope.decrypt_dicom_file(
            encrypted_input_path=str(enc_ext_dcm),
            output_dcm_path=str(dec_ext_dcm),
            cipher=cipher,
            source=ManifestSource.EXTERNAL,
        )
        assert restored_arr.shape == (16, 16)

        # Test corrupt external JSON
        corrupt_json_path = Path(tmp_dir) / "corrupt.pqc.json"
        corrupt_json_path.write_text("not_valid_json", encoding="utf-8")
        with pytest.raises(ManifestError, match="corrupt"):
            DICOMPACSEnvelope.decrypt_dicom_file(
                encrypted_input_path=str(Path(tmp_dir) / "corrupt"),
                output_dcm_path=str(dec_ext_dcm),
                cipher=cipher,
                source=ManifestSource.EXTERNAL,
            )

        # Test nonexistent external JSON
        with pytest.raises(ManifestError, match="not found"):
            DICOMPACSEnvelope.decrypt_dicom_file(
                encrypted_input_path=str(Path(tmp_dir) / "missing_file"),
                output_dcm_path=str(dec_ext_dcm),
                cipher=cipher,
                source=ManifestSource.EXTERNAL,
            )

        # Test fallback restoration path (no sealed_dataset in manifest)
        enc_embedded = Path(tmp_dir) / "enc_emb.dcm"
        dec_fallback = Path(tmp_dir) / "dec_fb.dcm"
        DICOMPACSEnvelope.encrypt_dicom_file(
            input_dcm_path=str(in_dcm),
            output_dcm_path=str(enc_embedded),
            cipher=cipher,
            site_key=site_key,
        )
        # Load embedded manifest and remove sealed_dataset
        import pydicom
        from medpqc.dicom.pacs import (
            PRIVATE_PAYLOAD_TAG,
            parse_binary_envelope,
            serialize_binary_envelope,
        )

        ds_emb = pydicom.dcmread(str(enc_embedded))
        parsed_manifest = parse_binary_envelope(ds_emb[PRIVATE_PAYLOAD_TAG].value)
        parsed_manifest.pop("sealed_dataset", None)
        ds_emb[PRIVATE_PAYLOAD_TAG].value = serialize_binary_envelope(parsed_manifest)
        tampered_emb = Path(tmp_dir) / "tampered_no_sealed.dcm"
        ds_emb.save_as(str(tampered_emb))

        restored_fb = DICOMPACSEnvelope.decrypt_dicom_file(
            encrypted_input_path=str(tampered_emb),
            output_dcm_path=str(dec_fallback),
            cipher=cipher,
            source=ManifestSource.EMBEDDED,
            original_template_dcm=str(in_dcm),
        )
        assert restored_fb.shape == (16, 16)


def test_dicom_additional_edge_coverage():
    from pydicom.dataset import Dataset
    from pydicom.sequence import Sequence
    from medpqc.dicom.pacs import (
        AuthenticationError,
        DICOMPACSEnvelope,
        DICOMPACSSession,
        compute_dataset_hash,
        deserialize_sealed_dataset,
        serialize_sealed_dataset,
    )

    # 1. Sealed dataset edge cases
    assert serialize_sealed_dataset(None) == b""
    assert deserialize_sealed_dataset(b"") is None

    # 2. compute_dataset_hash with None and with nested Sequence SQ
    assert compute_dataset_hash(None) == ""

    ds = create_synthetic_dicom(rows=8, cols=8)
    sub_ds = Dataset()
    sub_ds.CodeValue = "12345"
    sub_ds.CodingSchemeDesignator = "DCM"
    ds.AnatomicRegionSequence = Sequence([sub_ds])
    hash_val = compute_dataset_hash(ds)
    assert len(hash_val) == 64

    # 3. encrypt_phi_metadata error without site_salt/site_key
    with pytest.raises(TypeError, match="site_salt or site_key"):
        DICOMPACSEnvelope.encrypt_phi_metadata(ds, cipher=None, site_salt=None)

    # 4. DICOMPACSSession.decrypt_dicom_study edge errors
    id_a = IdentityKeyPair()
    ts = TrustStore()
    with pytest.raises(ValueError, match="Failed to read"):
        DICOMPACSSession.decrypt_dicom_study("nonexistent_path.dcm", "out.dcm", id_a, {}, ts)


def test_kem_rlwe_additional_edge_coverage(monkeypatch):
    import medpqc.kem.rlwe as rlwe_mod
    from medpqc.kem.rlwe import KEMError, PostQuantumKEM

    class MockOqsKEM:
        def __init__(self, alg_name: str) -> None:
            self.alg_name = alg_name

        def generate_keypair(self) -> bytes:
            return b"OQS_PUB_KEY_" + b"P" * 1172

        def encap_secret(self, pk: bytes) -> tuple[bytes, bytes]:
            return b"C" * 1088, b"S" * 32

        def decap_secret(self, ct: bytes) -> bytes:
            return b"S" * 32

    class MockOqsModule:
        KeyEncapsulation = MockOqsKEM

        @staticmethod
        def get_enabled_KEM_mechanisms() -> list[str]:
            return ["ML-KEM-768"]

    # 1. Fallback to liboqs when HAS_MLKEM is False and prefer_liboqs is False
    monkeypatch.setattr(rlwe_mod, "HAS_MLKEM", False)
    monkeypatch.setattr(rlwe_mod, "HAS_LIBOQS", True)
    monkeypatch.setattr(rlwe_mod, "oqs", MockOqsModule, raising=False)

    kem_oqs = PostQuantumKEM("ML-KEM-768", prefer_liboqs=False)
    assert kem_oqs.backend == "liboqs"

    # Encapsulate to peer via liboqs
    ct, ss = PostQuantumKEM.encapsulate_to_peer(b"P" * 1184)
    assert len(ct) == 1088
    assert len(ss) == 32

    # Decapsulate via liboqs
    recovered_ss = kem_oqs.decapsulate(ct)
    assert recovered_ss == b"S" * 32

    # Liboqs decapsulate error
    def fail_decap(ct):
        raise RuntimeError("liboqs decap fail")

    monkeypatch.setattr(kem_oqs._oqs_kem, "decap_secret", fail_decap)
    with pytest.raises(KEMError, match="liboqs ML-KEM-768 decapsulation failed"):
        kem_oqs.decapsulate(ct)

    # 2. No backend available for decapsulation
    kem_oqs._backend_type = "invalid_backend"
    monkeypatch.setattr(rlwe_mod, "HAS_MLKEM", False)
    with pytest.raises(KEMError, match="No standard FIPS 203 ML-KEM backend available for decapsulation"):
        kem_oqs.decapsulate(ct)


def test_dicom_comprehensive_branch_coverage(monkeypatch):
    import pydicom
    from pydicom.dataset import Dataset
    from pydicom.sequence import Sequence
    import medpqc.dicom.handler as handler_mod
    from medpqc.dicom.handler import MedicalImageIO
    from medpqc.dicom.pacs import (
        AuthenticationError,
        DICOMPACSEnvelope,
        ManifestError,
        ManifestSource,
        PRIVATE_CREATOR_TAG,
        PRIVATE_PAYLOAD_TAG,
        SitePseudonymizationKey,
        parse_binary_envelope,
        serialize_binary_envelope,
        serialize_sealed_dataset,
    )

    # 1. Handler missing cv2 branches
    monkeypatch.setattr(handler_mod, "HAS_CV2", False)
    with pytest.raises(RuntimeError, match="Unable to save image format"):
        MedicalImageIO.save("unsupported.xyz", np.zeros((4, 4), dtype=np.uint8))
    with pytest.raises(RuntimeError, match="No suitable image reader"):
        MedicalImageIO.load("unsupported.xyz")

    # 2. DICOMPACSEnvelope with existing private tags and nested sequence
    cipher = MedPQCCipher(b"K" * 32)
    site_key = SitePseudonymizationKey(b"P" * 32)

    ds = create_synthetic_dicom(rows=8, cols=8)
    ds.add_new(PRIVATE_CREATOR_TAG, "LO", "MEDPQC")
    ds.add_new(PRIVATE_PAYLOAD_TAG, "OB", b"OLD_PAYLOAD")
    ds.add_new((0x0019, 0x1010), "LO", "VENDOR_PRIVATE")

    sub_ds = Dataset()
    sub_ds.CodeValue = "123"
    sub_ds.add_new((0x0019, 0x1011), "LO", "SUB_VENDOR_PRIVATE")
    ds.AnatomicRegionSequence = Sequence([sub_ds])

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_dcm = Path(tmp_dir) / "in_complex.dcm"
        enc_dcm = Path(tmp_dir) / "enc_complex.dcm"
        out_dcm = Path(tmp_dir) / "out_complex.dcm"
        ds.save_as(str(in_dcm))

        # Encrypt successfully scrubbing private vendor tags and replacing old payload
        DICOMPACSEnvelope.encrypt_dicom_file(
            input_dcm_path=str(in_dcm),
            output_dcm_path=str(enc_dcm),
            cipher=cipher,
            site_key=site_key,
        )

        # 3. Decrypt error: not a .dcm file when EMBEDDED specified
        with pytest.raises(ManifestError, match="not a readable DICOM container"):
            DICOMPACSEnvelope.decrypt_dicom_file("file.txt", str(out_dcm), cipher, source=ManifestSource.EMBEDDED)

        # 4. Decrypt error: bare DICOM without private payload tag
        bare_dcm = Path(tmp_dir) / "bare.dcm"
        bare_ds = create_synthetic_dicom(rows=8, cols=8)
        bare_ds.save_as(str(bare_dcm))
        with pytest.raises(ManifestError, match="Embedded manifest tag"):
            DICOMPACSEnvelope.decrypt_dicom_file(str(bare_dcm), str(out_dcm), cipher, source=ManifestSource.EMBEDDED)

        # 5. Decrypt error: unsupported source
        with pytest.raises((ManifestError, ValueError)):
            DICOMPACSEnvelope.decrypt_dicom_file(str(enc_dcm), str(out_dcm), cipher, source=999)  # type: ignore

        # 6. Decrypt error: Sealed dataset mismatch with restored PHI
        enc_tampered = Path(tmp_dir) / "enc_tampered.dcm"
        loaded_enc = pydicom.dcmread(str(enc_dcm))
        manifest = parse_binary_envelope(loaded_enc[PRIVATE_PAYLOAD_TAG].value)

        # Alter PatientName in sealed_dataset so it conflicts with restored PHI
        fake_ds = create_synthetic_dicom(rows=8, cols=8)
        fake_ds.PatientName = "MISMATCHED_PATIENT_NAME"
        manifest["sealed_dataset"] = base64.b64encode(serialize_sealed_dataset(fake_ds)).decode("ascii")
        loaded_enc[PRIVATE_PAYLOAD_TAG].value = serialize_binary_envelope(manifest)
        loaded_enc.save_as(str(enc_tampered))

        with pytest.raises(AuthenticationError, match="Sealed dataset does not match authenticated PHI metadata"):
            DICOMPACSEnvelope.decrypt_dicom_file(str(enc_tampered), str(out_dcm), cipher, source=ManifestSource.EMBEDDED)

        # 7. Header tamper error cleanup: output_dcm exists prior to tamper failure
        out_dcm.write_bytes(b"existing_file")
        enc_header_tamper = Path(tmp_dir) / "enc_header_tamper.dcm"
        ht_ds = pydicom.dcmread(str(enc_dcm))
        ht_ds.PatientID = "TAMPERED_PATIENT_ID"
        ht_ds.save_as(str(enc_header_tamper))

        with pytest.raises(AuthenticationError, match="HEADER_TAMPER_DETECTED"):
            DICOMPACSEnvelope.decrypt_dicom_file(str(enc_header_tamper), str(out_dcm), cipher, source=ManifestSource.EMBEDDED)
        assert not out_dcm.exists()

        # 8. AEAD decrypt failure cleanup: output_dcm exists prior to decrypt failure
        out_dcm.write_bytes(b"existing_file")
        enc_aead_tamper = Path(tmp_dir) / "enc_aead_tamper.dcm"
        at_ds = pydicom.dcmread(str(enc_dcm))
        at_manifest = parse_binary_envelope(at_ds[PRIVATE_PAYLOAD_TAG].value)
        at_manifest["aead"]["gcm_tag"] = base64.b64encode(b"\x00" * 16).decode("ascii")
        at_ds[PRIVATE_PAYLOAD_TAG].value = serialize_binary_envelope(at_manifest)
        at_ds.save_as(str(enc_aead_tamper))

        with pytest.raises(Exception):
            DICOMPACSEnvelope.decrypt_dicom_file(str(enc_aead_tamper), str(out_dcm), cipher, source=ManifestSource.EMBEDDED)
        assert not out_dcm.exists()

        # 9. PHI decrypt failure cleanup: output_dcm exists prior to phi failure
        out_dcm.write_bytes(b"existing_file")
        enc_phi_tamper = Path(tmp_dir) / "enc_phi_tamper.dcm"
        pt_ds = pydicom.dcmread(str(enc_dcm))
        pt_manifest = parse_binary_envelope(pt_ds[PRIVATE_PAYLOAD_TAG].value)
        pt_manifest["encrypted_phi"] = base64.b64encode(b"invalid_phi_blob").decode("ascii")
        pt_ds[PRIVATE_PAYLOAD_TAG].value = serialize_binary_envelope(pt_manifest)
        pt_ds.save_as(str(enc_phi_tamper))

        with pytest.raises(AuthenticationError, match="Encrypted PHI metadata authentication failed"):
            DICOMPACSEnvelope.decrypt_dicom_file(str(enc_phi_tamper), str(out_dcm), cipher, source=ManifestSource.EMBEDDED)
        assert not out_dcm.exists()



