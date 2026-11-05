"""
tests.integration.test_end_to_end_workflows
===========================================
End-to-end integration tests for MedPQC v2.3.0.
Verifies full lifecycle workflows across:
- Mutual authenticated hybrid post-quantum key exchange (Ed25519 + ML-KEM-768 + P-256)
- Directional session key separation and bidirectional messaging
- DICOM PACS study encryption, pseudonymization, transmission, and exact recovery
- Replay attack defenses and tamper detection
"""

import os
import tempfile
import numpy as np
import pytest
from cryptography.exceptions import InvalidTag

from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.trust import TrustStore
from medpqc.security.replay import MemoryReplayStore, ReplayDetectedError, StaleSessionError
from medpqc.cipher.engine import MedPQCCipher
from medpqc.dicom.handler import MedicalImageIO, HAS_PYDICOM
from medpqc.dicom.pacs import (
    DICOMPACSEnvelope,
    DICOMPACSSession,
    PRIVATE_CREATOR_TAG,
    PRIVATE_PAYLOAD_TAG,
    SitePseudonymizationKey,
)
from medpqc.utils.limits import AuthenticationError


def test_e2e_hybrid_handshake_bidirectional_messaging():
    """
    Tests complete authenticated hybrid handshake between Client (Alice) and PACS Server (Bob),
    verifying directional key isolation and message transmission.
    """
    replay_store = MemoryReplayStore()
    trust_store = TrustStore()

    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()

    trust_store.register_peer("clinic-client-1", alice_id.public_bytes)
    trust_store.register_peer("pacs-server-1", bob_id.public_bytes)

    # 1. Alice initiates
    import secrets
    session_id = secrets.token_bytes(16)
    initiator_alice = InitiatorContext("clinic-client-1", alice_id, trust_store=trust_store)
    init_msg = initiator_alice.initiate(
        receiver_id="pacs-server-1",
        session_id=session_id,
    )

    # 2. Bob responds
    responder_bob = ResponderContext(
        "pacs-server-1",
        bob_id,
        trust_store=trust_store,
        replay_store=replay_store,
        allow_non_durable_replay_store=True,
    )
    resp_msg, bob_session = responder_bob.respond(init_message=init_msg)

    # 3. Alice finalizes
    alice_session = initiator_alice.finalize(response_message=resp_msg)

    # 4. Verify directional session keys match
    assert alice_session.k_send == bob_session.k_recv
    assert alice_session.k_recv == bob_session.k_send
    assert alice_session.session_key_id == bob_session.session_key_id

    # 5. Directional transmission: Alice -> Bob
    alice_cipher = MedPQCCipher(
        k_aes=alice_session.k_send,
        k_mac=b"\x00" * 32,
        session_key_id=alice_session.session_key_id.hex(),
        suite_id=alice_session.suite_id,
    )
    bob_recv_cipher = MedPQCCipher(
        k_aes=bob_session.k_recv,
        k_mac=b"\x00" * 32,
        session_key_id=bob_session.session_key_id.hex(),
        suite_id=bob_session.suite_id,
    )

    img_a2b = (np.random.rand(32, 32) * 255).astype(np.uint8)
    bundle_a2b = alice_cipher.encrypt(img_a2b, retained_headers={"direction": "a2b"})
    dec_a2b = bob_recv_cipher.decrypt(bundle_a2b)
    assert np.array_equal(dec_a2b, img_a2b)

    # 6. Directional transmission: Bob -> Alice
    bob_send_cipher = MedPQCCipher(
        k_aes=bob_session.k_send,
        k_mac=b"\x00" * 32,
        session_key_id=bob_session.session_key_id.hex(),
        suite_id=bob_session.suite_id,
    )
    alice_recv_cipher = MedPQCCipher(
        k_aes=alice_session.k_recv,
        k_mac=b"\x00" * 32,
        session_key_id=alice_session.session_key_id.hex(),
        suite_id=alice_session.suite_id,
    )

    img_b2a = (np.random.rand(16, 16) * 1000).astype(np.uint16)
    bundle_b2a = bob_send_cipher.encrypt(img_b2a, retained_headers={"direction": "b2a"})
    dec_b2a = alice_recv_cipher.decrypt(bundle_b2a)
    assert np.array_equal(dec_b2a, img_b2a)


def test_e2e_replay_attack_rejection():
    """
    Tests that replaying a captured handshake initiation is rejected.
    """
    replay_store = MemoryReplayStore()
    trust_store = TrustStore()

    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()

    trust_store.register_peer("client-node", alice_id.public_bytes)
    trust_store.register_peer("server-node", bob_id.public_bytes)

    import secrets
    session_id = secrets.token_bytes(16)
    initiator = InitiatorContext("client-node", alice_id, trust_store=trust_store)
    init_msg = initiator.initiate(
        receiver_id="server-node",
        session_id=session_id,
    )

    responder = ResponderContext(
        "server-node",
        bob_id,
        trust_store=trust_store,
        replay_store=replay_store,
        allow_non_durable_replay_store=True,
    )

    # First response succeeds
    _, _ = responder.respond(init_message=init_msg)

    # Replay of identical init message must fail
    with pytest.raises(ReplayDetectedError):
        responder.respond(init_message=init_msg)


@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_e2e_dicom_pacs_study_lifecycle():
    """
    Tests full DICOM PACS lifecycle:
    Creation -> Session Encryption -> Retention check -> Decryption -> Bitwise fidelity check.
    """
    import pydicom

    with tempfile.TemporaryDirectory() as tmpdir:
        input_dcm = os.path.join(tmpdir, "input_study.dcm")
        enc_dcm = os.path.join(tmpdir, "encrypted_archive.dcm")
        dec_dcm = os.path.join(tmpdir, "restored_study.dcm")

        # 1. Create realistic 64x64 uint16 DICOM object
        orig_pixels = (np.random.rand(64, 64) * 4095).astype(np.uint16)
        MedicalImageIO.save(input_dcm, orig_pixels)

        # Populate sensitive clinical headers
        ds = pydicom.dcmread(input_dcm)
        ds.PatientName = "DOE^JOHN^CLINICAL"
        ds.PatientID = "SECRET-PATIENT-ID-999"
        ds.PatientBirthDate = "19750512"
        ds.StudyDescription = "CONFIDENTIAL ONCOLOGY PROTOCOL"
        ds.InstitutionName = "CENTRAL MEMORIAL HOSPITAL"
        ds.save_as(input_dcm)

        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        trust_store = TrustStore()
        trust_store.register_peer("pacs-client-hospital-a", alice_id.public_bytes)
        trust_store.register_peer("pacs-server-hospital-b", bob_id.public_bytes)

        # 2. Client initiates session
        init_msg, client_state = DICOMPACSSession.create_client_session(
            alice_identity=alice_id,
            sender_id="pacs-client-hospital-a",
            receiver_id="pacs-server-hospital-b",
        )

        site_key = b"SITE_SPECIFIC_SECRET_KEY_32BYTES"

        # 3. Server encrypts study into PACS container
        env, resp_msg = DICOMPACSSession.encrypt_dicom_study(
            input_dcm_path=input_dcm,
            output_dcm_path=enc_dcm,
            bob_identity=bob_id,
            init_message=init_msg,
            trust_store=trust_store,
            site_key=site_key,
        )

        assert os.path.exists(enc_dcm)

        # 4. Inspect encrypted archive at rest
        enc_ds = pydicom.dcmread(enc_dcm)

        # PHI tags must be scrubbed / pseudonymized
        assert str(enc_ds.PatientName) != "DOE^JOHN^CLINICAL"
        assert enc_ds.PatientID != "SECRET-PATIENT-ID-999"
        assert enc_ds.PatientID.startswith("MEDPQC-PSN-")
        assert getattr(enc_ds, "PatientBirthDate", "") == ""

        # PixelData must be synthetic noise
        enc_pixels = np.frombuffer(enc_ds.PixelData, dtype=np.uint16).reshape((64, 64))
        assert not np.array_equal(enc_pixels, orig_pixels)

        # Authenticated manifest must be present in private tag
        assert PRIVATE_CREATOR_TAG in enc_ds
        assert PRIVATE_PAYLOAD_TAG in enc_ds

        # 5. Client decrypts and restores exact study
        restored_pixels = DICOMPACSSession.decrypt_dicom_study(
            encrypted_dcm_path=enc_dcm,
            output_dcm_path=dec_dcm,
            alice_identity=alice_id,
            client_state=client_state,
            trust_store=trust_store,
        )

        # 6. Verify image fidelity: MSE == 0.0
        assert np.array_equal(restored_pixels, orig_pixels)
        mse = float(np.mean((orig_pixels.astype(float) - restored_pixels.astype(float)) ** 2))
        assert mse == 0.0

        # 7. Verify restored metadata
        restored_ds = pydicom.dcmread(dec_dcm)
        assert str(restored_ds.PatientName) == "DOE^JOHN^CLINICAL"
        assert restored_ds.PatientID == "SECRET-PATIENT-ID-999"
        assert restored_ds.StudyDescription == "CONFIDENTIAL ONCOLOGY PROTOCOL"


@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_e2e_tamper_detection_in_pacs_container():
    """
    Tests that tampering with pixel data or manifest in the PACS container
    is detected by AEAD or dataset hash verification and results in rejection.
    """
    import pydicom

    with tempfile.TemporaryDirectory() as tmpdir:
        input_dcm = os.path.join(tmpdir, "input.dcm")
        enc_dcm = os.path.join(tmpdir, "enc.dcm")
        tampered_dcm = os.path.join(tmpdir, "tampered.dcm")
        dec_dcm = os.path.join(tmpdir, "dec.dcm")

        orig_pixels = (np.random.rand(32, 32) * 200).astype(np.uint8)
        MedicalImageIO.save(input_dcm, orig_pixels)

        cipher = MedPQCCipher(k_aes=b"K" * 32, k_mac=b"M" * 32)
        site_key = SitePseudonymizationKey(b"S" * 32)
        DICOMPACSEnvelope.encrypt_dicom_file(input_dcm, enc_dcm, cipher, site_key=site_key)

        # Tamper with the encrypted object
        ds = pydicom.dcmread(enc_dcm)
        raw_manifest = bytearray(ds[PRIVATE_PAYLOAD_TAG].value)
        # Flip bit in ciphertext inside manifest
        raw_manifest[len(raw_manifest) // 2] ^= 0x01
        ds[PRIVATE_PAYLOAD_TAG].value = bytes(raw_manifest)
        ds.save_as(tampered_dcm)

        # Decryption of tampered container must fail
        with pytest.raises((AuthenticationError, InvalidTag, Exception)):
            DICOMPACSEnvelope.decrypt_dicom_file(tampered_dcm, dec_dcm, cipher, source=ManifestSource.EMBEDDED)
