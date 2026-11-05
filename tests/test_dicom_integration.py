"""
tests.test_dicom_integration
============================
Unit tests for medpqc.dicom module (MedicalImageIO & DICOMPACSEnvelope).
"""

import os
import tempfile
import numpy as np
import pytest
from medpqc.dicom.handler import MedicalImageIO, HAS_PYDICOM
from medpqc.dicom.pacs import DICOMPACSEnvelope, ManifestSource, SitePseudonymizationKey
from medpqc.cipher.engine import MedPQCCipher

def test_image_io_standard_grayscale_png():
    img = np.random.randint(0, 256, size=(64, 64), dtype=np.uint8)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = os.path.join(tmpdir, "test_gray.png")
        MedicalImageIO.save(tmp_path, img)
        assert os.path.exists(tmp_path)

        loaded, meta = MedicalImageIO.load(tmp_path)
        assert loaded.shape[:2] == (64, 64)
        assert meta['format'] == '.png'

def test_image_io_standard_rgb_png():
    rgb = np.random.randint(0, 256, size=(32, 32, 3), dtype=np.uint8)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = os.path.join(tmpdir, "test_rgb.png")
        MedicalImageIO.save(tmp_path, rgb)
        assert os.path.exists(tmp_path)

        loaded, _ = MedicalImageIO.load(tmp_path)
        assert loaded.shape == (32, 32, 3)

def test_image_io_invalid_path_raises_error():
    with pytest.raises(ValueError, match="Failed to load image"):
        MedicalImageIO.load("non_existent_image_12345.png")

@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_real_clinical_dicom_roundtrip():
    from tests.factories.dicom_factory import create_synthetic_dicom
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dcm = os.path.join(tmpdir, "synthetic_ct.dcm")
        ds = create_synthetic_dicom(rows=64, cols=64, dtype=np.int16, patient_name="DOE^JOHN", patient_id="CLINICAL-12345")
        ds.save_as(test_dcm)

        pixels, _ = MedicalImageIO.load(test_dcm)
        assert pixels.dtype == np.int16

        cipher = MedPQCCipher(k_aes=b"D" * 32, k_mac=b"C" * 32)

        enc_dcm = os.path.join(tmpdir, "encrypted.dcm")
        dec_dcm = os.path.join(tmpdir, "decrypted.dcm")

        # PACS Envelope Encrypt
        env = DICOMPACSEnvelope.encrypt_dicom_file(
            test_dcm,
            enc_dcm,
            cipher,
            site_key=SitePseudonymizationKey(b"S" * 32),
            sidecar_path=enc_dcm + ".pqc.json",
        )
        assert os.path.exists(enc_dcm)
        assert os.path.exists(enc_dcm + ".pqc.json")

        # Verify anonymization occurred in encrypted file
        import pydicom
        enc_ds = pydicom.dcmread(enc_dcm)
        assert enc_ds.PatientName == "ANONYMIZED^MEDPQC"

        # PACS Envelope Decrypt with template and explicit external source
        restored_pixels = DICOMPACSEnvelope.decrypt_dicom_file(
            enc_dcm + ".pqc.json",
            dec_dcm,
            cipher,
            source=ManifestSource.EXTERNAL,
            original_template_dcm=test_dcm
        )

        assert np.array_equal(pixels, restored_pixels)
        assert float(np.mean((pixels.astype(float) - restored_pixels.astype(float))**2)) == 0.0

        # PACS Envelope Decrypt directly from self-contained .dcm container
        dec_dcm_direct = os.path.join(tmpdir, "decrypted_direct.dcm")
        restored_direct = DICOMPACSEnvelope.decrypt_dicom_file(
            enc_dcm,
            dec_dcm_direct,
            cipher,
            source=ManifestSource.EMBEDDED,
        )
        assert np.array_equal(pixels, restored_direct)
        restored_ds = pydicom.dcmread(dec_dcm_direct)
        assert restored_ds.PatientName == "DOE^JOHN"

        # PACS Envelope Decrypt without template from .pqc.json
        dec_dcm_notemplate = os.path.join(tmpdir, "decrypted_no_template.dcm")
        restored_no_tmpl = DICOMPACSEnvelope.decrypt_dicom_file(
            enc_dcm + ".pqc.json",
            dec_dcm_notemplate,
            cipher,
            source=ManifestSource.EXTERNAL,
            original_template_dcm=None
        )
        assert np.array_equal(pixels, restored_no_tmpl)

def test_dicom_save_uint16():
    import pydicom
    from pydicom.dataset import Dataset, FileDataset
    from pydicom.uid import ExplicitVRLittleEndian

    meta = pydicom.Dataset()
    meta.MediaStorageSOPClassUID = '1.2.840.10008.5.1.4.1.1.2'
    meta.MediaStorageSOPInstanceUID = '1.2.3'
    meta.TransferSyntaxUID = ExplicitVRLittleEndian

    with tempfile.TemporaryDirectory() as tmpdir:
        dcm_path = os.path.join(tmpdir, "test_uint16.dcm")
        ds = FileDataset(dcm_path, {}, file_meta=meta, preamble=b"\0" * 128)
        ds.Rows = 16
        ds.Columns = 16
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1

        img16 = np.zeros((16, 16), dtype=np.uint16)
        MedicalImageIO.save(dcm_path, img16, metadata=ds)
        assert os.path.exists(dcm_path)

def test_phi_metadata_edge_cases():
    cipher = MedPQCCipher(k_aes=b"D" * 32, k_mac=b"C" * 32)
    assert DICOMPACSEnvelope.decrypt_phi_metadata(b"", cipher) == {}
    with pytest.raises(ValueError, match="PHI metadata authentication failed"):
        DICOMPACSEnvelope.decrypt_phi_metadata(b"invalid_corrupt_data", cipher)

@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_dicom_pacs_session_end_to_end():
    from medpqc.dicom.pacs import DICOMPACSSession
    from medpqc.kem.auth import IdentityKeyPair, TrustStore
    import pydicom

    # Establish Identity Keys and TrustStore
    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()
    trust_store = TrustStore()
    trust_store.register_peer("hospital-a-pacs", alice_id.public_bytes)
    trust_store.register_peer("hospital-b-pacs", bob_id.public_bytes)

    with tempfile.TemporaryDirectory() as tmpdir:
        from tests.factories.dicom_factory import create_synthetic_dicom
        test_dcm = os.path.join(tmpdir, "input_ct.dcm")
        ds = create_synthetic_dicom(rows=64, cols=64, dtype=np.int16, patient_name="DOE^JOHN", patient_id="CLINICAL-12345")
        ds.save_as(test_dcm)
        orig_pixels, _ = MedicalImageIO.load(test_dcm)

        enc_dcm = os.path.join(tmpdir, "session_encrypted.dcm")
        dec_dcm = os.path.join(tmpdir, "session_decrypted.dcm")

        # Step 1: Alice creates client session
        init_msg, client_state = DICOMPACSSession.create_client_session(
            alice_identity=alice_id,
            sender_id="hospital-a-pacs",
            receiver_id="hospital-b-pacs"
        )

        # Step 2: Bob receives init_msg, encrypts DICOM study
        envelope, resp_msg = DICOMPACSSession.encrypt_dicom_study(
            input_dcm_path=test_dcm,
            output_dcm_path=enc_dcm,
            bob_identity=bob_id,
            init_message=init_msg,
            trust_store=trust_store
        )
        assert os.path.exists(enc_dcm)

        # Verify pseudonymization in container
        enc_ds = pydicom.dcmread(enc_dcm)
        assert enc_ds.PatientName == "ANONYMIZED^MEDPQC"
        assert str(enc_ds.PatientID).startswith("MEDPQC-PSN-")

        # Step 3: Alice receives encrypted .dcm, decrypts using client_state
        restored_pixels = DICOMPACSSession.decrypt_dicom_study(
            encrypted_dcm_path=enc_dcm,
            output_dcm_path=dec_dcm,
            alice_identity=alice_id,
            client_state=client_state,
            trust_store=trust_store
        )

        assert np.array_equal(orig_pixels, restored_pixels)
        restored_ds = pydicom.dcmread(dec_dcm)
        assert restored_ds.PatientName == "DOE^JOHN"

        # Edge cases: corrupt container or missing tag
        with pytest.raises(ValueError, match="does not contain MedPQC private payload tag"):
            DICOMPACSSession.decrypt_dicom_study(
                encrypted_dcm_path=test_dcm,  # unencrypted source file
                output_dcm_path=dec_dcm,
                alice_identity=alice_id,
                client_state=client_state,
                trust_store=trust_store
            )

        # Container without handshake payload
        bad_manifest_dcm = os.path.join(tmpdir, "bad_manifest.dcm")
        enc_ds_bad = pydicom.dcmread(enc_dcm)
        from medpqc.dicom.pacs import parse_binary_envelope, serialize_binary_envelope
        manifest_obj = parse_binary_envelope(enc_ds_bad[(0x0029, 0x1010)].value)
        manifest_obj['handshake_payload'] = {}
        enc_ds_bad[(0x0029, 0x1010)].value = serialize_binary_envelope(manifest_obj)
        enc_ds_bad.save_as(bad_manifest_dcm)

        with pytest.raises(ValueError, match="missing authenticated handshake payload"):
            DICOMPACSSession.decrypt_dicom_study(
                encrypted_dcm_path=bad_manifest_dcm,
                output_dcm_path=dec_dcm,
                alice_identity=alice_id,
                client_state=client_state,
                trust_store=trust_store
            )

def test_dicom_pacs_edge_coverage(monkeypatch):
    import pydicom
    # 1. extract_retained_routing_headers with None
    headers = DICOMPACSEnvelope.extract_retained_routing_headers(None)
    assert headers == {}

    # 2. encrypt_dicom_file failure on private tag embedding
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dcm = os.path.join(tmpdir, "test.dcm")
        enc_dcm = os.path.join(tmpdir, "enc.dcm")
        orig_pixels = (np.random.rand(32, 32) * 255).astype(np.uint8)
        MedicalImageIO.save(test_dcm, orig_pixels)

        cipher = MedPQCCipher(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)

        orig_dcmread = pydicom.dcmread
        def mock_dcmread(*args, **kwargs):
            ds = orig_dcmread(*args, **kwargs)
            def failing_add_new(*a, **k):
                raise ValueError("Mock write failure")
            ds.add_new = failing_add_new
            return ds

        monkeypatch.setattr(pydicom, 'dcmread', mock_dcmread)
        with pytest.raises(RuntimeError, match="DICOM_CONTAINER_ERROR: Failed to embed cryptographic manifest"):
            DICOMPACSEnvelope.encrypt_dicom_file(test_dcm, enc_dcm, cipher, site_key=SitePseudonymizationKey(b"S" * 32))
        monkeypatch.undo()

    # 3. decrypt_dicom_file fallback to .pqc.json when .dcm read fails
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dcm = os.path.join(tmpdir, "test.dcm")
        enc_dcm = os.path.join(tmpdir, "enc.dcm")
        dec_dcm = os.path.join(tmpdir, "dec.dcm")
        orig_pixels = (np.random.rand(32, 32) * 255).astype(np.uint8)
        MedicalImageIO.save(test_dcm, orig_pixels)

        cipher = MedPQCCipher(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
        DICOMPACSEnvelope.encrypt_dicom_file(
            test_dcm,
            enc_dcm,
            cipher,
            site_key=SitePseudonymizationKey(b"S" * 32),
            sidecar_path=enc_dcm + ".pqc.json",
        )

        # Corrupt the enc.dcm file so dcmread fails, but enc.dcm.pqc.json exists
        with open(enc_dcm, "wb") as f:
            f.write(b"not-a-valid-dicom-file")

        # D-10: Decrypting corrupt embedded manifest fails closed with ManifestError (no silent fallback)
        from medpqc.dicom.pacs import ManifestError
        with pytest.raises(ManifestError):
            DICOMPACSEnvelope.decrypt_dicom_file(enc_dcm, dec_dcm, cipher, source=ManifestSource.EMBEDDED)

        # Explicit EXTERNAL source decrypts via sidecar file
        restored = DICOMPACSEnvelope.decrypt_dicom_file(enc_dcm, dec_dcm, cipher, source=ManifestSource.EXTERNAL)
        assert np.array_equal(restored, orig_pixels)

def test_dicom_transfer_syntax_validation(monkeypatch):
    import pydicom
    real_dcmread = pydicom.dcmread

    def mock_dcmread(fp, *args, **kwargs):
        ds = real_dcmread(fp, *args, **kwargs)
        ds.file_meta.TransferSyntaxUID = pydicom.uid.UID("1.2.840.10008.1.2.4.50")
        return ds

    with tempfile.TemporaryDirectory() as tmpdir:
        test_dcm = os.path.join(tmpdir, "test.dcm")
        orig_pixels = np.zeros((16, 16), dtype=np.uint8)
        MedicalImageIO.save(test_dcm, orig_pixels)

        monkeypatch.setattr(pydicom, 'dcmread', mock_dcmread)
        with pytest.raises(ValueError, match="UNSUPPORTED_TRANSFER_SYNTAX"):
            MedicalImageIO.load(test_dcm)

def test_dicom_site_salt_security_and_aliases():
    from medpqc.dicom.pacs import generate_site_salt, DICOMPACSSession, DICOMPACSEnvelope
    from medpqc.kem.auth import IdentityKeyPair
    from medpqc.cipher.engine import MedPQCCipher

    # Test generate_site_salt
    salt = generate_site_salt(32)
    assert len(salt) == 32
    with pytest.raises(ValueError, match="Salt length must be at least 16 bytes"):
        generate_site_salt(10)

    # Test site_salt validation in encrypt_phi_metadata
    cipher = MedPQCCipher(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
    with pytest.raises(ValueError, match="Invalid site_salt"):
        DICOMPACSEnvelope.encrypt_phi_metadata(None, cipher, site_salt=b"short")

    # Test site_salt validation in encrypt_dicom_file
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dcm = os.path.join(tmpdir, "test.dcm")
        enc_dcm = os.path.join(tmpdir, "enc.dcm")
        orig_pixels = (np.random.rand(16, 16) * 255).astype(np.uint8)
        MedicalImageIO.save(test_dcm, orig_pixels)

        with pytest.raises((ValueError, TypeError)):
            DICOMPACSEnvelope.encrypt_dicom_file(test_dcm, enc_dcm, cipher, site_key=b"short")

    # Test client_initiate alias
    id_key = IdentityKeyPair()
    init_msg, state = DICOMPACSSession.client_initiate(id_key)
    assert init_msg['sender_id'] == "pacs-client-hospital-a"
    assert state['session_id'] is not None
    assert DICOMPACSSession.encrypt_and_stage_dicom == DICOMPACSSession.encrypt_dicom_study
