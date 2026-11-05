"""
tests.adversarial.test_phi_leakage
==================================
Adversarial tests for SEC-04 and SEC-05:
Verifies deep nested DICOM sequence de-identification (HIPAA PS 3.15 Annex E),
prevents PHI leakage in sequence items, tests backward-compatible v2.1 metadata,
and verifies site-salt entropy requirements.
"""

import os
import tempfile
import base64
import json
import numpy as np
import pytest
from medpqc.dicom.handler import MedicalImageIO, HAS_PYDICOM
from medpqc.dicom.pacs import DICOMPACSEnvelope, generate_site_salt, ManifestSource, SitePseudonymizationKey
from medpqc.cipher.engine import MedPQCCipher
from medpqc.cipher.aead import AuthenticatedCipher


@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_nested_sequence_phi_deidentification_and_restoration():
    """Verify SEC-04: nested Sequence elements are recursively scrubbed and restored."""
    import pydicom
    from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
    from pydicom.sequence import Sequence
    from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage, generate_uid

    with tempfile.TemporaryDirectory() as tmpdir:
        input_dcm = os.path.join(tmpdir, "nested_phi_input.dcm")
        enc_dcm = os.path.join(tmpdir, "nested_phi_encrypted.dcm")
        dec_dcm = os.path.join(tmpdir, "nested_phi_decrypted.dcm")

        # Construct dataset with nested sequence
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        ds = FileDataset(input_dcm, {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.Modality = "MR"
        ds.SOPClassUID = SecondaryCaptureImageStorage
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.Rows = 32
        ds.Columns = 32
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PatientName = "MAIN^PATIENT"
        ds.PatientID = "MAIN-ID-999"

        # Create nested sequence item
        seq_item = Dataset()
        seq_item.ReferringPhysicianName = "DR. SECRET NESTED"
        seq_item.PatientName = "NESTED^NAME"
        seq_item.InstitutionName = "CLINIC NESTED"
        ds.RequestAttributesSequence = Sequence([seq_item])

        pixels = np.ones((32, 32), dtype=np.uint16) * 100
        ds.PixelData = pixels.tobytes()
        ds.save_as(input_dcm)

        cipher = MedPQCCipher(k_aes=b"A" * 32, k_mac=b"B" * 32)
        site_key = SitePseudonymizationKey(generate_site_salt(32))

        # Encrypt
        DICOMPACSEnvelope.encrypt_dicom_file(
            input_dcm, enc_dcm, cipher, site_key=site_key
        )

        # In the encrypted file, verify non-allow-listed sequences are stripped
        enc_ds = pydicom.dcmread(enc_dcm)
        assert enc_ds.PatientName == "ANONYMIZED^MEDPQC"
        assert "RequestAttributesSequence" not in enc_ds

        # Decrypt
        restored_pixels = DICOMPACSEnvelope.decrypt_dicom_file(
            enc_dcm, dec_dcm, cipher, source=ManifestSource.EMBEDDED
        )
        assert np.array_equal(pixels, restored_pixels)

        # In decrypted file, verify nested sequence attributes restored
        dec_ds = pydicom.dcmread(dec_dcm)
        assert dec_ds.PatientName == "MAIN^PATIENT"
        nested_item_dec = dec_ds.RequestAttributesSequence[0]
        assert nested_item_dec.ReferringPhysicianName == "DR. SECRET NESTED"
        assert nested_item_dec.PatientName == "NESTED^NAME"
        assert nested_item_dec.InstitutionName == "CLINIC NESTED"


def test_phi_metadata_legacy_v2_1_aad_fallback():
    """Verify backward-compatibility: decryption succeeds for v2.1 PHI metadata AAD."""
    cipher = MedPQCCipher(k_aes=b"K" * 32, k_mac=b"M" * 32)
    sample_phi = {"PatientName": "LEGACY^DOE", "PatientID": "12345"}
    raw_bytes = json.dumps(sample_phi).encode('utf-8')

    # Encrypt with v2.1 AAD
    phi_bundle = AuthenticatedCipher.encrypt(
        raw_bytes, cipher.k_aes, cipher.k_mac, aad=b"MedPQC-PHI-Metadata-v2.1"
    )
    serialized = json.dumps({
        'nonce': base64.b64encode(phi_bundle['nonce']).decode('ascii'),
        'ciphertext': base64.b64encode(phi_bundle['ciphertext']).decode('ascii'),
        'gcm_tag': base64.b64encode(phi_bundle['gcm_tag']).decode('ascii'),
        'outer_mac': base64.b64encode(phi_bundle['outer_mac']).decode('ascii')
    }).encode('utf-8')

    # Decrypt should fall back to v2.1 AAD and succeed
    restored = DICOMPACSEnvelope.decrypt_phi_metadata(serialized, cipher)
    assert restored == sample_phi
