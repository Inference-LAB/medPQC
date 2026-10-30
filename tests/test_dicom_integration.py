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
from medpqc.dicom.pacs import DICOMPACSEnvelope
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
    test_dcm = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "tests_data", "real_ct_16bit.dcm"
    ))
    if not os.path.exists(test_dcm):
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage, generate_uid

        os.makedirs(os.path.dirname(test_dcm), exist_ok=True)
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        ds = FileDataset(test_dcm, {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.Modality = "CT"
        ds.SOPClassUID = SecondaryCaptureImageStorage
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 1
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        synthetic_ct = np.random.randint(-1000, 2000, size=(64, 64), dtype=np.int16)
        ds.PixelData = synthetic_ct.tobytes()
        ds.save_as(test_dcm)

    pixels, ds = MedicalImageIO.load(test_dcm)
    assert pixels.dtype == np.int16

    cipher = MedPQCCipher(k_aes=b"D" * 32, k_mac=b"C" * 32)

    with tempfile.TemporaryDirectory() as tmpdir:
        enc_dcm = os.path.join(tmpdir, "encrypted.dcm")
        dec_dcm = os.path.join(tmpdir, "decrypted.dcm")

        # PACS Envelope Encrypt
        env = DICOMPACSEnvelope.encrypt_dicom_file(test_dcm, enc_dcm, cipher)
        assert os.path.exists(enc_dcm)
        assert os.path.exists(enc_dcm + ".pqc.json")

        # PACS Envelope Decrypt with template
        restored_pixels = DICOMPACSEnvelope.decrypt_dicom_file(
            enc_dcm + ".pqc.json",
            dec_dcm,
            cipher,
            original_template_dcm=test_dcm
        )

        assert np.array_equal(pixels, restored_pixels)
        assert float(np.mean((pixels.astype(float) - restored_pixels.astype(float))**2)) == 0.0

        # PACS Envelope Decrypt without template
        dec_dcm_notemplate = os.path.join(tmpdir, "decrypted_no_template.dcm")
        restored_no_tmpl = DICOMPACSEnvelope.decrypt_dicom_file(
            enc_dcm + ".pqc.json",
            dec_dcm_notemplate,
            cipher,
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
        ds.is_little_endian = True
        ds.is_implicit_VR = False
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
