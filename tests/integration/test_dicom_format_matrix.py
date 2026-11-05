"""
tests.integration.test_dicom_format_matrix
==========================================
Integration tests for DICOM format matrix conformance and typed rejection.
Verifies that supported transfer syntaxes succeed and unsupported formats
raise typed UnsupportedDICOMError.
"""

from pathlib import Path
import tempfile
import pydicom
import pytest

from medpqc.cipher.engine import MedPQCCipher
from medpqc.dicom.pacs import (
    DICOMPACSEnvelope,
    SitePseudonymizationKey,
    UnsupportedDICOMError,
)
from tests.factories.dicom_factory import create_synthetic_dicom


@pytest.mark.parametrize(
    "syntax_uid",
    [
        "1.2.840.10008.1.2.1",  # Explicit VR Little Endian
        "1.2.840.10008.1.2",    # Implicit VR Little Endian
    ],
)
def test_supported_transfer_syntaxes_succeed(syntax_uid):
    ds = create_synthetic_dicom(rows=32, cols=32)
    ds.file_meta.TransferSyntaxUID = syntax_uid

    key = b"K" * 32
    site_key = SitePseudonymizationKey(b"S" * 32)

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_path = Path(tmp_dir) / "in.dcm"
        out_path = Path(tmp_dir) / "out.dcm"
        ds.save_as(str(in_path))

        env = DICOMPACSEnvelope.encrypt_dicom_file(
            input_dcm_path=str(in_path),
            output_dcm_path=str(out_path),
            cipher=MedPQCCipher(key),
            site_key=site_key,
        )
        assert env is not None
        assert out_path.exists()


@pytest.mark.parametrize(
    "unsupported_syntax_uid",
    [
        "1.2.840.10008.1.2.4.50",  # JPEG Baseline (Process 1)
        "1.2.840.10008.1.2.4.70",  # JPEG Lossless (Process 14)
        "1.2.840.10008.1.2.4.90",  # JPEG 2000 Image Compression (Lossless Only)
        "1.2.840.10008.1.2.4.91",  # JPEG 2000 Image Compression
        "1.2.840.10008.1.2.2",     # Explicit VR Big Endian
    ],
)
def test_unsupported_transfer_syntaxes_raise_typed_error(unsupported_syntax_uid):
    ds = create_synthetic_dicom(rows=32, cols=32)
    ds.file_meta.TransferSyntaxUID = unsupported_syntax_uid

    key = b"K" * 32
    site_key = SitePseudonymizationKey(b"S" * 32)

    with tempfile.TemporaryDirectory() as tmp_dir:
        in_path = Path(tmp_dir) / "unsupported.dcm"
        out_path = Path(tmp_dir) / "out.dcm"
        if unsupported_syntax_uid == "1.2.840.10008.1.2.2":
            ds.is_little_endian = False
            ds.is_implicit_VR = False
            pydicom.dcmwrite(str(in_path), ds, little_endian=False)
        else:
            from pydicom.encaps import encapsulate
            ds.is_little_endian = True
            ds.is_implicit_VR = False
            ds.PixelData = encapsulate([b"\xFF\xD8\xFF\xE0" + b"\x00" * 32])
            pydicom.dcmwrite(str(in_path), ds)

        with pytest.raises(UnsupportedDICOMError):
            DICOMPACSEnvelope.encrypt_dicom_file(
                input_dcm_path=str(in_path),
                output_dcm_path=str(out_path),
                cipher=MedPQCCipher(key),
                site_key=site_key,
            )
