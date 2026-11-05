"""
tests.factories.dicom_factory
=============================
Deterministic synthetic DICOM object factory for testing MedPQC without real patient data.
"""

import numpy as np
from typing import Tuple, List, Optional
import pydicom
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage, generate_uid
from pydicom.sequence import Sequence


def create_synthetic_dicom(
    rows: int = 64,
    cols: int = 64,
    frames: int = 1,
    dtype: np.dtype = np.uint16,
    samples_per_pixel: int = 1,
    photometric_interpretation: str = "MONOCHROME2",
    planar_configuration: int = 0,
    patient_name: str = "SYNTHETIC^DOE^JOHN",
    patient_id: str = "CANARY-PATIENT-ID-9999",
    study_instance_uid: Optional[str] = None,
    series_instance_uid: Optional[str] = None,
    sop_instance_uid: Optional[str] = None,
    add_canary_sequences: bool = True,
    add_private_tags: bool = True,
    seed: int = 42,
) -> FileDataset:
    """
    Creates a valid synthetic FileDataset in memory without reading external files.
    """
    rng = np.random.default_rng(seed)

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    file_meta.MediaStorageSOPInstanceUID = sop_instance_uid or generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = FileDataset("synthetic.dcm", {}, file_meta=file_meta, preamble=b"\0" * 128)

    # Core identification
    ds.SOPClassUID = SecondaryCaptureImageStorage
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = study_instance_uid or generate_uid()
    ds.SeriesInstanceUID = series_instance_uid or generate_uid()
    ds.Modality = "OT"
    ds.StudyDate = "20261031"
    ds.SeriesDate = "20261031"
    ds.AcquisitionDate = "20261031"
    ds.ContentDate = "20261031"

    # Patient PHI (Canaries)
    ds.PatientName = patient_name
    ds.PatientID = patient_id
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "O"
    ds.InstitutionName = "CANARY-HOSPITAL-METROPOLIS"
    ds.ReferringPhysicianName = "CANARY-PHYSICIAN^ALICE"

    # Image geometry & raster specs
    ds.Rows = rows
    ds.Columns = cols
    ds.SamplesPerPixel = samples_per_pixel
    ds.PhotometricInterpretation = photometric_interpretation

    if samples_per_pixel > 1:
        ds.PlanarConfiguration = planar_configuration

    if frames > 1:
        ds.NumberOfFrames = frames

    if dtype == np.uint8:
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7
        ds.PixelRepresentation = 0
    elif dtype == np.uint16:
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0
    elif dtype == np.int16:
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 1
    else:
        raise ValueError(f"Unsupported dtype: {dtype}")

    # Pixel Data generation
    if frames > 1:
        if samples_per_pixel == 1:
            shape = (frames, rows, cols)
        else:
            shape = (frames, rows, cols, samples_per_pixel)
    else:
        if samples_per_pixel == 1:
            shape = (rows, cols)
        else:
            shape = (rows, cols, samples_per_pixel)

    if dtype == np.uint8:
        raw_pixels = rng.integers(0, 256, size=shape, dtype=np.uint8)
    elif dtype == np.uint16:
        raw_pixels = rng.integers(0, 65536, size=shape, dtype=np.uint16)
    elif dtype == np.int16:
        raw_pixels = rng.integers(-32768, 32767, size=shape, dtype=np.int16)

    ds.PixelData = raw_pixels.tobytes()

    # Nested sequences with canaries
    if add_canary_sequences:
        seq_item = Dataset()
        seq_item.PatientID = "CANARY-NESTED-PATIENT-ID-8888"
        seq_item.PatientName = "CANARY-NESTED-NAME^BOB"
        seq_item.StudyInstanceUID = generate_uid()
        ds.OtherPatientIDsSequence = Sequence([seq_item])

        req_item = Dataset()
        req_item.RequestedProcedureDescription = "CANARY-PROCEDURE-DESC"
        req_item.StudyInstanceUID = generate_uid()
        ds.RequestAttributesSequence = Sequence([req_item])

    # Private tags with canaries
    if add_private_tags:
        block = ds.private_block(0x0011, "CANARY_PRIVATE_CREATOR", create=True)
        block.add_new(0x01, "LO", "CANARY-PRIVATE-TAG-VALUE-7777")
        block.add_new(0x02, "PN", "CANARY-PRIVATE-PERSON^EVE")

    return ds


def get_all_canary_strings() -> List[str]:
    """Returns all canary strings embedded by create_synthetic_dicom."""
    return [
        "SYNTHETIC^DOE^JOHN",
        "CANARY-PATIENT-ID-9999",
        "19800101",
        "CANARY-HOSPITAL-METROPOLIS",
        "CANARY-PHYSICIAN^ALICE",
        "CANARY-NESTED-PATIENT-ID-8888",
        "CANARY-NESTED-NAME^BOB",
        "CANARY-PROCEDURE-DESC",
        "CANARY-PRIVATE-TAG-VALUE-7777",
        "CANARY-PRIVATE-PERSON^EVE",
    ]
