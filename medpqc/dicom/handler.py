"""
medpqc.dicom.handler
====================
Clinical DICOM and standard medical image file I/O.
Preserves 8-bit and 16-bit raw pixel data without dynamic range compression.
"""

import os
import numpy as np
from typing import Tuple, Any

try:
    import pydicom
    HAS_PYDICOM = True
except ImportError:  # pragma: no cover
    HAS_PYDICOM = False

try:
    import cv2
    HAS_CV2 = True
except ImportError:  # pragma: no cover
    HAS_CV2 = False

class MedicalImageIO:
    """Handles medical image loading and saving preserving exact pixel depth."""

    @staticmethod
    def load(file_path: str) -> Tuple[np.ndarray, Any]:
        """
        Load an image file.
        Supports .dcm (DICOM), .png, .jpg, .tif, .bmp.
        Returns: (pixel_array, metadata)
        """
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".dcm":
            if not HAS_PYDICOM:  # pragma: no cover
                raise ImportError("pydicom is required to read DICOM files: pip install pydicom")
            ds = pydicom.dcmread(file_path)
            pixel_array = ds.pixel_array
            return pixel_array, ds

        # Standard images via OpenCV
        if HAS_CV2:
            img = cv2.imread(file_path, cv2.IMREAD_UNCHANGED)
            if img is None:
                raise ValueError(f"Failed to load image from: {file_path}")
            # If 3-channel BGR, convert to RGB
            if img.ndim == 3 and img.shape[2] == 3:
                img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            return img, {'format': ext}

        raise RuntimeError("No suitable image reader installed (need pydicom or opencv).")  # pragma: no cover

    @staticmethod
    def save(file_path: str, pixel_array: np.ndarray, metadata: Any = None):
        """
        Save decrypted pixel array to file.
        """
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".dcm":
            if not HAS_PYDICOM:  # pragma: no cover
                raise ImportError("pydicom is required to save DICOM files: pip install pydicom")
            if metadata is not None:
                ds = metadata
                ds.PixelData = pixel_array.tobytes()
                ds.save_as(file_path)
                return
            else:
                from pydicom.dataset import FileDataset, FileMetaDataset
                from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage, generate_uid

                file_meta = FileMetaDataset()
                file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
                file_meta.MediaStorageSOPInstanceUID = generate_uid()
                file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

                ds = FileDataset(file_path, {}, file_meta=file_meta, preamble=b"\0" * 128)
                ds.Modality = "OT"
                ds.SOPClassUID = SecondaryCaptureImageStorage
                ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
                ds.Rows = pixel_array.shape[0]
                ds.Columns = pixel_array.shape[1]
                ds.BitsAllocated = 16 if pixel_array.dtype in (np.uint16, np.int16) else 8
                ds.BitsStored = ds.BitsAllocated
                ds.HighBit = ds.BitsAllocated - 1
                ds.PixelRepresentation = 1 if pixel_array.dtype == np.int16 else 0
                ds.SamplesPerPixel = 1
                ds.PhotometricInterpretation = "MONOCHROME2"
                ds.PixelData = pixel_array.tobytes()
                ds.save_as(file_path)
                return

        if HAS_CV2:
            to_save = pixel_array
            if to_save.ndim == 3 and to_save.shape[2] == 3:
                to_save = cv2.cvtColor(to_save, cv2.COLOR_RGB2BGR)
            cv2.imwrite(file_path, to_save)
            return

        raise RuntimeError(f"Unable to save image format: {ext}")  # pragma: no cover
