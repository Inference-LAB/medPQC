"""
medpqc.dicom.pacs
=================
PACS-Ready DICOM Header Preservation and Tag Management.
Encrypts the pixel payload tag (7FE0, 0010) while preserving DICOM headers
(PatientID, StudyInstanceUID, Modality, etc.) for PACS routing.
"""

import json
import base64
from typing import Dict, Any, Tuple
import numpy as np

from .handler import MedicalImageIO, HAS_PYDICOM
from ..cipher.engine import MedPQCCipher

class DICOMPACSEnvelope:
    """Provides high-level DICOM encryption and decryption for PACS pipelines."""

    @staticmethod
    def encrypt_dicom_file(
        input_dcm_path: str,
        output_dcm_path: str,
        cipher: MedPQCCipher,
        kem_ciphertext: bytes = b""
    ) -> Dict[str, Any]:
        """
        Encrypts a clinical DICOM file while preserving routing headers.
        Saves encrypted DICOM file and returns security metadata.
        """
        pixel_array, ds = MedicalImageIO.load(input_dcm_path)
        encrypted_bundle = cipher.encrypt(pixel_array, enable_scrambling=True)

        if HAS_PYDICOM and ds is not None:
            # Mask the pixel data with ciphertext bytes
            ct_bytes = encrypted_bundle['aead']['ciphertext']
            # Match length if needed or replace directly
            ds.PixelData = ct_bytes[:len(pixel_array.tobytes())]
            ds.save_as(output_dcm_path)

        # Serialize complete cryptographic envelope for lossless decryption
        envelope = {
            'aead': {
                'nonce': base64.b64encode(encrypted_bundle['aead']['nonce']).decode('ascii'),
                'ciphertext': base64.b64encode(encrypted_bundle['aead']['ciphertext']).decode('ascii'),
                'gcm_tag': base64.b64encode(encrypted_bundle['aead']['gcm_tag']).decode('ascii'),
                'outer_mac': base64.b64encode(encrypted_bundle['aead']['outer_mac']).decode('ascii'),
            },
            'shape': list(encrypted_bundle['shape']),
            'dtype': encrypted_bundle['dtype'],
            'n_bytes': encrypted_bundle['n_bytes'],
            'kem_ciphertext': base64.b64encode(kem_ciphertext).decode('ascii') if kem_ciphertext else ""
        }

        # Save companion envelope file
        meta_path = output_dcm_path + ".pqc.json"
        with open(meta_path, 'w') as f:
            json.dump(envelope, f, indent=2)

        return envelope

    @staticmethod
    def decrypt_dicom_file(
        encrypted_envelope_path: str,
        output_dcm_path: str,
        cipher: MedPQCCipher,
        original_template_dcm: str = None
    ) -> np.ndarray:
        """
        Decrypts an encrypted DICOM envelope and restores original DICOM image.
        """
        with open(encrypted_envelope_path, 'r') as f:
            data = json.load(f)

        aead_raw = {
            'nonce': base64.b64decode(data['aead']['nonce']),
            'ciphertext': base64.b64decode(data['aead']['ciphertext']),
            'gcm_tag': base64.b64decode(data['aead']['gcm_tag']),
            'outer_mac': base64.b64decode(data['aead']['outer_mac']),
        }

        bundle = {
            'aead': aead_raw,
            'shape': tuple(data['shape']),
            'dtype': data['dtype'],
            'n_bytes': data['n_bytes'],
            'enable_scrambling': True
        }

        reconstructed_pixels = cipher.decrypt(bundle)

        # Restore to template DICOM if provided
        metadata = None
        if original_template_dcm and HAS_PYDICOM:
            _, metadata = MedicalImageIO.load(original_template_dcm)

        MedicalImageIO.save(output_dcm_path, reconstructed_pixels, metadata=metadata)
        return reconstructed_pixels
