"""
tests.adversarial.test_untruncated_recovery
===========================================
Adversarial test for SEC-03:
Verifies that DICOM ciphertext is not truncated, Private Tag (0x0029, 0x1010)
contains the untruncated cryptographic manifest, and PixelData contains a valid
synthetic noise raster of matching byte length.
"""

import os
import tempfile
import numpy as np
import pytest
from medpqc.dicom.handler import MedicalImageIO, HAS_PYDICOM
from medpqc.dicom.pacs import (
    DICOMPACSEnvelope,
    DICOMPACSSession,
    PRIVATE_CREATOR_TAG,
    PRIVATE_PAYLOAD_TAG,
    ManifestSource,
    SitePseudonymizationKey,
)
from medpqc.cipher.engine import MedPQCCipher
from medpqc.kem.auth import IdentityKeyPair


from medpqc.security.trust import TrustStore

@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_untruncated_dicom_ciphertext_and_synthetic_pixeldata():
    """Verify SEC-03: complete ciphertext preserved in private tag, PixelData has noise."""
    import pydicom

    with tempfile.TemporaryDirectory() as tmpdir:
        input_dcm = os.path.join(tmpdir, "orig.dcm")
        enc_dcm = os.path.join(tmpdir, "enc.dcm")
        dec_dcm = os.path.join(tmpdir, "dec.dcm")

        # Create original 48x48 uint16 DICOM
        orig_pixels = np.random.randint(100, 3000, size=(48, 48), dtype=np.uint16)
        MedicalImageIO.save(input_dcm, orig_pixels)

        cipher = MedPQCCipher(k_aes=b"U" * 32, k_mac=b"T" * 32)
        site_key = SitePseudonymizationKey(b"S" * 32)
        env = DICOMPACSEnvelope.encrypt_dicom_file(input_dcm, enc_dcm, cipher, site_key=site_key)

        # Inspect encrypted DICOM object
        enc_ds = pydicom.dcmread(enc_dcm)

        # 1. PixelData byte count matches original exactly
        assert len(enc_ds.PixelData) == orig_pixels.nbytes

        # 2. PixelData is obscured noise, not plaintext
        noise_arr = np.frombuffer(enc_ds.PixelData, dtype=np.uint16).reshape((48, 48))
        assert not np.array_equal(orig_pixels, noise_arr)

        # 3. Private tags are intact with v2.4 creator
        assert PRIVATE_CREATOR_TAG in enc_ds
        assert enc_ds[PRIVATE_CREATOR_TAG].value == DICOMPACSEnvelope.PRIVATE_CREATOR
        assert PRIVATE_PAYLOAD_TAG in enc_ds

        # 4. Decryption reconstructs original with MSE = 0.0
        restored = DICOMPACSEnvelope.decrypt_dicom_file(enc_dcm, dec_dcm, cipher, source=ManifestSource.EMBEDDED)
        assert np.array_equal(orig_pixels, restored)
        mse = float(np.mean((orig_pixels.astype(float) - restored.astype(float)) ** 2))
        assert mse == 0.0


@pytest.mark.skipif(not HAS_PYDICOM, reason="pydicom not installed")
def test_dicom_pacs_session_authenticated():
    """Verify DICOMPACSSession functions correctly with mutual authentication via TrustStore."""
    with tempfile.TemporaryDirectory() as tmpdir:
        input_dcm = os.path.join(tmpdir, "input.dcm")
        enc_dcm = os.path.join(tmpdir, "enc.dcm")
        dec_dcm = os.path.join(tmpdir, "dec.dcm")

        orig_pixels = (np.random.rand(32, 32) * 200).astype(np.uint8)
        MedicalImageIO.save(input_dcm, orig_pixels)

        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        trust_store = TrustStore()
        trust_store.add_trusted_peer("pacs-client-hospital-a", alice_id.public_bytes)
        trust_store.add_trusted_peer("pacs-server-hospital-b", bob_id.public_bytes)

        # Step 1: Alice initiates
        init_msg, client_state = DICOMPACSSession.create_client_session(alice_id)

        # Step 2: Bob encrypts with authenticated session
        env, resp_msg = DICOMPACSSession.encrypt_dicom_study(
            input_dcm_path=input_dcm,
            output_dcm_path=enc_dcm,
            bob_identity=bob_id,
            init_message=init_msg,
            trust_store=trust_store,
            site_key=b"S" * 32,
        )
        assert os.path.exists(enc_dcm)

        # Step 3: Alice decrypts with authenticated session
        restored = DICOMPACSSession.decrypt_dicom_study(
            encrypted_dcm_path=enc_dcm,
            output_dcm_path=dec_dcm,
            alice_identity=alice_id,
            client_state=client_state,
            trust_store=trust_store,
        )
        assert np.array_equal(orig_pixels, restored)
