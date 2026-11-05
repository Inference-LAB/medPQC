# MedPQC User and Developer Guide (v2.5)

**Target Release**: MedPQC v2.5.0  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab (INFERENCE Lab)  
**Date**: November 2026  

---

## 1. Quickstart: Authenticated Post-Quantum Handshake

This example demonstrates a mutual authenticated hybrid handshake between two clinical nodes using NIST FIPS 203 ML-KEM-768, ephemeral P-256 ECDH, and Ed25519 identity verification with `InitiatorContext` and `ResponderContext`.

```python
import secrets
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.trust import TrustStore
from medpqc.security.replay import MemoryReplayStore

# 1. Establish long-term Ed25519 node identities
alice_identity = IdentityKeyPair()
bob_identity = IdentityKeyPair()

# 2. Configure TrustStore (MANDATORY in MedPQC)
trust_store = TrustStore()
trust_store.register_peer("hospital-a-pacs", alice_identity.public_bytes)
trust_store.register_peer("hospital-b-pacs", bob_identity.public_bytes)

# 3. Setup Replay Store and Contexts
replay_store = MemoryReplayStore()
alice_ctx = InitiatorContext("hospital-a-pacs", alice_identity, trust_store)
bob_ctx = ResponderContext(
    "hospital-b-pacs",
    bob_identity,
    trust_store,
    replay_store,
    allow_non_durable_replay_store=True,
)

# Step 1: Alice initiates
init_msg = alice_ctx.initiate("hospital-b-pacs")

# Step 2: Bob responds and derives session keys
resp_msg, bob_session = bob_ctx.respond(init_msg)

# Step 3: Alice finalizes and derives identical directional session keys
alice_session = alice_ctx.finalize(resp_msg)

assert alice_session.k_send == bob_session.k_recv
assert alice_session.k_recv == bob_session.k_send
print("Authenticated Post-Quantum Handshake Successful!")
```

---

## 2. Lossless Medical Image Encryption

Encrypt 16-bit CT/MR images preserving exact numerical Hounsfield Units with zero loss ($\text{MSE} \equiv 0.0$):

```python
import numpy as np
from medpqc.cipher.engine import MedPQCCipher

# Instantiate cipher using key derived from the hybrid KEM
cipher = MedPQCCipher(k_aes=alice_session.k_send)

# Sample 16-bit CT scan slice (-1000 to +2000 Hounsfield Units)
ct_slice = np.random.randint(-1000, 2000, size=(64, 64), dtype=np.int16)

# Encrypt
encrypted_bundle = cipher.encrypt(
    ct_slice,
    enable_scrambling=False,
)

# Decrypt
restored_slice = cipher.decrypt(encrypted_bundle)

# Verify lossless reconstruction
assert np.array_equal(ct_slice, restored_slice)
assert float(np.mean((ct_slice.astype(float) - restored_slice.astype(float)) ** 2)) == 0.0
print("Lossless reconstruction verified! MSE = 0.0")
```

---

## 3. End-to-End Clinical DICOM PACS Workflow

Encrypt a clinical DICOM file creating a self-contained PACS container with sealed dataset integrity and synthetic noise raster:

```python
import tempfile
from pathlib import Path
from medpqc.dicom.pacs import DICOMPACSEnvelope, SitePseudonymizationKey, ManifestSource
from tests.factories.dicom_factory import create_synthetic_dicom

# Configure pseudonymization key
site_key = SitePseudonymizationKey(b"HOSPITAL_PSEUDONYM_KEY_32_BYTES!")

# Create a synthetic DICOM dataset
ds = create_synthetic_dicom(rows=32, cols=32)

with tempfile.TemporaryDirectory() as tmp_dir:
    input_path = Path(tmp_dir) / "raw_patient_study.dcm"
    enc_path = Path(tmp_dir) / "encrypted_pacs_container.dcm"
    restored_path = Path(tmp_dir) / "decrypted_study.dcm"
    ds.save_as(str(input_path))

    # Encrypt DICOM file into authenticated PACS container
    DICOMPACSEnvelope.encrypt_dicom_file(
        input_dcm_path=str(input_path),
        output_dcm_path=str(enc_path),
        cipher=cipher,
        site_key=site_key,
    )

    # Decrypt and restore exact clinical DICOM study
    DICOMPACSEnvelope.restore_dicom_file(
        encrypted_dcm_path=str(enc_path),
        output_dcm_path=str(restored_path),
        cipher=cipher,
        site_key=site_key,
        source=ManifestSource.EMBEDDED,
    )

print("DICOM PACS study successfully decrypted and original dataset restored!")
```

---

## 4. Multi-Worker Persistent Replay Defense

In persistent deployments running multiple worker processes (e.g. Gunicorn/Celery):

```python
import tempfile
from pathlib import Path
from medpqc.security.replay import SqliteReplayStore

with tempfile.TemporaryDirectory() as tmp_dir:
    db_path = Path(tmp_dir) / "replay_cache.db"
    store = SqliteReplayStore(db_path)
    # Replay store handles atomic persistence with WAL journaling
    store.close()
```
