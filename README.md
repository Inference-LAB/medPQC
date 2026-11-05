# MedPQC: Authenticated Hybrid Post-Quantum Medical Image Encryption and PACS Security Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com/Inference-Lab/medPQC)
[![Standard: NIST FIPS 203](https://img.shields.io/badge/standard-NIST%20FIPS%20203%20(ML--KEM--768)-blueviolet.svg)](https://csrc.nist.gov/pubs/fips/203/final)

---

## Authors and Affiliation

* **Muhammad Khubaib Ahmad**
  * Email: [khubaib.ahmad@inference-lab.org](mailto:khubaib.ahmad@inference-lab.org) | [muhammadkhubaibahmad854@gmail.com](mailto:muhammadkhubaibahmad854@gmail.com)
  * Affiliation: INFERENCE Lab
* **Muzammil Shadab**
  * Email: [muzammil.shadab@inference-lab.org](mailto:muzammil.shadab@inference-lab.org)
  * Affiliation: INFERENCE Lab

**Repository**: [https://github.com/Inference-Lab/medPQC](https://github.com/Inference-Lab/medPQC)

---

> [!WARNING]
> **Research Implementation Notice**: MedPQC is an experimental research framework designed for academic study and protocol evaluation. It is not certified for clinical HIPAA compliance, has not undergone formal Common Criteria or FIPS/CAVP validation, and is not certified for production medical infrastructure.

---

## Executive Summary

Picture Archiving and Communication Systems (PACS) and cloud-native healthcare networks transmit sensitive diagnostic imaging data across distributed environments. Classical key exchange protocols (such as unauthenticated ECDH or RSA) are vulnerable to polynomial-time quantum algorithms and retrospective *Harvest Now, Decrypt Later* (HNDL) collection.

**MedPQC (v1.1.0)** provides an authenticated hybrid post-quantum key establishment and authenticated encryption framework designed for medical imaging workflows.

### Core Architecture and Features

1. **Standardized NIST FIPS 203 ML-KEM-768**: Key encapsulation implements Module-Lattice-Based Key Encapsulation (FIPS 203 ML-KEM-768: 1,184-byte encapsulation key, 1,088-byte ciphertext, 32-byte shared secret, and Section 6.2 implicit rejection). Experimental polynomial constructions are isolated in `medpqc.experimental.toy_rlwe` with non-production warnings.
2. **Mandatory Peer Authentication**: Mutual authentication requires digital signature verification against a configured `TrustStore` or explicitly pinned Ed25519 public key.
3. **Context-Bound Key Derivation & Directional Keys**: Implements RFC 5869 HKDF-SHA-512 binding the full handshake transcript, party identifiers, nonces, and suite identifiers. Derives independent directional encryption keys (`k_enc_i2r` and `k_enc_r2i`) to prevent reflection and replay attacks.
4. **Persistent Replay Protection**: Provides atomic replay tracking with millisecond precision via `SqliteReplayStore` and `MemoryReplayStore`, rejecting replayed handshakes or expired sessions.
5. **Single Authenticated Encrypted Object Architecture**: Unifies DICOM ciphertext and metadata under authenticated encryption (AES-256-GCM AEAD). Associated Authenticated Data (AAD) cryptographically binds the envelope ID, dataset hash, transfer syntax UID, and cipher suite ID.
6. **Keyed Pseudonymization & De-Identification**: Mandates a 32-byte `SitePseudonymizationKey` with HMAC-SHA-256 domain separation, recursively de-identifying sensitive patient attributes and nested sequence elements (`VR == 'SQ'`).
7. **Lossless Clinical Reconstruction**: Bit-exact preservation of 8-bit, 12-bit, 16-bit CT Hounsfield Units, and multi-channel image rasters with zero numerical loss (MSE = 0.0).
8. **Experimental Chaos Scrambling**: Non-cryptographic pixel coordinate scrambling and chained diffusion are isolated as experimental research tools and disabled by default (`enable_scrambling=False`).

---

## Cryptographic Protocol Overview

```
+----------------------------------------------------------------------------------------------------------+
|                                        MedPQC v1.1.0 ARCHITECTURE                                        |
+----------------------------------------------------------------------------------------------------------+
|                                                                                                          |
|   1. AUTHENTICATED HYBRID POST-QUANTUM KEY EXCHANGE (Ed25519 + NIST P-256 + FIPS 203 ML-KEM-768)          |
|   +------------------------------------+   +-----------------------------------------------------+       |
|   |   Initiator (Alice)                |   |   Responder (Bob)                                   |       |
|   |   - Ephemeral P-256 ECDH KeyGen    |   |   - TrustStore & ReplayProtector Verification       |       |
|   |   - FIPS 203 ML-KEM-768 KeyGen     |   |   - Ephemeral P-256 ECDH KeyGen                     |       |
|   |   - Initiation Signature over      |   |   - FIPS 203 ML-KEM-768 Encapsulation               |       |
|   |     Identities, Keys, Nonce        |   |   - Response Signature Binding Full Transcript      |       |
|   +------------------------------------+   +-----------------------------------------------------+       |
|                     |                                                 ^                                  |
|                     +------------ Client Initiation Message --------->|                                  |
|                     |<----------- Server Response Message ------------+                                  |
|                                                                                                          |
|   2. TRANSCRIPT-BOUND KEY DERIVATION (RFC 5869 HKDF-SHA-512)                                             |
|      - Context: Hash(InitTranscript || RespTranscript || SuiteID || AliceID || BobID)                    |
|      - Directional Session Keys: k_enc_i2r, k_enc_r2i, session_key_id                                    |
|                                                                                                          |
|   3. AUTHENTICATED ENCRYPTION (AES-256-GCM AEAD)                                                         |
|      - Single Authenticated Encrypted Object: Raw Manifest + Ciphertext + Tag                             |
|      - Associated Authenticated Data (AAD): Canonical JSON binding envelope_id, dataset_hash, suite_id   |
|                                                                                                          |
+----------------------------------------------------------------------------------------------------------+
```

---

## Installation

MedPQC requires Python >= 3.11.

```bash
# Clone the repository
git clone https://github.com/Inference-LAB/medPQC.git
cd medPQC

# Install core dependencies
pip install -e .

# Install with medical DICOM and development support
pip install -e ".[dicom,dev]"
```

---

## Usage Examples

### 1. Authenticated Hybrid Key Exchange

```python
import secrets
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.trust import TrustStore
from medpqc.security.replay import MemoryReplayStore

# Generate long-term Ed25519 identity keypairs
alice_id = IdentityKeyPair()
bob_id = IdentityKeyPair()

# Configure mutual trust store
trust_store = TrustStore()
trust_store.register_peer("clinic-client", alice_id.public_bytes)
trust_store.register_peer("pacs-server", bob_id.public_bytes)

# Alice initiates handshake
replay_store = MemoryReplayStore()
alice = InitiatorContext("clinic-client", alice_id, trust_store)
bob = ResponderContext(
    "pacs-server",
    bob_id,
    trust_store,
    replay_store,
    allow_non_durable_replay_store=True,
)

init_msg = alice.initiate("pacs-server")

# Bob verifies Alice and responds
resp_msg, bob_session = bob.respond(init_msg)

# Alice finalizes and verifies Bob
alice_session = alice.finalize(resp_msg)

# Directional session keys match
assert alice_session.k_send == bob_session.k_recv
assert alice_session.k_recv == bob_session.k_send
```

### 2. Clinical DICOM PACS Study Encryption

```python
import tempfile
from pathlib import Path
from medpqc.cipher.engine import MedPQCCipher
from medpqc.dicom.pacs import DICOMPACSEnvelope, SitePseudonymizationKey, ManifestSource
from tests.factories.dicom_factory import create_synthetic_dicom

site_key = SitePseudonymizationKey(b"HOSPITAL_PSEUDONYM_KEY_32_BYTES!")
cipher = MedPQCCipher(alice_session.k_send)

# Create a sample clinical DICOM file
ds = create_synthetic_dicom(rows=32, cols=32)
with tempfile.TemporaryDirectory() as tmp_dir:
    in_path = Path(tmp_dir) / "patient_scan.dcm"
    enc_path = Path(tmp_dir) / "encrypted_scan.dcm"
    restored_path = Path(tmp_dir) / "restored_scan.dcm"
    ds.save_as(str(in_path))

    # Bob encrypts study into authenticated PACS container
    DICOMPACSEnvelope.encrypt_dicom_file(
        input_dcm_path=str(in_path),
        output_dcm_path=str(enc_path),
        cipher=cipher,
        site_key=site_key,
    )

    # Alice restores exact clinical study from encrypted container
    DICOMPACSEnvelope.restore_dicom_file(
        encrypted_dcm_path=str(enc_path),
        output_dcm_path=str(restored_path),
        cipher=cipher,
        site_key=site_key,
        source=ManifestSource.EMBEDDED,
    )
```

---

## Test Suite and Verification

Execute the automated test suite:

```bash
# Run unit, integration, adversarial, fuzz, and vector tests
python -m pytest tests/ --cov=medpqc --cov-report=term-missing
```

---

## Limitations

1. **Experimental Prototype**: This library is an exploratory research implementation. It has not undergone formal security audits by accredited testing laboratories.
2. **PACS Interoperability**: Validated on file-level DICOM datasets; live network integration requires site-specific PACS configuration and TLS network security.
3. **No Regulatory Approval**: This software is not certified as a medical device or for regulatory compliance.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
