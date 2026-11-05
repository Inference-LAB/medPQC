# MedPQC: Authenticated Hybrid Post-Quantum Medical Image Encryption and PACS Security Framework

[![PyPI Version](https://img.shields.io/pypi/v/medpqc.svg)](https://pypi.org/project/medpqc/)
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
> **Research Implementation Notice**: MedPQC is an exploratory research framework designed for academic study, protocol simulation, and cryptographic evaluation. It is not certified for clinical HIPAA compliance, has not undergone formal Common Criteria or FIPS/CAVP validation, and is not certified for production medical infrastructure.

---

## 1. Purpose: Why MedPQC?

Picture Archiving and Communication Systems (PACS), Vendor Neutral Archives (VNAs), and telemedicine workflows transmit multi-gigabyte diagnostic imaging studies (CT, MRI, X-Ray, Ultrasound, Mammography) across distributed networks and cloud perimeters. 

### The Post-Quantum Threat to Medical Data
Classical asymmetric cryptographic schemes (such as RSA, Diffie-Hellman, and Elliptic Curve Diffie-Hellman over P-256 or Curve25519) rely on the computational hardness of integer factorization or the discrete logarithm problem. These foundations can be compromised in polynomial time by Shor's algorithm executed on cryptanalytically relevant quantum computers.

Medical imaging data is exceptionally sensitive:
- **Prolonged Confidentiality Horizon**: Patient healthcare records frequently require confidentiality lifespans spanning 20 to 50+ years (often the patient's entire lifetime plus statutory retention periods).
- **Harvest Now, Decrypt Later (HNDL)**: Adversaries can capture and archive encrypted medical traffic today, holding it until quantum hardware becomes capable of breaking classical public-key exchanges retrospectively.
- **DICOM Vulnerabilities**: Standard DICOM payloads contain rich Protected Health Information (PHI) in unencrypted headers, creating severe leakage vectors when transmitted across non-isolated hospital networks.

**MedPQC** addresses this challenge by establishing an authenticated, hybrid post-quantum cryptographic protection layer engineered specifically for radiological datasets and DICOM/PACS workflows.

---

## 2. Key Improvements in v1.1.0 over Previous Versions

MedPQC v1.1.0 is a substantial architectural overhaul representing a shift from experimental prototypes to rigorous cryptographic standards:

| Capability / Primitive | Legacy MedPQC (v1.0.0) | MedPQC v1.1.0 (Current Release) |
| :--- | :--- | :--- |
| **Post-Quantum KEM** | Custom/toy polynomial RLWE without standard bounds | **Standard NIST FIPS 203 ML-KEM-768** (1,184-byte EK, 1,088-byte CT, 32-byte SS, Section 6.2 implicit rejection) |
| **Authentication** | Unauthenticated handshake vulnerable to active MITM | **Mandatory Ed25519 Digital Signatures** binding full handshake transcripts via `TrustStore` verification |
| **Session Key Derivation** | Single symmetric key derived from secret concatenation | **Directional Keys via RFC 5869 HKDF-SHA-512** deriving separate `k_send` and `k_recv` with party context |
| **Replay Protection** | Non-persistent memory cache vulnerable across restarts | **Atomic SQLite WAL Replay Store** with millisecond-precision timestamps and replay rejection |
| **DICOM Object Container** | Separate unauthenticated metadata sidecar files (`.pqc.json`) | **Single Authenticated Encrypted Object** unifying ciphertext and metadata in AES-256-GCM AEAD |
| **Authenticated Data (AAD)** | Static or minimal context bindings | **Canonical Context-Bound AAD** binding envelope ID, dataset hash, transfer syntax UID, and suite ID |
| **Patient De-Identification** | Elementary tag clearing | **Keyed Pseudonymization** via 32-byte `SitePseudonymizationKey` and HMAC-SHA-256 domain separation |
| **Experimental Modules** | Blended chaotic routines with cryptographic claims | **Strict Separation**: Non-cryptographic chaos isolated in `medpqc.experimental` with non-production warnings |
| **Test Suite Coverage** | 11 elementary unit tests | **363 Comprehensive Tests** covering NIST ACVP KAT vectors, fuzzing, property invariants, and adversarial red-team exploits |

---

## 3. Cryptographic Protocol Overview

MedPQC combines classical Elliptic Curve cryptography (NIST P-256) with standardized post-quantum lattice cryptography (NIST FIPS 203 ML-KEM-768) and Ed25519 digital signatures into a unified hybrid key encapsulation and authenticated encryption workflow:

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
|      - Directional Session Keys: k_send, k_recv, session_key_id                                          |
|                                                                                                          |
|   3. AUTHENTICATED ENCRYPTION (AES-256-GCM AEAD)                                                         |
|      - Single Authenticated Encrypted Object: Raw Manifest + Ciphertext + Tag                             |
|      - Associated Authenticated Data (AAD): Canonical JSON binding envelope_id, dataset_hash, suite_id   |
|                                                                                                          |
+----------------------------------------------------------------------------------------------------------+
```

---

## 4. Installation

MedPQC requires **Python >= 3.11**.

```bash
# Core package installation from PyPI
pip install medpqc

# Or clone from GitHub
git clone https://github.com/Inference-Lab/medPQC.git
cd medPQC

# Install core package locally
pip install -e .

# Install with medical DICOM and development support
pip install -e ".[dicom,dev]"

# Install all optional components (chaos experiments, benchmarks, tests)
pip install -e ".[all]"
```

### Optional Dependencies
- `dicom`: Enables `pydicom` and `opencv-python-headless` for full DICOM study handling.
- `chaos`: Enables `numba` and `scipy` for experimental dynamical systems simulation.
- `bench`: Enables `matplotlib` for benchmarking visualization.
- `dev`: Installs `pytest`, `pytest-cov`, `hypothesis`, `build`, `twine`, `ruff`, and `mypy`.
- `all`: Installs the complete suite of all above dependencies.

---

## 5. Core API and Subsystems

### 1. Key Encapsulation and Authentication (`medpqc.kem.auth`)
- `IdentityKeyPair`: Ed25519 signing keypair for long-term node identification, serialization, and encrypted PKCS#8 storage.
- `TrustStore`: Secure in-memory store registering authorized peer identifiers and their raw Ed25519 public keys.
- `InitiatorContext`: Orchestrates the client side of the handshake (`initiate` and `finalize`).
- `ResponderContext`: Orchestrates the server side (`respond`) with mandatory replay store and peer identity verification.

### 2. Replay Protection (`medpqc.security.replay`)
- `SqliteReplayStore`: Durable, atomic SQLite storage utilizing Write-Ahead Logging (WAL) and `INSERT ... ON CONFLICT DO NOTHING` for process-safe replay tracking.
- `MemoryReplayStore`: Lightweight in-memory replay store designed for non-production unit testing.

### 3. Authenticated Encryption (`medpqc.cipher.engine`)
- `MedPQCCipher`: High-level authenticated symmetric cipher managing AES-256-GCM encryption, decryption, and canonical metadata serialization.
- `AuthenticatedCipher`: Low-level AEAD wrapper handling nonce generation, tag verification, and authenticated data binding.

### 4. PACS DICOM Protection (`medpqc.dicom.pacs`)
- `DICOMPACSEnvelope`: Encapsulates clinical DICOM datasets into self-contained authenticated containers with encrypted PHI and synthetic placeholder pixel data.
- `SitePseudonymizationKey`: 32-byte cryptographic secret used for keyed de-identification of UIDs, patient names, and nested attributes.
- `ManifestSource`: Enum (`EMBEDDED` or `EXTERNAL`) enforcing explicit metadata manifest provenance.

---

## 6. Usage Examples

### Example 1: Authenticated Post-Quantum Handshake

```python
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.trust import TrustStore
from medpqc.security.replay import SqliteReplayStore

# 1. Establish long-term Ed25519 identities for Clinic and PACS Server
clinic_id = IdentityKeyPair()
pacs_id = IdentityKeyPair()

# 2. Configure mutually trusted identity stores
trust_store = TrustStore()
trust_store.register_peer("clinic-workstation-01", clinic_id.public_bytes)
trust_store.register_peer("central-pacs-server", pacs_id.public_bytes)

# 3. Initialize persistent replay protector for the PACS server
replay_store = SqliteReplayStore("pacs_replay.db")

# 4. Initialize initiator (Clinic) and responder (PACS) contexts
alice = InitiatorContext("clinic-workstation-01", clinic_id, trust_store)
bob = ResponderContext("central-pacs-server", pacs_id, trust_store, replay_store)

# 5. Clinic creates handshake initiation message
init_message = alice.initiate("central-pacs-server")

# 6. PACS verifies Clinic signature, checks replay store, and generates response
resp_message, bob_session = bob.respond(init_message)

# 7. Clinic finalizes handshake and verifies PACS signature
alice_session = alice.finalize(resp_message)

# 8. Directional session keys match perfectly across both endpoints
assert alice_session.k_send == bob_session.k_recv
assert alice_session.k_recv == bob_session.k_send
print(f"Session established successfully! Session Key ID: {alice_session.session_key_id.hex()}")
```

### Example 2: In-Memory Image Raster AEAD Encryption

```python
import numpy as np
from medpqc.cipher.engine import MedPQCCipher

# Create a sample 16-bit CT medical image slice (512x512 Hounsfield Units)
ct_slice = np.random.randint(-1000, 2000, size=(512, 512), dtype=np.int16)

# Initialize cipher with the established directional session key
cipher = MedPQCCipher(alice_session.k_send)

# Encrypt image array with authenticated context metadata
encrypted_payload = cipher.encrypt_image(
    image_array=ct_slice,
    metadata={"modality": "CT", "body_part": "CHEST", "slice_thickness_mm": 1.25}
)

# Decrypt and authenticate payload
restored_slice, restored_meta = cipher.decrypt_image(encrypted_payload)

# Verify bit-exact lossless clinical restoration
assert np.array_equal(ct_slice, restored_slice)
assert restored_meta["modality"] == "CT"
print("Lossless clinical preservation confirmed (MSE = 0.0).")
```

### Example 3: Clinical DICOM PACS Study De-Identification & Encryption

```python
from pathlib import Path
from medpqc.cipher.engine import MedPQCCipher
from medpqc.dicom.pacs import DICOMPACSEnvelope, SitePseudonymizationKey, ManifestSource

# Cryptographic site key for HMAC-SHA-256 de-identification
site_key = SitePseudonymizationKey(b"32_BYTE_SITE_PSEUDONYMIZATION_K!")
cipher = MedPQCCipher(alice_session.k_send)

# Encrypt input DICOM file into authenticated PACS container
DICOMPACSEnvelope.encrypt_dicom_file(
    input_dcm_path="patient_mri_study.dcm",
    output_dcm_path="secure_pacs_mri.dcm",
    cipher=cipher,
    site_key=site_key,
)

# Restore exact clinical study at authorized endpoint
DICOMPACSEnvelope.restore_dicom_file(
    encrypted_dcm_path="secure_pacs_mri.dcm",
    output_dcm_path="restored_mri_study.dcm",
    cipher=cipher,
    site_key=site_key,
    source=ManifestSource.EMBEDDED,
)
```

---

## 7. Empirical Benchmarks & Performance Evaluation

All measurements were conducted under rigorous empirical conditions ($N \ge 30$ randomized iterations per cell with 95% bootstrap confidence intervals):

### 1. Handshake Throughput & Latency

Evaluates the full hybrid handshake (ECDH P-256 + NIST FIPS 203 ML-KEM-768 + Ed25519 signature generation and verification):

| Storage Backend | Mean Latency (ms) | 95% Bootstrap CI (ms) | Median (ms) | p95 (ms) | Handshakes/sec | Memory Footprint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **MemoryReplayStore** | 2.34 +/- 0.17 | [2.29, 2.40] | 2.29 | 2.68 | **426.6 ops/s** | 0.040 MB |
| **SqliteReplayStore** | 7.75 +/- 0.80 | [7.50, 8.10] | 7.59 | 9.52 | **129.1 ops/s** | 0.039 MB |

### 2. Payload Encryption Throughput (AES-256-GCM AEAD)

Evaluates authenticated encryption and decryption performance across typical diagnostic pixel resolutions and representations:

| Resolution | Representation | Payload Size | Encrypt Time (ms) | Decrypt Time (ms) | Encrypt Speed | Decrypt Speed | Mean Squared Error |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **64 x 64** | `uint8` | 4.0 KB | 0.17 ms | 0.15 ms | 22.45 MB/s | 26.08 MB/s | **0.000000** |
| **128 x 128** | `uint8` | 16.0 KB | 0.27 ms | 0.23 ms | 57.42 MB/s | 67.75 MB/s | **0.000000** |
| **128 x 128** | `uint16` | 32.0 KB | 0.36 ms | 0.32 ms | 87.40 MB/s | 98.40 MB/s | **0.000000** |
| **128 x 128** | `int16` | 32.0 KB | 0.40 ms | 0.34 ms | 79.05 MB/s | 91.66 MB/s | **0.000000** |
| **256 x 256** | `uint8` | 64.0 KB | 0.58 ms | 0.55 ms | 107.59 MB/s | 113.72 MB/s | **0.000000** |
| **256 x 256** | `int16` | 128.0 KB | 0.99 ms | 0.94 ms | 126.08 MB/s | 133.41 MB/s | **0.000000** |
| **256 x 256** | `uint16` | 128.0 KB | 0.99 ms | 0.94 ms | 125.66 MB/s | 133.64 MB/s | **0.000000** |

*Note: In all cases, Mean Squared Error ($\text{MSE} = 0.0$) confirms bit-perfect numerical preservation of radiological pixel data.*

---

## 8. Test Suite & Verification

The MedPQC test framework comprises **363 automated tests** organized across seven testing tiers:

```bash
# Execute the full automated test suite with coverage
python -m pytest tests/ --cov=medpqc --cov-report=term-missing
```

- **NIST ACVP KAT Vectors (`tests/vectors/`)**: Validates ML-KEM-768 key encapsulation against official NIST ACVP known-answer vectors.
- **Fuzz Testing (`tests/fuzz/`)**: Hypothesis-driven stress testing on malformed handshakes, dictionary injections, and corrupt DICOM headers.
- **Adversarial Red-Team Exploits (`tests/adversarial/exploits/`)**: Rigorous verification against reflection attacks, recipient bypass, cross-session splicing, and replay attempts.
- **Property Invariants (`tests/property/`)**: Mathematical checks for bijectivity, reversibility, and lossless data reconstruction.
- **PACS Integration (`tests/integration/`)**: Complete DICOM format matrix testing across transfer syntaxes and multi-frame studies.

---

## 9. Future Work & Roadmap

1. **Hardware-Accelerated Lattice Cryptography**: Implementing AVX-512, ARM Neon, and GPU-accelerated polynomial multiplication for high-throughput batch ML-KEM-768 operations.
2. **Transparent PACS TLS Proxy Gateway**: Developing a lightweight network sidecar proxy capable of transparently intercepting standard DICOM C-STORE, C-FIND, and C-MOVE wire protocols to apply MedPQC encapsulation transparently.
3. **Hardware Security Module (HSM) Integration**: Providing PKCS#11 and KMIP drivers for enterprise hospital Key Management Systems to protect long-term Ed25519 signing keys.
4. **Formal CAVP & FIPS 140-3 Validation**: Preparing test evidence and reference implementations for formal cryptographic laboratory validation.

---

## 10. Limitations

1. **Exploratory Implementation**: MedPQC is an experimental research framework for protocol evaluation. It has not undergone formal security audits by accredited external testing laboratories.
2. **PACS Interoperability**: Validated on file-level DICOM datasets; live network integration requires site-specific PACS configuration and TLS network security.
3. **No Regulatory Approval**: This software is not certified as a medical device or for regulatory compliance.

---

## 11. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
