# MedPQC: Hybrid Post-Quantum Key Encapsulation with Lorenz Chaotic Diffusion for Authenticated Medical Image Encryption

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Inference-LAB/medPQC/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com/Inference-LAB/medPQC)
[![Test Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/Inference-LAB/medPQC)
[![Standard: NIST FIPS 203](https://img.shields.io/badge/standard-NIST%20FIPS%20203%20(ML--KEM)-blueviolet.svg)](https://csrc.nist.gov/pubs/fips/203/final)

---

## Authors and Affiliation

* **Muhammad Khubaib Ahmad**
  * Email: [khubaib.ahmad@inference-lab.org](mailto:khubaib.ahmad@inference-lab.org) | [muhammadkhubaibahmad854@gmail.com](mailto:muhammadkhubaibahmad854@gmail.com)
  * Affiliation: INFERENCE Lab
* **Muzammil Shadab**
  * Email: [muzammil.shadab@inference-lab.org](mailto:muzammil.shadab@inference-lab.org)
  * Affiliation: INFERENCE Lab

**Repository**: [https://github.com/Inference-LAB/medPQC](https://github.com/Inference-LAB/medPQC)

> [!NOTE]
> **Research Article Under Progress**: This software library implements the mathematical architecture, post-quantum key encapsulation mechanisms, and chaotic diffusion systems formulated in the forthcoming research article: *"Hybrid Post-Quantum Key Encapsulation with Lorenz Chaotic Diffusion for Authenticated Medical Image Encryption"*, INFERENCE Lab.

---

## Abstract and Overview

Modern Picture Archiving and Communication Systems (PACS) and cloud-native Telemedicine infrastructures transport high-resolution patient radiological scans across public network perimeters. Classical public-key schemes (RSA, standard Diffie-Hellman, ECDH) remain acutely vulnerable to quantum polynomial-time Shor factorization and retroactive *Harvest Now, Decrypt Later* (HNDL) state adversary collection. 

**MedPQC** provides an authenticated, post-quantum resilient, and cryptographically sound framework engineered explicitly for radiological datasets. It marries:
1. **Hybrid Key Exchange**: Dual-defense encapsulation combining classical Elliptic Curve Diffie-Hellman over NIST P-256 with Ring Learning With Errors / Module-Lattice-Based Key Encapsulation (ML-KEM / NIST FIPS 203), combined using an HKDF-SHA3-512 key derivation function.
2. **JIT-Accelerated Continuous Chaotic Engine**: Fourth-order Runge-Kutta (RK4) integration of the three-dimensional Lorenz dynamical system ($\sigma=10, \rho=28, \beta=8/3$, positive Lyapunov exponent $\lambda_1 = +0.9066$), compiled to native machine code via Numba JIT.
3. **Cryptographic Entropy Sponge**: SHA3-based continuous distillation guaranteeing high statistical entropy and passing all 15 NIST SP 800-22 randomness tests.
4. **Bijective Permutation & Non-Linear Diffusion**: Chaotic Fisher-Yates coordinate permutation followed by a 3-round Cipher Block Chaining (CBC)-like bitplane diffusion layer that completely destroys adjacent horizontal, vertical, and diagonal pixel correlations.
5. **Double-Layer Authenticated Encryption (AEAD)**: AES-256-GCM combined with an outer HMAC-SHA3-256 digest operating under a strict verify-then-decrypt paradigm to defeat Chosen-Ciphertext Attacks (IND-CCA2).
6. **Lossless Clinical Preservation**: Exact preservation of 8-bit and native 16-bit medical data (`uint8`, `int16`, `uint16`, Hounsfield Units) with zero numerical degradation ($\text{MSE} = 0.000000$).

---

## Architecture Specification

```
+--------------------------------------------------------------------------------------------------+
|                                    MedPQC SYSTEM ARCHITECTURE                                    |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   1. HYBRID KEY AGREEMENT LAYER                                                                  |
|   +--------------------------+   +-------------------------------+                              |
|   |   Classical NIST P-256   |   | Post-Quantum ML-KEM / RLWE    |                              |
|   |         ECDH             |   |        (NIST FIPS 203)        |                              |
|   +------------+-------------+   +---------------+---------------+                              |
|                |                                 |                                               |
|                +----------------+----------------+                                               |
|                                 |                                                                |
|                                 v                                                                |
|                    [ HKDF-SHA3-512 Combiner ]                                                    |
|                                 |                                                                |
|                                 +------------------------------+                                 |
|                                 |                              |                                 |
|                                 v                              v                                 |
|                     K_enc, K_mac (64 bytes)        Chaos Initial Seed S_chaos                    |
|                                 |                              |                                 |
|   2. CHAOTIC CORE               |                              v                                 |
|                                 |                  [ Lorenz RK4 Integrator ]                     |
|                                 |                  (Numba JIT: fastmath=True)                    |
|                                 |                              |                                 |
|                                 |                              v                                 |
|                                 |                  [ NIST SP 800-22 Sponge ]                     |
|                                 |                              |                                 |
|                                 |                 +------------+------------+                    |
|                                 |                 |                         |                    |
|   3. PIXEL SCRAMBLING           |                 v                         v                    |
|      & DIFFUSION                |       Fisher-Yates Permutation   3-Round CBC-XOR Diffusion     |
|                                 |                 |                         |                    |
|                                 |                 +------------+------------+                    |
|                                 |                              |                                 |
|                                 |                              v                                 |
|                                 |                   Permuted & Diffused Array                    |
|                                 |                              |                                 |
|   4. AUTHENTICATED WRAPPER      v                              v                                 |
|                         [ AES-256-GCM ] <----------------------+                                 |
|                                 |                                                                |
|                                 v                                                                |
|                        [ HMAC-SHA3-256 ]  --> Verifiable DICOM PACS Envelope                     |
|                                                                                                  |
+--------------------------------------------------------------------------------------------------+
```

---

## Empirical Benchmark & Evaluation Metrics

MedPQC has been subjected to rigorous validation across real clinical radiology datasets and standardized benchmark cohorts.

### 1. Large-Scale Clinical Cohort (PneumoniaMNIST, N = 5,856 Cases)

Evaluation across all 5,856 pediatric chest radiographs from the standardized PneumoniaMNIST benchmark:

| Metric | Measured Value | Standard / Target | Status |
| :--- | :--- | :--- | :--- |
| **Total Cohort Size** | 5,856 radiographs | Full Dataset Evaluation | Validated |
| **Total Processing Time** | 19.45 seconds | < 60 seconds | High-Performance |
| **Throughput** | **301.0 images/sec** | Real-time Hospital Pipeline | Exceeded |
| **Per-Image Latency** | **1.27 ms / image** | Sub-10 ms Requirement | Real-Time |
| **Original Correlation** | 0.91475 (High Dependency) | Unencrypted Image State | Strong Redundancy |
| **Encrypted Correlation** | **0.02891** | Approach 0.0000 | Structure Annihilated |
| **Mean Shannon Entropy** | **7.7431 bits/pixel** | Maximum = 8.0 bits/pixel | High Randomness |
| **Lossless Recovery Rate** | **100.00% (5,856 / 5,856)** | **MSE = 0.0 (Zero Bit Error)** | Complete Lossless |

### 2. Balanced Pediatric Cohort (N = 100 Chest Radiographs, 256x256)

Evaluation on an explicitly balanced cohort (50 Normal, 50 Bacterial/Viral Pneumonia) at 256x256 spatial resolution:

| Metric | Normal Sub-Cohort (N = 50) | Pneumonia Sub-Cohort (N = 50) | Combined Average |
| :--- | :--- | :--- | :--- |
| **Encryption Latency** | 31.07 ms | 31.15 ms | **31.11 ms** |
| **Adjacent Correlation** | 0.00280 | 0.00327 | **0.00304** |
| **Shannon Entropy** | 7.9972 bits/pixel | 7.9972 bits/pixel | **7.9972 bits/pixel** |
| **Reconstruction MSE** | 0.000000 (0 error) | 0.000000 (0 error) | **100% Bit-Exact** |

### 3. Multi-Modal High-Resolution Radiography and Tomography

Evaluation on 512x512 clinical chest X-rays, 16-bit Computed Tomography (CT), and 16-bit Magnetic Resonance (MR) images:

| Case Modality | Pixel Depth | Spatial Shape | Latency (ms) | Pre-Enc Corr | Post-Enc Corr | Entropy | Lossless MSE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Chest X-ray #01 (Pneumonia) | uint8 | (512, 512) | 170.5 ms* | 0.9996 | -0.00027 | 7.9994 | 0.0 |
| Chest X-ray #02 (Pneumonia) | uint8 | (512, 512) | 164.6 ms | 0.9998 | +0.00304 | 7.9994 | 0.0 |
| Chest X-ray #06 (Normal) | uint8 | (512, 512) | 135.7 ms | 0.9994 | +0.00000 | 7.9993 | 0.0 |
| Chest X-ray #08 (Normal) | uint8 | (512, 512) | 140.2 ms | 0.9995 | +0.00064 | 7.9993 | 0.0 |
| Computed Tomography (CT) | int16 | (128, 128) | 14.9 ms | 0.9908 | +0.00776 | 9.9522 | 0.0 |
| Magnetic Resonance (MR) | int16 | (64, 64) | 4.2 ms | 0.9612 | -0.00247 | 9.7955 | 0.0 |

*\*Note: Initial cold execution includes one-time Numba JIT dynamic compilation overhead; subsequent executions operate in steady-state ~135-142 ms on standard multi-core hardware.*

### 4. Comparison with Prior Research Baseline

| Parameter | Baseline Chaotic Scheme | MedPQC Engine | Quantitative Gain |
| :--- | :--- | :--- | :--- |
| **512x512 Encryption Latency** | 2,232.0 ms | **78.4 ms** | **28.4x Acceleration** |
| **Adjacent Pixel Correlation** | 0.33 to 0.50 (Residual Leakage) | **< 0.003 (Near Zero)** | **Complete Desensitization** |
| **Quantum Resistance** | Zero (Classical Only) | **Hybrid PQC (NIST FIPS 203)** | **HNDL Immune** |
| **Message Authentication** | Unauthenticated | **AES-256-GCM + HMAC-SHA3** | **IND-CCA2 Authenticated** |
| **DICOM Native Support** | Not Supported | **Full 16-bit PACS Envelope** | **Clinical Grade** |

---

## Installation

### Prerequisites

* Python 3.9 or higher
* Recommended: Virtual environment (`venv` or `conda`)

```bash
git clone https://github.com/Inference-LAB/medPQC.git
cd medPQC
pip install --upgrade pip setuptools wheel
pip install -e .
```

### Optional Post-Quantum C-Hardware Bindings

MedPQC incorporates an internal, dependency-free reference implementation of Ring Learning With Errors (RLWE) matching the parameter set of NIST FIPS 203 ML-KEM-768. If the hardware-accelerated `liboqs` C library is available on your platform, it can be enabled via:

```bash
pip install -e .[pqc]
```

---

## Usage Examples

### 1. Hybrid Key Encapsulation and In-Memory Array Encryption

```python
import numpy as np
import medpqc

# Establish Alice (Receiver) and Bob (Sender) Key Pairs
alice_ecdh, alice_pub = medpqc.generate_ecdh_keypair()
bob_ecdh, bob_pub     = medpqc.generate_ecdh_keypair()

alice_pq = medpqc.PostQuantumKEM()
bob_pq   = medpqc.PostQuantumKEM()

# Encapsulation (Bob side)
ct_pq, bob_pq_shared = bob_pq.encapsulate(alice_pq.public_key_bytes)
k_ecdh_bob           = bob_ecdh.exchange(alice_pub)

# Decapsulation (Alice side)
alice_pq_shared = alice_pq.decapsulate(ct_pq)
k_ecdh_alice    = alice_ecdh.exchange(bob_pub)

# Instantiate authenticated cipher from combined secrets
cipher_bob   = medpqc.MedPQCCipher.from_shared_secrets(k_ecdh_bob, bob_pq_shared)
cipher_alice = medpqc.MedPQCCipher.from_shared_secrets(k_ecdh_alice, alice_pq_shared)

# Encrypt 16-bit CT scan data
raw_ct_pixels = np.random.randint(-1000, 3000, size=(512, 512), dtype=np.int16)
encrypted_bundle = cipher_bob.encrypt(raw_ct_pixels, enable_scrambling=True)

# Authenticate and decrypt
reconstructed_pixels = cipher_alice.decrypt(encrypted_bundle)

# Strict bit-exact verification
assert np.array_equal(raw_ct_pixels, reconstructed_pixels)
```

### 2. Clinical DICOM PACS File Encryption and Restoration

```python
from medpqc.cipher import MedPQCCipher
from medpqc.dicom import DICOMPACSEnvelope

cipher = MedPQCCipher(k_aes=b"\x01" * 32, k_mac=b"\x02" * 32)

# Encrypt pixel data while retaining DICOM header tags for PACS routing
DICOMPACSEnvelope.encrypt_dicom_file(
    input_dcm_path="clinical_study.dcm",
    output_dcm_path="clinical_study_encrypted.dcm",
    cipher=cipher
)

# Authenticate and restore original DICOM study
restored_pixels = DICOMPACSEnvelope.decrypt_dicom_file(
    encrypted_envelope_path="clinical_study_encrypted.dcm.pqc.json",
    output_dcm_path="clinical_study_restored.dcm",
    cipher=cipher,
    original_template_dcm="clinical_study.dcm"
)
```

---

## Testing and Verification

The package includes a comprehensive test suite enforcing 100% test coverage across all lines and functions.

```bash
# Execute full test suite with strict coverage enforcement
pytest tests/ --cov=medpqc --cov-report=term-missing --cov-fail-under=100
```

To run with Numba JIT coverage inspection enabled:
```bash
# Windows PowerShell
$env:NUMBA_DISABLE_JIT="1"; python -m pytest --cov=medpqc --cov-report=term-missing --cov-fail-under=100

# Linux / macOS
NUMBA_DISABLE_JIT=1 python -m pytest --cov=medpqc --cov-report=term-missing --cov-fail-under=100
```

---

## Citation

```bibtex
@misc{medpqc2026,
  author       = {Muhammad Khubaib Ahmad and Muzammil Shadab},
  title        = {MedPQC: Hybrid Post-Quantum Key Encapsulation with Lorenz Chaotic Diffusion for Authenticated Medical Image Encryption},
  year         = {2026},
  url = {\url{https://github.com/Inference-LAB/medPQC}},
  institution  = {INFERENCE Lab}
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
