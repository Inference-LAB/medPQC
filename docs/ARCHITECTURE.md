# MedPQC Framework Architectural Specification

**Target Release**: MedPQC v2.2.0  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab  
**Affiliation**: INFERENCE Lab  
**Date**: November 2026  

---

## 1. System Overview

MedPQC is a modular cryptographic library designed specifically for the protection of clinical medical images and PACS (Picture Archiving and Communication Systems) networks against both classical and quantum computing adversaries.

The framework provides an end-to-end security architecture combining standards-conformant post-quantum key encapsulation (NIST FIPS 203 ML-KEM-768), classical ephemeral key agreement (NIST P-256 ECDH), mutual peer authentication (Ed25519 digital signatures), persistent replay protection (SQLite-backed sliding-window filtering), authenticated symmetric encryption (AES-256-GCM with strict AAD binding), and full DICOM PS 3.15 Annex E patient privacy protection.

```
+-------------------------------------------------------------------------+
|                         Clinical Client / Modality                      |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                             medpqc.kem                                  |
|  - Ephemeral ECDH P-256                                                 |
|  - NIST FIPS 203 ML-KEM-768                                             |
|  - Ed25519 Identity Signatures                                          |
|  - HKDF-SHA3-512 Dual-Transcript Combiner                               |
+-------------------------------------------------------------------------+
         |                                                       |
         v                                                       v
+-----------------------------+             +-----------------------------+
|       medpqc.security       |             |        medpqc.utils         |
|  - TrustStore (Peer PKI)    |             |  - Canonical JSON Framing   |
|  - ReplayProtector          |             |  - Input Bounds Validation  |
|  - MemoryReplayStore        |             |  - Metadata Integrity       |
|  - SqliteReplayStore (ACID) |             +-----------------------------+
+-----------------------------+
         |
         v
+-------------------------------------------------------------------------+
|                            medpqc.chaos                                 |
|  - Lorenz Dynamical Attractor (RK4)                                     |
|  - Chaotic Entropy Sponge (SHA3-256 Keystream)                          |
|  - Spatial Permuter (Sorting & Unbiased Fisher-Yates Shuffle)           |
+-------------------------------------------------------------------------+
         |
         v
+-------------------------------------------------------------------------+
|                            medpqc.cipher                                |
|  - 3-Round Chained Chaotic Diffusion (CCD)                              |
|  - AES-256-GCM Authenticated Encryption (NIST SP 800-38D)               |
|  - Strict Associated Authenticated Data (AAD) Header Protection         |
+-------------------------------------------------------------------------+
         |
         v
+-------------------------------------------------------------------------+
|                             medpqc.dicom                                |
|  - MedicalImageIO (8-bit, 16-bit, multi-channel loaders)                |
|  - Recursive Sequence PHI De-identification (DICOM PS 3.15 Annex E)     |
|  - Keyed Salted Pseudonymization (HMAC-SHA256)                          |
|  - Self-Contained Encrypted DICOM Container (Private Tag 0029,1010)     |
|  - Deterministic Synthetic Noise Raster in standard PixelData           |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                       PACS Archive / VNA Storage                        |
+-------------------------------------------------------------------------+
```

---

## 2. Layered Subsystems

### 2.1 Key Establishment Subsystem (`medpqc.kem`)
- **Classical Key Agreement (`medpqc.kem.ecdh`)**:
  Generates ephemeral P-256 keypairs (`SECP256R1`) using OpenSSL via `cryptography.hazmat`. Derives classical shared secret $K_{\text{ecdh}} \in \{0,1\}^{32}$.
- **Post-Quantum KEM (`medpqc.kem.rlwe`)**:
  Wraps NIST FIPS 203 ML-KEM-768. Produces encapsulation key (1184 bytes), decapsulation key (2400 bytes), ciphertext (1088 bytes), and shared secret $K_{\text{pq}} \in \{0,1\}^{32}$.
- **Key Combiner (`medpqc.kem.combiner`)**:
  Applies HKDF-SHA3-512 in extract-and-expand mode over $K_{\text{ecdh}} \parallel K_{\text{pq}}$ bound to the dual-transcript hash and session context. Expands to 96 bytes:
  $$\text{OKM} = K_{\text{aes}} (32\text{B}) \parallel K_{\text{mac}} (32\text{B}) \parallel S_{\text{chaos}} (32\text{B})$$
- **Peer Authentication (`medpqc.kem.auth`)**:
  Integrates long-term Ed25519 identity keypairs. Both initiator and responder sign length-prefixed canonical transcripts, ensuring non-repudiation and MITM immunity.

### 2.2 Security & Trust Subsystem (`medpqc.security`)
- **TrustStore (`medpqc.security.trust`)**:
  Maintains the authorized public key registry of hospital workstations and PACS archives. Supports in-memory lookups, dynamic node revocation, and file-based persistence.
- **Replay Protection (`medpqc.security.replay`)**:
  Implements a dual-layer replay filter. Provides `MemoryReplayStore` for high-throughput single-process deployments and `SqliteReplayStore` for multi-worker PACS servers requiring ACID persistence across restarts.

### 2.3 Image Pre-transformation Subsystem (`medpqc.chaos`)
- **Lorenz Chaos Engine (`medpqc.chaos.lorenz`)**:
  Simulates the 3D Lorenz continuous dynamical system using 4th-order Runge-Kutta (RK4) integration with step size $\Delta t = 0.001$.
- **Chaotic Entropy Sponge (`medpqc.chaos.sponge`)**:
  Hashes continuous trajectory states into 256-bit entropy blocks to generate pseudo-random uint8 byte streams.
- **Permutation (`medpqc.chaos.permutation`)**:
  Provides two reversible spatial permuters:
  1. Keystream coordinate sorting permutation.
  2. Unbiased chaotic Fisher-Yates shuffle.

### 2.4 Symmetric AEAD Subsystem (`medpqc.cipher`)
- **Chained Chaotic Diffusion (`medpqc.cipher.diffusion`)**:
  Executes bitplane XOR diffusion and 3 rounds of chained CBC-style mixing to disperse pixel correlations across the raster.
- **Authenticated Cipher (`medpqc.cipher.aead`)**:
  Implements AES-256-GCM with a 96-bit random nonce and 128-bit authentication tag, reinforced with an outer HMAC-SHA3-256 tag.
- **Unified Engine (`medpqc.cipher.engine`)**:
  Orchestrates encryption and decryption, enforces bounds and metadata validation, and binds critical headers to AAD.

### 2.5 DICOM & PACS Subsystem (`medpqc.dicom`)
- **MedicalImageIO (`medpqc.dicom.handler`)**:
  Standardized I/O interface supporting clinical DICOM datasets, 16-bit CT/MR images, and standard 8-bit/RGB PNG files.
- **DICOMPACSEnvelope (`medpqc.dicom.pacs`)**:
  Generates self-contained DICOM containers. Recursively de-identifies PHI per DICOM PS 3.15 Annex E, embeds complete untruncated ciphertexts in Private Tag `(0x0029, 0x1010)`, and writes synthetic noise rasters into `PixelData`.
- **DICOMPACSSession (`medpqc.dicom.pacs`)**:
  Unified high-level API binding client initiation, archive study encryption, and client study decryption into a 3-step workflow.

---

## 3. Cryptographic Separation of Concerns

MedPQC establishes a strict architectural boundary between standardized cryptography and image-domain heuristics:

| Layer | Component | Cryptographic Guarantee | Standards / Verification |
| :--- | :--- | :--- | :--- |
| **Confidentiality** | AES-256-GCM | Authenticated encryption (AEAD) | NIST SP 800-38D |
| **Authenticity** | GCM Tag + Ed25519 | Digital signature verification (EUF-CMA) | RFC 8032 |
| **Post-Quantum KEM** | ML-KEM-768 | Lattice-based key encapsulation | NIST FIPS 203 |
| **Classical KEM** | P-256 ECDH | Computational Diffie-Hellman (CDH) | NIST SP 800-56A |
| **Spatial Scrambling** | Lorenz / Fisher-Yates | Image correlation breakdown (heuristic) | Lossless Inversion (MSE = 0.0) |

The chaotic pre-transformations provide experimental entropy dispersion in the spatial pixel domain, while cryptographic confidentiality is provided by standard AES-256-GCM.
