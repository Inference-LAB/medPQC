# MedPQC Threat Model for Clinical PACS Networks

**Target Release**: MedPQC v2.2.0  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab (INFERENCE Lab)  
**Date**: November 2026  

---

## 1. Protected Clinical Assets

| Asset | Sensitivity | Impact of Compromise | MedPQC Protection Mechanism |
| :--- | :--- | :--- | :--- |
| **Diagnostic Pixel Data** | High (Confidentiality & Diagnostic Integrity) | Medical misdiagnosis, privacy violation, clinical data breach | Lossless AES-256-GCM encryption; chaotic spatial scrambling and CCD |
| **Patient Demographics (PHI)** | Critical (Confidentiality & Compliance) | Identity theft, privacy regulation penalties, targeted patient tracking | Recursive PS 3.15 Annex E scrubbing, keyed-salted pseudonymization, AEAD container |
| **DICOM Routing Headers** | High (Routing & Archive Integrity) | PACS misfiling, study mix-up, buffer overflow on client rendering | Retained non-PHI headers bound to AES-256-GCM AAD |
| **Ephemeral Session Keys** | Critical (Key Isolation) | Decryption of clinical imaging studies | Hybrid ML-KEM-768 + P-256 HKDF derivation |
| **Long-Term Node Identity Keys** | Critical (Authentication) | Node impersonation, rogue archive injection | Stored in TrustStore; hardware security module (HSM) deployment recommended |

---

## 2. Threat Actors & Capabilities

### 2.1 Nation-State / Advanced Persistent Threat (Quantum Adversary)
- **Objective**: Intercept vast volumes of encrypted medical diagnostic data from healthcare networks and store it until cryptanalytically relevant quantum computers (CRQC) can execute Shor's algorithm.
- **MedPQC Defense**: NIST FIPS 203 ML-KEM-768 lattice-based key encapsulation resists quantum polynomial-time attacks.

### 2.2 Active Network Attacker (Man-in-the-Middle)
- **Objective**: Intercept DICOM C-STORE and C-MOVE network transmissions, inject modified diagnostic scans, or alter patient routing tags to redirect studies.
- **MedPQC Defense**:
  - Mutual peer authentication via Ed25519 digital signatures.
  - Strict mandatory TrustStore verification (`SEC-01`).
  - Associated Authenticated Data (AAD) protection over all retained routing headers.

### 2.3 Replay / Packet Injection Attacker
- **Objective**: Capture and re-transmit previously executed session initiation messages to cause resource exhaustion or study duplication in PACS archives.
- **MedPQC Defense**:
  - Sliding-window timestamp checking (maximum variance 300 seconds).
  - Thread-safe, persistent SQLite replay filtering (`SqliteReplayStore`, `SEC-02`).

### 2.4 Untrusted Viewer / Eavesdropping PACS Client
- **Objective**: Access unauthorized clinical images stored in hospital PACS archives.
- **MedPQC Defense**: Standard DICOM `PixelData` displays deterministic synthetic visual noise. True pixel data can only be recovered by decrypting the private container tag with the valid session key.

---

## 3. Threat Matrix & Countermeasure Mapping

| Attack Vector | Vulnerability Pre-v2.2 | MedPQC v2.2 Countermeasure | Validation Test |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Handshake Injection** | Default handshake allowed key derivation without trust verification (`SEC-01`) | Mandatory TrustStore verification by default; raises `PermissionError` | `test_unauthenticated_handshake_rejected_by_default` |
| **Multi-Worker Server Replay Attack** | In-memory cache reset across process restarts or worker nodes (`SEC-02`) | Persistent transactional `SqliteReplayStore` with indexed pruning | `test_sqlite_replay_attacks_across_distinct_instances` |
| **Ciphertext Truncation Loss** | Ciphertext truncated to fit raw pixel array length (`SEC-03`) | Untruncated container in Private Tag `(0x0029, 0x1010)`; noise in PixelData | `test_untruncated_dicom_ciphertext_and_synthetic_pixeldata` |
| **Nested Sequence PHI Leakage** | Top-level scrubbing skipped nested DICOM sequence elements (`SEC-04`) | Recursive sequence traversal and restoration | `test_nested_sequence_phi_deidentification_and_restoration` |
| **Rainbow Table Patient ID Inversion** | Static default site salt permitted cross-site correlation (`SEC-05`) | Mandatory dynamic `site_salt` validation (>= 16 bytes) | `test_dicom_site_salt_security_and_aliases` |
| **Routing Header Manipulation** | Unauthenticated DICOM tags could be altered in transit | Cryptographic AAD binding to AES-256-GCM | `test_cipher_retained_headers_roundtrip_and_tamper` |
| **Ciphertext Bit-Flipping** | Tampering with encrypted pixels | AES-256-GCM GHASH tag + outer HMAC-SHA3-256 | `test_aead_tamper_detection_ciphertext` |

---

## 4. Trust Boundaries and Assumptions

1. **Local Node Integrity**: The local workstation running MedPQC has not suffered complete kernel-level compromise or memory dumping by root adversaries.
2. **Key Storage Protection**: Ed25519 private keys are stored with appropriate filesystem access permissions (`chmod 600`) or inside hardware security modules.
3. **Site Salt Secrecy**: The hospital-wide `site_salt` used for keyed patient pseudonymization is treated as a high-security institutional secret.
