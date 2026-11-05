# MedPQC v2.3.0 Security Review and Architecture Audit Report

**Target**: MedPQC Authenticated Hybrid Post-Quantum Medical Image Encryption Framework  
**Release**: v2.3.0 (Research Release)  
**Date**: November 2026  
**Status**: Research Prototype Implementation  

---

## 1. Executive Summary

MedPQC v2.3.0 incorporates corrective source-level remediations addressing findings identified in previous audits (F-HS-01 through F-HS-06, F-CORE-01 through F-CORE-03, F-ENV-01 through F-ENV-03, F-DICOM-01 through F-DICOM-10, F-CHAOS-01 through F-CHAOS-03, F-QA-01 through F-QA-07, and F-DOC-01 through F-DOC-04).

The framework implements:
- Standardized NIST FIPS 203 ML-KEM-768 for post-quantum key encapsulation.
- Ephemeral NIST P-256 ECDH for classical key agreement.
- Ed25519 digital signatures for mutual peer authentication.
- RFC 5869 HKDF-SHA-512 transcript-bound key derivation producing directional session keys (`k_enc_i2r` and `k_enc_r2i`).
- Single Authenticated Encrypted Object architecture with AES-256-GCM AEAD cryptographically binding routing headers and dataset hash into Associated Authenticated Data (AAD).
- Atomic SQLite and memory-backed replay filtering.

> [!NOTE]
> MedPQC is an exploratory research prototype. It has not received formal certification under NIST CAVP, Common Criteria, or HIPAA compliance programs.

---

## 2. Threat Model and Security Defenses

### 2.1 Harvest-Now-Decrypt-Later (HNDL) Threat
- **Adversary Capability**: An adversary intercepts and stores encrypted DICOM transmissions today, anticipating future availability of a cryptanalytically relevant quantum computer (CRQC).
- **MedPQC Defense**: The hybrid key combiner uses HKDF-SHA-512 to combine classical P-256 ECDH with NIST FIPS 203 ML-KEM-768. Even if classical discrete-logarithm keys are compromised in the future, ML-KEM-768 provides post-quantum confidentiality.

### 2.2 Active Network Adversary (Dolev-Yao Model)
- **Adversary Capability**: An active attacker controls the network between PACS nodes and can inject, alter, drop, or replay packets.
- **MedPQC Defense**:
  - Mutual peer identity authentication via Ed25519 digital signatures over canonical initiation and response transcripts.
  - Mandatory node verification in `TrustStore` prevents rogue node impersonation.
  - Sliding-window timestamp checking and atomic SQLite replay filtering prevent session injection and replay attacks.
  - Directional session key separation prevents reflection attacks.

### 2.3 Adaptive Chosen-Ciphertext and Tamper Threats
- **Adversary Capability**: The adversary queries decapsulation and decryption endpoints with mutated or chosen ciphertexts.
- **MedPQC Defense**:
  - ML-KEM-768 implements the Fujisaki-Okamoto transformation with implicit rejection.
  - AES-256-GCM authenticated encryption enforces a 128-bit authentication tag. Any modification of ciphertext or AAD headers causes immediate authentication failure before any memory allocation.

### 2.4 DICOM Header Manipulation and Routing Tampering
- **Adversary Capability**: An attacker modifies DICOM routing tags to misroute studies or alter clinical interpretation.
- **MedPQC Defense**: Non-sensitive retained routing headers, the dataset hash, envelope ID, and transfer syntax UID are bound into the AES-256-GCM Associated Authenticated Data (AAD). Any modification of retained headers causes authentication failure during decryption.

---

## 3. Cryptographic Primitives Assessment

| Primitive | Standard | Parameter Set | Role | Implementation Status |
| :--- | :--- | :--- | :--- | :--- |
| **Post-Quantum KEM** | NIST FIPS 203 | ML-KEM-768 | Key Encapsulation | Standardized reference provider |
| **Classical KEM** | NIST SP 800-56A | P-256 (secp256r1) | Classical Ephemeral Key Agreement | `cryptography.hazmat` OpenSSL |
| **Identity Signatures** | RFC 8032 | Ed25519 | Mutual Authentication | `cryptography.hazmat` OpenSSL |
| **Key Derivation** | RFC 5869 | HKDF-SHA-512 | Transcript-Bound KDF | Standard library implementation |
| **Authenticated Cipher** | NIST SP 800-38D | AES-256-GCM | Authenticated Encryption | `cryptography.hazmat` OpenSSL |
| **Replay Defense** | Custom / Atomic SQL | Sliding Window + SQLite | Replay Filtering | Implemented (`medpqc.security.replay`) |
| **Spatial Scrambling** | Heuristic | Chaotic Sorting / Fisher-Yates | Image Pre-transformation | Experimental only; disabled by default |

---

## 4. Healthcare Imaging and De-Identification Alignment

### 4.1 De-Identification Objectives
- Sensitive patient identifiers (PatientName, PatientID, BirthDate, Address, ReferringPhysician, etc.) are extracted recursively across top-level and nested sequences (`VR == 'SQ'`) and encrypted inside the AEAD container.
- Keyed pseudonymization is performed using a site-specific 32-byte `SitePseudonymizationKey` with HMAC-SHA-256 domain separation.
- `ds.PixelData` contains a deterministic synthetic noise raster matching original byte lengths and dimensions, allowing standard PACS viewing workstations to parse files without crashing.

### 4.2 Regulatory Clarification
- While designed to align with the technical objectives of health data privacy rules, this software is **not formally certified for HIPAA compliance** or recognized by any regulatory body as a medical device.

---

## 5. Residual Risks and Operational Requirements

1. **Identity Key Management**: Ed25519 private keys must be stored in secure hardware or protected key stores with restricted filesystem access (`0600`).
2. **Site Pseudonymization Key Security**: Each clinical institution must generate and protect a secret, 32-byte `SitePseudonymizationKey`. Never share site keys across unrelated institutions.
3. **Database Maintenance**: When using `SqliteReplayStore`, ensure the database file resides on a high-availability persistent volume with periodic maintenance.
4. **PACS Archive Configuration**: PACS archives must be configured to retain Private Group `0x0029` elements to allow decryption from the self-contained DICOM container.
