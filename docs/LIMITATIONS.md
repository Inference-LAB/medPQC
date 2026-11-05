# MedPQC Operational Boundaries and Limitations (v2.4.0)

**Status**: Research Prototype Implementation  
**Date**: November 2026  

---

## 1. Cryptographic Scope and Post-Quantum Boundaries

### 1.1 Hybrid Key Establishment
- **ML-KEM-768**: Provides lattice-based post-quantum key encapsulation (NIST FIPS 203) against quantum adversaries executing Shor's algorithm. Note that MedPQC is an exploratory research implementation and does not claim a formal security reduction proof.
- **Classical P-256 ECDH**: Combined with ML-KEM-768 via HKDF-SHA-512 to provide dual security against unknown lattice attacks while retaining classical security under ephemeral per-session key agreement with the explicit limitation that no unproven forward secrecy is formally claimed.
- **Ed25519 Identity Signatures**: Digital signatures used for peer authentication rely on classical elliptic-curve discrete logarithms (Ed25519 / Curve25519). In a future operating environment where real-time active quantum attacks are realized, digital signatures must be transitioned to post-quantum signature standards such as NIST FIPS 204 (ML-DSA) or NIST FIPS 205 (SLH-DSA).

### 1.2 Demarcation of Experimental Image Heuristics
- The Lorenz continuous dynamical attractor and chaotic permuters (coordinate sorting and Fisher-Yates shuffle) are **image-domain pre-transformations** designed to break spatial adjacent-pixel correlation.
- **They are not cryptographic primitives and are not relied upon for computational security.** Core confidentiality is provided by standard AES-256-GCM.
- Chaotic scrambling is disabled by default in standard workflows (`enable_scrambling=False`) and isolated under `medpqc.experimental.*`.

---

## 2. PACS and DICOM Deployment Boundaries

### 2.1 Private Tag Preservation
- MedPQC embeds the complete untruncated cryptographic manifest into Private DICOM Tag `(0x0029, 0x1010)` with Private Creator `(0x0029, 0x0010) = "MEDPQC"`.
- PACS routers, gateways, or clinical image scrubbers configured to aggressively strip unrecognized private tags will discard the cryptographic manifest, rendering the file un-decryptable from the DICOM container alone.
- **Remedy**: Healthcare network administrators must configure PACS archive rules to retain Private Group `0x0029` elements. Additionally, MedPQC outputs a companion `.pqc.json` manifest file alongside every encrypted `.dcm` file for redundant archival.
- PACS Interoperability: NOT VERIFIED against live commercial PACS servers.

### 2.2 Transfer Syntax Support
- MedPQC natively processes uncompressed DICOM transfer syntaxes (`ExplicitVRLittleEndian`, `ImplicitVRLittleEndian`, `DeflatedExplicitVRLittleEndian`).
- Lossy compressed transfer syntaxes (e.g., JPEG Baseline, JPEG 2000, JPEG-LS) must be decompressed prior to ingestion or handled through dedicated codec pipelines.

---

## 3. Operational & Network Requirements

### 3.1 Network Clock Synchronization
- `ReplayProtector` enforces a sliding-window freshness check (default window: 300 seconds).
- All PACS modalities, imaging workstations, and archive servers participating in MedPQC authenticated handshakes must maintain synchronized system clocks using Network Time Protocol (NTP). Clock drift exceeding 300 seconds will trigger `StaleSessionError`.

### 3.2 Site Pseudonymization Key Management
- Keyed pseudonymization of patient identifiers relies on a secret, site-specific key (`SitePseudonymizationKey`, minimum 32 bytes).
- If an institution fails to securely maintain and back up its site key, pseudonymized records cannot be deterministically correlated with institutional master patient indices (MPI) across hospital encounters.

---

## 4. Hardware, Testing, and Compliance Boundaries

- Pure AES-256-GCM encryption utilizes hardware AES-NI instructions, achieving high throughput (~600-900 MB/s).
- Software-based chaotic scrambling incurs $O(N \log N)$ complexity, making it unsuitable for real-time high-throughput hospital ingress. It is therefore isolated for academic research only.
- The framework is not certified for clinical HIPAA compliance, has no HIPAA compliance claim, and has not been tested in live patient PACS clinical workflows.
- FIPS 140/CAVP validation: none.
- External security audit: not externally audited.
