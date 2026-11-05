# Changelog

All notable changes to the MedPQC project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-11-06

### Core Cryptographic & Protocol Enhancements
- **NIST FIPS 203 ML-KEM-768 Implementation**: Standardized key encapsulation mechanism adhering to NIST FIPS 203 with 1,184-byte encapsulation keys, 1,088-byte ciphertexts, and 32-byte shared secrets with Section 6.2 implicit rejection.
- **Mutual Peer Authentication with TrustStore**: Integrated Ed25519 digital signatures for client and server handshakes with mandatory `TrustStore` identity verification.
- **Context-Bound Directional Key Derivation**: RFC 5869 HKDF-SHA-512 binding initiator and responder identities, nonces, and cipher suites, producing independent directional session keys (`k_send`, `k_recv`).
- **Atomic Replay Protection**: SQLite-backed durable replay detection with millisecond timestamp verification.
- **Unified Authenticated DICOM/PACS Protection**: Envelope-bound AES-256-GCM authenticated encryption with context-bound AAD and keyed HMAC-SHA-256 de-identification / pseudonymization.
- **Comprehensive Quality Assurance**: Full test matrix covering NIST ACVP known-answer vectors, fuzzing, property tests, and adversarial threat mitigation.

---

## [2.4.0] - 2026-11-01

### Security & Protocol Remediation
- **Explicit Role & Recipient Binding (D-01)**:
  Mandated `ResponderContext` and `InitiatorContext` for all handshake operations. Responders strictly reject messages where `receiver_id != ctx.node_id` with `WrongRecipientError`.
- **Atomic Replay & Storage Hardening (D-02)**:
  Replaced non-production in-memory replay stores with atomic SQLite WAL storage using `INSERT ... ON CONFLICT DO NOTHING`.
- **Wire Framing & Timestamp Strictness (D-03)**:
  Rejected floating-point and non-uint64 millisecond timestamps. Implemented strict binary wire framing parsers rejecting trailing unauthenticated bytes.
- **Strict Cryptographic Parameter Bounds (D-04, D-05)**:
  Enforced SECP256R1 uncompressed point validation (`0x04` prefix, exact 65-byte length). Added encrypted PKCS#8 identity export/import with Argon2id / AES-256-GCM.
- **Direction-Bound Traffic Ciphers (D-06)**:
  Structured session completion to return distinct `sender_cipher` and `receiver_cipher` with thread-safe atomic invocation caps (`KeyUsageLimitExceeded`).
- **Domain-Separated HKDF (D-07)**:
  Updated transcript key combiner to use strict RFC 5869 HKDF-SHA-512 with `MedPQC-v2.4` domain tags.
- **Comprehensive AAD Technical Binding (D-08, D-09)**:
  Extended AEAD Associated Authenticated Data to bind `envelope_id`, `dataset_hash`, `transfer_syntax_uid`, image dimensions, dtype, and version. Standardized Private Creator Tag to `"MEDPQC"`.

### DICOM & Privacy Hardening
- **Mandatory Manifest Origin (D-10)**:
  Deleted `ManifestSource.AUTO`. Handlers require explicit selection between `EMBEDDED` and `EXTERNAL` manifests, preventing silent fallback.
- **Strict Error Propagation (D-11)**:
  Eliminated all swallowed exceptions (`except ...: pass`) across DICOM processing pipelines.
- **Pseudonymization Key Hardening (D-12, D-13)**:
  Enforced strict 32-byte requirement on `SitePseudonymizationKey` with no zero-padding. Standardized UID pseudonymization under ITU-T OID arc 2.25. Implemented exact binary dataset restoration via `DicomBytesIO`.
- **Independent Placeholder Noise (D-14)**:
  Generated synthetic placeholder raster data using HMAC-SHA-256 expansion, eliminating reliance on experimental chaotic algorithms for noise generation.

### Provider Verification & Quality Engineering
- **NIST ACVP FIPS 203 Provenance (D-16)**:
  Integrated official NIST ACVP ML-KEM-768 test vectors sourced from commit `15c0f3d` with verified SHA-256 provenance.
- **Type Safety & Static Hygiene (D-17)**:
  Enabled `strict = true` in `mypy` with zero type errors across all 26 source files.
- **Native Mutation Testing (D-19)**:
  Implemented `scripts/run_mutation_tests.py` providing 65% mutation score on cryptographic core.
- **Clean Subprocess Imports (D-20)**:
  Isolated all experimental components into `medpqc.experimental.*`. Verified light-core imports in clean environments lacking optional dependencies.
- **Multi-Arm Empirical Benchmarks (D-22)**:
  Executed multi-arm benchmarking suite recording raw per-repetition CSVs (>=30 reps per cell).
- **Machine-Readable Ledger (D-23, D-24)**:
  Established `AUDIT/ledger.yaml` tracking all 68 register items with validated status vocabulary. Sanitized all audit evidence to strict LF line endings.

---

## [2.3.0] - 2026-11-01

### Security
- **Elimination of `allow_unauthenticated` (F-HS-01)**:
  Removed `allow_unauthenticated` parameter entirely from `AuthenticatedHybridKEM` and `DICOMPACSSession`. Mutual authentication via `TrustStore` or pinned keys is strictly required.
- **Transcript Context Binding & Directional Key Derivation (F-HS-02, F-HS-03)**:
  Rewrote key combiner to follow RFC 5869 HKDF-SHA-512 with context-bound transcripts. Derived separate directional keys (`k_enc_i2r` and `k_enc_r2i`) to prevent reflection and cross-direction replays. Removed redundant outer HMAC (`k_mac`).
- **Atomic Replay Protection (F-HS-04)**:
  Implemented atomic millisecond-precision `consume()` using SQLite `INSERT OR IGNORE` and thread-locked memory stores. Replay attempts raise `ReplayDetectedError`.
- **Single Authenticated Encrypted Object Architecture (F-DICOM-01, F-DICOM-02, ADR-001)**:
  Eliminated dual-source divergence between embedded private tags and sidecar JSON. Cryptographic metadata and pixel data are unified under AEAD with Associated Authenticated Data (AAD) binding `envelope_id`, `dataset_hash`, `transfer_syntax_uid`, and `suite_id`.
- **Site Key Enforcement (F-DICOM-04)**:
  Deleted `DEFAULT_SITE_SALT`. Enforced mandatory 32-byte `SitePseudonymizationKey` with HMAC-SHA-256 domain separation.
- **Operational Resource Caps & Canonical JSON (F-ENV-01, F-ENV-02)**:
  Implemented `medpqc.utils.limits` with strict thresholds: `MAX_PAYLOAD_BYTES=256MB`, `MAX_MANIFEST_BYTES=64KB`, `MAX_IMAGE_DIM=65536`, and `MAX_CIPHERTEXTS_PER_KEY=65536`. Implemented canonical JSON parsing rejecting duplicate keys and non-finite floats.
- **Experimental Component Isolation (F-CORE-02, F-CHAOS-01)**:
  Relocated non-standard RLWE to `medpqc.experimental.toy_rlwe`. Disabled chaotic scrambling by default (`enable_scrambling=False`). Implemented unbiased Fisher-Yates shuffle with rejection sampling.
- **Documentation & Claims Purge (F-DOC-01)**:
  Does not assert production readiness, formal security reductions, or regulatory certifications across documentation and audit records.

---

## [2.2.0] - 2026-11-01

### Added
- Standardized ML-KEM-768 interface with length and round-trip verification.
- Initial replay defense and trust store abstractions.
- Synthetic noise raster in DICOM PixelData.
- Recursive nested sequence DICOM de-identification.

---

## [2.1.0] - 2026-10-31

### Added
- Initial hybrid ECDH P-256 + post-quantum KEM framework.
- Basic AES-256-GCM AEAD encryption pipeline.
- Experimental Lorenz chaotic coordinate sorting and chained diffusion.
- Initial DICOM handling and PACS envelope prototypes.
