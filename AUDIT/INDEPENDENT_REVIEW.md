# MedPQC v2.4.0 Independent Security Review & Red-Team Assessment

**Date**: November 2026  
**Auditor**: Independent Adversarial Cryptographic Security Review  
**Subject**: MedPQC v2.4.0 Research Implementation  
**Status Ceiling**: `RESEARCH RELEASE: SECURITY REVIEW INCOMPLETE`  

---

## 1. Executive Summary

This independent security review evaluated the MedPQC v2.4.0 source tree against the 25 findings (D-01 through D-25) identified in the prior audit, followed by an adversarial red-team assessment across 9 attack vectors implemented as automated regression tests.

All 25 defects from the v2.3.0 baseline have been remediated and substantiated through regression tests in `tests/adversarial/exploits/`. The red-team evaluation verified that key agreement, replay protection, DICOM privacy boundaries, wire deserialization, and cipher suites fail closed under active attack.

However, because MedPQC is an exploratory research framework that has not been submitted to an accredited NIST Cryptographic Algorithm Validation Program (CAVP) testing laboratory, has not been audited by an accredited commercial cybersecurity firm, and has not been evaluated against physical, clinical PACS hardware, the overall package status is strictly designated:
**`RESEARCH RELEASE: SECURITY REVIEW INCOMPLETE`**.

---

## 2. Red-Team Findings and Probe Outcomes

### 2.1 Identity String & Framing Attacks
- **Probe**: Cyrillic confusable homoglyphs (`\u043e`), NUL byte truncations (`alice\x00extra`), and delimiter injections (`:`, `/`) in node identifiers.
- **Result**: `TrustStore` enforces exact codepoint matching. Mismatched or confusable node identifiers fail authentication with `PermissionError` (`UNTRUSTED_PEER`). Length-prefixed serialization in transcripts prevents field-boundary shifting attacks.
- **Test Reference**: `tests/adversarial/exploits/redteam_identity.py` (3 tests passed).

### 2.2 Cross-Session Splice & Key ID Substitution
- **Probe**: Transplanting encrypted private payload tags from Study A (Session X) into Study B (Session Y) encrypted under the same site key; bit-flipping `session_key_id`.
- **Result**: Decryption of spliced manifests fails closed due to AEAD tag verification failure and Associated Authenticated Data (AAD) mismatch binding `envelope_id`.
- **Test Reference**: `tests/adversarial/exploits/redteam_session_splice.py` (2 tests passed).

### 2.3 Direction Confusion & Key Isolation
- **Probe**: Decrypting outbound initiator traffic using initiator receive ciphers, or using responder send keys to decrypt responder outbound traffic.
- **Result**: HKDF-SHA-512 domain tags derive distinct, cryptographically isolated directional keys (`k_init_send` vs `k_resp_send`). Cross-direction decryption attempts fail closed with AEAD authentication exceptions.
- **Test Reference**: `tests/adversarial/exploits/redteam_direction_confusion.py` (1 test passed).

### 2.4 Parser & Deserialization Bombing
- **Probe**: Injecting duplicate JSON keys (RFC 8259), non-standard IEEE 754 constants (`NaN`, `Infinity`), deep recursion structures (depth > 10), length-prefix truncation, unauthenticated trailing bytes, and metadata shape/byte-count discrepancies.
- **Result**: Canonical deserializers reject duplicate keys with `DUPLICATE_KEY` ValueError, reject constants with `INVALID_JSON_CONSTANT`, enforce `MAX_JSON_DEPTH = 10`, and reject trailing bytes via strict wire parsers.
- **Test Reference**: `tests/adversarial/exploits/redteam_parser_attacks.py` (6 tests passed).

### 2.5 Resource Exhaustion & Denial of Service
- **Probe**: Hostile payloads declaring single dimension > 65,536, volumetric frame counts > 2,048, total payload > 256 MiB, and manifests > 64 KiB.
- **Result**: Explicit bounds checking in `medpqc.utils.limits` and `medpqc.utils.validation` triggers before buffer allocation, raising typed `DimensionLimitExceededError`, `PayloadLimitExceededError`, or `ManifestLimitExceededError`.
- **Test Reference**: `tests/adversarial/exploits/redteam_resource_exhaustion.py` (4 tests passed).

### 2.6 State & Replay Persistence
- **Probe**: Replay attacks across `SqliteReplayStore` restarts on disk; unauthenticated message injection attempts to exhaust replay slots; boundary-condition clock skews.
- **Result**: Consumed sessions persist on disk in SQLite WAL storage. Messages with invalid signatures fail verification immediately and do NOT consume replay cache slots. Clock skews exceeding 300,000 ms fail closed with `StaleSessionError`.
- **Test Reference**: `tests/adversarial/exploits/redteam_state_attacks.py` (3 tests passed).

### 2.7 Cipher Suite Downgrade
- **Probe**: Intercepting handshake messages to strip `MLKEM768` from offered suites or reordering the offered suite list.
- **Result**: The complete offered suite list is bound into the initiation transcript and signed by the initiator. Modifying the offered suites invalidates the signature, causing `AuthenticationError` and handshake abort.
- **Test Reference**: `tests/adversarial/exploits/redteam_downgrade.py` (2 tests passed).

### 2.8 Partial-Plaintext Release
- **Probe**: Flipping single bits in the AES-256-GCM authentication tag or truncating ciphertext bytes.
- **Result**: Decryption aborts immediately upon AEAD verification failure. The output file is never written or is cleanly unlinked on error, ensuring zero partial-plaintext leakage on disk.
- **Test Reference**: `tests/adversarial/exploits/redteam_partial_plaintext.py` (2 tests passed).

### 2.9 Concurrency & Race Conditions
- **Probe**: Multithreaded concurrent encrypt/decrypt operations; high-contention simultaneous consumption of replay store entries across 16 worker threads.
- **Result**: Atomic SQLite transactions (`INSERT ... ON CONFLICT DO NOTHING`) ensure exactly 1 thread consumes the session slot while all 15 competing threads fail. Cipher operations execute without race conditions or memory corruption.
- **Test Reference**: `tests/adversarial/exploits/redteam_concurrency.py` (2 tests passed).

---

## 3. Explicit Operational Boundaries and Disclaimers

1. **External Security Audit**: Not externally audited by an accredited independent testing laboratory.
2. **PACS Interoperability**: NOT VERIFIED against live commercial PACS servers (e.g., GE Centricity, Philips IntelliSpace, Siemens syngo). Testing conducted strictly on synthetic in-memory and local file DICOM fixtures.
3. **FIPS 203 Vectors**: Verified against 100 official NIST ACVP ML-KEM-768 test vectors (keyGen, encap, decap) sourced from NIST ACVP-Server commit `15c0f3d`.
4. **FIPS 140 / CAVP Validation**: None. The implementation and underlying providers do not possess a NIST CAVP certificate or FIPS 140-3 validation.
5. **HIPAA Compliance**: Does not provide HIPAA compliance. MedPQC provides research cryptographic algorithms and de-identification utilities; organizational, administrative, and clinical HIPAA compliance is not provided and is out of scope.

---

## 4. Computed Release Status

In accordance with Section 0.1 Rule 4:
- All Critical (C) and High (H) findings from the baseline audit have been remediated and verified through executable regression tests.
- Because no accredited third-party CAVP laboratory or commercial security audit has evaluated the implementation in clinical deployments, the release status ceiling is mechanically computed as:

**`RESEARCH RELEASE: SECURITY REVIEW INCOMPLETE`**
