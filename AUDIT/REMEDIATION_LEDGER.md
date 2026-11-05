# MedPQC v2.5.0 Remediation Ledger

- **Status Ceiling**: RESEARCH RELEASE: SECURITY REVIEW INCOMPLETE
- **Release Version**: 2.5.0
- **Single Source of Truth**: `AUDIT/ledger.yaml` (dynamic status derivation)

---

## 1. Executive Remediation Summary

| ID | Severity | Title | Status | Evidence Path |
| :--- | :--- | :--- | :--- | :--- |
| **F-HS-01** | Critical | Handshake unauthenticated mode permitted security bypass | **FIXED AND TESTED** | `AUDIT/evidence/D-01/after.txt` |
| **F-HS-02** | High | Redundant outer HMAC over AES-GCM ciphertext | **FIXED AND TESTED** | `AUDIT/evidence/D-09/after.txt` |
| **F-HS-03** | Critical | Bidirectional symmetric session key reuse | **FIXED AND TESTED** | `AUDIT/evidence/D-05/after.txt` |
| **F-HS-04** | High | Non-atomic replay protection vulnerable to race conditions | **FIXED AND TESTED** | `AUDIT/evidence/D-04/after.txt` |
| **F-HS-05** | Medium | TrustStore lacked peer lifecycle management | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-HS-06** | High | Arbitrary cryptographic suite acceptance by responder | **FIXED AND TESTED** | `AUDIT/evidence/D-02/after.txt` |
| **F-HS-07** | High | Direction confusion in session key derivation | **FIXED AND TESTED** | `AUDIT/evidence/D-05/after.txt` |
| **F-HS-08** | Medium | Session ID entropy and length validation | **FIXED AND TESTED** | `AUDIT/evidence/D-03/after.txt` |
| **F-HS-09** | High | Handshake timestamp bounds and replay window checking | **FIXED AND TESTED** | `AUDIT/evidence/D-03/after.txt` |
| **F-ENV-01** | High | Unbounded memory allocation during envelope deserialization | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-ENV-02** | High | Missing invocation bounds on AES-GCM nonces | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-ENV-03** | Medium | Non-canonical JSON parsing permitted duplicate keys | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-ENV-04** | Medium | In-memory DICOM element bounds check | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-ENV-05** | Medium | Streaming decompression memory exhaustion protection | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-ENV-06** | Medium | Envelope header schema validation and critical extension rejection | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DICOM-01** | High | Dual-source divergence between private tag and sidecar manifest | **FIXED AND TESTED** | `AUDIT/evidence/D-10/after.txt` |
| **F-DICOM-02** | High | Silent decryption fallback to external sidecar file | **FIXED AND TESTED** | `AUDIT/evidence/D-10/after.txt` |
| **F-DICOM-03** | High | Retained DICOM headers unauthenticated against dataset hash | **FIXED AND TESTED** | `AUDIT/evidence/D-14/after.txt` |
| **F-DICOM-04** | High | Default pseudonymization salt permitted cross-site correlation | **FIXED AND TESTED** | `AUDIT/evidence/D-11/after.txt` |
| **F-DICOM-05** | High | Real clinical imaging artifacts in test directory | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DICOM-06** | High | Partial file leakage on decryption failure | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DICOM-07** | Medium | Silent corruption from lossy/compressed transfer syntaxes | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DICOM-08** | Medium | Incomplete deep sequence de-identification | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DICOM-09** | Low | Inconsistent private creator tag versions | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DICOM-10** | Medium | Missing Architectural Decision Record for envelope | **FIXED AND TESTED** | `docs/adr/ADR-001-encrypted-object.md` |
| **F-CHAOS-01** | High | Chaotic scrambling enabled by default in cipher engine | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-CHAOS-02** | Medium | Modulo bias in Fisher-Yates chaotic permutation | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-CHAOS-03** | Medium | Lorenz RK4 floating-point drift across platforms | **FIXED AND TESTED** | `AUDIT/evidence/D-20/after.txt` |
| **F-QA-01** | High | Missing end-to-end integration workflows | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-QA-02** | High | Incomplete adversarial and tamper test suite | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-QA-03** | Medium | Test coverage artificially inflated by blanket pragmas | **FIXED AND TESTED** | `AUDIT/evidence/D-17/after.txt` |
| **F-QA-04** | Medium | Lack of automated property and fuzz testing | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-QA-05** | Medium | Missing automated static analysis in verification pipeline | **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED** | `AUDIT/evidence/D-17/after.txt, AUDIT/evidence/D-18/after.txt, AUDIT/evidence/D-19/after.txt` |
| **F-QA-06** | Medium | Wheel package not validated in clean isolated virtual environment | **FIXED AND TESTED** | `AUDIT/evidence/D-21/after.txt` |
| **F-QA-07** | Medium | CI/CD lacked multi-platform matrix and published directly on tag | **FIXED AND TESTED** | `.github/workflows/ci-cd.yml` |
| **F-PKG-01** | Medium | Package metadata inconsistencies and eager namespace imports | **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED** | `AUDIT/evidence/D-20/after.txt, AUDIT/evidence/D-21/after.txt` |
| **F-BENCH-01** | High | Single-shot benchmarks with anomalous reported values | **FIXED AND TESTED** | `AUDIT/evidence/D-22/after.txt` |
| **F-DOC-01** | Critical | Forbidden marketing and unsupported cryptographic security claims | **FIXED AND TESTED** | `AUDIT/TEST_REPORT.md` |
| **F-DOC-02** | High | Protocol specification mismatched actual implementation vectors | **FIXED AND TESTED** | `AUDIT/evidence/D-25/after.txt` |
| **F-DOC-03** | High | Audit documentation contained fake machine signatures and self-certified sign-offs | **FIXED AND TESTED** | `AUDIT/evidence/D-23/after.txt` |
| **F-DOC-04** | Low | Duplicate changelogs and inconsistent documentation casing | **FIXED AND TESTED** | `CHANGELOG.md` |
| **F-REL-01** | Medium | Staged release artifacts contained cache files and CRLF checksums | **FIXED AND TESTED** | `AUDIT/evidence/D-24/after.txt` |
| **F-KAT-01** | Critical | NIST ACVP FIPS 203 Known-Answer Test validation and provenance | **FIXED AND TESTED** | `AUDIT/evidence/D-16/after.txt` |
| **D-01** | Critical | Missing recipient binding in handshake state machines | **FIXED AND TESTED** | `AUDIT/evidence/D-01/after.txt` |
| **D-02** | High | Protocol version negotiation and domain separation mismatch | **FIXED AND TESTED** | `AUDIT/evidence/D-02/after.txt` |
| **D-03** | High | Lax timestamp bounds and replay window enforcement | **FIXED AND TESTED** | `AUDIT/evidence/D-03/after.txt` |
| **D-04** | High | Missing ReplayStore contract test suite | **FIXED AND TESTED** | `AUDIT/evidence/D-04/after.txt` |
| **D-05** | High | Direction confusion in session traffic ciphers | **FIXED AND TESTED** | `AUDIT/evidence/D-05/after.txt` |
| **D-06** | Medium | Lax PKCS#8 Ed25519 identity key format and node binding | **FIXED AND TESTED** | `AUDIT/evidence/D-06/after.txt` |
| **D-07** | Medium | Missing SECP256R1 ECDH public key format validation | **FIXED AND TESTED** | `AUDIT/evidence/D-07/after.txt` |
| **D-08** | High | ML-KEM-768 length validation and secret leakage in error messages | **FIXED AND TESTED** | `AUDIT/evidence/D-08/after.txt` |
| **D-09** | Medium | RFC 5869 HKDF-SHA-512 domain-separated context tags | **FIXED AND TESTED** | `AUDIT/evidence/D-09/after.txt` |
| **D-10** | High | ManifestSource.AUTO permitted silent fallback in DICOM decryption | **FIXED AND TESTED** | `AUDIT/evidence/D-10/after.txt` |
| **D-11** | High | Lax SitePseudonymizationKey length and silent padding | **FIXED AND TESTED** | `AUDIT/evidence/D-11/after.txt` |
| **D-12** | High | Lossy element serialization corrupted private tags in roundtrip | **FIXED AND TESTED** | `AUDIT/evidence/D-12/after.txt` |
| **D-13** | Medium | UID pseudonymization non-compliance and phantom PatientID synthesis | **FIXED AND TESTED** | `AUDIT/evidence/D-13/after.txt` |
| **D-14** | Medium | BurnedInAnnotation normalization mismatch during dataset hashing | **FIXED AND TESTED** | `AUDIT/evidence/D-14/after.txt` |
| **D-15** | Medium | Swallowed exceptions in DICOM decompression and parsing | **FIXED AND TESTED** | `AUDIT/evidence/D-15/after.txt` |
| **D-16** | Critical | Missing NIST ACVP FIPS 203 KAT vectors and provider pinning | **FIXED AND TESTED** | `AUDIT/evidence/D-16/after.txt` |
| **D-17** | Medium | Lax Mypy type-checking and coverage exclusion pragmas | **FIXED AND TESTED** | `AUDIT/evidence/D-17/after.txt` |
| **D-18** | Low | Ruff linting and formatting violations | **FIXED AND TESTED** | `AUDIT/evidence/D-18/after.txt` |
| **D-19** | Medium | Bandit automated security scan findings | **FIXED AND TESTED** | `AUDIT/evidence/D-19/after.txt` |
| **D-20** | Medium | Mandatory heavy dependencies in core imports and experimental chaos isolation | **FIXED AND TESTED** | `AUDIT/evidence/D-20/after.txt` |
| **D-21** | Medium | Single-source version bump to 2.4.0 | **FIXED AND TESTED** | `AUDIT/evidence/D-21/after.txt` |
| **D-22** | High | Reproducible empirical benchmarks with raw per-repetition measurements | **FIXED AND TESTED** | `AUDIT/evidence/D-22/after.txt` |
| **D-23** | High | Machine-readable audit ledger and prohibited legacy status | **FIXED AND TESTED** | `AUDIT/evidence/D-23/after.txt` |
| **D-24** | Low | Evidence report formatting, strict LF endings, and normalized paths | **FIXED AND TESTED** | `AUDIT/evidence/D-24/after.txt` |
| **D-25** | High | Protocol specification vector synchronization and pinning | **FIXED AND TESTED** | `AUDIT/evidence/D-25/after.txt` |
| **N-01** | Critical | Handshake API split: InitiatorContext and ResponderContext | **FIXED AND TESTED** | `AUDIT/evidence/N-01/after.txt` |
| **N-02** | High | Replay store durability warning and strict operational enforcement | **FIXED AND TESTED** | `AUDIT/evidence/N-02/after.txt` |
| **N-03** | Medium | Obsolete handshake API removal and compatibility documentation | **FIXED AND TESTED** | `AUDIT/evidence/N-03/after.txt` |
| **N-04** | Critical | Default-deny retained attributes allow-list for DICOM headers | **FIXED AND TESTED** | `AUDIT/evidence/N-04/after.txt` |
| **N-05** | High | Element-exact restoration from sealed dataset | **FIXED AND TESTED** | `AUDIT/evidence/N-05/after.txt` |
| **N-06** | Medium | restore_dicom_file interface and sidecar elimination | **FIXED AND TESTED** | `AUDIT/evidence/N-06/after.txt` |
| **N-07** | Medium | Atomic file writes via NamedTemporaryFile and os.replace | **FIXED AND TESTED** | `AUDIT/evidence/N-07/after.txt` |
| **N-08** | High | Removal of insecure site_salt and anonymize_headers parameters | **FIXED AND TESTED** | `AUDIT/evidence/N-08/after.txt` |
| **N-09** | High | Rejection of curves, overlays, burned-in annotations, and unsupported transfer syntaxes | **FIXED AND TESTED** | `AUDIT/evidence/N-09/after.txt` |
| **N-10** | High | Targeted mutation testing with score >= 85% | **FIXED AND TESTED** | `AUDIT/evidence/N-10/after.txt` |
| **N-11** | High | Branch coverage floors: >= 90% core, >= 85% utils | **FIXED AND TESTED** | `AUDIT/evidence/N-11/after.txt` |
| **N-12** | Medium | Clean mypy strict typing and machine-generated pip-audit report | **FIXED AND TESTED** | `AUDIT/evidence/N-12/after.txt` |
| **N-13** | Low | Benchmark CSV line ending normalization (LF) | **FIXED AND TESTED** | `AUDIT/evidence/N-13/after.txt` |
| **N-14** | High | Documentation and claims scanner with zero un-negated forbidden terms | **FIXED AND TESTED** | `AUDIT/evidence/N-14/after.txt` |
| **N-15** | High | Dynamic ledger status derivation and forbidden status tokens | **FIXED AND TESTED** | `AUDIT/evidence/N-15/after.txt` |
| **N-16** | Low | Strict LF line endings in release artifacts and SHA256SUMS.txt | **FIXED AND TESTED** | `AUDIT/evidence/N-16/after.txt` |
| **N-17** | Medium | Specification-code agreement and executable doc examples script | **FIXED AND TESTED** | `AUDIT/evidence/N-17/after.txt` |
| **N-18** | Critical | Release verifier hardening with code_tree_hash and zero status exclusions | **FIXED AND TESTED** | `AUDIT/evidence/N-18/after.txt` |

---

## 2. Detailed Findings Register

### F-HS-01: Handshake unauthenticated mode permitted security bypass

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py, medpqc/dicom/pacs.py`
- **Original Problem**: Parameter allow_unauthenticated permitted handshake completion without verifying peer Ed25519 identity.
- **Required Correction**: Eliminate allow_unauthenticated entirely; mandate valid TrustStore and signed transcripts.
- **Implementation Summary**: Removed parameter from InitiatorContext, ResponderContext, and pacs handlers; all handshakes fail closed without trusted peer key.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d01.py`
- **Evidence**: `AUDIT/evidence/D-01/after.txt`
- **Notes**: Verified in D-01.

### F-HS-02: Redundant outer HMAC over AES-GCM ciphertext

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/combiner.py, medpqc/cipher/engine.py`
- **Original Problem**: Double encryption/MAC construction used redundant outer HMAC over already authenticated AES-GCM ciphertext.
- **Required Correction**: Rely on AES-GCM AEAD authentication tag and bind context properly in HKDF.
- **Implementation Summary**: Streamlined AEAD authentication into single SP 800-38D AES-GCM construction; directional keys derived via HKDF.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d09.py`
- **Evidence**: `AUDIT/evidence/D-09/after.txt`
- **Notes**: Streamlined in v2.3.

### F-HS-03: Bidirectional symmetric session key reuse

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/combiner.py, medpqc/kem/auth.py`
- **Original Problem**: Single symmetric key was shared for both initiator-to-responder and responder-to-initiator flows.
- **Required Correction**: Derive distinct directional traffic keys (k_enc_i2r, k_enc_r2i) bound to session transcript.
- **Implementation Summary**: HKDF derives distinct directional traffic keys with domain-separated context tags.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d05.py`
- **Evidence**: `AUDIT/evidence/D-05/after.txt`
- **Notes**: Hardened in D-05.

### F-HS-04: Non-atomic replay protection vulnerable to race conditions

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/security/replay.py`
- **Original Problem**: Replay checks checked seen nonces and recorded them non-atomically.
- **Required Correction**: Implement atomic check-and-insert using SQLite single-winner constraint or thread-locked memory store.
- **Implementation Summary**: SqliteReplayStore uses atomic INSERT with UNIQUE constraint; MemoryReplayStore uses threading.Lock.
- **Verification Tests**: `tests/contract/test_replay_store_contract.py, tests/adversarial/exploits/test_exploit_d04.py`
- **Evidence**: `AUDIT/evidence/D-04/after.txt`
- **Notes**: Verified in D-04.

### F-HS-05: TrustStore lacked peer lifecycle management

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/security/trust.py`
- **Original Problem**: No mechanism existed to revoke or rotate trusted peer identity keys.
- **Required Correction**: Add rotation, revocation, and node validation methods.
- **Implementation Summary**: Implemented register_peer, revoke_peer, and rotate_peer with timestamp audits.
- **Verification Tests**: `tests/unit/test_unit_trust.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Completed in v2.3.

### F-HS-06: Arbitrary cryptographic suite acceptance by responder

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: Responder accepted any offered suite string without validating against allowed suites.
- **Required Correction**: Validate offered suite against strict ALLOWED_SUITES set; raise UnsupportedSuiteError.
- **Implementation Summary**: Strict set membership check against ALLOWED_SUITES in ResponderContext.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d02.py`
- **Evidence**: `AUDIT/evidence/D-02/after.txt`
- **Notes**: Verified in D-02.

### F-HS-07: Direction confusion in session key derivation

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: Transcript-derived traffic keys did not enforce strict directional bindings.
- **Required Correction**: Enforce distinct InitiatorCipher and ResponderCipher types preventing cross-direction decryptions.
- **Implementation Summary**: InitiatorContext returns InitiatorCipher; ResponderContext returns ResponderCipher; cross-direction calls fail closed.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d05.py`
- **Evidence**: `AUDIT/evidence/D-05/after.txt`
- **Notes**: Verified in D-05.

### F-HS-08: Session ID entropy and length validation

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: Short or predictable session IDs were accepted during handshake initiation.
- **Required Correction**: Enforce minimum 16-byte random session ID.
- **Implementation Summary**: Enforced 16-32 byte session_id check with ValueError on invalid lengths.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d03.py`
- **Evidence**: `AUDIT/evidence/D-03/after.txt`
- **Notes**: Verified in D-03.

### F-HS-09: Handshake timestamp bounds and replay window checking

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py, medpqc/security/replay.py`
- **Original Problem**: Negative timestamps, timestamps far in the past, or future drift were accepted without validation.
- **Required Correction**: Enforce strict uint64 ms timestamp validation against configurable replay window (default 300s).
- **Implementation Summary**: Enforced 0 <= timestamp_ms < 2^64-1 and abs(now_ms - timestamp_ms) <= window_ms.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d03.py`
- **Evidence**: `AUDIT/evidence/D-03/after.txt`
- **Notes**: Verified in D-03.

### F-ENV-01: Unbounded memory allocation during envelope deserialization

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/utils/limits.py, medpqc/utils/canonical.py`
- **Original Problem**: Deserialization of malformed envelopes could exhaust host memory.
- **Required Correction**: Enforce MAX_PAYLOAD_BYTES (1 GB) and MAX_MANIFEST_BYTES (10 MB).
- **Implementation Summary**: Strict limits enforced across canonical decoder and DICOM reader.
- **Verification Tests**: `tests/unit/test_unit_limits.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced in v2.3.

### F-ENV-02: Missing invocation bounds on AES-GCM nonces

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/cipher/engine.py`
- **Original Problem**: NIST SP 800-38D limits AES-GCM to 2^32 invocations per key to prevent nonce collision.
- **Required Correction**: Implement session key invocation counter capped at MAX_CIPHERTEXTS_PER_KEY (65536).
- **Implementation Summary**: Added invocation counter throwing KeyExhaustedError when exceeded.
- **Verification Tests**: `tests/unit/test_unit_cipher_limits.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced in v2.3.

### F-ENV-03: Non-canonical JSON parsing permitted duplicate keys

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/utils/canonical.py`
- **Original Problem**: Standard json.loads silently overwrote duplicate dictionary keys.
- **Required Correction**: Implement strict RFC 8785 canonical JSON parser rejecting duplicate keys and non-finite floats.
- **Implementation Summary**: Implemented CanonicalDecoder with strict object_pairs_hook.
- **Verification Tests**: `tests/fuzz/test_fuzz_manifest.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced in v2.3.

### F-ENV-04: In-memory DICOM element bounds check

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/handler.py, medpqc/utils/limits.py`
- **Original Problem**: Unbounded DICOM element values could cause memory exhaustion during parsing.
- **Required Correction**: Enforce element length and recursion depth caps on nested sequences.
- **Implementation Summary**: Enforced max sequence depth (16) and max element value length.
- **Verification Tests**: `tests/unit/test_dicom_handler.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced in handler.

### F-ENV-05: Streaming decompression memory exhaustion protection

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/utils/limits.py`
- **Original Problem**: Compressed payloads lacked decompression ratio caps, risking zip-bomb conditions.
- **Required Correction**: Enforce max expansion ratio (100x) and max unpacked buffer size.
- **Implementation Summary**: Checked unpacked byte limits prior to processing pixel data.
- **Verification Tests**: `tests/unit/test_unit_limits.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced in limits.

### F-ENV-06: Envelope header schema validation and critical extension rejection

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/utils/canonical.py, medpqc/dicom/pacs.py`
- **Original Problem**: Envelope parser ignored unknown header fields that could alter security semantics.
- **Required Correction**: Fail closed on unrecognized critical header extensions.
- **Implementation Summary**: Strict schema validation rejects unrecognized keys in manifest envelopes.
- **Verification Tests**: `tests/unit/test_unit_canonical.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced in canonical.

### F-DICOM-01: Dual-source divergence between private tag and sidecar manifest

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Security manifest was read from external sidecar or embedded private tag with diverging precedence.
- **Required Correction**: Implement Single Authenticated Encrypted Object architecture (ADR-001) with explicit source specification.
- **Implementation Summary**: Removed AUTO mode; manifest source must be explicitly declared; embedded mode fails closed if tag missing.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d10.py`
- **Evidence**: `AUDIT/evidence/D-10/after.txt`
- **Notes**: Remediated in D-10.

### F-DICOM-02: Silent decryption fallback to external sidecar file

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: If private DICOM tag was absent, decrypt_dicom_file searched for external sidecar on disk.
- **Required Correction**: Eliminate silent fallback; fail closed with MissingManifestError.
- **Implementation Summary**: Fail closed implementation when EMBEDDED manifest is requested but tag is missing.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d10.py`
- **Evidence**: `AUDIT/evidence/D-10/after.txt`
- **Notes**: Verified in D-10.

### F-DICOM-03: Retained DICOM headers unauthenticated against dataset hash

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Header elements retained in DICOM wrapper were not cryptographically bound to ciphertext.
- **Required Correction**: Compute SHA-256 hash of retained dataset elements and bind as AAD in AES-GCM.
- **Implementation Summary**: compute_dataset_hash binds normalized header state directly into AEAD AAD.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d14.py`
- **Evidence**: `AUDIT/evidence/D-14/after.txt`
- **Notes**: Verified in D-14.

### F-DICOM-04: Default pseudonymization salt permitted cross-site correlation

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Hardcoded DEFAULT_SITE_SALT was used if caller did not supply custom salt.
- **Required Correction**: Delete DEFAULT_SITE_SALT; require explicit 32-byte SitePseudonymizationKey.
- **Implementation Summary**: Removed default constant; SitePseudonymizationKey requires exactly 32 bytes without silent padding.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d11.py`
- **Evidence**: `AUDIT/evidence/D-11/after.txt`
- **Notes**: Remediated in D-11.

### F-DICOM-05: Real clinical imaging artifacts in test directory

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `tests_data/`
- **Original Problem**: Repository contained non-synthetic DICOM files with potential privacy risks.
- **Required Correction**: Purge all test artifacts; replace with synthetic generator fixtures.
- **Implementation Summary**: Purged non-synthetic DICOM test files; all tests generate synthetic data in memory.
- **Verification Tests**: `tests/contract/test_dicom_roundtrip_contract.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Purged in v2.3.

### F-DICOM-06: Partial file leakage on decryption failure

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Failed decryption left partially-written unauthenticated files on disk.
- **Required Correction**: Use atomic write to temporary file with mandatory try/finally cleanup.
- **Implementation Summary**: Writes output only after full AEAD verification and element restoration succeed.
- **Verification Tests**: `tests/integration/test_end_to_end_workflows.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Remediated in v2.3.

### F-DICOM-07: Silent corruption from lossy/compressed transfer syntaxes

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/handler.py`
- **Original Problem**: JPEG/RLE compressed transfer syntaxes were unpacked without checking support.
- **Required Correction**: Explicitly validate transfer syntax; raise UnsupportedTransferSyntaxError.
- **Implementation Summary**: Explicit transfer syntax validation rejecting compressed encodings.
- **Verification Tests**: `tests/unit/test_dicom_handler.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Validated in handler.

### F-DICOM-08: Incomplete deep sequence de-identification

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Nested DICOM sequence items were not recursively traversed for PHI tags.
- **Required Correction**: Recursively scrub nested elements per PS 3.15 Annex E basic profile.
- **Implementation Summary**: Recursive sequence traversal scrubs all nested patient tags.
- **Verification Tests**: `tests/contract/test_dicom_roundtrip_contract.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Traversed in pacs.

### F-DICOM-09: Inconsistent private creator tag versions

- **Severity**: Low
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Creator tags differed across experimental versions causing interoperability failures.
- **Required Correction**: Standardize on MEDPQC_SECURITY_V2.3 tag identification.
- **Implementation Summary**: Standardized private creator tag identification.
- **Verification Tests**: `tests/contract/test_dicom_roundtrip_contract.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Standardized in v2.3.

### F-DICOM-10: Missing Architectural Decision Record for envelope

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `docs/adr/ADR-001-encrypted-object.md`
- **Original Problem**: No documentation explaining rationale for single authenticated encrypted object vs sidecar.
- **Required Correction**: Author ADR-001 detailing design decisions, threat model, and alternatives.
- **Implementation Summary**: Authored ADR-001 document detailing security rationale.
- **Verification Tests**: `docs/adr/ADR-001-encrypted-object.md`
- **Evidence**: `docs/adr/ADR-001-encrypted-object.md`
- **Notes**: Authored in docs.

### F-CHAOS-01: Chaotic scrambling enabled by default in cipher engine

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/cipher/engine.py`
- **Original Problem**: Unproven chaotic scrambling was active by default, suggesting cryptographic confidentiality.
- **Required Correction**: Default enable_scrambling to False; document as non-cryptographic transform.
- **Implementation Summary**: Defaulted enable_scrambling=False; added prominent security warnings in docstrings.
- **Verification Tests**: `tests/unit/test_unit_cipher.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Remediated in v2.3.

### F-CHAOS-02: Modulo bias in Fisher-Yates chaotic permutation

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/experimental/chaos/permutation.py`
- **Original Problem**: Permutation index selection used modulo arithmetic on chaotic byte streams.
- **Required Correction**: Implement rejection sampling to eliminate modulo bias.
- **Implementation Summary**: Implemented uniform rejection sampling in ChaoticPermuter.
- **Verification Tests**: `tests/unit/test_unit_permutation.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Eliminated in permutation.

### F-CHAOS-03: Lorenz RK4 floating-point drift across platforms

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/experimental/chaos/lorenz.py`
- **Original Problem**: Lorenz RK4 simulation with fastmath resulted in divergent trajectories across architectures.
- **Required Correction**: Document dynamical sensitivity; clarify non-PRNG status; isolate to experimental package.
- **Implementation Summary**: Relocated to medpqc.experimental.chaos; documented non-PRNG status.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d20.py`
- **Evidence**: `AUDIT/evidence/D-20/after.txt`
- **Notes**: Relocated in D-20.

### F-QA-01: Missing end-to-end integration workflows

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `tests/integration/test_end_to_end_workflows.py`
- **Original Problem**: Integration test suite was empty; only unit tests were executed.
- **Required Correction**: Implement comprehensive multi-node PACS workflow integration tests.
- **Implementation Summary**: Implemented complete PACS ingest, transmit, store, and decrypt workflow tests.
- **Verification Tests**: `tests/integration/test_end_to_end_workflows.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Implemented in v2.3.

### F-QA-02: Incomplete adversarial and tamper test suite

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `tests/adversarial/`
- **Original Problem**: Lack of negative test cases verifying system fails closed against malicious inputs.
- **Required Correction**: Add comprehensive adversarial tests for bit-flipping, truncation, and replays.
- **Implementation Summary**: Implemented full suite of adversarial tamper, replay, and exploit tests.
- **Verification Tests**: `tests/adversarial/`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Implemented in adversarial.

### F-QA-03: Test coverage artificially inflated by blanket pragmas

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `pyproject.toml`
- **Original Problem**: pyproject.toml excluded critical branches with pragma: no cover.
- **Required Correction**: Remove blanket pragmas; enforce branch coverage floors across packages.
- **Implementation Summary**: Removed pragma: no cover; enabled branch coverage in pyproject.toml.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d17.py`
- **Evidence**: `AUDIT/evidence/D-17/after.txt`
- **Notes**: Remediated in D-17.

### F-QA-04: Lack of automated property and fuzz testing

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `tests/fuzz/`
- **Original Problem**: Edge cases in parsers and decoders were unexercised by deterministic unit tests.
- **Required Correction**: Implement Hypothesis property-based fuzz tests for parser, manifest, and cipher.
- **Implementation Summary**: Implemented Hypothesis fuzz tests covering canonical JSON, manifest decoding, and cipher.
- **Verification Tests**: `tests/fuzz/`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Implemented in fuzz.

### F-QA-05: Missing automated static analysis in verification pipeline

- **Severity**: Medium
- **Status**: **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED**
- **Target Files**: `AUDIT/evidence/static/`
- **Original Problem**: Static analysis tools were not integrated into gate checks.
- **Required Correction**: Integrate strict mypy, ruff, bandit, and dependency vulnerability scans.
- **Implementation Summary**: Automated mypy --strict, ruff check, and bandit scans with clean reports.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d17.py, tests/adversarial/exploits/test_exploit_d18.py, tests/adversarial/exploits/test_exploit_d19.py`
- **Evidence**: `AUDIT/evidence/D-17/after.txt, AUDIT/evidence/D-18/after.txt, AUDIT/evidence/D-19/after.txt`
- **Notes**: Integrated in D-17..D-19.

### F-QA-06: Wheel package not validated in clean isolated virtual environment

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `dist/`
- **Original Problem**: Distribution wheel was built but never tested in isolated environment.
- **Required Correction**: Automate wheel install and test execution in temporary clean venv.
- **Implementation Summary**: Verified wheel building and clean pip install test pass.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d21.py`
- **Evidence**: `AUDIT/evidence/D-21/after.txt`
- **Notes**: Validated in packaging.

### F-QA-07: CI/CD lacked multi-platform matrix and published directly on tag

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `.github/workflows/ci-cd.yml`
- **Original Problem**: Single-OS CI run with automatic PyPI publish risks publishing untested binaries.
- **Required Correction**: Add test matrix across OS and Python versions; remove automatic publishing.
- **Implementation Summary**: Updated CI workflow with multi-platform matrix and decoupled release trigger.
- **Verification Tests**: `.github/workflows/ci-cd.yml`
- **Evidence**: `.github/workflows/ci-cd.yml`
- **Notes**: Updated in CI.

### F-PKG-01: Package metadata inconsistencies and eager namespace imports

- **Severity**: Medium
- **Status**: **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED**
- **Target Files**: `pyproject.toml, medpqc/__init__.py`
- **Original Problem**: Top-level __init__.py eagerly loaded heavy DICOM dependencies and had duplicate authors.
- **Required Correction**: Single-source version, remove duplicate metadata, implement lazy loading.
- **Implementation Summary**: Cleaned metadata in pyproject.toml; implemented __getattr__ lazy loading in __init__.py.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d20.py, tests/adversarial/exploits/test_exploit_d21.py`
- **Evidence**: `AUDIT/evidence/D-20/after.txt, AUDIT/evidence/D-21/after.txt`
- **Notes**: Remediated in D-20 and D-21.

### F-BENCH-01: Single-shot benchmarks with anomalous reported values

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `benchmarks/`
- **Original Problem**: Benchmarks reported single iterations with high variance and hand-edited tables.
- **Required Correction**: Rebuild benchmark harness with >=30 randomized reps, warmup, bootstrap 95% CIs, and raw CSVs.
- **Implementation Summary**: Implemented master benchmark runner generating per-repetition raw CSVs and statistical summaries.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d22.py`
- **Evidence**: `AUDIT/evidence/D-22/after.txt`
- **Notes**: Remediated in D-22.

### F-DOC-01: Forbidden marketing and unsupported cryptographic security claims

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `README.md, docs/, AUDIT/`
- **Original Problem**: Documentation contained unverified formal security claims, regulatory compliance assertions, and unsupported readiness claims.
- **Required Correction**: Purge all forbidden claims; enforce research implementation disclaimer ceiling.
- **Implementation Summary**: Purged all forbidden terms; added automated forbidden claim scanning test.
- **Verification Tests**: `tests/docs/test_docs_claim_hygiene.py`
- **Evidence**: `AUDIT/TEST_REPORT.md`
- **Notes**: Enforced across repository.

### F-DOC-02: Protocol specification mismatched actual implementation vectors

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `docs/PROTOCOL_SPECIFICATION.md, tests/vectors/transcripts.json`
- **Original Problem**: Hex transcripts in PROTOCOL_SPECIFICATION.md did not match test vectors.
- **Required Correction**: Synchronize specification with bit-for-bit test vector output.
- **Implementation Summary**: Updated protocol specification with exact matching hex transcripts for MedPQC-v2.4.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d25.py`
- **Evidence**: `AUDIT/evidence/D-25/after.txt`
- **Notes**: Synchronized in D-25.

### F-DOC-03: Audit documentation contained fake machine signatures and self-certified sign-offs

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `AUDIT/`
- **Original Problem**: Audit reports claimed complete criteria satisfaction with author sign-offs and foreign paths.
- **Required Correction**: Remove all author sign-offs, replace with machine-enforced gates, set status ceiling to RESEARCH RELEASE.
- **Implementation Summary**: Replaced manual sign-offs with verify_release.py 13-gate machine verification.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d23.py`
- **Evidence**: `AUDIT/evidence/D-23/after.txt`
- **Notes**: Remediated in D-23.

### F-DOC-04: Duplicate changelogs and inconsistent documentation casing

- **Severity**: Low
- **Status**: **FIXED AND TESTED**
- **Target Files**: `CHANGELOG.md, docs/`
- **Original Problem**: Multiple changelogs existed with inconsistent version entries.
- **Required Correction**: Consolidate into single root CHANGELOG.md and standardize uppercase filenames.
- **Implementation Summary**: Consolidated changelog and standardized documentation file naming.
- **Verification Tests**: `CHANGELOG.md`
- **Evidence**: `CHANGELOG.md`
- **Notes**: Consolidated in docs.

### F-REL-01: Staged release artifacts contained cache files and CRLF checksums

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `release/`
- **Original Problem**: release/ directory contained .pyc files and SHA256SUMS.txt with CRLF line endings.
- **Required Correction**: Clean release directory, enforce LF endings, and compute sha256 sums mechanically.
- **Implementation Summary**: Automated clean release artifact creation with strict LF line endings and verified SHA-256 sums.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d24.py`
- **Evidence**: `AUDIT/evidence/D-24/after.txt`
- **Notes**: Cleaned in D-24.

### F-KAT-01: NIST ACVP FIPS 203 Known-Answer Test validation and provenance

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `tests/vectors/nist_fips203_kat_vectors.json, tests/vectors/PROVENANCE.json`
- **Original Problem**: ACVP test vectors were synthetic or duplicated without provenance tracing.
- **Required Correction**: Acquire official NIST ACVP FIPS 203 vectors from usnistgov/ACVP-Server; pin mlkem provider.
- **Implementation Summary**: Fetched official NIST ACVP vectors (commit 15c0f3d), documented provenance, validated keygen/encap/decap.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d16.py, tests/vectors/test_fips203_acvp.py`
- **Evidence**: `AUDIT/evidence/D-16/after.txt`
- **Notes**: Remediated in D-16.

### D-01: Missing recipient binding in handshake state machines

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: InitiatorContext and ResponderContext lacked strict peer receiver_id validation.
- **Required Correction**: Mandate receiver_id binding in both initiator and responder; fail on mismatch.
- **Implementation Summary**: Added receiver_id validation and context checking; cross-recipient handshakes rejected.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d01.py`
- **Evidence**: `AUDIT/evidence/D-01/after.txt`
- **Notes**: Closed in Phase 1.

### D-02: Protocol version negotiation and domain separation mismatch

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py, medpqc/utils/validation.py`
- **Original Problem**: Handshake permitted version confusion between legacy and current protocol tags.
- **Required Correction**: Enforce MedPQC-v2.4 domain separation and reject mismatched protocol versions.
- **Implementation Summary**: Standardized on MedPQC-v2.4 across transcripts, suites, and validation helpers.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d02.py`
- **Evidence**: `AUDIT/evidence/D-02/after.txt`
- **Notes**: Closed in Phase 1.

### D-03: Lax timestamp bounds and replay window enforcement

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py, medpqc/security/replay.py`
- **Original Problem**: Negative or out-of-bounds timestamps were accepted by handshake state machine.
- **Required Correction**: Enforce strict uint64 ms bounds and window checking in ResponderContext.
- **Implementation Summary**: Added strict uint64 ms bounds checking and replay window enforcement.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d03.py`
- **Evidence**: `AUDIT/evidence/D-03/after.txt`
- **Notes**: Closed in Phase 1.

### D-04: Missing ReplayStore contract test suite

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/security/replay.py, tests/contract/test_replay_store_contract.py`
- **Original Problem**: ReplayStore implementations lacked unified behavioral contract verification.
- **Required Correction**: Create contract test verifying memory and SQLite stores satisfy identical atomicity semantics.
- **Implementation Summary**: Authored contract tests verifying idempotency, race safety, window expiration, and fail-closed cleanup.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d04.py, tests/contract/test_replay_store_contract.py`
- **Evidence**: `AUDIT/evidence/D-04/after.txt`
- **Notes**: Closed in Phase 1.

### D-05: Direction confusion in session traffic ciphers

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: Single cipher instance permitted encrypting and decrypting with identical traffic keys.
- **Required Correction**: Enforce distinct InitiatorCipher and ResponderCipher types.
- **Implementation Summary**: Implemented direction-bounded cipher wrappers preventing wrong-direction AEAD operations.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d05.py`
- **Evidence**: `AUDIT/evidence/D-05/after.txt`
- **Notes**: Closed in Phase 1.

### D-06: Lax PKCS#8 Ed25519 identity key format and node binding

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: Identity keys lacked standard PEM encoding and node-id attribute binding.
- **Required Correction**: Implement PKCS#8 PEM serialization with embedded Node-ID header.
- **Implementation Summary**: Added to_pem and from_pem methods enforcing PKCS#8 format and embedded Node-ID attribute.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d06.py`
- **Evidence**: `AUDIT/evidence/D-06/after.txt`
- **Notes**: Closed in Phase 1.

### D-07: Missing SECP256R1 ECDH public key format validation

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/ecdh.py`
- **Original Problem**: Lax public key validation permitted compressed or malformed EC points.
- **Required Correction**: Enforce strictly 65-byte uncompressed EC point starting with 0x04.
- **Implementation Summary**: Added explicit byte length and prefix validation in SECP256R1ECDHKEM.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d07.py`
- **Evidence**: `AUDIT/evidence/D-07/after.txt`
- **Notes**: Closed in Phase 1.

### D-08: ML-KEM-768 length validation and secret leakage in error messages

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/rlwe.py`
- **Original Problem**: KEM exceptions included sensitive internal state in string representations.
- **Required Correction**: Enforce exact FIPS 203 lengths and sanitize KEMError messages.
- **Implementation Summary**: Validated 1184B pubkey, 1088B ciphertext, 32B shared secret, and sanitized KEMError exceptions.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d08.py`
- **Evidence**: `AUDIT/evidence/D-08/after.txt`
- **Notes**: Closed in Phase 1.

### D-09: RFC 5869 HKDF-SHA-512 domain-separated context tags

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/combiner.py`
- **Original Problem**: Key combiner used ad-hoc info strings without versioned domain tags.
- **Required Correction**: Update context tags to RFC 5869 format with MedPQC-v2.4 prefix.
- **Implementation Summary**: Updated HKDF info strings with strict MedPQC-v2.4 domain separation.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d09.py`
- **Evidence**: `AUDIT/evidence/D-09/after.txt`
- **Notes**: Closed in Phase 1.

### D-10: ManifestSource.AUTO permitted silent fallback in DICOM decryption

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: decrypt_dicom_file searched for external sidecar if embedded private tag was missing.
- **Required Correction**: Remove ManifestSource.AUTO; require explicit source parameter and fail closed.
- **Implementation Summary**: Removed AUTO enum; decryption fails closed with MissingManifestError if requested source is absent.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d10.py`
- **Evidence**: `AUDIT/evidence/D-10/after.txt`
- **Notes**: Closed in Phase 2.

### D-11: Lax SitePseudonymizationKey length and silent padding

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Short site salt keys were silently padded with zeros instead of raising an error.
- **Required Correction**: Require exactly 32 bytes for SitePseudonymizationKey with no silent zero-padding.
- **Implementation Summary**: Enforced len(key) == 32 check throwing ValueError on invalid length.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d11.py`
- **Evidence**: `AUDIT/evidence/D-11/after.txt`
- **Notes**: Closed in Phase 2.

### D-12: Lossy element serialization corrupted private tags in roundtrip

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Dictionary-based serialization lost binary VR and element representation.
- **Required Correction**: Implement binary serialization preserving exact VR and byte sequence.
- **Implementation Summary**: Implemented serialize_sealed_dataset using DicomBytesIO preserving exact binary dataset.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d12.py`
- **Evidence**: `AUDIT/evidence/D-12/after.txt`
- **Notes**: Closed in Phase 2.

### D-13: UID pseudonymization non-compliance and phantom PatientID synthesis

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Pseudonymized UIDs did not follow ITU-T OID standard arc, and missing PatientID was synthesized.
- **Required Correction**: Use ITU-T 2.25 arc for UIDs and preserve absent PatientID.
- **Implementation Summary**: Standardized UID generation on 2.25 arc and preserved absent PatientID attribute.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d13.py`
- **Evidence**: `AUDIT/evidence/D-13/after.txt`
- **Notes**: Closed in Phase 2.

### D-14: BurnedInAnnotation normalization mismatch during dataset hashing

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: BurnedInAnnotation was modified after dataset hash computation, causing AEAD AAD verification failure.
- **Required Correction**: Normalize BurnedInAnnotation to NO prior to computing dataset hash.
- **Implementation Summary**: Set BurnedInAnnotation = NO before dataset hash calculation.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d14.py`
- **Evidence**: `AUDIT/evidence/D-14/after.txt`
- **Notes**: Closed in Phase 2.

### D-15: Swallowed exceptions in DICOM decompression and parsing

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/handler.py, medpqc/dicom/pacs.py`
- **Original Problem**: Broad except clauses masked underlying format errors during DICOM processing.
- **Required Correction**: Eliminate bare except clauses; re-raise specific typed exceptions.
- **Implementation Summary**: Replaced broad try/except blocks with specific exception handling.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d15.py`
- **Evidence**: `AUDIT/evidence/D-15/after.txt`
- **Notes**: Closed in Phase 2.

### D-16: Missing NIST ACVP FIPS 203 KAT vectors and provider pinning

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `tests/vectors/nist_fips203_kat_vectors.json, tests/vectors/PROVENANCE.json, pyproject.toml`
- **Original Problem**: KAT tests lacked official NIST test vectors with provenance tracking.
- **Required Correction**: Acquire official NIST vectors from usnistgov/ACVP-Server and pin mlkem provider.
- **Implementation Summary**: Integrated official NIST ACVP FIPS 203 vectors, provenance metadata, and pinned mlkem provider.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d16.py`
- **Evidence**: `AUDIT/evidence/D-16/after.txt`
- **Notes**: Closed in Phase 3.

### D-17: Lax Mypy type-checking and coverage exclusion pragmas

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `pyproject.toml`
- **Original Problem**: Mypy ran with lenient options and coverage excluded branches via blanket pragmas.
- **Required Correction**: Enable strict = true in mypy and remove pragma: no cover from coverage config.
- **Implementation Summary**: Enabled strict mypy, fixed all type annotations across codebase, and enabled branch coverage.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d17.py`
- **Evidence**: `AUDIT/evidence/D-17/after.txt`
- **Notes**: Closed in Phase 4.

### D-18: Ruff linting and formatting violations

- **Severity**: Low
- **Status**: **FIXED AND TESTED**
- **Target Files**: `pyproject.toml, medpqc/`
- **Original Problem**: Codebase had linting issues and formatting deviations.
- **Required Correction**: Format codebase and configure ruff rules without disabling security linters.
- **Implementation Summary**: Executed ruff check and format across all 26 source files with 0 violations.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d18.py`
- **Evidence**: `AUDIT/evidence/D-18/after.txt`
- **Notes**: Closed in Phase 4.

### D-19: Bandit automated security scan findings

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/`
- **Original Problem**: Automated security scan flagged unsafe constructions or broad exceptions.
- **Required Correction**: Resolve security scan warnings and verify bandit passes with zero findings.
- **Implementation Summary**: Executed Bandit security scan: zero findings of any severity across 26 source files.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d19.py`
- **Evidence**: `AUDIT/evidence/D-19/after.txt`
- **Notes**: Closed in Phase 4.

### D-20: Mandatory heavy dependencies in core imports and experimental chaos isolation

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/__init__.py, medpqc/experimental/`
- **Original Problem**: Importing medpqc failed without pydicom, and experimental chaos modules were in main namespace.
- **Required Correction**: Implement lazy loading for heavy dependencies and relocate chaos/diffusion to experimental.
- **Implementation Summary**: Relocated chaos and diffusion into medpqc.experimental; implemented __getattr__ lazy imports.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d20.py`
- **Evidence**: `AUDIT/evidence/D-20/after.txt`
- **Notes**: Closed in Phase 4.

### D-21: Single-source version bump to 2.4.0

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `pyproject.toml, medpqc/__init__.py`
- **Original Problem**: Package version remained at 2.3.0 across pyproject.toml and package metadata.
- **Required Correction**: Bump version to 2.4.0 and verify single-source of truth.
- **Implementation Summary**: Updated version to 2.4.0 in pyproject.toml and medpqc.__version__.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d21.py`
- **Evidence**: `AUDIT/evidence/D-21/after.txt`
- **Notes**: Closed in Phase 5.

### D-22: Reproducible empirical benchmarks with raw per-repetition measurements

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `benchmarks/run_benchmarks.py, benchmarks/analyze.py, benchmarks/plot.py`
- **Original Problem**: Benchmarks reported hand-edited summaries without per-repetition raw CSVs or bootstrap CIs.
- **Required Correction**: Rebuild benchmark runner with raw CSV outputs, bootstrap 95% CIs, and 4-arm ablation.
- **Implementation Summary**: Implemented raw per-repetition CSV collection, separate analyze/plot scripts, and disclaimers.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d22.py`
- **Evidence**: `AUDIT/evidence/D-22/after.txt`
- **Notes**: Closed in Phase 5.

### D-23: Machine-readable audit ledger and prohibited legacy status

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `AUDIT/ledger.yaml, scripts/generate_ledger_md.py`
- **Original Problem**: Ledger dropped register IDs, contained prohibited non-mandated status vocabulary, and lacked machine enforcement.
- **Required Correction**: Maintain AUDIT/ledger.yaml as single source of truth with mandated status vocabulary.
- **Implementation Summary**: Created AUDIT/ledger.yaml with all register IDs and rendered markdown reports mechanically.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d23.py`
- **Evidence**: `AUDIT/evidence/D-23/after.txt`
- **Notes**: Closed in Phase 5.

### D-24: Evidence report formatting, strict LF endings, and normalized paths

- **Severity**: Low
- **Status**: **FIXED AND TESTED**
- **Target Files**: `AUDIT/evidence/`
- **Original Problem**: Evidence files contained CRLF endings and local absolute Windows paths.
- **Required Correction**: Normalize line endings to LF and strip local absolute filesystem paths.
- **Implementation Summary**: Normalized all evidence files to LF line endings and /workspace/medpqc relative paths.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d24.py`
- **Evidence**: `AUDIT/evidence/D-24/after.txt`
- **Notes**: Closed in Phase 5.

### D-25: Protocol specification vector synchronization and pinning

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `docs/PROTOCOL_SPECIFICATION.md, tests/vectors/transcripts.json, tests/vectors/test_transcripts.py`
- **Original Problem**: PROTOCOL_SPECIFICATION.md transcripts differed from tests/vectors/transcripts.json.
- **Required Correction**: Synchronize specification with bit-for-bit test vector output and add synchronization test.
- **Implementation Summary**: Synchronized fixed-byte transcript hexes in specification and added test_spec_vectors_sync.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_d25.py, tests/vectors/test_transcripts.py`
- **Evidence**: `AUDIT/evidence/D-25/after.txt`
- **Notes**: Closed in Phase 5.

### N-01: Handshake API split: InitiatorContext and ResponderContext

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py`
- **Original Problem**: Monolithic HandshakeState conflated initiator and responder roles, allowing cross-role state confusion.
- **Required Correction**: Split handshake into explicit InitiatorContext and ResponderContext classes.
- **Implementation Summary**: Created InitiatorContext and ResponderContext with strict role validation and directional state machines.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n01.py, tests/test_handshake_state_machine.py`
- **Evidence**: `AUDIT/evidence/N-01/after.txt`
- **Notes**: Closed in Phase 1.

### N-02: Replay store durability warning and strict operational enforcement

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/security/replay.py, medpqc/kem/auth.py`
- **Original Problem**: In-memory replay store could be instantiated without explicit acknowledgment of non-durability.
- **Required Correction**: Emit NonDurableReplayStoreWarning and require allow_non_durable_replay_store=True in ResponderContext.
- **Implementation Summary**: Added NonDurableReplayStoreWarning, enforced explicit parameter for non-durable stores in ResponderContext.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n02.py, tests/test_replay.py`
- **Evidence**: `AUDIT/evidence/N-02/after.txt`
- **Notes**: Closed in Phase 1.

### N-03: Obsolete handshake API removal and compatibility documentation

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/kem/auth.py, AUDIT/compat_paths.yaml`
- **Original Problem**: Deprecated handshake functions remained with silent shims and lacked clear upgrade documentation.
- **Required Correction**: Raise RemovedAPIError with clear migration guidance and provide AUDIT/compat_paths.yaml.
- **Implementation Summary**: Removed obsolete functions with RemovedAPIError pointing to InitiatorContext/ResponderContext and documented mappings.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n03.py`
- **Evidence**: `AUDIT/evidence/N-03/after.txt`
- **Notes**: Closed in Phase 1.

### N-04: Default-deny retained attributes allow-list for DICOM headers

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/retained_attributes.py, medpqc/dicom/pacs.py`
- **Original Problem**: Permissive attribute retention exposed potentially sensitive patient metadata in encrypted containers.
- **Required Correction**: Enforce strict default-deny allow-list containing only structural tags necessary for routing.
- **Implementation Summary**: Defined MANDATORY_STRUCTURAL_TAGS and OPTIONAL_ALLOWLIST_TAGS in retained_attributes.py with default-deny filtering.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n04.py, tests/test_dicom_allowlist.py`
- **Evidence**: `AUDIT/evidence/N-04/after.txt`
- **Notes**: Closed in Phase 2.

### N-05: Element-exact restoration from sealed dataset

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: DICOM decryption reconstructed headers from partial metadata rather than bit-for-bit sealed dataset.
- **Required Correction**: Serialize and encrypt complete original dataset, restore exactly upon decryption.
- **Implementation Summary**: Serialized original dataset into encrypted payload and deserialized element-for-element during decryption.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n05.py, tests/test_dicom_exact_restoration.py`
- **Evidence**: `AUDIT/evidence/N-05/after.txt`
- **Notes**: Closed in Phase 2.

### N-06: restore_dicom_file interface and sidecar elimination

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Manifest sidecar file was generated by default, potentially leaking file existence or metadata.
- **Required Correction**: Eliminate default sidecar creation and require explicit ManifestSource parameter in decrypt_dicom_file.
- **Implementation Summary**: Removed default sidecar creation; decrypt_dicom_file requires explicit source parameter; restored restore_dicom_file.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n06.py`
- **Evidence**: `AUDIT/evidence/N-06/after.txt`
- **Notes**: Closed in Phase 2.

### N-07: Atomic file writes via NamedTemporaryFile and os.replace

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: File operations wrote directly to destination paths, risking partial or corrupted files upon crash.
- **Required Correction**: Perform all file writes using NamedTemporaryFile in the target directory followed by os.replace.
- **Implementation Summary**: Implemented atomic_write helper using NamedTemporaryFile with delete=False and os.replace.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n07.py`
- **Evidence**: `AUDIT/evidence/N-07/after.txt`
- **Notes**: Closed in Phase 2.

### N-08: Removal of insecure site_salt and anonymize_headers parameters

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: Pseudonymization accepted arbitrary site_salt or anonymize_headers toggles that bypassed key derivation.
- **Required Correction**: Remove site_salt and anonymize_headers parameters; require SitePseudonymizationKey.
- **Implementation Summary**: Removed obsolete parameters; enforced SitePseudonymizationKey across all pseudonymization paths.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n08.py`
- **Evidence**: `AUDIT/evidence/N-08/after.txt`
- **Notes**: Closed in Phase 2.

### N-09: Rejection of curves, overlays, burned-in annotations, and unsupported transfer syntaxes

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/dicom/pacs.py`
- **Original Problem**: DICOM parser accepted datasets containing unsafe curve data, overlay planes, or unhandled compressed syntaxes.
- **Required Correction**: Explicitly validate and reject curves, overlays, burned-in annotations, and unsupported transfer syntaxes.
- **Implementation Summary**: Added validation checks rejecting curve tags (50xx), overlay tags (60xx), burned-in annotations, and unhandled syntaxes.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n09.py`
- **Evidence**: `AUDIT/evidence/N-09/after.txt`
- **Notes**: Closed in Phase 2.

### N-10: Targeted mutation testing with score >= 85%

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `scripts/run_mutation_tests.py, AUDIT/evidence/mutation/mutation_results.json`
- **Original Problem**: Mutation testing was limited to a subset of files and lacked comprehensive mutant coverage across core modules.
- **Required Correction**: Expand mutation suite across 6 core modules, evaluate >= 60 mutants with >= 85% killed score.
- **Implementation Summary**: Expanded mutant generator across core modules: 63 mutants evaluated, 60 killed (95.24% mutation score).
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n10.py`
- **Evidence**: `AUDIT/evidence/N-10/after.txt`
- **Notes**: Closed in Phase 3.

### N-11: Branch coverage floors: >= 90% core, >= 85% utils

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `scripts/verify_release.py, scripts/generate_test_report.py`
- **Original Problem**: Coverage verifier permitted 80% coverage floors, allowing unverified branches in critical security modules.
- **Required Correction**: Raise branch coverage floors to >= 90% for core modules (kem, cipher, security, dicom) and >= 85% for utils.
- **Implementation Summary**: Updated verify_release.py with raised floors: kem (93.9%), cipher (95.2%), security (96.7%), dicom (92.4%), utils (88.6%).
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n11.py`
- **Evidence**: `AUDIT/evidence/N-11/after.txt`
- **Notes**: Closed in Phase 3.

### N-12: Clean mypy strict typing and machine-generated pip-audit report

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `medpqc/experimental/toy_rlwe.py, AUDIT/evidence/static/pip_audit_report.json, scripts/run_static_analysis.py`
- **Original Problem**: mypy reported type issues in experimental modules and pip-audit evidence was hand-written prose.
- **Required Correction**: Fix type cast in toy_rlwe.py for clean mypy and generate machine-readable JSON for pip-audit.
- **Implementation Summary**: Added explicit type cast in toy_rlwe.py; updated static analysis runner to produce machine JSON for pip-audit.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n12.py`
- **Evidence**: `AUDIT/evidence/N-12/after.txt`
- **Notes**: Closed in Phase 3.

### N-13: Benchmark CSV line ending normalization (LF)

- **Severity**: Low
- **Status**: **FIXED AND TESTED**
- **Target Files**: `benchmarks/results/ablation_results.csv, benchmarks/results/handshake_bench.csv, benchmarks/results/raw/`
- **Original Problem**: Benchmark CSV files in benchmarks/results/ contained CRLF line endings.
- **Required Correction**: Normalize all benchmark CSV files to strict LF line endings.
- **Implementation Summary**: Re-saved all benchmark CSV files with unix LF line endings.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n13.py`
- **Evidence**: `AUDIT/evidence/N-13/after.txt`
- **Notes**: Closed in Phase 3.

### N-14: Documentation and claims scanner with zero un-negated forbidden terms

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `README.md, CHANGELOG.md, docs/, AUDIT/`
- **Original Problem**: Documentation and audit files contained un-negated marketing and compliance assertions.
- **Required Correction**: Audit all text files and eliminate or negate all forbidden terms across docs and audit reports.
- **Implementation Summary**: Scanned and eliminated un-negated forbidden words; added automated scanner in test_exploit_n14.py.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n14.py, tests/docs/test_forbidden_claims.py`
- **Evidence**: `AUDIT/evidence/N-14/after.txt`
- **Notes**: Closed in Phase 4.

### N-15: Dynamic ledger status derivation and forbidden status tokens

- **Severity**: High
- **Status**: **FIXED AND TESTED**
- **Target Files**: `AUDIT/ledger.yaml, scripts/generate_ledger_md.py`
- **Original Problem**: AUDIT/ledger.yaml contained hardcoded status fields and reports contained forbidden legacy status tokens.
- **Required Correction**: Strip status from ledger.yaml, derive status dynamically from tests/evidence, ban legacy tokens.
- **Implementation Summary**: Removed hardcoded status from ledger.yaml; updated generate_ledger_md.py to dynamically derive status.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n15.py`
- **Evidence**: `AUDIT/evidence/N-15/after.txt`
- **Notes**: Closed in Phase 4.

### N-16: Strict LF line endings in release artifacts and SHA256SUMS.txt

- **Severity**: Low
- **Status**: **FIXED AND TESTED**
- **Target Files**: `.gitattributes, release/SHA256SUMS.txt`
- **Original Problem**: .gitattributes did not strictly enforce LF for release manifests and SHA256SUMS.txt had CRLF.
- **Required Correction**: Enforce LF via .gitattributes and normalize SHA256SUMS.txt line endings.
- **Implementation Summary**: Updated .gitattributes to enforce eol=lf and normalized release checksum manifests.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n16.py, tests/adversarial/exploits/test_exploit_d24.py`
- **Evidence**: `AUDIT/evidence/N-16/after.txt`
- **Notes**: Closed in Phase 4.

### N-17: Specification-code agreement and executable doc examples script

- **Severity**: Medium
- **Status**: **FIXED AND TESTED**
- **Target Files**: `docs/PROTOCOL_SPECIFICATION.md, scripts/run_doc_examples.py`
- **Original Problem**: PROTOCOL_SPECIFICATION.md lacked context API documentation, referenced K_mac, and doc examples lacked CI runner.
- **Required Correction**: Document InitiatorContext/ResponderContext, remove K_mac, and implement scripts/run_doc_examples.py.
- **Implementation Summary**: Updated PROTOCOL_SPECIFICATION.md with context API details and directional keys; added run_doc_examples.py.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n17.py`
- **Evidence**: `AUDIT/evidence/N-17/after.txt`
- **Notes**: Closed in Phase 4.

### N-18: Release verifier hardening with code_tree_hash and zero status exclusions

- **Severity**: Critical
- **Status**: **FIXED AND TESTED**
- **Target Files**: `scripts/verify_release.py`
- **Original Problem**: verify_release.py filtered dirty git status lines with whitelist and lacked code_tree_hash binding.
- **Required Correction**: Enforce zero git status exclusions and implement cryptographic code_tree_hash binding.
- **Implementation Summary**: Hardened Gate 1 to forbid all porcelain status lines and bound verification to code_tree_hash.
- **Verification Tests**: `tests/adversarial/exploits/test_exploit_n18.py`
- **Evidence**: `AUDIT/evidence/N-18/after.txt`
- **Notes**: Closed in Phase 5.

