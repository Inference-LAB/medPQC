# MedPQC Baseline Security and Architectural Audit Report

**Target Package**: MedPQC (Research Implementation for Medical Image Cryptographic Protection)  
**Baseline Inspected**: v2.2.0 (Git Commit: `7367c26d05c2ef9ada3f7e2a0684362aa614e00d`)  
**Target Release**: v2.3.0  
**Audit Date**: November 1, 2026  
**Status**: RESEARCH IMPLEMENTATION - AUDIT IN PROGRESS  

---

## 1. Executive Summary

This audit report evaluates the MedPQC v2.2.0 baseline against cryptographic engineering standards, DICOM protocol specifications, and secure coding practices. 

An adversarial investigation was conducted directly against the unmodified v2.2 source code. The investigation confirmed that despite previous remediation passes, multiple Critical and High-severity defects remain in the baseline codebase. Automated exploit tests were constructed under `tests/adversarial/exploits/` and executed against the v2.2 baseline; 20 test cases failed, confirming reproducible vulnerabilities across handshake authentication, replay protection, DICOM privacy, key derivation, and input validation.

---

## 2. Section 0.2 Unverified Items: Direct Verification Outcomes

The following technical points were unverified in prior reviews and were empirically tested:

### 2.1 `medpqc.utils.canonical` (`canonical_json_loads`)
- **Duplicate Keys**: Refuted / Defective. `canonical_json_loads` uses standard `json.loads` without an `object_pairs_hook`. `canonical_json_loads('{"a":1, "a":2}')` silently returns `{"a": 2}`, permitting duplicate key collision attacks.
- **NaN / Infinity**: Refuted / Defective. Standard `json.loads` parses `NaN`, `Infinity`, and `-Infinity` into float constants by default (`parse_constant` is not disabled), violating RFC 8785 canonical JSON specifications.
- **Nesting Depth & Input Size**: Refuted / Defective. There is no recursion depth cap or byte length limit prior to JSON parsing, leaving the parser vulnerable to stack exhaustion and memory exhaustion DoS.

### 2.2 DICOM-Level Behavior for Complex Formats
- **Multiframe, RGB, Signed Pixels, Bit Depths**: Defective. While `MedPQCCipher` operates on in-memory NumPy arrays for various dtypes, `medpqc.dicom.handler.MedicalImageIO.save` and `DICOMPACSEnvelope` assume 2D single-frame monochrome images (`Rows`, `Columns`, `PhotometricInterpretation="MONOCHROME2"`, `SamplesPerPixel=1`). Multiframe or RGB inputs lack planar configuration handling and frame dimension parsing at the DICOM object level.
- **Big-Endian and Compressed Syntaxes**: Unsupported. Handled by raising exceptions, but explicit profile validation at the dataset level is missing.

### 2.3 `.github/workflows/ci-cd.yml`
- **Supported Python Matrix**: Defective. The workflow executes only on Python 3.10, 3.11, and 3.12 on Ubuntu and Windows. Declared support in `pyproject.toml` claims `requires-python = ">=3.9"` and classifiers through 3.14. Python 3.13, Python 3.14, and macOS are omitted from CI testing.
- **Publish Step in CI**: Defective. Line 77 of `.github/workflows/ci-cd.yml` invokes `pypa/gh-action-pypi-publish@release/v1` on tag pushes. The release engineering rules mandate that CI workflows must not publish packages.
- **Static Analysis & QA Gates**: Missing. The workflow lacks type checking (`mypy`), linting (`ruff`), security scanning (`bandit`), dependency vulnerability scanning (`pip-audit`), and wheel installation testing.

### 2.4 Provenance and Version of `mlkem` Provider
- **Installed Package**: `mlkem` version 0.2.0 (PyPI: `https://pypi.org/project/mlkem/`).
- **Implementation**: PyO3 Rust extension implementing NIST FIPS 203 ML-KEM.
- **Interface Limitations**: The public API exposes `ML_KEM.key_gen()` (takes 0 arguments, generates internal entropy) and `ML_KEM.encaps(ek)` (takes 1 argument, generates internal entropy). It does NOT expose deterministic `(d, z)` seeds for key generation or `m` seeds for encapsulation. Consequently, deterministic NIST ACVP Known-Answer-Testing with this provider is strictly limited to `decaps(dk, c) -> ss` and cipher-text rejection testing. Passing KAT decapsulation tests does not constitute formal FIPS 140 or CAVP certification.

### 2.5 Test Coverage Claims
- **Exclusion Analysis**: The prior claim had no 100% test coverage in reality and relied on `pyproject.toml` excluding `pragma: no cover`, `except ImportError:`, `def njit`, `@njit`, and error handling paths, while branch coverage (`branch = true`) was disabled. With exclusions removed and branch coverage evaluated, actual line and branch coverage is lower.

### 2.6 Wheel Installability in Clean Virtual Environment
- **Wheel Build & Install**: The wheel `medpqc-2.2.0-py3-none-any.whl` builds and installs via pip, but tests were executed against the source tree (`tests/`) rather than an isolated installation with `--import-mode=importlib`.

### 2.7 Import-Time Dependency Footprint
- **Eager Heavy Imports**: Confirmed defective. Executing `import medpqc` immediately imports `numba`, `scipy`, `cv2`, and `pydicom`. Core cryptographic primitives (KEM, AEAD, KDF) cannot be used in lightweight environments without installing all heavy image and JIT dependencies.

### 2.8 Sidecar Filenames and PHI Leakage
- **Path Generation**: Confirmed defective. `DICOMPACSEnvelope` constructs sidecar paths as `output_dcm_path + ".pqc.json"`. If the output file is named using patient identifiers (e.g. `DOE_JOHN_CT.dcm`), the sidecar filename leaks PHI. Furthermore, sidecar files are created unconditionally by default.

### 2.9 Provenance and PHI Status of `tests_data/`
- **Clinical/Non-Synthetic Files**: Confirmed defective. The repository contains `tests_data/real_ct_16bit.dcm` (containing PatientName `DOE^JOHN`, PatientID `CLINICAL-12345`), `tests_data/real_mr_16bit.dcm`, ten clinical chest X-ray PNGs (`tests_data/clinical_cohort/real_chest_xray_*.png`), and `tests_data/pneumoniamnist.npz` (4.17 MB). Shipping non-synthetic data or files named "real" violates synthetic data isolation requirements.

---

## 3. Vulnerability Register Summary

| ID | Sev | Component | Description | Exploit Status |
| :--- | :--- | :--- | :--- | :--- |
| **F-HS-01** | C | `kem/auth.py` | `allow_unauthenticated` parameter present in public handshake and PACS APIs. | Confirmed by `test_exploit_f_hs_01.py` |
| **F-HS-02** | C | `kem/auth.py` | No suite or version allow-list; responder accepts arbitrary weak suites (e.g. `NONE+ECDH-only`). | Confirmed by `test_exploit_f_hs_02.py` |
| **F-HS-03** | H | `kem/auth.py` | Missing recipient binding; Carol can respond to messages addressed to Bob. | Confirmed by `test_exploit_f_hs_03.py` |
| **F-HS-04** | C | `security/replay.py` | Replay protection is optional (`replay_protector=None`) and non-atomic under concurrency. | Confirmed by `test_exploit_f_hs_04.py` |
| **F-HS-05** | H | `security/trust.py` | TrustStore lacks key rotation, validity windows, atomic saves, and safe revocation semantics. | Confirmed by source inspection |
| **F-HS-06** | H | `kem/combiner.py` | Hand-rolled HKDF with silent `sha3_512` fallback and fixed `MedPQC-Salt-v2.1` salt. | Confirmed by `test_exploit_f_hs_06.py` |
| **F-HS-07** | M | `kem/ecdh.py`, `rlwe.py` | Missing validation of uncompressed P-256 points; responder generates wasteful throwaway keypair. | Confirmed by source inspection |
| **F-HS-08** | M | `kem/auth.py` | `IdentityKeyPair.verify` swallows all exceptions; private key lifecycle undefined. | Confirmed by source inspection |
| **F-HS-09** | H | `kem/auth.py` | No canonical binary wire format, message parsing, or formal session state machine. | Confirmed by source inspection |
| **F-KAT-01**| H | `tests/vectors/` | 4 unsourced decapsulation-only vectors; duplicate vector files; toy RLWE alias exported. | Confirmed by file comparison |
| **F-ENV-01**| H | `cipher/engine.py` | No size, dimension, or manifest limits enforced before memory allocation. | Confirmed by `test_exploit_f_env_01.py` |
| **F-ENV-02**| H | `cipher/aead.py` | AAD omits session context, envelope ID, transfer syntax, and dataset hash binding. | Confirmed by source inspection |
| **F-ENV-03**| M | `cipher/aead.py` | Redundant outer HMAC-SHA3-256 layer and unused `k_mac`. | Confirmed by source inspection |
| **F-ENV-04**| H | `cipher/engine.py` | 96-bit random nonces without per-key usage counters, rekey limits, or direction separation. | Confirmed by source inspection |
| **F-ENV-05**| M | `cipher/aead.py` | Duplicate crypto libraries; AES-GCM implemented via PyCryptodome instead of `cryptography`. | Confirmed by dependencies check |
| **F-ENV-06**| M | `dicom/pacs.py` | Base64-in-JSON envelope representation introduces parsing overhead and serialization hazards. | Confirmed by source inspection |
| **F-DICOM-01**| C | `dicom/pacs.py` | Hard-coded default site salt `b"MedPQC-Site-Salt-2026"` used as default parameter. | Confirmed by `test_exploit_f_dicom_01.py` |
| **F-DICOM-02**| C | `dicom/pacs.py` | Static PHI AAD allows cross-object PHI blob substitution; cleartext header tampering accepted. | Confirmed by `test_exploit_f_dicom_02.py` |
| **F-DICOM-03**| H | `dicom/pacs.py` | Silent fallback from corrupted embedded manifest to unauthenticated sidecar file. | Confirmed by `test_exploit_f_dicom_03.py` |
| **F-DICOM-04**| H | `dicom/pacs.py` | Swallowed exceptions (`try: setattr ... except: pass`) and legacy v2.1 AAD fallback. | Confirmed by source inspection |
| **F-DICOM-05**| H | `dicom/pacs.py` | Incomplete PHI de-identification: Study UIDs, dates, and private tags survive in cleartext. | Confirmed by `test_exploit_f_dicom_05.py` |
| **F-DICOM-06**| H | `dicom/pacs.py` | Encrypted DICOM masquerades as valid image; version embedded in private creator name. | Confirmed by source inspection |
| **F-DICOM-07**| H | `dicom/handler.py` | DICOM-level profile constraints not enforced; unsupported formats fail unpredictably. | Confirmed by source inspection |
| **F-DICOM-08**| M | docs / audit | Interoperability claims with clinical PACS are unverified. | Confirmed: no live PACS tested |
| **F-DICOM-09**| M | `dicom/pacs.py` | Non-atomic file writes and potential path traversal vulnerabilities. | Confirmed by source inspection |
| **F-DICOM-10**| M | `tests_data/` | Repository ships non-synthetic images and clinical datasets (`real_ct_16bit.dcm`, etc.). | Confirmed by `test_exploit_f_rel_01.py` |
| **F-CHAOS-01**| H | `cipher/engine.py` | Chaotic scrambling is enabled by default; experimental code integrated into default path. | Confirmed by `test_exploit_f_chaos_01.py` |
| **F-CHAOS-02**| M | `chaos/permutation.py`| Permutation relies on `np.argsort` with potential float collision bias. | Confirmed by source inspection |
| **F-CHAOS-03**| M | `chaos/lorenz.py` | JIT compilation uses `fastmath=True` with potential cross-platform divergence. | Confirmed by source inspection |
| **F-QA-01** | H | `tests/integration` | Integration test directory is empty (`__init__.py` only). | Confirmed by directory check |
| **F-QA-02** | H | `tests/adversarial` | Adversarial test suite is incomplete. | Confirmed by test coverage check |
| **F-QA-03** | M | `pyproject.toml` | Coverage artificially inflated by blanket exclusion pragmas. | Confirmed by configuration check |
| **F-QA-04** | M | `tests/fuzz` | No fuzzing targets implemented for message parsers or manifests. | Confirmed: fuzz directory missing |
| **F-QA-05** | M | CI / tooling | No automated static analysis (`mypy`, `ruff`, `bandit`, `pip-audit`). | Confirmed by CI inspection |
| **F-QA-06** | M | packaging | Tests not executed against installed wheel in isolated virtual environment. | Confirmed by test workflow check |
| **F-QA-07** | M | CI | CI workflow does not cover declared Python versions or OS matrix; publishes on tag. | Confirmed by `ci-cd.yml` check |
| **F-PKG-01** | M | `pyproject.toml` | Stale build artifacts, duplicate author declarations, eager top-level imports. | Confirmed by package inspection |
| **F-BENCH-01**| H | `benchmarks/` | Single-shot measurements without variance or confidence intervals; 1070ms anomaly. | Confirmed by benchmark review |
| **F-DOC-01** | C | `docs/`, `AUDIT/` | Unsupported claims: contains no valid IND-CCA2 proofs, is not HIPAA-compliant, is not production-grade, and makes no Elsevier Q1 claims. | Confirmed by `test_exploit_f_doc_01.py` |
| **F-DOC-02** | H | `docs/` | Protocol specifications mismatch actual code implementation; missing ADRs and limits. | Confirmed by doc review |
| **F-DOC-03** | H | `AUDIT/` | Foreign-machine test logs and self-certified sign-offs instead of reproducible outputs. | Confirmed by audit review |
| **F-DOC-04** | L | `docs/` | Duplicate changelog files and inconsistent casing in documentation paths. | Confirmed by directory check |
| **F-REL-01** | M | `release/` | Release staging contains `.coverage`, `.pytest_cache`, stale artifacts, CRLF checksums. | Confirmed by `test_exploit_f_rel_01.py` |

---

## 4. Remediation Plan

The remediation proceeds systematically across 10 sequential phases:
1. **Phase 1: Cryptographic Core**: Deduplicate vectors, isolate toy KEM to `medpqc.experimental`, enforce strict key-share validation.
2. **Phase 2: Handshake, Trust, Replay**: Eliminate `allow_unauthenticated`, implement suite registry and downgrade defense, bind recipient identities, require atomic SQLite/memory replay store, standardize on library HKDF.
3. **Phase 3: Cipher and Envelope**: Introduce `limits.py`, construct canonical binary envelope AAD binding dataset hash and envelope ID, remove redundant outer HMAC and unused `k_mac`, enforce nonce lifecycle.
4. **Phase 4: DICOM Redesign**: Remove hardcoded salt, implement single authenticated encrypted object with dataset hash comparison, eliminate silent sidecar fallback, implement recursive PS 3.15 Annex E scrubbing, purge clinical test data.
5. **Phase 5: Experimental Chaos Isolation**: Relocate all chaos code to `medpqc.experimental/`, default cipher to pure `aes-gcm`, implement unbiased Fisher-Yates shuffle.
6. **Phase 6: QA, Tooling, Fuzzing**: Implement integration tier, adversarial suite, Hypothesis fuzz targets, static analysis (`mypy`, `ruff`, `bandit`), wheel-install test harness.
7. **Phase 7: Benchmarks**: Re-run multi-repetition (>=30) benchmarks with confidence intervals and memory profiling.
8. **Phase 8: Documentation & Claims**: Purge all forbidden marketing and formal proof claims; update specifications and ADRs.
9. **Phase 9: Adversarial Review**: Execute exploit tests against remediated code and verify resolution.
10. **Phase 10: Release Engineering**: Generate clean release tree, source tarball, wheel, zip, and LF-delimited SHA256SUMS.txt.
