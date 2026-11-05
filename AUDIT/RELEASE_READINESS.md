# MedPQC v2.5.0 Release Readiness Assessment

- **Status**: RESEARCH RELEASE: SECURITY REVIEW INCOMPLETE
- **Target Package**: `medpqc` v2.5.0
- **Verification Enforced By**: `scripts/verify_release.py` (13 machine-checked gates)

---

## 1. Defect Register Status Breakdown

| Status | Count | Mandated Meaning |
| :--- | :--- | :--- |
| **FIXED AND TESTED** | 84 | Reproducing exploit test passed, fix committed, regression tested. |
| **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED** | 2 | Remediated in tree but awaiting external confirmation. |
| **PARTIALLY FIXED** | 0 | Initial remediation committed; residual aspects remain. |
| **NOT APPLICABLE** | 0 | Finding rendered irrelevant by architectural redesign. |

---

## 2. Release Gate Verification Matrix

All 13 gates must be mechanically checked by `scripts/verify_release.py`:

| Gate # | Gate Name | Command / Inspection | Status | Evidence Path |
| :--- | :--- | :--- | :--- | :--- |
| **Gate 1** | Clean Git Tree & Tag | `git status --porcelain` and `git describe --tags` | PASSED | `AUDIT/evidence/gates/gate_01_git.txt` |
| **Gate 2** | Exploit Tests (D-01..D-25, N-01..N-18) | `pytest tests/adversarial/exploits/` | PASSED | `AUDIT/evidence/gates/gate_02_exploits.txt` |
| **Gate 3** | Full Regression Suite | `pytest tests/` | PASSED | `AUDIT/evidence/gates/gate_03_test_suite.txt` |
| **Gate 4** | Branch Coverage Floors | `pytest --cov=medpqc --cov-branch` | PASSED | `AUDIT/evidence/gates/gate_04_coverage.txt` |
| **Gate 5** | Static Analysis Suite | `mypy`, `ruff`, `bandit`, `pip-audit` | PASSED | `AUDIT/evidence/gates/gate_05_static.txt` |
| **Gate 6** | AST Policy Checks | AST scan for forbidden functions and patterns | PASSED | `AUDIT/evidence/gates/gate_06_ast_policy.txt` |
| **Gate 7** | Import Isolation | Subprocess minimal import check | PASSED | `AUDIT/evidence/gates/gate_07_imports.txt` |
| **Gate 8** | KAT Provenance | Hash check on `nist_fips203_kat_vectors.json` | PASSED | `AUDIT/evidence/gates/gate_08_kat.txt` |
| **Gate 9** | Documentation & Claims | Regex scan for forbidden marketing terms | PASSED | `AUDIT/evidence/gates/gate_09_docs.txt` |
| **Gate 10** | Packaging Verification | `python -m build` wheel and sdist check | PASSED | `AUDIT/evidence/gates/gate_10_packaging.txt` |
| **Gate 11** | Checksum Verification | `sha256sum -c release/SHA256SUMS.txt` | PASSED | `AUDIT/evidence/gates/gate_11_checksums.txt` |
| **Gate 12** | Reproducible Benchmarks | Multi-arm microbenchmark and dataset validation | PASSED | `AUDIT/evidence/gates/gate_12_benchmarks.txt` |
| **Gate 13** | Audit Ledger Validation | `ledger.yaml` completeness and vocabulary | PASSED | `AUDIT/evidence/gates/gate_13_ledger.txt` |

---

## 3. Explicit Residual Limitations

1. **Research Implementation**: MedPQC is an exploratory research framework and is neither evaluated nor certified for clinical deployment.
2. **Replay Cache Durability**: In-memory replay stores are strictly non-durable across process restarts. Operational environments must configure SQLite WAL replay stores or equivalent persistent stores.
3. **Experimental Cryptographic Primitives**: Lorenz chaotic scrambling in `medpqc.chaos.lorenz` and toy RLWE in `medpqc.experimental.toy_rlwe` are isolated for experimental and academic study only.

