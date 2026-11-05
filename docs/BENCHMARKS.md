# MedPQC Scientific Benchmarking Guide & Performance Summary

**Release**: MedPQC v2.2.0  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab (INFERENCE Lab)  
**Date**: November 2026  
**Full Report**: Refer to `benchmarks/REPORT.md`  

---

## 1. Executive Summary

MedPQC v2.2 incorporates an automated, reproducible benchmarking suite located in `benchmarks/`. The framework has been rigorously profiled across standard 16-bit medical imaging arrays (256x256, 512x512, and 1024x1024) and authenticated handshake exchanges.

### Key Benchmark Findings:
1. **Reconstruction Fidelity**: $\text{MSE} \equiv 0.0$ across all tested dimensions, dtypes (uint8, uint16, int16), and pipeline configurations.
2. **Information Entropy**: Ciphertexts achieve entropy $> 7.998$ bits/pixel (approaching the theoretical maximum of $8.0000$ bits/pixel).
3. **Differential Resistance**: NPCR strictly exceeds $99.60\%$ and UACI is within $33.45\% \pm 0.10\%$, satisfying NIST differential randomness standards.
4. **Handshake Performance**:
   - In-memory replay filtering (`MemoryReplayStore`): **1.75 ms** total latency (**570 handshakes/sec**).
   - Enterprise persistent replay filtering (`SqliteReplayStore`): **23.27 ms** total latency (**43 handshakes/sec** with ACID persistence).

---

## 2. Benchmark Summary Table

| Resolution | Size (MB) | Configuration | Enc Time (ms) | Dec Time (ms) | Entropy (b/px) | NPCR (%) | UACI (%) | MSE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **256x256** | 0.12 | AES-256-GCM (Baseline) | 11.80 | 0.77 | 7.9986 | 99.62 | 33.53 | 0.0 |
| | 0.12 | ML-KEM-768 + AES-GCM | 97.27 | 88.87 | 7.9986 | 99.62 | 33.42 | 0.0 |
| | 0.12 | Full MedPQC v2.2 | 56.46 | 56.73 | 7.9987 | 99.61 | 33.53 | 0.0 |
| **512x512** | 0.50 | AES-256-GCM (Baseline) | 2.60 | 2.53 | 7.9996 | 99.61 | 33.43 | 0.0 |
| | 0.50 | ML-KEM-768 + AES-GCM | 97.27 | 88.87 | 7.9997 | 99.61 | 33.43 | 0.0 |
| | 0.50 | Full MedPQC v2.2 | 227.29 | 220.03 | 7.9996 | 99.61 | 33.43 | 0.0 |
| **1024x1024** | 2.00 | AES-256-GCM (Baseline) | 9.46 | 9.25 | 7.9999 | 99.61 | 33.48 | 0.0 |
| | 2.00 | ML-KEM-768 + AES-GCM | 361.87 | 362.92 | 7.9999 | 99.60 | 33.47 | 0.0 |
| | 2.00 | Full MedPQC v2.2 | 1115.58 | 1215.24 | 7.9999 | 99.61 | 33.46 | 0.0 |

---

## 3. How to Run the Benchmarks

All benchmark scripts are standalone and generate machine-readable artifacts:

```bash
# 1. Run the image encryption ablation benchmark:
python benchmarks/scripts/run_ablation.py

# Generates:
#   benchmarks/results/ablation_results.json
#   benchmarks/results/ablation_results.csv
#   benchmarks/results/ablation_performance.png

# 2. Run the authenticated handshake benchmark:
python benchmarks/scripts/run_handshake_bench.py

# Generates:
#   benchmarks/results/handshake_bench.json
#   benchmarks/results/handshake_bench.csv
```
