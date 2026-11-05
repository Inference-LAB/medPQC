# MedPQC v2.4.0 Scientific Benchmarking and Empirical Evaluation Report

- **Status**: RESEARCH RELEASE: SECURITY REVIEW INCOMPLETE
- **Git Commit**: `a0ad75652c53f59ec59391f1fddce98939747af6`
- **Operating System**: Windows 11 (AMD64)
- **Python Runtime**: 3.14.0 (CPython)
- **Numba Status**: Available (njit enabled for CCD loops)
- **Statistical Methodology**: N >= 30 randomized repetitions per cell, warmup executed, 95% bootstrap confidence intervals computed.

---

## 1. Cryptographic Handshake Performance

Evaluates the authenticated hybrid post-quantum handshake (P-256 + ML-KEM-768 + Ed25519) across replay storage backends:

| Replay Store Backend | Reps | Mean Total (ms) | 95% Bootstrap CI (ms) | Median (ms) | p95 (ms) | Handshakes/sec | Peak RAM (MB) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **MemoryReplayStore** | 30 | 2.34 +/- 0.17 | [2.29, 2.40] | 2.29 | 2.68 | **426.6** | 0.040 |
| **SqliteReplayStore** | 30 | 7.75 +/- 0.80 | [7.50, 8.10] | 7.59 | 9.52 | **129.1** | 0.039 |

---

## 2. Payload Encryption Ablation (4 Arms Across Dtypes & Dimensions)

Evaluates encryption and decryption latencies across the four architectural arms:
- **Arm 1 (aes_gcm_only)**: Pure authenticated AES-256-GCM AEAD.
- **Arm 2 (aes_gcm_permutation)**: AES-256-GCM with chaotic pixel coordinate permutation.
- **Arm 3 (aes_gcm_diffusion)**: AES-256-GCM with bit-plane diffusion and 3-round CCD.
- **Arm 4 (aes_gcm_both)**: Complete experimental pipeline (permutation + diffusion + AES-GCM).

| Arm | Resolution | Dtype | Size (MB) | Enc Mean (ms) | 95% Enc CI | Dec Mean (ms) | 95% Dec CI | Enc MB/s | Dec MB/s | Entropy | NPCR (%) | UACI (%) | MSE |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `aes_gcm_permutation` | 128x128 | uint16 | 0.0312 | 56.86 | [54.75, 59.22] | 57.40 | [54.38, 60.42] | 0.55 | 0.54 | 7.9944 | 99.61 | 33.42 | 0.0 |
| `aes_gcm_both` | 64x64 | int16 | 0.0078 | 27.71 | [26.27, 29.54] | 28.33 | [26.66, 30.34] | 0.28 | 0.28 | 7.9777 | 99.62 | 33.48 | 0.0 |
| `aes_gcm_only` | 128x128 | uint8 | 0.0156 | 0.27 | [0.24, 0.30] | 0.23 | [0.21, 0.25] | 57.42 | 67.75 | 7.9887 | 99.60 | 33.45 | 0.0 |
| `aes_gcm_diffusion` | 32x32 | int16 | 0.002 | 3.99 | [3.65, 4.42] | 0.44 | [0.35, 0.55] | 0.49 | 4.46 | 7.9098 | 99.58 | 33.54 | 0.0 |
| `aes_gcm_permutation` | 64x64 | int16 | 0.0078 | 16.86 | [15.75, 18.22] | 16.61 | [15.71, 17.70] | 0.46 | 0.47 | 7.9771 | 99.61 | 33.47 | 0.0 |
| `aes_gcm_permutation` | 32x32 | int16 | 0.002 | 5.65 | [5.33, 6.04] | 5.63 | [5.35, 5.91] | 0.35 | 0.35 | 7.9051 | 99.62 | 33.40 | 0.0 |
| `aes_gcm_diffusion` | 128x128 | uint16 | 0.0312 | 41.79 | [39.81, 44.23] | 0.93 | [0.89, 0.97] | 0.75 | 33.60 | 7.9944 | 99.62 | 33.45 | 0.0 |
| `aes_gcm_both` | 256x256 | uint8 | 0.0625 | 199.57 | [189.04, 210.49] | 204.78 | [195.84, 212.86] | 0.31 | 0.31 | 7.9972 | 99.61 | 33.46 | 0.0 |
| `aes_gcm_only` | 64x64 | uint8 | 0.0039 | 0.17 | [0.16, 0.19] | 0.15 | [0.14, 0.16] | 22.45 | 26.08 | 7.9536 | 99.62 | 33.54 | 0.0 |
| `aes_gcm_both` | 32x32 | uint8 | 0.001 | 6.36 | [6.06, 6.68] | 6.64 | [6.27, 7.00] | 0.15 | 0.15 | 7.8040 | 99.57 | 33.50 | 0.0 |
| `aes_gcm_both` | 128x128 | int16 | 0.0312 | 100.44 | [95.44, 106.80] | 100.93 | [95.57, 107.34] | 0.31 | 0.31 | 7.9945 | 99.60 | 33.46 | 0.0 |
| `aes_gcm_only` | 32x32 | uint16 | 0.002 | 0.15 | [0.14, 0.17] | 0.14 | [0.13, 0.15] | 12.84 | 14.02 | 7.9063 | 99.64 | 33.59 | 0.0 |
| `aes_gcm_both` | 256x256 | uint16 | 0.125 | 398.83 | [382.32, 416.78] | 404.09 | [381.63, 429.08] | 0.31 | 0.31 | 7.9986 | 99.61 | 33.45 | 0.0 |
| `aes_gcm_diffusion` | 128x128 | uint8 | 0.0156 | 21.31 | [20.46, 22.29] | 0.68 | [0.60, 0.78] | 0.73 | 22.86 | 7.9887 | 99.61 | 33.43 | 0.0 |
| `aes_gcm_both` | 32x32 | int16 | 0.002 | 9.47 | [8.99, 9.99] | 9.64 | [9.09, 10.23] | 0.21 | 0.20 | 7.9056 | 99.55 | 33.44 | 0.0 |
| `aes_gcm_permutation` | 128x128 | int16 | 0.0312 | 56.54 | [54.11, 59.07] | 58.40 | [55.15, 62.59] | 0.55 | 0.54 | 7.9945 | 99.61 | 33.39 | 0.0 |
| `aes_gcm_only` | 128x128 | uint16 | 0.0312 | 0.36 | [0.32, 0.41] | 0.32 | [0.29, 0.35] | 87.40 | 98.40 | 7.9944 | 99.61 | 33.47 | 0.0 |
| `aes_gcm_permutation` | 256x256 | uint16 | 0.125 | 235.36 | [221.59, 252.34] | 232.37 | [220.50, 245.07] | 0.53 | 0.54 | 7.9986 | 99.61 | 33.45 | 0.0 |
| `aes_gcm_diffusion` | 64x64 | uint16 | 0.0078 | 11.23 | [10.65, 11.89] | 0.55 | [0.46, 0.67] | 0.70 | 14.18 | 7.9771 | 99.61 | 33.46 | 0.0 |
| `aes_gcm_both` | 128x128 | uint16 | 0.0312 | 100.59 | [95.29, 107.05] | 98.73 | [94.77, 103.19] | 0.31 | 0.32 | 7.9944 | 99.61 | 33.49 | 0.0 |
| `aes_gcm_diffusion` | 256x256 | int16 | 0.125 | 168.24 | [157.72, 180.91] | 4.60 | [4.33, 4.90] | 0.74 | 27.17 | 7.9986 | 99.61 | 33.47 | 0.0 |
| `aes_gcm_only` | 128x128 | int16 | 0.0312 | 0.40 | [0.36, 0.44] | 0.34 | [0.31, 0.38] | 79.05 | 91.66 | 7.9944 | 99.61 | 33.45 | 0.0 |
| `aes_gcm_only` | 256x256 | uint8 | 0.0625 | 0.58 | [0.54, 0.63] | 0.55 | [0.52, 0.59] | 107.59 | 113.72 | 7.9972 | 99.61 | 33.46 | 0.0 |
| `aes_gcm_permutation` | 128x128 | uint8 | 0.0156 | 31.13 | [29.04, 34.09] | 29.43 | [28.25, 30.71] | 0.50 | 0.53 | 7.9887 | 99.61 | 33.40 | 0.0 |
| `aes_gcm_only` | 64x64 | int16 | 0.0078 | 0.21 | [0.18, 0.23] | 0.18 | [0.16, 0.19] | 37.94 | 44.60 | 7.9769 | 99.63 | 33.44 | 0.0 |
| `aes_gcm_diffusion` | 64x64 | int16 | 0.0078 | 10.98 | [10.48, 11.57] | 0.60 | [0.50, 0.71] | 0.71 | 13.06 | 7.9773 | 99.61 | 33.42 | 0.0 |
| `aes_gcm_both` | 256x256 | int16 | 0.125 | 399.69 | [378.91, 425.09] | 396.38 | [377.38, 419.75] | 0.31 | 0.32 | 7.9986 | 99.61 | 33.47 | 0.0 |
| `aes_gcm_only` | 256x256 | int16 | 0.125 | 0.99 | [0.93, 1.06] | 0.94 | [0.88, 0.99] | 126.08 | 133.41 | 7.9986 | 99.61 | 33.45 | 0.0 |
| `aes_gcm_only` | 32x32 | uint8 | 0.001 | 0.14 | [0.12, 0.15] | 0.13 | [0.12, 0.14] | 7.18 | 7.81 | 7.8141 | 99.63 | 33.33 | 0.0 |
| `aes_gcm_both` | 64x64 | uint16 | 0.0078 | 28.30 | [26.72, 30.46] | 28.25 | [26.59, 30.34] | 0.28 | 0.28 | 7.9773 | 99.62 | 33.45 | 0.0 |
| `aes_gcm_only` | 64x64 | uint16 | 0.0078 | 0.21 | [0.19, 0.23] | 0.19 | [0.16, 0.24] | 37.52 | 40.31 | 7.9782 | 99.61 | 33.51 | 0.0 |
| `aes_gcm_diffusion` | 256x256 | uint16 | 0.125 | 166.61 | [157.08, 176.78] | 4.36 | [4.12, 4.64] | 0.75 | 28.65 | 7.9986 | 99.62 | 33.46 | 0.0 |
| `aes_gcm_permutation` | 64x64 | uint8 | 0.0039 | 9.34 | [8.95, 9.79] | 9.58 | [8.90, 10.48] | 0.42 | 0.41 | 7.9546 | 99.61 | 33.49 | 0.0 |
| `aes_gcm_diffusion` | 256x256 | uint8 | 0.0625 | 80.99 | [77.82, 84.64] | 1.74 | [1.65, 1.83] | 0.77 | 35.99 | 7.9972 | 99.60 | 33.48 | 0.0 |
| `aes_gcm_permutation` | 256x256 | int16 | 0.125 | 229.01 | [216.40, 244.95] | 242.32 | [226.26, 260.81] | 0.55 | 0.52 | 7.9986 | 99.60 | 33.48 | 0.0 |
| `aes_gcm_diffusion` | 32x32 | uint8 | 0.001 | 2.73 | [2.52, 2.97] | 0.38 | [0.31, 0.48] | 0.36 | 2.54 | 7.8076 | 99.64 | 33.45 | 0.0 |
| `aes_gcm_both` | 128x128 | uint8 | 0.0156 | 52.62 | [49.75, 56.13] | 52.90 | [49.86, 56.76] | 0.30 | 0.30 | 7.9888 | 99.61 | 33.49 | 0.0 |
| `aes_gcm_permutation` | 256x256 | uint8 | 0.0625 | 117.45 | [110.87, 126.98] | 116.62 | [110.37, 124.39] | 0.53 | 0.54 | 7.9971 | 99.61 | 33.49 | 0.0 |
| `aes_gcm_permutation` | 32x32 | uint16 | 0.002 | 5.61 | [5.35, 5.93] | 5.45 | [5.25, 5.64] | 0.35 | 0.36 | 7.9085 | 99.57 | 33.46 | 0.0 |
| `aes_gcm_diffusion` | 128x128 | int16 | 0.0312 | 43.97 | [40.86, 47.93] | 1.13 | [0.97, 1.33] | 0.71 | 27.60 | 7.9945 | 99.61 | 33.45 | 0.0 |
| `aes_gcm_diffusion` | 32x32 | uint16 | 0.002 | 3.90 | [3.67, 4.15] | 0.40 | [0.33, 0.50] | 0.50 | 4.91 | 7.9102 | 99.58 | 33.46 | 0.0 |
| `aes_gcm_only` | 32x32 | int16 | 0.002 | 0.16 | [0.14, 0.18] | 0.14 | [0.13, 0.15] | 12.37 | 14.38 | 7.9085 | 99.61 | 33.59 | 0.0 |
| `aes_gcm_diffusion` | 64x64 | uint8 | 0.0039 | 6.46 | [5.99, 7.10] | 0.49 | [0.40, 0.61] | 0.61 | 7.93 | 7.9538 | 99.61 | 33.49 | 0.0 |
| `aes_gcm_both` | 64x64 | uint8 | 0.0039 | 16.07 | [15.32, 16.94] | 16.17 | [15.47, 16.91] | 0.24 | 0.24 | 7.9550 | 99.62 | 33.39 | 0.0 |
| `aes_gcm_permutation` | 64x64 | uint16 | 0.0078 | 15.89 | [15.12, 16.73] | 15.49 | [14.89, 16.13] | 0.49 | 0.50 | 7.9774 | 99.60 | 33.49 | 0.0 |
| `aes_gcm_permutation` | 32x32 | uint8 | 0.001 | 4.13 | [3.90, 4.35] | 3.97 | [3.74, 4.21] | 0.24 | 0.25 | 7.8074 | 99.69 | 33.55 | 0.0 |
| `aes_gcm_both` | 32x32 | uint16 | 0.002 | 9.70 | [9.13, 10.39] | 11.72 | [9.13, 16.48] | 0.20 | 0.17 | 7.9079 | 99.61 | 33.38 | 0.0 |
| `aes_gcm_only` | 256x256 | uint16 | 0.125 | 0.99 | [0.93, 1.07] | 0.94 | [0.88, 1.02] | 125.66 | 133.64 | 7.9986 | 99.61 | 33.46 | 0.0 |

---

## 3. Scientific Disclaimers and Descriptive Metrics

- **Cryptographic Confidentiality**: All confidentiality guarantees in MedPQC derive solely from AES-256-GCM with ephemeral P-256 and ML-KEM-768 key encapsulation.
- **Non-Cryptographic Diagnostics**: Entropy, NPCR, and UACI values are reported exclusively as descriptive statistical diagnostics of the experimental chaotic permutation and diffusion transforms. They do not constitute proofs of cryptographic security, pseudo-randomness, or clinical suitability.
- **Lossless Fidelity**: MSE = 0.0 across all cells confirms bit-perfect data preservation for clinical pixel arrays.

---

Generated automatically by `benchmarks/analyze.py` from raw measurements in `benchmarks/results/raw/`.
