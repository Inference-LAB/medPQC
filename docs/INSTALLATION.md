# MedPQC Installation and Environment Setup Guide

**Target Release**: MedPQC v2.2.0  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab (INFERENCE Lab)  
**Date**: November 2026  

---

## 1. System Requirements

- **Supported Operating Systems**:
  - Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, Alpine 3.18+)
  - macOS (macOS 12 Monterey or newer, Apple Silicon and Intel)
  - Microsoft Windows (Windows 10, Windows 11, Windows Server 2019+)
- **Python Runtime**: Python 3.9, 3.10, 3.11, 3.12, 3.13, or 3.14 (64-bit).

---

## 2. Installation Options

### 2.1 Installing Pre-Built Distribution (Recommended)

From the `release/` directory:

```bash
# Create and activate an isolated virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Install built wheel
pip install release/medpqc-2.2.0-py3-none-any.whl
```

### 2.2 Installing from Source Distribution

```bash
# Install source tarball
pip install release/medpqc-2.2.0.tar.gz

# Or clone from git repository:
git clone https://github.com/Inference-LAB/medPQC.git
cd medPQC
pip install .[all]
```

---

## 3. Dependency Specification

MedPQC modularizes dependencies across operational profiles:

### 3.1 Core Cryptographic Dependencies
- `cryptography>=38.0.0`: OpenSSL backend for ephemeral P-256 and AES-256-GCM.
- `mlkem>=0.2.0`: Standards-conformant NIST FIPS 203 ML-KEM-768 implementation.
- `numpy>=1.22.0`: Vectorized pixel arrays and memory buffer manipulation.

### 3.2 Optional Subsystem Profiles
Install specific profiles via pip extras:

```bash
# PACS and DICOM image processing:
pip install "medpqc[dicom]"       # Installs pydicom>=2.3.0, opencv-python-headless

# High-performance chaotic dynamical simulation:
pip install "medpqc[chaos]"       # Installs numba>=0.56.0, scipy>=1.8.0

# Scientific benchmarking and visualization:
pip install "medpqc[bench]"       # Installs matplotlib>=3.5.0

# Development, testing, and release engineering:
pip install "medpqc[dev]"         # Installs pytest>=7.0.0, pytest-cov>=4.0.0, build, twine

# Complete installation:
pip install "medpqc[all]"
```

---

## 4. Verification and Self-Test

To verify that MedPQC is installed and functional:

```bash
python -c "import medpqc; print(f'MedPQC version: {medpqc.__version__}'); from medpqc.kem import PostQuantumKEM; kem = PostQuantumKEM(); print('FIPS 203 ML-KEM-768 initialized successfully!')"
```

To run the complete automated verification test suite:

```bash
python -m pytest --cov=medpqc --cov-report=term-missing
```
All 165 tests should pass with 100.00% statement coverage.
