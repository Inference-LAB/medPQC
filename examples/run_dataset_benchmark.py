"""
run_dataset_benchmark.py
========================
Batch benchmark runner for medical datasets.
Tests MedPQC across all images in a folder (or built-in clinical cohort).
Outputs metrics:
  - Encryption Latency (ms)
  - Reconstruction MSE (Lossless Verification)
  - Original Correlation vs Encrypted Correlation
  - Shannon Entropy
  - NPCR and UACI
"""

import sys
import os
import time
import glob
import zipfile
import argparse
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Ensure medpqc is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import medpqc

def extract_builtin_dataset(target_dir: str):
    """Extract real chest X-rays and DICOM files from revision_5_results/notebooks.zip."""
    os.makedirs(target_dir, exist_ok=True)
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    zip_path = os.path.join(repo_root, 'revision_5_results', 'notebooks.zip')

    if not os.path.exists(zip_path):
        return

    targets = [
        f'notebooks/data/real_chest_xray_{i:02d}_{label}.png'
        for i, label in [
            (1, 'pneumonia'), (2, 'pneumonia'), (3, 'pneumonia'), (4, 'pneumonia'),
            (5, 'pneumonia'), (6, 'normal'), (7, 'pneumonia'), (8, 'normal'),
            (9, 'pneumonia'), (10, 'pneumonia')
        ]
    ] + ['notebooks/data/real_ct_16bit.dcm', 'notebooks/data/real_mr_16bit.dcm']

    with zipfile.ZipFile(zip_path, 'r') as z:
        for t in targets:
            dest = os.path.join(target_dir, os.path.basename(t))
            if not os.path.exists(dest) and t in z.namelist():
                with open(dest, 'wb') as f:
                    f.write(z.read(t))

def calculate_correlation(arr: np.ndarray) -> float:
    """Adjacent-pixel horizontal correlation."""
    if arr.ndim == 3:
        arr = arr[:, :, 0]
    f = arr.astype(float)
    x = f[:, :-1].flatten()
    y = f[:, 1:].flatten()
    if len(x) < 2 or np.all(x == x[0]):
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])

def calculate_entropy(arr: np.ndarray) -> float:
    """Shannon entropy."""
    flat = arr.flatten().astype(float)
    bins = 1024 if arr.dtype in [np.uint16, np.int16] else 256
    hist, _ = np.histogram(flat, bins=bins)
    p = hist / hist.sum()
    p = p[p > 0]
    return float(-np.sum(p * np.log2(p)))

def calculate_npcr_uaci(a: np.ndarray, b: np.ndarray) -> tuple:
    """NPCR and UACI between two arrays."""
    d = a.astype(float) - b.astype(float)
    max_val = 65535.0 if a.dtype in [np.uint16, np.int16] else 255.0
    npcr = 100.0 * np.count_nonzero(d) / d.size
    uaci = 100.0 * np.sum(np.abs(d)) / (max_val * d.size)
    return round(float(npcr), 3), round(float(uaci), 3)

def main():
    parser = argparse.ArgumentParser(description="MedPQC Batch Dataset Benchmark")
    parser.add_argument("--data_dir", type=str, default="", help="Path to custom image/DICOM folder")
    args = parser.parse_args()

    default_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tests_data", "clinical_cohort"))

    if args.data_dir and os.path.exists(args.data_dir):
        data_dir = args.data_dir
        print(f"Using Custom Dataset Folder: {data_dir}")
    else:
        print("Extracting & Preparing Built-in Real Clinical Medical Dataset...")
        extract_builtin_dataset(default_data_dir)
        data_dir = default_data_dir
        print(f"Using Built-in Clinical Dataset: {data_dir}")

    # Discover images (.png, .dcm, .jpg, .tif)
    exts = ["*.png", "*.dcm", "*.jpg", "*.jpeg", "*.tif"]
    file_list = []
    for ext in exts:
        file_list.extend(glob.glob(os.path.join(data_dir, ext)))
    file_list.sort()

    if not file_list:
        print(f"No image or DICOM files found in {data_dir}!")
        return

    print(f"\nDiscovered {len(file_list)} medical files. Starting Batch Encryption Benchmark...")
    print("=" * 105)
    header = f"{'File Name':<30} {'Type':<8} {'Shape':<12} {'Enc(ms)':>8} {'MSE':>6} {'OrigCorr':>9} {'EncCorr':>9} {'Entropy':>8}"
    print(header)
    print("-" * 105)

    # Initialize Hybrid KEM once for session
    alice_ecdh, alice_pub = medpqc.generate_ecdh_keypair()
    bob_ecdh, bob_pub     = medpqc.generate_ecdh_keypair()
    alice_pq = medpqc.PostQuantumKEM()
    bob_pq   = medpqc.PostQuantumKEM()
    ct_pq, bob_pq_secret = bob_pq.encapsulate(alice_pq.public_key_bytes)
    k_ecdh = alice_ecdh.exchange(bob_pub)

    cipher = medpqc.MedPQCCipher.from_shared_secrets(k_ecdh, bob_pq_secret)

    results = []
    enc_times = []
    enc_corrs = []

    for file_path in file_list:
        base_name = os.path.basename(file_path)
        try:
            pixels, meta = medpqc.MedicalImageIO.load(file_path)
        except Exception as e:
            print(f"{base_name:<30} ERROR loading: {e}")
            continue

        shape_str = str(pixels.shape)
        dtype_str = str(pixels.dtype)
        orig_corr = calculate_correlation(pixels)

        # 1. Measure Encryption Time
        t0 = time.perf_counter()
        enc_bundle = cipher.encrypt(pixels, enable_scrambling=True)
        t_enc = (time.perf_counter() - t0) * 1000
        enc_times.append(t_enc)

        # 2. Measure Decryption & Lossless MSE
        dec_pixels = cipher.decrypt(enc_bundle)
        mse = float(np.mean((pixels.astype(float) - dec_pixels.astype(float)) ** 2))

        # 3. Encrypted Correlation & Entropy
        ct_bytes = enc_bundle['aead']['ciphertext']
        ct_arr = np.frombuffer(ct_bytes[:pixels.size * pixels.itemsize], dtype=pixels.dtype).reshape(pixels.shape)
        enc_corr = calculate_correlation(ct_arr)
        enc_corrs.append(abs(enc_corr))
        entropy = calculate_entropy(ct_arr)

        print(f"{base_name:<30} {dtype_str:<8} {shape_str:<12} {t_enc:>7.1f}ms {mse:>6.1f} {orig_corr:>9.4f} {enc_corr:>+9.5f} {entropy:>8.4f}")

        results.append({
            'file': base_name,
            'dtype': dtype_str,
            'shape': shape_str,
            'time_ms': round(t_enc, 2),
            'mse': mse,
            'orig_corr': round(orig_corr, 5),
            'enc_corr': round(enc_corr, 5),
            'entropy': round(entropy, 4)
        })

    print("=" * 105)
    avg_time = float(np.mean(enc_times))
    avg_corr = float(np.mean(enc_corrs))
    all_lossless = all(r['mse'] == 0.0 for r in results)

    print(f"\n[SUMMARY SUMMARY]")
    print(f"  * Total Files Processed       : {len(results)}")
    print(f"  * Average Encryption Latency  : {avg_time:.2f} ms")
    print(f"  * Average Encrypted Correlation: {avg_corr:.5f} (Ideal -> 0.0)")
    print(f"  * 100% Bit-Exact Lossless     : {'YES (MSE = 0.0 for ALL)' if all_lossless else 'NO'}")

    out_csv = os.path.join(os.path.dirname(__file__), "dataset_benchmark_results.csv")
    import csv
    with open(out_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"\nDetailed CSV Report saved to: {out_csv}\n")

if __name__ == '__main__':
    main()
