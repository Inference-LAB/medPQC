"""
run_full_pneumoniamnist.py
==========================
Runs MedPQC encryption directly on the entire PneumoniaMNIST dataset.
No internet download required — uses the built-in 'pneumoniamnist.npz' archive.

Usage:
  python run_full_pneumoniamnist.py               # Runs on all 624 test images
  python run_full_pneumoniamnist.py --count 1000  # Runs on 1,000 images
  python run_full_pneumoniamnist.py --split all   # Runs on all 5,856 images!
"""

import sys
import os
import io
import time
import zipfile
import argparse
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Ensure medpqc is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import medpqc

def load_npz_dataset():
    """Extract and load pneumoniamnist.npz from revision_5_results/notebooks.zip."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    cached_path = os.path.join(repo_root, 'medpqc', 'tests_data', 'pneumoniamnist.npz')

    if os.path.exists(cached_path):
        return np.load(cached_path)

    zip_path = os.path.join(repo_root, 'revision_5_results', 'notebooks.zip')
    with zipfile.ZipFile(zip_path, 'r') as z:
        raw = z.read('notebooks/data/pneumoniamnist.npz')

    os.makedirs(os.path.dirname(cached_path), exist_ok=True)
    with open(cached_path, 'wb') as f:
        f.write(raw)

    return np.load(io.BytesIO(raw))

def calculate_correlation(arr: np.ndarray) -> float:
    f = arr.astype(float)
    x = f[:, :-1].flatten()
    y = f[:, 1:].flatten()
    if len(x) < 2 or np.all(x == x[0]):
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])

def calculate_entropy(arr: np.ndarray) -> float:
    flat = arr.flatten().astype(float)
    hist, _ = np.histogram(flat, bins=256, range=(0, 256))
    p = hist / hist.sum()
    p = p[p > 0]
    return float(-np.sum(p * np.log2(p)))

def main():
    parser = argparse.ArgumentParser(description="MedPQC Full PneumoniaMNIST Runner")
    parser.add_argument("--split", type=str, default="test", choices=["test", "train", "val", "all"],
                        help="Dataset partition to test (default: test [624 images])")
    parser.add_argument("--count", type=int, default=0,
                        help="Limit number of images to process (0 = all images in split)")
    args = parser.parse_args()

    print("=" * 80)
    print("      MedPQC LARGE-SCALE PneumoniaMNIST BENCHMARK")
    print("=" * 80)
    print("Loading built-in 'pneumoniamnist.npz'...")
    data = load_npz_dataset()

    # Select split
    if args.split == "test":
        images = data['test_images']
        labels = data['test_labels'].flatten()
    elif args.split == "train":
        images = data['train_images']
        labels = data['train_labels'].flatten()
    elif args.split == "val":
        images = data['val_images']
        labels = data['val_labels'].flatten()
    else:  # all
        images = np.concatenate([data['train_images'], data['val_images'], data['test_images']], axis=0)
        labels = np.concatenate([data['train_labels'], data['val_labels'], data['test_labels']], axis=0).flatten()

    total_available = len(images)
    n_run = total_available if args.count <= 0 else min(args.count, total_available)

    images = images[:n_run]
    labels = labels[:n_run]

    n_normal = int((labels == 0).sum())
    n_pneu   = int((labels == 1).sum())

    print(f"Cohort Split      : {args.split.upper()}")
    print(f"Total Images      : {n_run:,} (Normal: {n_normal:,}, Pneumonia: {n_pneu:,})")
    print(f"Resolution        : {images.shape[1]}x{images.shape[2]} pixels (Native)")

    # 1. Establish Hybrid KEM once for session
    print("\n[1] Initializing Hybrid KEM (Classical P-256 + Post-Quantum RLWE)...")
    alice_ecdh, alice_pub = medpqc.generate_ecdh_keypair()
    bob_ecdh, bob_pub     = medpqc.generate_ecdh_keypair()
    alice_pq = medpqc.PostQuantumKEM()
    bob_pq   = medpqc.PostQuantumKEM()
    ct_pq, bob_pq_secret = bob_pq.encapsulate(alice_pq.public_key_bytes)
    k_ecdh = alice_ecdh.exchange(bob_pub)

    cipher = medpqc.MedPQCCipher.from_shared_secrets(k_ecdh, bob_pq_secret)

    # Warmup JIT
    _ = cipher.encrypt(images[0])

    # 2. Benchmark Loop
    print(f"\n[2] Encrypting and decrypting all {n_run:,} images...")
    t0_start = time.perf_counter()

    enc_times = []
    enc_corrs = []
    orig_corrs = []
    entropies = []
    lossless_count = 0

    print("Progress: ", end="", flush=True)
    report_step = max(1, n_run // 20)

    for i in range(n_run):
        im = images[i]
        orig_corrs.append(calculate_correlation(im))

        # Encrypt
        t0 = time.perf_counter()
        bundle = cipher.encrypt(im, enable_scrambling=True)
        t_enc = (time.perf_counter() - t0) * 1000
        enc_times.append(t_enc)

        # Decrypt
        dec_im = cipher.decrypt(bundle)
        mse = float(np.mean((im.astype(float) - dec_im.astype(float)) ** 2))
        if mse == 0.0:
            lossless_count += 1

        # Security metrics
        ct_bytes = bundle['aead']['ciphertext']
        ct_arr = np.frombuffer(ct_bytes[:im.size], dtype=im.dtype).reshape(im.shape)
        enc_corrs.append(abs(calculate_correlation(ct_arr)))
        entropies.append(calculate_entropy(ct_arr))

        if (i + 1) % report_step == 0 or (i + 1) == n_run:
            pct = ((i + 1) / n_run) * 100
            print(f"[{pct:.0f}%]", end=" ", flush=True)

    total_time = time.perf_counter() - t0_start
    print("\n")

    # 3. Final Summary
    avg_enc_time = float(np.mean(enc_times))
    throughput_fps = n_run / total_time
    avg_orig_corr = float(np.mean(orig_corrs))
    avg_enc_corr = float(np.mean(enc_corrs))
    avg_entropy = float(np.mean(entropies))
    lossless_pct = (lossless_count / n_run) * 100.0

    print("=" * 80)
    print("                    LARGE-SCALE BENCHMARK RESULTS")
    print("=" * 80)
    print(f"  * Total Images Processed      : {n_run:,} images")
    print(f"  * Total Processing Time       : {total_time:.2f} seconds")
    print(f"  * Throughput                  : {throughput_fps:.1f} images/sec")
    print(f"  * Avg Encryption Latency      : {avg_enc_time:.2f} ms per image")
    print(f"  * Original Correlation (Mean) : {avg_orig_corr:.5f} (Heavily correlated)")
    print(f"  * Encrypted Correlation (Mean): {avg_enc_corr:.5f} (Crushed to pure noise)")
    print(f"  * Shannon Entropy (Mean)      : {avg_entropy:.4f} bits/pixel (Ideal -> 8.0)")
    print(f"  * Lossless Recovery Rate      : {lossless_pct:.2f}% ({lossless_count}/{n_run} Bit-Exact MSE=0.0)")
    print("=" * 80)

if __name__ == '__main__':
    main()
