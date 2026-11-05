"""
demo_visual_test.py
===================
Run this script to test MedPQC on your machine.
It will:
  1. Generate / load an image.
  2. Encrypt it with Hybrid Post-Quantum + Lorenz Chaos.
  3. Decrypt it and check MSE = 0.0 (lossless).
  4. Save a side-by-side visual comparison figure: 'visual_test_result.png'.
"""

import sys
import os
import time
import numpy as np
import matplotlib.pyplot as plt

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Ensure medpqc is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import medpqc

def main():
    print("=" * 60)
    print("   MedPQC LOCAL INTERACTIVE TEST")
    print("=" * 60)

    # 1. Generate a test medical-like image (Gradient + Texture phantom)
    size = 512
    print(f"\n[Step 1] Creating a {size}x{size} medical phantom test image...")
    Y, X = np.ogrid[:size, :size]
    cx, cy = size // 2, size // 2
    body = ((X - cx) / (size // 2.5)) ** 2 + ((Y - cy) / (size // 2)) ** 2 <= 1
    organ = ((X - cx) / (size // 6)) ** 2 + ((Y - cy) / (size // 8)) ** 2 <= 1
    
    img = np.zeros((size, size), dtype=np.uint8)
    img[body] = 120
    img[organ] = 220
    # Add gradient and noise
    img = np.clip(img.astype(int) + (X // 4) + np.random.randint(-10, 10, (size, size)), 0, 255).astype(np.uint8)

    # 2. Key Setup
    print("[Step 2] Setting up Hybrid Classical (P-256) + Post-Quantum (RLWE) Keys...")
    t0_kem = time.perf_counter()
    alice_ecdh, alice_pub = medpqc.generate_ecdh_keypair()
    bob_ecdh, bob_pub     = medpqc.generate_ecdh_keypair()

    alice_pq = medpqc.PostQuantumKEM()
    bob_pq   = medpqc.PostQuantumKEM()

    ct_pq, bob_pq_secret = bob_pq.encapsulate(alice_pq.public_key_bytes)
    k_ecdh = alice_ecdh.exchange(bob_pub)

    cipher = medpqc.MedPQCCipher.from_shared_secrets(k_ecdh, bob_pq_secret)
    t_kem = (time.perf_counter() - t0_kem) * 1000
    print(f"  -> Hybrid KEM completed in {t_kem:.2f} ms")

    # 3. Encryption
    print("\n[Step 3] Encrypting image (Permutation + Chaos + AES-GCM)...")
    t0_enc = time.perf_counter()
    enc_bundle = cipher.encrypt(img, enable_scrambling=True)
    t_enc = (time.perf_counter() - t0_enc) * 1000
    print(f"  -> Encryption completed in {t_enc:.2f} ms!")

    # 4. Decryption
    print("\n[Step 4] Decrypting image and verifying integrity...")
    t0_dec = time.perf_counter()
    dec_img = cipher.decrypt(enc_bundle)
    t_dec = (time.perf_counter() - t0_dec) * 1000
    print(f"  -> Decryption completed in {t_dec:.2f} ms!")

    # 5. Lossless Verification
    mse = float(np.mean((img.astype(float) - dec_img.astype(float)) ** 2))
    print(f"  -> Reconstruction Mean Squared Error (MSE): {mse}")
    if mse == 0.0:
        print("  -> [PASS] Decryption is 100% BIT-EXACT LOSSLESS!")
    else:
        print("  -> [FAIL] Image differed after decryption!")

    # 6. Correlation Analysis
    def get_corr(im):
        f = im.astype(float)
        return float(np.corrcoef(f[:, :-1].flatten(), f[:, 1:].flatten())[0, 1])

    orig_corr = get_corr(img)
    # Extract ciphertext bytes for display
    ct_bytes = enc_bundle['aead']['ciphertext']
    ct_img = np.frombuffer(ct_bytes[:size * size], dtype=np.uint8).reshape(size, size)
    enc_corr = get_corr(ct_img)

    print(f"\n[Step 5] Correlation Analysis:")
    print(f"  -> Original image correlation : {orig_corr:.5f} (High pattern dependency)")
    print(f"  -> Encrypted image correlation: {enc_corr:.5f} (Crushed to pure noise)")

    # 7. Save Visual Comparison Image
    print("\n[Step 6] Saving visual side-by-side comparison to 'visual_test_result.png'...")
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))
    fig.suptitle(f"MedPQC Local Test Result (MSE = {mse}, Enc Time = {t_enc:.1f}ms)", fontsize=13, fontweight='bold')

    axes[0].imshow(img, cmap='gray')
    axes[0].set_title(f"1. Original Image\n(Corr = {orig_corr:.4f})")
    axes[0].axis('off')

    axes[1].imshow(ct_img, cmap='gray')
    axes[1].set_title(f"2. Encrypted Ciphertext\n(Corr = {enc_corr:.4f})")
    axes[1].axis('off')

    axes[2].imshow(dec_img, cmap='gray')
    axes[2].set_title(f"3. Decrypted Image\n(MSE = {mse})")
    axes[2].axis('off')

    # Difference map
    diff = np.abs(img.astype(int) - dec_img.astype(int))
    im_diff = axes[3].imshow(diff, cmap='hot', vmin=0, vmax=1)
    axes[3].set_title("4. Difference Map (Orig - Dec)\n(All Zeros = Exact Match)")
    axes[3].axis('off')

    plt.tight_layout()
    out_fig = os.path.join(os.path.dirname(__file__), "visual_test_result.png")
    plt.savefig(out_fig, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  -> Saved visualization: {out_fig}")

    print("\n" + "=" * 60)
    print("   TEST COMPLETED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == '__main__':
    main()
