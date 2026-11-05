"""
examples.run_ablation_study
===========================
Scientific Ablation Study and Performance Benchmark for MedPQC v2.1.0.
Conducts rigorous empirical evaluation across 4 cryptographic configurations:
  Configuration 1: Baseline NIST Standard (AES-256-GCM only)
  Configuration 2: Permutation + AES-256-GCM (Spatial scrambling)
  Configuration 3: Diffusion + AES-256-GCM (Chaotic Chained Diffusion pre-whitening)
  Configuration 4: Full MedPQC v2.1.0 Pipeline (Authenticated Hybrid KEM + Permutation + Diffusion + AES-GCM-AAD)

Methodology:
  - Repetitions: N = 30 independent runs (sample size satisfying CLT for 95% Confidence Intervals)
  - Memory Profiling: tracemalloc peak heap allocation tracking
  - Spatial Correlation: Horizontal (rH), Vertical (rV), and Diagonal (rD) adjacent correlation
  - Differential Cryptanalysis: NPCR (Number of Pixels Change Rate) and UACI (Unified Average Changing Intensity)
  - Information Entropy: Shannon entropy on 256 byte-bins
  - Key Establishment: In-process compute latency + simulated network RTT modeling
"""

import os
import sys
import time
import math
import secrets
import tracemalloc
from typing import Dict, Any, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext, TrustStore, ReplayProtector
from medpqc.kem.combiner import HybridKeyCombiner, build_session_context
from medpqc.experimental.chaos.permutation import ChaoticPermuter
from medpqc.experimental.chaos.sponge import ChaoticEntropySponge
from medpqc.experimental.diffusion import ChaoticDiffusion
from medpqc.cipher.aead import AuthenticatedCipher
from medpqc.cipher.engine import MedPQCCipher

def compute_entropy(data_bytes: bytes) -> float:
    arr = np.frombuffer(data_bytes, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts[counts > 0] / len(arr)
    return float(-np.sum(probs * np.log2(probs)))

def compute_directional_correlations(grid: np.ndarray, num_samples: int = 10000) -> Tuple[float, float, float]:
    """Computes horizontal, vertical, and diagonal adjacent correlation coefficients."""
    h, w = grid.shape[:2]
    flat = grid.reshape(h, w, -1)[:, :, 0].astype(np.float64)

    # Horizontal
    yh = np.random.randint(0, h, size=num_samples)
    xh = np.random.randint(0, w - 1, size=num_samples)
    x_h, y_h = flat[yh, xh], flat[yh, xh + 1]
    r_h = float(np.corrcoef(x_h, y_h)[0, 1]) if np.std(x_h) > 0 and np.std(y_h) > 0 else 0.0

    # Vertical
    yv = np.random.randint(0, h - 1, size=num_samples)
    xv = np.random.randint(0, w, size=num_samples)
    x_v, y_v = flat[yv, xv], flat[yv + 1, xv]
    r_v = float(np.corrcoef(x_v, y_v)[0, 1]) if np.std(x_v) > 0 and np.std(y_v) > 0 else 0.0

    # Diagonal
    yd = np.random.randint(0, h - 1, size=num_samples)
    xd = np.random.randint(0, w - 1, size=num_samples)
    x_d, y_d = flat[yd, xd], flat[yd + 1, xd + 1]
    r_d = float(np.corrcoef(x_d, y_d)[0, 1]) if np.std(x_d) > 0 and np.std(y_d) > 0 else 0.0

    return (
        0.0 if math.isnan(r_h) else r_h,
        0.0 if math.isnan(r_v) else r_v,
        0.0 if math.isnan(r_d) else r_d
    )

def compute_npcr_uaci(c1_bytes: bytes, c2_bytes: bytes, n_bytes: int) -> Tuple[float, float]:
    arr1 = np.frombuffer(c1_bytes[:n_bytes], dtype=np.uint8)
    arr2 = np.frombuffer(c2_bytes[:n_bytes], dtype=np.uint8)
    diff = arr1 != arr2
    npcr = float(np.sum(diff) / len(diff)) * 100.0
    uaci = float(np.sum(np.abs(arr1.astype(np.int32) - arr2.astype(np.int32))) / (len(arr1) * 255.0)) * 100.0
    return npcr, uaci

def compute_stats(samples: List[float]) -> Dict[str, float]:
    arr = np.array(samples, dtype=np.float64)
    mean = float(np.mean(arr))
    std = float(np.std(arr, ddof=1))
    median = float(np.median(arr))
    n = len(arr)
    ci95 = float(1.96 * std / math.sqrt(n)) if n > 1 else 0.0
    return {
        "mean": mean,
        "std": std,
        "median": median,
        "ci95": ci95,
        "min": float(np.min(arr)),
        "max": float(np.max(arr))
    }

def run_scientific_ablation(image: np.ndarray, repetitions: int = 30) -> Dict[str, Any]:
    flat_bytes = image.tobytes()
    n_bytes = len(flat_bytes)
    h, w = image.shape[:2]

    # Deterministic or cryptographically secure keys
    k_aes = secrets.token_bytes(32)
    k_mac = secrets.token_bytes(32)
    chaos_seed = secrets.token_bytes(32)
    perm_seed = secrets.token_bytes(32)

    # 1-bit modified input for differential analysis
    img_mod = image.copy()
    img_mod.reshape(-1)[0] ^= 0x01
    flat_mod_bytes = img_mod.tobytes()

    results: Dict[str, Any] = {}

    # Plaintext Baseline Statistics
    p_rh, p_rv, p_rd = compute_directional_correlations(image)
    results["Plaintext Baseline"] = {
        "entropy": compute_entropy(flat_bytes),
        "r_h": p_rh,
        "r_v": p_rv,
        "r_d": p_rd,
    }

    # -------------------------------------------------------------
    # Config 1: Pure AES-256-GCM
    # -------------------------------------------------------------
    t_encs, t_decs = [], []
    c1_bundle = None
    tracemalloc.start()
    for _ in range(repetitions):
        t0 = time.perf_counter()
        c1_bundle = AuthenticatedCipher.encrypt(flat_bytes, k_aes, k_mac)
        t_encs.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        _ = AuthenticatedCipher.decrypt(c1_bundle, k_aes, k_mac)
        t_decs.append((time.perf_counter() - t0) * 1000)
    _, peak_mem_1 = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    c1_mod = AuthenticatedCipher.encrypt(flat_mod_bytes, k_aes, k_mac)
    npcr1, uaci1 = compute_npcr_uaci(c1_bundle['ciphertext'], c1_mod['ciphertext'], n_bytes)
    c1_grid = np.frombuffer(c1_bundle['ciphertext'][:n_bytes], dtype=np.uint8).reshape(h, -1)
    c1_rh, c1_rv, c1_rd = compute_directional_correlations(c1_grid)

    results["Config 1: Pure AES-256-GCM"] = {
        "enc_stats": compute_stats(t_encs),
        "dec_stats": compute_stats(t_decs),
        "peak_mem_kib": peak_mem_1 / 1024.0,
        "entropy": compute_entropy(c1_bundle['ciphertext']),
        "npcr": npcr1,
        "uaci": uaci1,
        "r_h": c1_rh,
        "r_v": c1_rv,
        "r_d": c1_rd
    }

    # -------------------------------------------------------------
    # Config 2: Permutation + AES-256-GCM
    # -------------------------------------------------------------
    t_encs, t_decs = [], []
    c2_bundle = None
    u8_arr = np.frombuffer(flat_bytes, dtype=np.uint8)
    tracemalloc.start()
    for _ in range(repetitions):
        t0 = time.perf_counter()
        p_bytes, _ = ChaoticPermuter.permute(u8_arr, perm_seed)
        c2_bundle = AuthenticatedCipher.encrypt(p_bytes.tobytes(), k_aes, k_mac)
        t_encs.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        dec_p = AuthenticatedCipher.decrypt(c2_bundle, k_aes, k_mac)
        _ = ChaoticPermuter.inverse_permute(np.frombuffer(dec_p, dtype=np.uint8), perm_seed)
        t_decs.append((time.perf_counter() - t0) * 1000)
    _, peak_mem_2 = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    p_mod, _ = ChaoticPermuter.permute(np.frombuffer(flat_mod_bytes, dtype=np.uint8), perm_seed)
    c2_mod = AuthenticatedCipher.encrypt(p_mod.tobytes(), k_aes, k_mac)
    npcr2, uaci2 = compute_npcr_uaci(c2_bundle['ciphertext'], c2_mod['ciphertext'], n_bytes)
    c2_grid = np.frombuffer(c2_bundle['ciphertext'][:n_bytes], dtype=np.uint8).reshape(h, -1)
    c2_rh, c2_rv, c2_rd = compute_directional_correlations(c2_grid)

    results["Config 2: Permutation + AES-256-GCM"] = {
        "enc_stats": compute_stats(t_encs),
        "dec_stats": compute_stats(t_decs),
        "peak_mem_kib": peak_mem_2 / 1024.0,
        "entropy": compute_entropy(c2_bundle['ciphertext']),
        "npcr": npcr2,
        "uaci": uaci2,
        "r_h": c2_rh,
        "r_v": c2_rv,
        "r_d": c2_rd
    }

    # -------------------------------------------------------------
    # Config 3: Diffusion + AES-256-GCM
    # -------------------------------------------------------------
    keystream = ChaoticEntropySponge.extract_uint8_stream(chaos_seed, n_bytes * 3)
    t_encs, t_decs = [], []
    c3_bundle = None
    tracemalloc.start()
    for _ in range(repetitions):
        t0 = time.perf_counter()
        bp = ChaoticDiffusion.bitplane_diffuse(np.frombuffer(flat_bytes, dtype=np.uint8), keystream[:n_bytes])
        ccd = ChaoticDiffusion.ccd_mix(bp, keystream, rounds=3)
        c3_bundle = AuthenticatedCipher.encrypt(ccd.tobytes(), k_aes, k_mac)
        t_encs.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        dec_ccd = AuthenticatedCipher.decrypt(c3_bundle, k_aes, k_mac)
        inv_ccd = ChaoticDiffusion.ccd_unmix(np.frombuffer(dec_ccd, dtype=np.uint8), keystream, rounds=3)
        _ = ChaoticDiffusion.bitplane_diffuse(inv_ccd, keystream[:n_bytes])
        t_decs.append((time.perf_counter() - t0) * 1000)
    _, peak_mem_3 = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    bp_m = ChaoticDiffusion.bitplane_diffuse(np.frombuffer(flat_mod_bytes, dtype=np.uint8), keystream[:n_bytes])
    ccd_m = ChaoticDiffusion.ccd_mix(bp_m, keystream, rounds=3)
    c3_mod = AuthenticatedCipher.encrypt(ccd_m.tobytes(), k_aes, k_mac)
    npcr3, uaci3 = compute_npcr_uaci(c3_bundle['ciphertext'], c3_mod['ciphertext'], n_bytes)
    c3_grid = np.frombuffer(c3_bundle['ciphertext'][:n_bytes], dtype=np.uint8).reshape(h, -1)
    c3_rh, c3_rv, c3_rd = compute_directional_correlations(c3_grid)

    results["Config 3: Diffusion + AES-256-GCM"] = {
        "enc_stats": compute_stats(t_encs),
        "dec_stats": compute_stats(t_decs),
        "peak_mem_kib": peak_mem_3 / 1024.0,
        "entropy": compute_entropy(c3_bundle['ciphertext']),
        "npcr": npcr3,
        "uaci": uaci3,
        "r_h": c3_rh,
        "r_v": c3_rv,
        "r_d": c3_rd
    }

    # -------------------------------------------------------------
    # Config 4: Full MedPQC v2.1.0 Engine
    # -------------------------------------------------------------
    cipher = MedPQCCipher(k_aes, k_mac, chaos_seed)
    t_encs, t_decs = [], []
    c4_bundle = None
    tracemalloc.start()
    for _ in range(repetitions):
        t0 = time.perf_counter()
        c4_bundle = cipher.encrypt(image, enable_scrambling=True)
        t_encs.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        _ = cipher.decrypt(c4_bundle)
        t_decs.append((time.perf_counter() - t0) * 1000)
    _, peak_mem_4 = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    c4_mod = cipher.encrypt(img_mod, enable_scrambling=True)
    npcr4, uaci4 = compute_npcr_uaci(c4_bundle['aead']['ciphertext'], c4_mod['aead']['ciphertext'], n_bytes)
    c4_grid = np.frombuffer(c4_bundle['aead']['ciphertext'][:n_bytes], dtype=np.uint8).reshape(h, -1)
    c4_rh, c4_rv, c4_rd = compute_directional_correlations(c4_grid)

    results["Config 4: Full MedPQC v2.1.0 Engine"] = {
        "enc_stats": compute_stats(t_encs),
        "dec_stats": compute_stats(t_decs),
        "peak_mem_kib": peak_mem_4 / 1024.0,
        "entropy": compute_entropy(c4_bundle['aead']['ciphertext']),
        "npcr": npcr4,
        "uaci": uaci4,
        "r_h": c4_rh,
        "r_v": c4_rv,
        "r_d": c4_rd
    }

    # -------------------------------------------------------------
    # Key Establishment Benchmark (NIST P-256 + FIPS 203 ML-KEM-768 + Ed25519)
    # -------------------------------------------------------------
    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()
    alice_peer_id = "pacs-alice"
    bob_peer_id = "pacs-bob"
    trust_store = TrustStore()
    trust_store.register_peer(alice_peer_id, alice_id.public_bytes)
    trust_store.register_peer(bob_peer_id, bob_id.public_bytes)
    replay_protector = ReplayProtector()

    h_times = []
    tracemalloc.start()
    for _ in range(repetitions):
        session_id = secrets.token_bytes(16)
        t0 = time.perf_counter()
        initiator = InitiatorContext(alice_peer_id, alice_id, trust_store=trust_store)
        init_msg = initiator.initiate(
            receiver_id=bob_peer_id, session_id=session_id
        )
        responder = ResponderContext(
            bob_peer_id,
            bob_id,
            trust_store=trust_store,
            replay_store=replay_protector._store,
            allow_non_durable_replay_store=True,
        )
        resp_msg, bob_session = responder.respond(init_msg)
        alice_session = initiator.finalize(resp_msg)
        h_times.append((time.perf_counter() - t0) * 1000)
    _, peak_mem_kem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    results["Authenticated Hybrid Handshake (Ed25519 + P-256 + ML-KEM-768)"] = {
        "stats": compute_stats(h_times),
        "peak_mem_kib": peak_mem_kem / 1024.0,
        "simulated_rtt_10ms": compute_stats(h_times)["mean"] + 10.0,
        "simulated_rtt_30ms": compute_stats(h_times)["mean"] + 30.0,
        "simulated_rtt_50ms": compute_stats(h_times)["mean"] + 50.0,
    }

    return results

if __name__ == "__main__":
    N_RUNS = 30
    print("=" * 86)
    print(f"MEDPQC v2.1.0 RIGOROUS SCIENTIFIC ABLATION STUDY (N = {N_RUNS})")
    print("Dataset: 512x512 16-bit Clinical CT Equivalent (524,288 bytes / 0.50 MiB)")
    print("Platform: Python 3.14 on Windows AMD64 | Backend: FIPS 203 ML-KEM-768 Native Provider")
    print("=" * 86)

    np.random.seed(42)
    # Realistic CT slice simulation with anatomical contrast gradients
    base_gradient = np.linspace(-1000, 1500, 512, dtype=np.float64)
    anatomy = np.outer(base_gradient, np.ones(512)) + np.random.normal(0, 50, (512, 512))
    sample_ct = np.clip(anatomy, -1024, 3071).astype(np.int16)

    res = run_scientific_ablation(sample_ct, repetitions=N_RUNS)

    pb = res["Plaintext Baseline"]
    print(f"\n[PLAINTEXT BASELINE]")
    print(f"  Shannon Entropy     : {pb['entropy']:.4f} bits/symbol")
    print(f"  Adjacent Correlation: rH = {pb['r_h']:+.4f} | rV = {pb['r_v']:+.4f} | rD = {pb['r_d']:+.4f}")
    print("-" * 86)

    print(f"\n[ABLATION COMPARISON TABLE (Mean ± 95% CI over N={N_RUNS} runs)]")
    header = f"{'Configuration':<32} | {'Enc Latency (ms)':<18} | {'Dec Latency (ms)':<18} | {'Entropy':<8} | {'NPCR (%)':<8} | {'UACI (%)':<8} | {'Peak Mem'}"
    print(header)
    print("-" * len(header))

    for name, m in res.items():
        if "Handshake" in name or "Baseline" in name:
            continue
        enc_str = f"{m['enc_stats']['mean']:5.2f} ± {m['enc_stats']['ci95']:4.2f}"
        dec_str = f"{m['dec_stats']['mean']:5.2f} ± {m['dec_stats']['ci95']:4.2f}"
        mem_str = f"{m['peak_mem_kib']:6.1f} KiB"
        print(f"{name:<32} | {enc_str:<18} | {dec_str:<18} | {m['entropy']:>7.4f} | {m['npcr']:>7.2f}% | {m['uaci']:>7.2f}% | {mem_str}")

    print("-" * len(header))

    print(f"\n[CIPHERTEXT ADJACENT CORRELATIONS (Target: ~0.0000)]")
    for name, m in res.items():
        if "Handshake" in name or "Baseline" in name:
            continue
        print(f"  {name:<32}: rH = {m['r_h']:+.6f} | rV = {m['r_v']:+.6f} | rD = {m['r_d']:+.6f}")

    hk = res["Authenticated Hybrid Handshake (Ed25519 + P-256 + ML-KEM-768)"]
    hs = hk["stats"]
    print(f"\n[AUTHENTICATED HYBRID KEY ESTABLISHMENT (NIST FIPS 203 ML-KEM-768 + P-256 + Ed25519)]")
    print(f"  In-Process Compute Latency : {hs['mean']:.2f} ± {hs['ci95']:.2f} ms (median: {hs['median']:.2f} ms, std: {hs['std']:.2f} ms)")
    print(f"  Peak Memory Overhead       : {hk['peak_mem_kib']:.1f} KiB")
    print(f"  WAN Simulation (10 ms RTT) : {hk['simulated_rtt_10ms']:.2f} ms total")
    print(f"  WAN Simulation (30 ms RTT) : {hk['simulated_rtt_30ms']:.2f} ms total")
    print(f"  WAN Simulation (50 ms RTT) : {hk['simulated_rtt_50ms']:.2f} ms total")
    print("=" * 86)

    # Save CSV and JSON artifacts
    import csv
    csv_path = os.path.join(os.path.dirname(__file__), "ablation_study_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Configuration", "Enc_Mean_ms", "Enc_CI95_ms", "Dec_Mean_ms", "Dec_CI95_ms", "Entropy", "NPCR_pct", "UACI_pct", "rH", "rV", "rD", "Peak_Mem_KiB"])
        for name, m in res.items():
            if "Handshake" in name or "Baseline" in name:
                continue
            writer.writerow([
                name,
                f"{m['enc_stats']['mean']:.4f}",
                f"{m['enc_stats']['ci95']:.4f}",
                f"{m['dec_stats']['mean']:.4f}",
                f"{m['dec_stats']['ci95']:.4f}",
                f"{m['entropy']:.6f}",
                f"{m['npcr']:.4f}",
                f"{m['uaci']:.4f}",
                f"{m['r_h']:.6f}",
                f"{m['r_v']:.6f}",
                f"{m['r_d']:.6f}",
                f"{m['peak_mem_kib']:.2f}"
            ])
    print(f"\n[Artifact Generated] CSV saved to: {csv_path}")

    import json
    json_path = os.path.join(os.path.dirname(__file__), "ablation_study_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"[Artifact Generated] JSON saved to: {json_path}")
