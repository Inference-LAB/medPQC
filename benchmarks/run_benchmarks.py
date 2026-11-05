#!/usr/bin/env python3
"""
benchmarks.run_benchmarks
=========================
Master reproducible benchmark runner for MedPQC v2.4.0.

Executes:
  1. Handshake latency across Memory and SQLite replay backends (>=30 reps).
  2. Payload encryption ablation across 4 arms:
     - Arm 1: AES-256-GCM only
     - Arm 2: AES-256-GCM + Permutation
     - Arm 3: AES-256-GCM + Diffusion
     - Arm 4: AES-256-GCM + Both (Permutation + Diffusion)
     Evaluated on 4 dimensions (32x32, 64x64, 128x128, 256x256) and 3 dtypes (uint8, uint16, int16).
  3. Writes raw per-repetition CSV data to benchmarks/results/raw/.
  4. Triggers benchmarks/analyze.py and benchmarks/plot.py.
"""

import csv
import hashlib
import os
from pathlib import Path
import random
import secrets
import sys
import tempfile
import time
import tracemalloc
from typing import Any

import numpy as np

# Ensure medpqc is importable
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from medpqc.cipher.aead import AuthenticatedCipher
from medpqc.cipher.engine import MedPQCCipher
from medpqc.experimental.chaos.permutation import ChaoticPermuter
from medpqc.experimental.chaos.sponge import ChaoticEntropySponge
from medpqc.experimental.diffusion import ChaoticDiffusion
from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.replay import MemoryReplayStore, SqliteReplayStore
from medpqc.security.trust import TrustStore


def calculate_entropy(arr: np.ndarray) -> float:
    flat = np.frombuffer(arr.tobytes(), dtype=np.uint8)
    counts = np.bincount(flat, minlength=256)
    probs = counts[counts > 0] / flat.size
    return float(-np.sum(probs * np.log2(probs)))


def calculate_npcr_uaci(c1_bytes: bytes, c2_bytes: bytes) -> tuple[float, float]:
    b1 = np.frombuffer(c1_bytes, dtype=np.uint8)
    b2 = np.frombuffer(c2_bytes, dtype=np.uint8)
    n = min(b1.size, b2.size)
    if n == 0:
        return 0.0, 0.0
    b1, b2 = b1[:n], b2[:n]
    diff = (b1 != b2).astype(np.float64)
    npcr = float(np.mean(diff) * 100.0)
    uaci = float(np.mean(np.abs(b1.astype(float) - b2.astype(float)) / 255.0) * 100.0)
    return round(npcr, 2), round(uaci, 2)


# =========================================================================
# Handshake Benchmarks
# =========================================================================
def run_handshake_benchmarks(raw_dir: Path, n_reps: int = 30) -> None:
    print(f"Running handshake benchmarks ({n_reps} reps per backend)...")
    raw_csv = raw_dir / "handshake_benchmarks_raw.csv"

    alice_id = IdentityKeyPair.generate("alice")
    bob_id = IdentityKeyPair.generate("bob")
    ts = TrustStore()
    ts.register_peer("alice", alice_id.public_bytes)
    ts.register_peer("bob", bob_id.public_bytes)

    fieldnames = [
        "rep",
        "backend",
        "init_ms",
        "resp_ms",
        "finalize_ms",
        "total_ms",
        "peak_ram_bytes",
    ]

    with open(raw_csv, "w", newline="\n", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for backend_name in ["MemoryReplayStore", "SqliteReplayStore"]:
            temp_db = None
            if backend_name == "MemoryReplayStore":
                store = MemoryReplayStore()
            else:
                tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
                temp_db = tf.name
                tf.close()
                store = SqliteReplayStore(temp_db)

            # Warmup
            for _ in range(3):
                a_ctx = InitiatorContext(node_id="alice", identity=alice_id, trust_store=ts)
                b_ctx = ResponderContext(node_id="bob", identity=bob_id, trust_store=ts, replay_store=store)
                init_msg = a_ctx.initiate(receiver_id="bob")
                resp_msg = b_ctx.respond(init_msg)
                _ = a_ctx.finalize(resp_msg)

            for r in range(n_reps):
                tracemalloc.start()
                a_ctx = InitiatorContext(node_id="alice", identity=alice_id, trust_store=ts)
                b_ctx = ResponderContext(node_id="bob", identity=bob_id, trust_store=ts, replay_store=store)

                t0 = time.perf_counter()
                init_msg = a_ctx.initiate(receiver_id="bob")
                t1 = time.perf_counter()
                resp_msg = b_ctx.respond(init_msg)
                t2 = time.perf_counter()
                sess = a_ctx.finalize(resp_msg)
                t3 = time.perf_counter()

                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                init_ms = (t1 - t0) * 1000.0
                resp_ms = (t2 - t1) * 1000.0
                finalize_ms = (t3 - t2) * 1000.0
                total_ms = (t3 - t0) * 1000.0

                writer.writerow({
                    "rep": r + 1,
                    "backend": backend_name,
                    "init_ms": round(init_ms, 3),
                    "resp_ms": round(resp_ms, 3),
                    "finalize_ms": round(finalize_ms, 3),
                    "total_ms": round(total_ms, 3),
                    "peak_ram_bytes": peak,
                })

            store.close()
            if temp_db and os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except OSError:
                    pass


# =========================================================================
# Payload Ablation Benchmarks
# =========================================================================
def run_payload_benchmarks(raw_dir: Path, n_reps: int = 30) -> None:
    print(f"Running payload ablation benchmarks ({n_reps} reps per cell across 4 arms)...")
    raw_csv = raw_dir / "payload_ablation_raw.csv"

    fieldnames = [
        "rep",
        "arm",
        "resolution",
        "shape",
        "dtype",
        "size_bytes",
        "enc_time_ms",
        "dec_time_ms",
        "peak_ram_bytes",
        "entropy",
        "npcr",
        "uaci",
        "mse",
    ]

    resolutions = [
        ("32x32", (32, 32)),
        ("64x64", (64, 64)),
        ("128x128", (128, 128)),
        ("256x256", (256, 256)),
    ]
    dtypes = ["uint8", "uint16", "int16"]
    arms = ["aes_gcm_only", "aes_gcm_permutation", "aes_gcm_diffusion", "aes_gcm_both"]

    cells = []
    for res_name, shape in resolutions:
        for dt in dtypes:
            for arm in arms:
                cells.append((res_name, shape, dt, arm))

    random.seed(42)
    np.random.seed(42)

    k_aes = b"\x11" * 32
    k_mac = b"\x22" * 32
    s_chaos = b"\x33" * 32
    cipher = MedPQCCipher(k_aes=k_aes, k_mac=k_mac, s_chaos=s_chaos)

    with open(raw_csv, "w", newline="\n", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        # Warmup
        dummy = np.zeros((32, 32), dtype=np.uint8)
        for _ in range(3):
            enc = cipher.encrypt(dummy, enable_scrambling=True)
            _ = cipher.decrypt(enc)

        for rep in range(1, n_reps + 1):
            random.shuffle(cells)
            for res_name, shape, dt, arm in cells:
                if dt == "uint8":
                    arr = np.random.randint(0, 256, size=shape, dtype=np.uint8)
                elif dt == "uint16":
                    arr = np.random.randint(0, 65536, size=shape, dtype=np.uint16)
                else:
                    arr = np.random.randint(-1000, 3000, size=shape, dtype=np.int16)

                n_bytes = arr.nbytes
                flat_bytes = arr.tobytes()
                flat_u8 = np.frombuffer(flat_bytes, dtype=np.uint8)

                tracemalloc.start()
                t0 = time.perf_counter()

                if arm == "aes_gcm_only":
                    bundle = AuthenticatedCipher.encrypt(flat_bytes, k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    enc_time = (time.perf_counter() - t0) * 1000.0

                    t_dec0 = time.perf_counter()
                    raw_dec = AuthenticatedCipher.decrypt(bundle, k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    dec_arr = np.frombuffer(raw_dec, dtype=dt).reshape(shape)
                    dec_time = (time.perf_counter() - t_dec0) * 1000.0
                    ct_bytes = bundle["ciphertext"]

                elif arm == "aes_gcm_permutation":
                    perm_seed = hashlib.sha3_512(s_chaos + b"perm-bench").digest()
                    scrambled, _ = ChaoticPermuter.permute(flat_u8, perm_seed)
                    bundle = AuthenticatedCipher.encrypt(scrambled.tobytes(), k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    enc_time = (time.perf_counter() - t0) * 1000.0

                    t_dec0 = time.perf_counter()
                    raw_dec = AuthenticatedCipher.decrypt(bundle, k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    dec_scrambled = np.frombuffer(raw_dec, dtype=np.uint8)
                    unperm = ChaoticPermuter.inverse_permute(dec_scrambled, perm_seed)
                    dec_arr = np.frombuffer(unperm.tobytes(), dtype=dt).reshape(shape)
                    dec_time = (time.perf_counter() - t_dec0) * 1000.0
                    ct_bytes = bundle["ciphertext"]

                elif arm == "aes_gcm_diffusion":
                    chaos_seed = hashlib.sha3_512(s_chaos + b"diff-bench").digest()
                    keystream = ChaoticEntropySponge.extract_uint8_stream(chaos_seed, n_bytes * 3)
                    diffused = ChaoticDiffusion.bitplane_diffuse(flat_u8, keystream[:n_bytes])
                    ccd_mixed = ChaoticDiffusion.ccd_mix(diffused, keystream, rounds=3).tobytes()
                    bundle = AuthenticatedCipher.encrypt(ccd_mixed, k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    enc_time = (time.perf_counter() - t0) * 1000.0

                    t_dec0 = time.perf_counter()
                    raw_dec = AuthenticatedCipher.decrypt(bundle, k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    raw_cbc = np.frombuffer(raw_dec, dtype=np.uint8)
                    undiffused_ccd = ChaoticDiffusion.ccd_unmix(raw_cbc, keystream, rounds=3)
                    undiffused = ChaoticDiffusion.bitplane_undiffuse(undiffused_ccd, keystream[:n_bytes])
                    dec_arr = np.frombuffer(undiffused.tobytes(), dtype=dt).reshape(shape)
                    dec_time = (time.perf_counter() - t_dec0) * 1000.0
                    ct_bytes = bundle["ciphertext"]

                else:  # arm == "aes_gcm_both"
                    enc_bundle = cipher.encrypt(arr, enable_scrambling=True)
                    enc_time = (time.perf_counter() - t0) * 1000.0

                    t_dec0 = time.perf_counter()
                    dec_arr = cipher.decrypt(enc_bundle)
                    dec_time = (time.perf_counter() - t_dec0) * 1000.0
                    ct_bytes = enc_bundle["aead"]["ciphertext"]

                current, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                mse = float(np.mean((arr.astype(np.float64) - dec_arr.astype(np.float64)) ** 2))
                entropy = calculate_entropy(np.frombuffer(ct_bytes, dtype=np.uint8))

                arr_perturbed = arr.copy()
                arr_perturbed.flat[0] ^= 1
                arr_pert_u8 = np.frombuffer(arr_perturbed.tobytes(), dtype=np.uint8)
                if arm == "aes_gcm_only":
                    b2 = AuthenticatedCipher.encrypt(arr_perturbed.tobytes(), k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    ct2 = b2["ciphertext"]
                elif arm == "aes_gcm_permutation":
                    sc2, _ = ChaoticPermuter.permute(arr_pert_u8, perm_seed)
                    b2 = AuthenticatedCipher.encrypt(sc2.tobytes(), k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    ct2 = b2["ciphertext"]
                elif arm == "aes_gcm_diffusion":
                    diff2 = ChaoticDiffusion.bitplane_diffuse(arr_pert_u8, keystream[:n_bytes])
                    mix2 = ChaoticDiffusion.ccd_mix(diff2, keystream, rounds=3).tobytes()
                    b2 = AuthenticatedCipher.encrypt(mix2, k_aes, k_mac, aad=b"MEDPQC-BENCH")
                    ct2 = b2["ciphertext"]
                else:
                    b2 = cipher.encrypt(arr_perturbed, enable_scrambling=True)
                    ct2 = b2["aead"]["ciphertext"]

                npcr, uaci = calculate_npcr_uaci(ct_bytes, ct2)

                writer.writerow({
                    "rep": rep,
                    "arm": arm,
                    "resolution": res_name,
                    "shape": f"{shape[0]}x{shape[1]}",
                    "dtype": dt,
                    "size_bytes": n_bytes,
                    "enc_time_ms": round(enc_time, 3),
                    "dec_time_ms": round(dec_time, 3),
                    "peak_ram_bytes": peak,
                    "entropy": round(entropy, 4),
                    "npcr": npcr,
                    "uaci": uaci,
                    "mse": mse,
                })


def main() -> None:
    benchmarks_dir = Path(__file__).resolve().parent
    raw_dir = benchmarks_dir / "results" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 1. Run benchmarks
    run_handshake_benchmarks(raw_dir, n_reps=30)
    run_payload_benchmarks(raw_dir, n_reps=30)

    # 2. Run analyze
    from benchmarks.analyze import main as analyze_main
    analyze_main()

    # 3. Run plot
    from benchmarks.plot import main as plot_main
    plot_main()

    print("All benchmark raw data gathered and analyzed successfully.")


if __name__ == "__main__":
    main()
