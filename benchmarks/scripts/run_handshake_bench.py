"""
benchmarks.scripts.run_handshake_bench
======================================
Cryptographic Handshake Latency and Scalability Benchmark for MedPQC v2.3.0.
Evaluates:
  - NIST FIPS 203 ML-KEM-768 + Ephemeral P-256 + Ed25519 Mutual Authentication
  - Step 1: Alice Initiate
  - Step 2: Bob Respond (with TrustStore & Replay filtering)
  - Step 3: Alice Finalize (Decapsulation & Transcript verification)
  - MemoryReplayStore vs SqliteReplayStore performance comparison
  - Peak memory profiling via tracemalloc
  - Sample size N >= 30 with mean, standard deviation, and percentiles
"""

import os
import sys
import time
import json
import csv
import secrets
import tempfile
import tracemalloc
import numpy as np

# Ensure medpqc is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from medpqc.kem.auth import IdentityKeyPair, InitiatorContext, ResponderContext
from medpqc.security.trust import TrustStore
from medpqc.security.replay import MemoryReplayStore, SqliteReplayStore, ReplayProtector


def benchmark_handshakes(n_iterations: int = 50, warmup_iterations: int = 5):
    print(f"Running handshake benchmark (warmup={warmup_iterations}, n={n_iterations})...")

    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()

    trust_store = TrustStore()
    trust_store.register_peer("alice-pacs-node", alice_id.public_bytes)
    trust_store.register_peer("bob-pacs-node", bob_id.public_bytes)

    # Warmup runs to avoid JIT/import overhead
    for _ in range(warmup_iterations):
        sid = secrets.token_bytes(16)
        init_ctx = InitiatorContext("alice-pacs-node", alice_id, trust_store=trust_store)
        msg_init = init_ctx.initiate(receiver_id="bob-pacs-node", session_id=sid)
        resp_ctx = ResponderContext(
            "bob-pacs-node",
            bob_id,
            trust_store=trust_store,
            replay_store=MemoryReplayStore(),
            allow_non_durable_replay_store=True,
        )
        msg_resp, bob_sess = resp_ctx.respond(init_message=msg_init)
        alice_sess = init_ctx.finalize(response_message=msg_resp)
        assert alice_sess.k_send == bob_sess.k_recv

    # 1. Benchmark with MemoryReplayStore
    mem_store = MemoryReplayStore()

    init_times_mem = []
    resp_times_mem = []
    fin_times_mem = []
    total_times_mem = []

    tracemalloc.start()
    for _ in range(n_iterations):
        sid = secrets.token_bytes(16)
        init_ctx = InitiatorContext("alice-pacs-node", alice_id, trust_store=trust_store)
        resp_ctx = ResponderContext(
            "bob-pacs-node",
            bob_id,
            trust_store=trust_store,
            replay_store=mem_store,
            allow_non_durable_replay_store=True,
        )

        t0 = time.perf_counter()
        init_msg = init_ctx.initiate(
            receiver_id="bob-pacs-node",
            session_id=sid,
        )
        t_init = (time.perf_counter() - t0) * 1000.0

        t0 = time.perf_counter()
        resp_msg, bob_session = resp_ctx.respond(
            init_message=init_msg,
        )
        t_resp = (time.perf_counter() - t0) * 1000.0

        t0 = time.perf_counter()
        alice_session = init_ctx.finalize(
            response_message=resp_msg,
        )
        t_fin = (time.perf_counter() - t0) * 1000.0

        assert alice_session.k_send == bob_session.k_recv

        init_times_mem.append(t_init)
        resp_times_mem.append(t_resp)
        fin_times_mem.append(t_fin)
        total_times_mem.append(t_init + t_resp + t_fin)

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mem_mb = peak_mem / (1024 * 1024)

    # 2. Benchmark with SqliteReplayStore
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "bench_replay.db")
        sql_store = SqliteReplayStore(db_path)

        init_times_sql = []
        resp_times_sql = []
        fin_times_sql = []
        total_times_sql = []

        tracemalloc.start()
        for _ in range(n_iterations):
            sid = secrets.token_bytes(16)
            init_ctx = InitiatorContext("alice-pacs-node", alice_id, trust_store=trust_store)
            resp_ctx = ResponderContext(
                "bob-pacs-node",
                bob_id,
                trust_store=trust_store,
                replay_store=sql_store,
            )

            t0 = time.perf_counter()
            init_msg = init_ctx.initiate(
                receiver_id="bob-pacs-node",
                session_id=sid,
            )
            t_init = (time.perf_counter() - t0) * 1000.0

            t0 = time.perf_counter()
            resp_msg, bob_session = resp_ctx.respond(
                init_message=init_msg,
            )
            t_resp = (time.perf_counter() - t0) * 1000.0

            t0 = time.perf_counter()
            alice_session = init_ctx.finalize(
                response_message=resp_msg,
            )
            t_fin = (time.perf_counter() - t0) * 1000.0

            init_times_sql.append(t_init)
            resp_times_sql.append(t_resp)
            fin_times_sql.append(t_fin)
            total_times_sql.append(t_init + t_resp + t_fin)

        _, peak_sql_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_sql_mb = peak_sql_mem / (1024 * 1024)
        sql_store.close()

    summary = [
        {
            'replay_backend': 'MemoryReplayStore',
            'iterations': n_iterations,
            'init_mean_ms': round(float(np.mean(init_times_mem)), 2),
            'init_std_ms': round(float(np.std(init_times_mem)), 2),
            'resp_mean_ms': round(float(np.mean(resp_times_mem)), 2),
            'resp_std_ms': round(float(np.std(resp_times_mem)), 2),
            'finalize_mean_ms': round(float(np.mean(fin_times_mem)), 2),
            'finalize_std_ms': round(float(np.std(fin_times_mem)), 2),
            'total_handshake_ms': round(float(np.mean(total_times_mem)), 2),
            'total_handshake_p50_ms': round(float(np.percentile(total_times_mem, 50)), 2),
            'total_handshake_p95_ms': round(float(np.percentile(total_times_mem, 95)), 2),
            'handshakes_per_sec': round(1000.0 / float(np.mean(total_times_mem)), 1),
            'peak_memory_mb': round(peak_mem_mb, 3),
        },
        {
            'replay_backend': 'SqliteReplayStore',
            'iterations': n_iterations,
            'init_mean_ms': round(float(np.mean(init_times_sql)), 2),
            'init_std_ms': round(float(np.std(init_times_sql)), 2),
            'resp_mean_ms': round(float(np.mean(resp_times_sql)), 2),
            'resp_std_ms': round(float(np.std(resp_times_sql)), 2),
            'finalize_mean_ms': round(float(np.mean(fin_times_sql)), 2),
            'finalize_std_ms': round(float(np.std(fin_times_sql)), 2),
            'total_handshake_ms': round(float(np.mean(total_times_sql)), 2),
            'total_handshake_p50_ms': round(float(np.percentile(total_times_sql, 50)), 2),
            'total_handshake_p95_ms': round(float(np.percentile(total_times_sql, 95)), 2),
            'handshakes_per_sec': round(1000.0 / float(np.mean(total_times_sql)), 1),
            'peak_memory_mb': round(peak_sql_mb, 3),
        }
    ]

    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results"))
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "handshake_bench.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    csv_path = os.path.join(out_dir, "handshake_bench.csv")
    fieldnames = list(summary[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary)

    print(f"Handshake benchmark completed:\n  {json_path}\n  {csv_path}")
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    benchmark_handshakes()
