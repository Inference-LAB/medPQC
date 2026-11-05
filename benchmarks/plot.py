#!/usr/bin/env python3
"""
benchmarks.plot
===============
Generates performance figures from raw benchmark summary data in benchmarks/results/.
"""

import json
from pathlib import Path


def generate_plots(benchmarks_dir: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping plot generation.")
        return

    res_dir = benchmarks_dir / "results"
    summary_file = res_dir / "ablation_summary.json"
    if not summary_file.exists():
        print(f"Summary file {summary_file} not found, skipping plot.")
        return

    with open(summary_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Filter to uint16 across resolutions for clean arm comparison
    uint16_data = [d for d in data if d["dtype"] == "uint16"]
    if not uint16_data:
        return

    resolutions = sorted(list({d["resolution"] for d in uint16_data}), key=lambda r: int(r.split("x")[0]))
    arms = ["aes_gcm_only", "aes_gcm_permutation", "aes_gcm_diffusion", "aes_gcm_both"]
    labels = {
        "aes_gcm_only": "Arm 1: AES-256-GCM Only",
        "aes_gcm_permutation": "Arm 2: + Permutation",
        "aes_gcm_diffusion": "Arm 3: + Diffusion",
        "aes_gcm_both": "Arm 4: + Both (Full Pipeline)",
    }

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    for arm in arms:
        arm_pts = [d for d in uint16_data if d["arm"] == arm]
        arm_pts_by_res = {d["resolution"]: d for d in arm_pts}
        x_vals = []
        enc_y = []
        dec_y = []
        for res in resolutions:
            if res in arm_pts_by_res:
                x_vals.append(res)
                enc_y.append(arm_pts_by_res[res]["enc_mean_ms"])
                dec_y.append(arm_pts_by_res[res]["dec_mean_ms"])

        axes[0].plot(x_vals, enc_y, marker="o", label=labels.get(arm, arm))
        axes[1].plot(x_vals, dec_y, marker="s", label=labels.get(arm, arm))

    axes[0].set_title("Encryption Latency by Arm (uint16)")
    axes[0].set_xlabel("Resolution")
    axes[0].set_ylabel("Latency (ms)")
    axes[0].grid(True, linestyle="--", alpha=0.5)
    axes[0].legend()

    axes[1].set_title("Decryption Latency by Arm (uint16)")
    axes[1].set_xlabel("Resolution")
    axes[1].set_ylabel("Latency (ms)")
    axes[1].grid(True, linestyle="--", alpha=0.5)
    axes[1].legend()

    plt.tight_layout()
    plot_path = res_dir / "ablation_performance.png"
    plt.savefig(plot_path, dpi=150)
    plt.close()
    print(f"Generated plot: {plot_path}")


def main() -> None:
    benchmarks_dir = Path(__file__).resolve().parent
    generate_plots(benchmarks_dir)


if __name__ == "__main__":
    main()
