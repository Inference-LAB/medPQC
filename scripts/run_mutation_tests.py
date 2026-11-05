#!/usr/bin/env python3
"""Run targeted mutation testing on core MedPQC security and cryptographic modules.

Works natively across platforms without relying on WSL. Applies standard mutation
operators to security-critical code paths, executes associated test suites,
and records killed vs surviving mutants to AUDIT/evidence/mutation/.
"""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


MUTATION_TARGETS = [
    {
        "file": "medpqc/kem/auth.py",
        "tests": [
            "tests/test_kem_auth.py",
            "tests/adversarial/exploits/test_exploit_d01.py",
            "tests/adversarial/exploits/test_exploit_d02.py",
            "tests/adversarial/exploits/test_exploit_n10.py",
        ],
        "max_mutants": 12,
    },
    {
        "file": "medpqc/kem/combiner.py",
        "tests": [
            "tests/test_kem_combiner.py",
            "tests/adversarial/exploits/test_exploit_n10.py",
        ],
        "max_mutants": 12,
    },
    {
        "file": "medpqc/security/replay.py",
        "tests": [
            "tests/unit/test_replay.py",
            "tests/adversarial/test_replay_attacks.py",
        ],
        "max_mutants": 10,
    },
    {
        "file": "medpqc/security/trust.py",
        "tests": [
            "tests/unit/test_trust.py",
        ],
        "max_mutants": 10,
    },
    {
        "file": "medpqc/cipher/aead.py",
        "tests": [
            "tests/test_cipher_aead.py",
        ],
        "max_mutants": 10,
    },
    {
        "file": "medpqc/cipher/engine.py",
        "tests": [
            "tests/test_cipher_integration.py",
        ],
        "max_mutants": 10,
    },
]

OPERATOR_MUTATIONS = [
    ("==", "!="),
    ("!=", "=="),
    (" not in ", " in "),
    (" is None", " is not None"),
    (" is not None", " is None"),
    ("True", "False"),
    ("False", "True"),
    (" + ", " - "),
    (" - ", " + "),
]


def run_tests_for_target(repo_root: Path, test_paths: list[str]) -> bool:
    """Returns True if tests pass, False if tests fail (mutant killed)."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *test_paths,
        "-q",
        "--tb=no",
    ]
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def generate_candidate_mutations(source_text: str, max_mutations_per_file: int = 15) -> list[tuple[int, str, str]]:
    """Generates simple single-token line mutations on comparison and boolean logic."""
    mutations: list[tuple[int, str, str]] = []
    lines = source_text.splitlines()
    in_docstring = False

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('"""') or stripped.startswith("'''"):
            if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            continue

        if not stripped or stripped.startswith("#") or stripped.startswith("@") or stripped.startswith("="):
            continue
        if stripped.startswith("import ") or stripped.startswith("from "):
            continue

        for orig, repl in OPERATOR_MUTATIONS:
            if orig in line:
                mutated_line = line.replace(orig, repl, 1)
                mutations.append((idx, line, mutated_line))
                if len(mutations) >= max_mutations_per_file:
                    return mutations

    return mutations


def run_mutation_analysis() -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parent.parent
    evidence_dir = repo_root / "AUDIT" / "evidence" / "mutation"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    print("Starting targeted mutation analysis...")
    start_time = time.time()

    total_mutants = 0
    killed_mutants = 0
    survived_mutants = 0
    mutation_records: list[dict[str, Any]] = []

    for target in MUTATION_TARGETS:
        target_rel = target["file"]
        target_path = repo_root / target_rel
        test_paths = target["tests"]

        if not target_path.exists():
            continue

        orig_source = target_path.read_text(encoding="utf-8")
        max_m = target.get("max_mutants", 10)
        candidates = generate_candidate_mutations(orig_source, max_mutations_per_file=max_m)
        print(f"Target {target_rel}: evaluating {len(candidates)} mutants...")

        for line_no, orig_line, mut_line in candidates:
            total_mutants += 1
            lines = orig_source.splitlines()
            lines[line_no] = mut_line
            mutated_source = "\n".join(lines) + "\n"

            # Apply mutation
            target_path.write_text(mutated_source, encoding="utf-8")
            try:
                passed = run_tests_for_target(repo_root, test_paths)
            finally:
                # Always restore original source
                target_path.write_text(orig_source, encoding="utf-8")

            if passed:
                status = "SURVIVED"
                survived_mutants += 1
            else:
                status = "KILLED"
                killed_mutants += 1

            record = {
                "file": target_rel.replace("\\", "/"),
                "line": line_no + 1,
                "original": orig_line.strip(),
                "mutated": mut_line.strip(),
                "status": status,
            }
            mutation_records.append(record)

    duration = time.time() - start_time
    score = (killed_mutants / total_mutants * 100.0) if total_mutants > 0 else 0.0

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_seconds": round(duration, 2),
        "total_mutants": total_mutants,
        "killed_mutants": killed_mutants,
        "survived_mutants": survived_mutants,
        "mutation_score": round(score, 2),
        "mutation_score_percent": round(score, 2),
        "mutations": mutation_records,
    }

    # Save JSON reports
    json_content = json.dumps(summary, indent=2) + "\n"
    json_content = json_content.replace("\r\n", "\n")
    (evidence_dir / "mutation_results.json").write_bytes(json_content.encode("utf-8"))
    (evidence_dir / "mutation_report.json").write_bytes(json_content.encode("utf-8"))

    # Save text report
    txt_path = evidence_dir / "mutation_report.txt"
    lines_out = [
        f"MedPQC Mutation Analysis Report",
        f"Timestamp: {summary['timestamp']}",
        f"Duration: {summary['duration_seconds']}s",
        f"Total Mutants Evaluated: {total_mutants}",
        f"Killed: {killed_mutants}",
        f"Survived: {survived_mutants}",
        f"Mutation Score: {summary['mutation_score_percent']}%",
        "",
        "--- Details by Mutant ---",
    ]
    for r in mutation_records:
        lines_out.append(f"[{r['status']}] {r['file']}:{r['line']} | {r['original']} -> {r['mutated']}")
    lines_out.append("")

    txt_content = "\n".join(lines_out).replace("\r\n", "\n")
    txt_path.write_bytes(txt_content.encode("utf-8"))

    print(
        f"Mutation analysis complete: Score = {summary['mutation_score_percent']}% ({killed_mutants}/{total_mutants})"
    )
    print(f"Evidence saved to {evidence_dir} and {txt_path}")
    return summary


if __name__ == "__main__":
    run_mutation_analysis()
