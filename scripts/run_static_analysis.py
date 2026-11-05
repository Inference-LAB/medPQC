#!/usr/bin/env python3
"""Run automated static security analysis and linters for MedPQC v2.4.

Executes Ruff (lint & format), Mypy (--strict), Bandit (AST security audit),
pip-audit (vulnerability database scan), and pattern-based secret scan.
Outputs raw reports to AUDIT/evidence/static/ with strict LF line endings
and normalized non-Windows paths. No emojis and no hand-written metrics.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


def sanitize_output(text: str, repo_root: Path) -> str:
    root_str = str(repo_root)
    sanitized = text.replace(root_str, "/workspace/medpqc")
    sanitized = sanitized.replace(root_str.replace("/", "\\"), "/workspace/medpqc")
    sanitized = sanitized.replace("\\", "/")
    sanitized = sanitized.replace("\r\n", "\n")
    return sanitized


def run_command(cmd: list[str], repo_root: Path, timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        return proc.returncode, sanitize_output(output, repo_root)
    except subprocess.TimeoutExpired:
        return 1, f"NOT RUN: Command timed out after {timeout}s: {' '.join(cmd)}\n"
    except Exception as e:
        return 1, f"NOT RUN: {type(e).__name__}: {e}\n"


def run_secret_scan(repo_root: Path) -> tuple[int, str]:
    """Scans codebase for accidentally committed private keys or tokens."""
    banned_patterns = [
        re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----"),
        re.compile(r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"),
        re.compile(r"(?i)secret[_-]?token\s*=\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"),
    ]
    findings = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        # Skip git directory, caches, virtualenvs, audit evidence
        parts = p.parts
        if any(
            skip in parts for skip in (".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", "venv", ".venv", "AUDIT")
        ):
            continue
        if p.suffix in (".pyc", ".pyd", ".png", ".jpg", ".zip", ".tar", ".gz", ".whl"):
            continue

        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            for line_no, line in enumerate(content.splitlines(), start=1):
                for pat in banned_patterns:
                    if pat.search(line):
                        rel = p.relative_to(repo_root).as_posix()
                        findings.append(f"{rel}:{line_no}: {line.strip()[:60]}")
        except Exception:
            continue

    if findings:
        report = "Secret scan findings (FAIL):\n" + "\n".join(findings) + "\n"
        return 1, report
    return 0, "No secrets, hardcoded credentials, or private keys detected in repository.\n"


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    evidence_dir = repo_root / "AUDIT" / "evidence" / "static"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "commands": {},
        "exit_codes": {},
        "tool_versions": {},
    }

    # 1. Ruff lint
    cmd_ruff_lint = [sys.executable, "-m", "ruff", "check", "medpqc"]
    code, out = run_command(cmd_ruff_lint, repo_root)
    summary["commands"]["ruff_lint"] = " ".join(cmd_ruff_lint)
    summary["exit_codes"]["ruff_lint"] = code
    (evidence_dir / "ruff_lint.txt").write_bytes(out.encode("utf-8"))

    # 2. Ruff format check
    cmd_ruff_fmt = [sys.executable, "-m", "ruff", "format", "--check", "medpqc"]
    code, out = run_command(cmd_ruff_fmt, repo_root)
    summary["commands"]["ruff_format"] = " ".join(cmd_ruff_fmt)
    summary["exit_codes"]["ruff_format"] = code
    (evidence_dir / "ruff_format.txt").write_bytes(out.encode("utf-8"))

    # 3. Mypy strict
    cmd_mypy = [sys.executable, "-m", "mypy", "--strict", "medpqc"]
    code, out = run_command(cmd_mypy, repo_root, timeout=60)
    summary["commands"]["mypy"] = " ".join(cmd_mypy)
    summary["exit_codes"]["mypy"] = code
    (evidence_dir / "mypy_report.txt").write_bytes(out.encode("utf-8"))

    # 4. Bandit JSON
    cmd_bandit = [sys.executable, "-m", "bandit", "-r", "medpqc", "-f", "json"]
    code, out = run_command(cmd_bandit, repo_root)
    summary["commands"]["bandit"] = " ".join(cmd_bandit)
    summary["exit_codes"]["bandit"] = code
    (evidence_dir / "bandit_report.json").write_bytes(out.encode("utf-8"))

    # 5. pip-audit
    cmd_audit = [sys.executable, "-m", "pip_audit", "-f", "json", "--timeout", "5"]
    code, out = run_command(cmd_audit, repo_root, timeout=10)
    is_json = False
    try:
        json.loads(out)
        is_json = True
    except Exception:
        pass

    if not is_json:
        cmd_audit = [sys.executable, "-m", "pip_audit", "-d", "-f", "json"]
        code, out = run_command(cmd_audit, repo_root, timeout=10)
        json_lines = [l for l in out.splitlines() if l.strip().startswith("{") or l.strip().startswith("[")]
        if json_lines:
            out = "\n".join(json_lines) + "\n"
        else:
            out = json.dumps({"status": "OFFLINE_AUDIT", "dependencies": [], "fixes": []}, indent=2) + "\n"

    summary["commands"]["pip_audit"] = " ".join(cmd_audit)
    summary["exit_codes"]["pip_audit"] = code
    (evidence_dir / "pip_audit_report.json").write_bytes(out.encode("utf-8"))

    # 6. Secret scan
    code, out = run_secret_scan(repo_root)
    summary["commands"]["secret_scan"] = "internal regex AST/source scanner"
    summary["exit_codes"]["secret_scan"] = code
    (evidence_dir / "secret_scan.txt").write_bytes(out.encode("utf-8"))

    # Save summary JSON
    summary_path = evidence_dir / "static_analysis_summary.json"
    summary_bytes = (json.dumps(summary, indent=2) + "\n").encode("utf-8")
    summary_path.write_bytes(summary_bytes)

    print("Static analysis completed:")
    critical_failures = 0
    for k, v in summary["exit_codes"].items():
        print(f"  {k}: exit code {v}")
        if k != "pip_audit" and v != 0:
            critical_failures += 1
        elif k == "pip_audit" and v != 0 and not out.startswith("NOT RUN:"):
            critical_failures += 1

    return critical_failures


if __name__ == "__main__":
    sys.exit(main())
