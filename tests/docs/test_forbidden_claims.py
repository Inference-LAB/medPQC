"""
Documentation test suite: test_forbidden_claims.py.
Scans README, docs/, AUDIT/, benchmarks/REPORT.md, CHANGELOG.md for un-negated forbidden terms.
"""

from pathlib import Path
import re
import pytest

BANNED_WORDS = [
    "Safe Harbor",
    "HIPAA",
    "Complies with",
    "Forward Secrecy",
    "conforms",
    "compliant",
    "production",
    "clinical deployment",
    "100%",
    "IND-CCA",
    "OPEN",
    "WONTFIX",
    "RESOLVED",
]

NEGATION_TERMS = ["not", "no ", "does not", "limitation", "neither", "never", "non-production"]


def _check_forbidden_in_text(text: str, filename: str) -> list[str]:
    violations = []
    sentences = re.split(r"[\.\n]", text)
    for line_idx, sentence in enumerate(sentences, start=1):
        s_strip = sentence.strip()
        if not s_strip:
            continue
        s_lower = s_strip.lower()
        for word in BANNED_WORDS:
            pattern = r"\b" + re.escape(word) + r"\b" if not word.endswith("%") else re.escape(word)
            if re.search(pattern, s_strip, re.IGNORECASE):
                is_negated = any(neg in s_lower for neg in NEGATION_TERMS)
                if not is_negated:
                    violations.append(f"{filename} (near line {line_idx}): un-negated '{word}' -> '{s_strip[:80]}'")
    return violations


def test_no_unnegated_forbidden_claims():
    """Enforces that no un-negated forbidden marketing or compliance terms appear anywhere in docs."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    targets = [
        repo_root / "README.md",
        repo_root / "CHANGELOG.md",
        repo_root / "benchmarks" / "REPORT.md",
    ]
    targets.extend((repo_root / "docs").rglob("*.md"))
    targets.extend((repo_root / "AUDIT").rglob("*.md"))
    targets.extend((repo_root / "AUDIT").glob("*.yaml"))

    all_violations = []
    for path in targets:
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="ignore")
            violations = _check_forbidden_in_text(text, path.name)
            all_violations.extend(violations)

    assert not all_violations, f"Found {len(all_violations)} un-negated forbidden claims:\n" + "\n".join(all_violations)
