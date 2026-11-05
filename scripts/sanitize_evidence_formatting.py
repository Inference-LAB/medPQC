#!/usr/bin/env python3
"""
scripts.sanitize_evidence_formatting
====================================
Normalizes all files under AUDIT/evidence/ and docs/:
1. Enforces strict LF line endings.
2. Replaces absolute Windows paths with normalized '/workspace/medpqc' paths.
"""

from pathlib import Path


def sanitize_file(f: Path) -> None:
    try:
        data = f.read_bytes()
    except Exception:
        return

    # Replace CRLF
    data = data.replace(b"\r\n", b"\n")

    # Try decode
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except Exception:
            f.write_bytes(data)
            return

    # Normalize Windows paths
    text = text.replace("D:\\INFERENCE Lab\\crypto paper\\medpqc", "/workspace/medpqc")
    text = text.replace("d:\\INFERENCE Lab\\crypto paper\\medpqc", "/workspace/medpqc")
    text = text.replace("D:/INFERENCE Lab/crypto paper/medpqc", "/workspace/medpqc")
    text = text.replace("d:/INFERENCE Lab/crypto paper/medpqc", "/workspace/medpqc")
    text = text.replace("C:\\Users\\Muzammil Shadab", "/home/user")
    text = text.replace("c:\\Users\\Muzammil Shadab", "/home/user")
    text = text.replace("C:/Users/Muzammil Shadab", "/home/user")
    text = text.replace("c:/Users/Muzammil Shadab", "/home/user")

    text = text.replace("\r\n", "\n")
    f.write_bytes(text.encode("utf-8"))


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    evidence_dir = repo_root / "AUDIT" / "evidence"

    count = 0
    for f in evidence_dir.rglob("*"):
        if f.is_file() and f.suffix in (".txt", ".json", ".md", ".csv"):
            sanitize_file(f)
            count += 1

    # Also audit docs/ and root AUDIT/ markdown files
    for f in (repo_root / "docs").rglob("*.md"):
        if f.is_file():
            sanitize_file(f)
            count += 1

    for f in (repo_root / "AUDIT").glob("*.md"):
        if f.is_file():
            sanitize_file(f)
            count += 1

    print(f"Sanitized line endings and paths in {count} files.")


if __name__ == "__main__":
    main()
