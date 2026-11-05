#!/usr/bin/env python3
"""Normalize all evidence text files to strict LF and /workspace/medpqc relative paths."""
from pathlib import Path
import re

repo_root = Path(__file__).resolve().parent.parent
evidence_dir = repo_root / "AUDIT" / "evidence"

count = 0
for p in evidence_dir.rglob("*.txt"):
    data = p.read_bytes()
    text = data.decode("utf-8", errors="ignore")
    # Normalize CRLF
    text = text.replace("\r\n", "\n")
    # Normalize Windows absolute paths
    text = re.sub(r"[A-Za-z]:\\[^ \n\r\t\"']+\\medpqc-baseline", "/workspace/medpqc-baseline", text)
    text = re.sub(r"[A-Za-z]:\\[^ \n\r\t\"']+\\medpqc", "/workspace/medpqc", text)
    text = text.replace("D:\\INFERENCE Lab\\crypto paper\\medpqc", "/workspace/medpqc")
    text = text.replace("D:/INFERENCE Lab/crypto paper/medpqc", "/workspace/medpqc")
    text = text.replace("d:\\INFERENCE Lab\\crypto paper\\medpqc", "/workspace/medpqc")
    text = text.replace("d:/INFERENCE Lab/crypto paper/medpqc", "/workspace/medpqc")
    text = text.replace("C:\\Users\\Muzammil Shadab\\.gemini", "/home/user/.gemini")
    text = text.replace("C:\\Users\\Muzammil Shadab", "/home/user")
    text = text.replace("C:\\Program Files\\Python314", "/usr/bin")
    text = text.replace("C:\\", "/c/")
    text = text.replace("D:\\", "/d/")

    p.write_bytes(text.encode("utf-8"))
    count += 1

print(f"Normalized {count} evidence text files.")
