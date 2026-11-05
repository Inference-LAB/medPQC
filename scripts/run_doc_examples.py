#!/usr/bin/env python3
"""
scripts.run_doc_examples
========================
Extracts and executes Python code examples from README.md and docs/
to ensure documentation never drifts from the implementation.
"""

import sys
from pathlib import Path
import re


def extract_python_blocks(file_path: Path) -> list[str]:
    text = file_path.read_text(encoding="utf-8")
    return re.findall(r"```python\n(.*?)```", text, re.DOTALL)


def run_file_examples(file_path: Path) -> None:
    print(f"--- Running examples from {file_path.name} ---")
    blocks = extract_python_blocks(file_path)
    if not blocks:
        print(f"No python blocks found in {file_path.name}")
        return

    shared_scope: dict = {
        "__name__": "__main__",
        "__file__": str(file_path),
    }

    for idx, block in enumerate(blocks, start=1):
        print(f"Executing Block {idx} ({len(block.splitlines())} lines)...")
        try:
            exec(block, shared_scope)
            print(f"Block {idx} PASSED")
        except Exception as e:
            print(f"Block {idx} FAILED in {file_path.name}: {e}")
            raise


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    targets = [
        repo_root / "README.md",
        repo_root / "docs" / "USAGE.md",
    ]

    for target in targets:
        if target.exists():
            run_file_examples(target)

    print("\nAll documentation code examples executed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
