#!/usr/bin/env python3
"""Package MedPQC v2.4.0 Research Release Candidate.

Builds clean staging tree, copies distributions, creates release zip,
computes SHA256 checksums with strict LF line endings, and validates artifacts.
No emojis and no self-certification.
"""

import hashlib
import os
import shutil
import sys
import zipfile
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def package_release(repo_root: Path) -> None:
    release_dir = repo_root / "release"
    dist_dir = repo_root / "dist"
    target_stage = release_dir / "medpqc-v2.4.0"
    zip_path = release_dir / "medpqc-v2.4.0.zip"
    sums_path = release_dir / "SHA256SUMS.txt"

    # Ensure dist files exist
    tar_src = dist_dir / "medpqc-2.4.0.tar.gz"
    whl_src = dist_dir / "medpqc-2.4.0-py3-none-any.whl"

    if not tar_src.exists() or not whl_src.exists():
        print("Error: Distribution artifacts missing in dist/. Run python -m build first.", file=sys.stderr)
        sys.exit(1)

    # Copy distributions into release directory
    release_dir.mkdir(parents=True, exist_ok=True)
    tar_dst = release_dir / "medpqc-2.4.0.tar.gz"
    whl_dst = release_dir / "medpqc-2.4.0-py3-none-any.whl"

    shutil.copy2(tar_src, tar_dst)
    shutil.copy2(whl_src, whl_dst)

    # Clean old target_stage if present
    if target_stage.exists():
        shutil.rmtree(target_stage)
    target_stage.mkdir(parents=True)

    # Elements to include in clean release export
    include_dirs = ["medpqc", "tests", "benchmarks", "docs", "AUDIT", "scripts", "examples"]
    include_files = ["LICENSE", "README.md", "CHANGELOG.md", "pyproject.toml", "MANIFEST.in"]

    forbidden_names = {
        "__pycache__",
        ".pytest_cache",
        ".hypothesis",
        ".coverage",
        ".git",
        ".github",
        "medpqc.egg-info",
        "dist",
        "release",
    }
    forbidden_exts = {".pyc", ".pyo", ".pyd"}

    def ignore_patterns(dir_path: str, contents: list[str]) -> set[str]:
        ignored = set()
        for item in contents:
            if item in forbidden_names:
                ignored.add(item)
            elif any(item.endswith(ext) for ext in forbidden_exts):
                ignored.add(item)
        return ignored

    # Copy directories
    for d in include_dirs:
        src = repo_root / d
        if src.exists():
            shutil.copytree(src, target_stage / d, ignore=ignore_patterns)

    # Copy root files
    for f in include_files:
        src = repo_root / f
        if src.exists():
            shutil.copy2(src, target_stage / f)

    # Check for forbidden image or cache extensions inside target_stage
    forbidden_image_exts = (".dcm", ".npz", ".png", ".jpg", ".jpeg")
    staged_tests_data = target_stage / "tests_data"
    if staged_tests_data.exists():
        for root, _, files in os.walk(staged_tests_data):
            for file_name in files:
                if file_name.lower().endswith(forbidden_image_exts):
                    raise RuntimeError(f"Forbidden image file staged in tests_data: {file_name}")

    # Build zip archive
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(target_stage):
            for file_name in files:
                full_path = Path(root) / file_name
                rel_path = full_path.relative_to(release_dir)
                zf.write(full_path, arcname=str(rel_path).replace("\\", "/"))

    # Compute SHA256 sums
    artifacts = [
        tar_dst,
        whl_dst,
        zip_path,
    ]

    lines = []
    for art in artifacts:
        digest = compute_sha256(art)
        lines.append(f"{digest}  {art.name}")

    # Write SHA256SUMS.txt with strictly LF line endings
    sums_content = "\n".join(lines) + "\n"
    sums_path.write_bytes(sums_content.encode("ascii"))

    print("Release packaged successfully.")
    print(f"Directory: {target_stage}")
    print(f"Archive:   {zip_path} ({zip_path.stat().st_size} bytes)")
    print("SHA256SUMS.txt contents:")
    print(sums_content.strip())


if __name__ == "__main__":
    repo = Path(__file__).resolve().parent.parent
    package_release(repo)
