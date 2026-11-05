import json
import pathlib

p = pathlib.Path("AUDIT/coverage.json")
if not p.exists():
    p = pathlib.Path("medpqc/AUDIT/coverage.json")
data = json.loads(p.read_text())

packages = {"kem": [], "cipher": [], "security": [], "dicom": [], "utils": []}
for f, fdata in data.get("files", {}).items():
    fn = f.replace("\\", "/")
    for pkg in packages:
        if f"medpqc/{pkg}/" in fn:
            packages[pkg].append((fn, fdata["summary"]))

for pkg, items in packages.items():
    stmts = sum(s["num_statements"] for _, s in items)
    lines = sum(s["covered_lines"] for _, s in items)
    nbr = sum(s.get("num_branches", 0) for _, s in items)
    cbr = sum(s.get("covered_branches", 0) for _, s in items)
    tot = stmts + nbr
    cov = lines + cbr
    pct = (cov / tot * 100) if tot else 100
    print(f"{pkg:10s}: {pct:.2f}% (lines: {lines}/{stmts}, branches: {cbr}/{nbr})")
    if (pct < 90.0 and pkg != "utils") or (pkg == "utils" and pct < 85.0):
        for fn, s in items:
            t = s["num_statements"] + s.get("num_branches", 0)
            c = s["covered_lines"] + s.get("covered_branches", 0)
            fp = (c / t * 100) if t else 100
            print(f"   {fn}: {fp:.2f}% (missing lines: {s['missing_lines']}, missing branches: {s.get('missing_branches', 0)})")
