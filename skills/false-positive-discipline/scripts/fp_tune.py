#!/usr/bin/env python3
"""Export false_positive / benign_expected dispositions as a suppression file for `argus hunt --suppress`.

python -I fp_tune.py --case argus-cases/pc1 --out suppress.json [--merge existing.json]
Suppression = exact artifact keys only (path + normalised command line), never rule-wide.
"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--merge")
    a = ap.parse_args()
    case = Path(a.case).resolve(strict=True)
    disp = json.loads((case / "dispositions.json").read_text(encoding="utf-8"))
    entries = {}
    if a.merge:
        old = json.loads(Path(a.merge).read_text(encoding="utf-8"))
        entries = {e["key"]: e for e in old.get("suppressions", [])}
    for key, d in disp.items():
        if d.get("verdict") in ("false_positive", "benign_expected"):
            entries[key] = {"key": key, "reason": d.get("note"), "by": d.get("by"), "time": d.get("time"),
                            "case": case.name}
    out = Path(a.out)
    if out.is_symlink():
        sys.exit("refusing symlinked output")
    out.write_text(json.dumps({"schema": "argus.suppress/1", "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
                               "suppressions": sorted(entries.values(), key=lambda e: e["key"])}, indent=2), encoding="utf-8")
    print(f"{len(entries)} suppression(s) -> {out}")


if __name__ == "__main__":
    main()
