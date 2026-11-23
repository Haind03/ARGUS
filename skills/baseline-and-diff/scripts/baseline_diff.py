#!/usr/bin/env python3
"""Baseline helper: `create` or `diff`. Run isolated: python -I baseline_diff.py create --input t.json --out-dir d"""
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
import argus_cli  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("create", "diff"):
        sys.exit("usage: baseline_diff.py create --input T.json [--out-dir D] | diff --baseline B.json --input T.json")
    sub = "baseline" if sys.argv[1] == "create" else "diff"
    sys.exit(argus_cli.main([sub, *sys.argv[2:]]))
