#!/usr/bin/env python3
"""Persistence (TA0003) detector, thin wrapper over the ARGUS engine. Run with: python -I persistence_hunting.py"""
import sys
from pathlib import Path

_here = Path(__file__).resolve()
for _p in [*_here.parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
else:
    sys.exit("argus: cannot locate engine/ (keep the skill inside the ARGUS repo or ~/.claude/argus)")

import argus_cli  # noqa: E402

if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print("usage: hunt_persistence_hunting.py --input TELEMETRY.json [--baseline B.json] [--out-dir DIR] [--online]")
        sys.exit(0)
    sys.exit(argus_cli.main(["hunt", "--tactics", "TA0003", *argv]))
