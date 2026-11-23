#!/usr/bin/env python3
"""Scope check for an ARGUS case. Exit 0 = in scope, 3 = out of scope / not attested, 2 = error.

python -I scope_check.py --case argus-cases/pc1 [--telemetry t.json] [--allow-host OTHERHOST] [--target PATH]
"""
import argparse
import json
import platform
import re
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
from argus.safeio import load_json  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--telemetry")
    ap.add_argument("--allow-host", action="append", default=[])
    ap.add_argument("--target", action="append", default=[], help="paths/hosts you are about to touch")
    a = ap.parse_args()
    problems = []
    try:
        case = json.loads((Path(a.case) / "case.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read case: {e}")
        return 2
    if not (case.get("scope") or {}).get("authorized_attestation"):
        problems.append("case has no authorisation attestation")
    allowed = {platform.node().lower(), *(h.lower() for h in a.allow_host)}
    if a.telemetry:
        tel = load_json(a.telemetry)
        h = str((tel.get("host") or {}).get("hostname") or "").lower()
        if h and h not in allowed:
            problems.append(f"telemetry host '{h}' is not this machine ({platform.node()}); pass --allow-host if you "
                            "collected it on your OWN other device")
    for t in a.target:
        if re.match(r"^(\\\\|//)", t):
            problems.append(f"network/UNC target '{t}', remote shares are out of scope")
        elif re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", t) or re.match(r"^[a-z][\w.-]*\.[a-z]{2,}$", t, re.I):
            problems.append(f"remote host target '{t}', ARGUS does not touch other hosts (passive intel only)")
    if problems:
        print("OUT OF SCOPE / NOT ATTESTED:")
        for p in problems:
            print(f"  - {p}")
        return 3
    print("in scope: local, attested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
