#!/usr/bin/env python3
"""Merge an offline IOC export into skills/references/ioc/<kind>.txt. No network access.

python -I update_iocs.py --kind sha256 --from-file malwarebazaar.csv
kinds: sha256 | domains | ips | vuln_drivers
"""
import argparse
import re
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        IOC = _p / "skills" / "references" / "ioc"
        break
from argus.safeio import safe_input_file  # noqa: E402

FILES = {"sha256": "hashes_sha256.txt", "domains": "domains.txt", "ips": "ips.txt", "vuln_drivers": "vuln_drivers.txt"}
PAT = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "domains": re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.I),
    "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "vuln_drivers": re.compile(r"\b[\w.-]+\.sys\b", re.I),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=FILES, required=True)
    ap.add_argument("--from-file", required=True)
    a = ap.parse_args()
    src = safe_input_file(a.from_file, 1 << 30)
    found = {m.group(0).lower() for m in PAT[a.kind].finditer(src.read_text(encoding="utf-8", errors="ignore"))}
    dst = IOC / FILES[a.kind]
    existing = set()
    if dst.is_file():
        existing = {l.split("#", 1)[0].strip().lower() for l in dst.read_text(encoding="utf-8").splitlines()} - {""}
    new = sorted(found - existing)
    with open(dst, "a", encoding="utf-8") as fh:
        for v in new:
            fh.write(v + "\n")
    print(f"{len(new)} new {a.kind} IOCs added to {dst}")


if __name__ == "__main__":
    main()
