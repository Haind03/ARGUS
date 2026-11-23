#!/usr/bin/env python3
"""Hash + copy one artefact into a case's evidence folder with a custody record. Never executes or modifies the source.

python -I evidence_hash.py --case argus-cases/pc1 --file <path> [--note "..."]
python -I evidence_hash.py --file <path>          # hash only, print JSON
"""
import argparse
import datetime as dt
import getpass
import hashlib
import json
import platform
import shutil
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
from argus.safeio import MAX_SAMPLE_BYTES, safe_input_file  # noqa: E402


def hashes(p: Path) -> dict:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for x in h.values():
                x.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--case")
    ap.add_argument("--note", default="")
    a = ap.parse_args()
    src = safe_input_file(a.file, MAX_SAMPLE_BYTES * 64)
    st = src.stat()
    rec = {"time_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "source": str(src), "size": st.st_size,
           "mtime_utc": dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).isoformat(),
           "ctime_utc": dt.datetime.fromtimestamp(st.st_ctime, dt.timezone.utc).isoformat(),
           "hashes": hashes(src), "host": platform.node(), "by": getpass.getuser(), "note": a.note}
    if a.case:
        ev = Path(a.case).resolve(strict=True) / "evidence"
        ev.mkdir(exist_ok=True)
        dst = ev / f"{rec['hashes']['sha256']}.bin"
        if not dst.exists():
            shutil.copyfile(src, dst)  # content only; no metadata/ACL/ADS copied
        if hashes(dst)["sha256"] != rec["hashes"]["sha256"]:
            sys.exit("hash mismatch after copy — source changed during acquisition?")
        rec["evidence_copy"] = str(dst)
        with open(ev / "custody.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    main()
