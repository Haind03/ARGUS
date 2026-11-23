#!/usr/bin/env python3
"""Regenerate skills-lock.json: per-skill SHA-256 over all files (path-sorted). python -I tools/lock.py [--check]"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def digest(d: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(p for p in d.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        h.update(f.relative_to(d).as_posix().encode() + b"\0")
        h.update(f.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


lock = {"schema": "argus.skills-lock/1", "skills": {}}
for d in sorted(p for p in (ROOT / "skills").iterdir() if p.is_dir()):
    lock["skills"][d.name] = {"path": f"skills/{d.name}", "sha256": digest(d),
                              "files": sum(1 for p in d.rglob("*") if p.is_file() and "__pycache__" not in p.parts)}
text = json.dumps(lock, indent=2) + "\n"
out = ROOT / "skills-lock.json"
if "--check" in sys.argv:
    ok = out.is_file() and out.read_text(encoding="utf-8") == text
    print("skills-lock.json up to date" if ok else "skills-lock.json OUT OF DATE (run tools/lock.py)")
    sys.exit(0 if ok else 1)
out.write_text(text, encoding="utf-8")
print(f"{len(lock['skills'])} skills locked")
