#!/usr/bin/env python3
"""Print the ARGUS skill routing table from SKILL.md frontmatter. python -I list_skills.py [--json]"""
import json
import re
import sys
from pathlib import Path

ROOT = next(p for p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"] if (p / "engine").is_dir())


def frontmatter(p: Path) -> dict:
    m = re.match(r"^---\n(.*?)\n---", p.read_text(encoding="utf-8"), re.S)
    out = {}
    for line in (m.group(1).splitlines() if m else []):
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


rows = []
for s in sorted((ROOT / "skills").glob("*/SKILL.md")):
    fm = frontmatter(s)
    rows.append({"name": fm.get("name", s.parent.name), "description": fm.get("description", "")})
if "--json" in sys.argv:
    print(json.dumps(rows, indent=2))
else:
    for r in rows:
        print(f"{r['name']:<28} {r['description'][:140]}")
