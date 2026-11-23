#!/usr/bin/env python3
"""Validate every ARGUS skill. python -I validate_skills.py   (exit 1 on errors)

Checks per skills/<name>/: SKILL.md frontmatter (name == dir, description starts 'Use when'),
references/ and scripts/ exist and are non-empty, scope/detect-only statement present,
relative links resolve, ATT&CK IDs well-formed, Python scripts parse, no AI attribution lines,
ttp-index references exist.
"""
import ast
import json
import re
import sys
from pathlib import Path

ROOT = next(p for p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"] if (p / "engine").is_dir())
SCOPE_HINT = re.compile(r"scope|own(?:ed)? machine|authori[sz]ed|detect-only", re.I)
ATTR = re.compile("|".join(["Co-" + "Authored-By", "Generated with " + "Claude", "\U0001F916"]), re.I)


def fm(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    d = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def main():
    errs = []
    skills = sorted(p for p in (ROOT / "skills").iterdir() if p.is_dir() and p.name != "references")
    for s in skills:
        sk = s / "SKILL.md"
        if not sk.is_file():
            errs.append(f"{s.name}: missing SKILL.md")
            continue
        text = sk.read_text(encoding="utf-8")
        meta = fm(text)
        if not meta:
            errs.append(f"{s.name}: no frontmatter")
            continue
        if meta.get("name") != s.name:
            errs.append(f"{s.name}: frontmatter name '{meta.get('name')}' != directory")
        if not meta.get("description", "").startswith("Use when"):
            errs.append(f"{s.name}: description must start with 'Use when'")
        if len(meta.get("description", "")) > 1024:
            errs.append(f"{s.name}: description too long")
        if not SCOPE_HINT.search(text):
            errs.append(f"{s.name}: no scope / detect-only statement")
        for sub in ("references", "scripts"):
            if not (s / sub).is_dir() or not any((s / sub).iterdir()):
                errs.append(f"{s.name}: {sub}/ missing or empty")
        for link in re.findall(r"\]\(((?!https?:)[^)#]+)\)", text):
            if not (s / link).resolve().exists():
                errs.append(f"{s.name}: broken link {link}")
        for f in s.rglob("*"):
            if f.is_file() and f.suffix in (".md", ".py", ".ps1", ".yml", ".json"):
                t = f.read_text(encoding="utf-8", errors="ignore")
                if ATTR.search(t):
                    errs.append(f"{f.relative_to(ROOT)}: AI attribution line found")
                for tid in re.findall(r"\bT\d{4}(?:\.\d{1,3})?\b", t):
                    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
                        errs.append(f"{f.relative_to(ROOT)}: malformed ATT&CK id {tid}")
            if f.suffix == ".py":
                try:
                    ast.parse(f.read_text(encoding="utf-8"))
                except SyntaxError as e:
                    errs.append(f"{f.relative_to(ROOT)}: syntax error {e}")
    idx = ROOT / "skills" / "references" / "ttp-index.json"
    if idx.is_file():
        for tid, e in json.loads(idx.read_text(encoding="utf-8"))["techniques"].items():
            for r in e["references"]:
                if not (ROOT / r).is_file():
                    errs.append(f"ttp-index: {tid} reference missing {r}")
    for e in errs:
        print("ERROR:", e)
    print(f"{len(skills)} skills checked, {len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
