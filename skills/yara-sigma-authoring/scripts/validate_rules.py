#!/usr/bin/env python3
"""Validate YARA and Sigma rules (structure + compile + AV-safety). python -I validate_rules.py [paths...]

YARA : compiles with yara-python (or `yara` CLI); requires meta author/description/attack;
       warns on plain-text strings longer than 12 chars that look like tool/malware signatures
       (prefer hex or \\xNN-escaped regex, see references/av-safe-rules.md).
Sigma: required fields (title, id UUID, status, description, logsource, detection.condition, level),
       ATT&CK tags (attack.tXXXX), falsepositives present; needs PyYAML for full parsing.
Exit 1 on any error.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = next(p for p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"] if (p / "engine").is_dir())
DEFAULT = [ROOT / "skills" / "references" / "yara", ROOT / "skills" / "references" / "sigma"]
PLAIN_STRING = re.compile(r'^\s*\$\w*\s*=\s*"([^"]{13,})"', re.M)


def check_yara(p: Path) -> list[str]:
    errs = []
    text = p.read_text(encoding="utf-8")
    for rule in re.findall(r"rule\s+(\w+)\s*(?::[^{]*)?\{(.*?)\n\}", text, re.S):
        name, body = rule
        for field in ("author", "description", "attack"):
            if not re.search(rf"\b{field}\s*=", body):
                errs.append(f"{p.name}:{name}: missing meta {field}")
    for m in PLAIN_STRING.finditer(text):
        errs.append(f"{p.name}: WARN plain-text string may trip AV static scan: \"{m.group(1)[:30]}...\" (use hex/escaped regex)")
    try:
        import yara  # type: ignore
        yara.compile(filepath=str(p))
    except ImportError:
        exe = shutil.which("yara") or shutil.which("yara64")
        if exe:
            r = subprocess.run([exe, str(p), str(p)], capture_output=True, text=True)
            if r.returncode not in (0, 1):
                errs.append(f"{p.name}: compile error: {r.stderr.strip()[:300]}")
        else:
            errs.append(f"{p.name}: WARN yara not installed, compile not checked")
    except Exception as e:  # yara.SyntaxError
        errs.append(f"{p.name}: compile error: {e}")
    return errs


def check_sigma(p: Path) -> list[str]:
    errs = []
    try:
        import yaml  # type: ignore
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
    except ImportError:
        return [f"{p.name}: WARN PyYAML missing, Sigma structure not checked"]
    except Exception as e:
        return [f"{p.name}: YAML error: {e}"]
    for k in ("title", "id", "status", "description", "logsource", "detection", "level", "falsepositives"):
        if k not in d:
            errs.append(f"{p.name}: missing {k}")
    try:
        uuid.UUID(str(d.get("id")))
    except ValueError:
        errs.append(f"{p.name}: id is not a UUID")
    if "condition" not in (d.get("detection") or {}):
        errs.append(f"{p.name}: detection.condition missing")
    if not any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t)) for t in d.get("tags") or []):
        errs.append(f"{p.name}: no attack.tXXXX technique tag")
    if d.get("level") not in ("informational", "low", "medium", "high", "critical"):
        errs.append(f"{p.name}: invalid level")
    return errs


def main(argv):
    targets = [Path(a) for a in argv] or DEFAULT
    files = []
    for t in targets:
        files += [t] if t.is_file() else sorted(t.rglob("*.yar")) + sorted(t.rglob("*.yml"))
    errors = warns = 0
    for f in files:
        if f.is_symlink():
            continue
        res = check_yara(f) if f.suffix == ".yar" else check_sigma(f)
        for e in res:
            print(e)
            if "WARN" in e:
                warns += 1
            else:
                errors += 1
    print(f"checked {len(files)} rule files: {errors} error(s), {warns} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
