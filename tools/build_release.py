#!/usr/bin/env python3
"""Build ARGUS release artefacts into dist/:
  argus_defense-<v>-py3-none-any.whl, argus_defense-<v>.tar.gz   (pip packages, data bundled)
  argus-<v>-toolkit.zip                                         (full toolkit for Windows / Claude Code / Codex)
  SHA256SUMS
python -I tools/build_release.py      (needs: pip install build)
ARGUS by HaiND from the Post and Telecommunication Institute of Technology
"""
import hashlib
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "engine" / "argus" / "_data"
DIST = ROOT / "dist"
version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
INCLUDE = [".claude-plugin", "agents", "commands", "docs", "engine", "hooks", "integrations", "presets", "skills",
           "tests", "tools", "workflows", "AGENTS.md", "CLAUDE.md", "CHANGELOG.md", "LICENSE", "README.md", "TERMS.md",
           "install.ps1", "install.sh", "pyproject.toml", "pytest.ini", "settings.json", "skills-lock.json"]

shutil.rmtree(DIST, ignore_errors=True)
shutil.rmtree(DATA, ignore_errors=True)
DIST.mkdir()
for d in ("presets", "workflows", "skills"):
    shutil.copytree(ROOT / d, DATA / d, ignore=shutil.ignore_patterns("__pycache__"))
try:
    subprocess.run([sys.executable, "-m", "build", "--outdir", str(DIST), str(ROOT)], check=True)
finally:
    shutil.rmtree(DATA, ignore_errors=True)
    for p in (ROOT / "engine").glob("*.egg-info"):
        shutil.rmtree(p, ignore_errors=True)

zpath = DIST / f"argus-{version}-toolkit.zip"
with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
    for item in INCLUDE:
        p = ROOT / item
        files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())
        for f in files:
            if "__pycache__" in f.parts or "_data" in f.parts or f.suffix == ".pyc":
                continue
            z.write(f, f"argus-{version}/{f.relative_to(ROOT).as_posix()}")
sums = []
for f in sorted(DIST.iterdir()):
    sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
(DIST / "SHA256SUMS").write_text("\n".join(sums) + "\n")
print("\n".join(sums))
