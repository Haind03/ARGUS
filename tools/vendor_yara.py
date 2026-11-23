#!/usr/bin/env python3
"""Vendor third-party YARA rule sets (from Exhume and Unveil) into an AV-safe ARGUS bundle.

ARGUS by HaiND from the Post and Telecommunication Institute of Technology

  python -I tools/vendor_yara.py --src <exhume>/rules --src <unveil>/rules

Why a bundle: public rule sets contain plaintext malware / webshell / tool strings, and antivirus
products quarantine such .yar files on Windows. Like commercial scanners (THOR, LOKI), ARGUS stores
them gzip-compressed and XOR-masked in one file and only decodes them in memory when compiling.
Nothing is decoded to disk.

Steps: collect *.yar/*.yara (honouring rules/disabled.txt), de-duplicate by content across sources,
compile each file with yara-python (same externals as runtime), keep only compiling files, write
  skills/references/yara/vendor/argus-rules.bundle      (masked payload)
  skills/references/yara/vendor/manifest.json           (sources, counts, upstream licences, skipped files)
  skills/references/yara/vendor/LICENSES/<set>/...      (licence texts, unmodified)
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
from argus.yara_bundle import EXTERNALS, MAGIC, mask  # noqa: E402

OUT = ROOT / "skills" / "references" / "yara" / "vendor"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", action="append", required=True, help="a rules/ folder (repeatable)")
    a = ap.parse_args()
    import yara  # type: ignore

    files: dict[str, str] = {}
    seen: dict[str, str] = {}
    skipped: list[dict] = []
    sources = []
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "LICENSES").mkdir(parents=True)
    for src in a.src:
        src = Path(src).resolve(strict=True)
        repo = src.parent.name
        disabled = set()
        dfile = src / "disabled.txt"
        if dfile.is_file():
            disabled = {l.strip() for l in dfile.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")}
        per_set: dict[str, int] = {}
        for f in sorted(src.rglob("*")):
            if f.suffix.lower() not in (".yar", ".yara") or not f.is_file() or f.is_symlink():
                continue
            rel = f.relative_to(src).as_posix()
            if rel in disabled or f.name in disabled:
                skipped.append({"file": f"{repo}/{rel}", "reason": "disabled upstream"})
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            h = hashlib.sha256(text.encode()).hexdigest()
            if h in seen:
                continue
            try:
                yara.compile(source=text, externals=EXTERNALS)
            except Exception as e:  # yara-x vs libyara dialect differences, missing modules
                skipped.append({"file": f"{repo}/{rel}", "reason": str(e)[:160]})
                continue
            seen[h] = rel
            key = f"{repo}/{rel}"
            files[key] = text
            per_set[rel.split("/")[0]] = per_set.get(rel.split("/")[0], 0) + 1
        for lic in list(src.glob("*/LICENSE*")):
            d = OUT / "LICENSES" / repo / lic.parent.name
            d.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(lic, d / lic.name)
        top = src.parent / "LICENSE"
        if top.is_file():
            shutil.copyfile(top, OUT / "LICENSES" / repo / "LICENSE")
        for extra in ("THIRD_PARTY_NOTICES.md",):
            if (src.parent / extra).is_file():
                shutil.copyfile(src.parent / extra, OUT / "LICENSES" / repo / extra)
        sources.append({"repo": f"https://github.com/Haind03/{repo}", "rule_sets": per_set})

    payload = json.dumps(files, ensure_ascii=False).encode()
    blob = MAGIC + mask(gzip.compress(payload, 9))
    (OUT / "argus-rules.bundle").write_bytes(blob)
    # final whole-bundle compile check (namespaces per file)
    yara.compile(sources={k: v for k, v in files.items()}, externals=EXTERNALS)
    manifest = {
        "schema": "argus.yara-bundle/1",
        "author": "ARGUS by HaiND from the Post and Telecommunication Institute of Technology",
        "sources": sources,
        "files": len(files),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "licenses": {
            "signature-base": "Detection Rule License 1.1 (Neo23x0/signature-base), author/reference metadata kept",
            "elastic": "Elastic License 2.0 (elastic/protections-artifacts)",
            "reversinglabs": "MIT, Copyright (c) 2020 ReversingLabs",
            "eset": "BSD 2-Clause (eset/malware-ioc)",
            "custom": "MIT, HaiND",
        },
        "encoding": "gzip then XOR mask (AV-safe storage, not secrecy); decoded only in memory",
        "skipped": skipped,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"bundled {len(files)} rule files ({len(skipped)} skipped) -> {OUT / 'argus-rules.bundle'}")


if __name__ == "__main__":
    main()
