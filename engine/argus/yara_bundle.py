"""Load the vendored YARA bundle (Exhume + Unveil rule sets) in memory and compile it.

ARGUS by HaiND from the Post and Telecommunication Institute of Technology

The bundle is gzip-compressed and XOR-masked so antivirus static scans of the checkout do not see
plaintext signature strings (same approach as THOR/LOKI). This is storage hygiene, not secrecy:
anyone can decode it with this module. Rules are never written back to disk.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

MAGIC = b"ARGUSYB1"
_KEY = b"ARGUS/defensive/HaiND/PTIT"
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": "", "filemode": 0}
_cache: dict = {}


def mask(data: bytes) -> bytes:
    k = _KEY
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))


def bundle_path(root: Path) -> Path:
    return root / "skills" / "references" / "yara" / "vendor" / "argus-rules.bundle"


def load_sources(path: Path) -> dict[str, str]:
    blob = path.read_bytes()
    if not blob.startswith(MAGIC):
        raise ValueError("not an ARGUS YARA bundle")
    return json.loads(gzip.decompress(mask(blob[len(MAGIC):])).decode("utf-8"))


def compile_all(root: Path, extra_files: list[Path] | None = None):
    """Compile vendored bundle + local .yar files with yara-python. Returns (rules, count) or (None, reason)."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None, "yara-python not installed (pip install yara-python)"
    key = (str(root), tuple(str(p) for p in extra_files or []))
    if key in _cache:
        return _cache[key]
    sources: dict[str, str] = {}
    bp = bundle_path(root)
    if bp.is_file():
        sources.update(load_sources(bp))
    for f in extra_files or []:
        sources[f"local/{f.name}"] = f.read_text(encoding="utf-8")
    if not sources:
        return None, "no rules"
    rules = yara.compile(sources=sources, externals=EXTERNALS)
    _cache[key] = (rules, len(sources))
    return _cache[key]
