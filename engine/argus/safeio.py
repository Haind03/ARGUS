"""Defensive file I/O helpers.

Input paths are never trusted: they are resolved, must be regular files
(not symlinks, devices or directories), and are size-capped before being read.
Output is only written below an explicitly chosen output directory.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

MAX_JSON_BYTES = 512 * 1024 * 1024  # 512 MiB telemetry ceiling
MAX_SAMPLE_BYTES = 256 * 1024 * 1024  # 256 MiB triage ceiling


class UnsafePathError(ValueError):
    """Raised when a user-supplied path fails validation."""


def safe_input_file(raw: str | os.PathLike, max_bytes: int = MAX_JSON_BYTES) -> Path:
    if raw is None or str(raw).strip() == "":
        raise UnsafePathError("empty path")
    raw_s = str(raw)
    if "\x00" in raw_s:
        raise UnsafePathError("NUL byte in path")
    p = Path(raw_s).expanduser()
    try:
        st = os.lstat(p)
    except OSError as exc:
        raise UnsafePathError(f"cannot stat {p}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise UnsafePathError(f"refusing symlink: {p}")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(f"not a regular file: {p}")
    if st.st_size > max_bytes:
        raise UnsafePathError(f"file too large ({st.st_size} > {max_bytes} bytes): {p}")
    return p.resolve(strict=True)


def safe_output_dir(raw: str | os.PathLike) -> Path:
    if raw is None or str(raw).strip() == "" or "\x00" in str(raw):
        raise UnsafePathError("invalid output directory")
    p = Path(str(raw)).expanduser()
    if p.is_symlink():
        raise UnsafePathError(f"refusing symlinked output dir: {p}")
    p.mkdir(parents=True, exist_ok=True)
    if not p.is_dir():
        raise UnsafePathError(f"output path is not a directory: {p}")
    return p.resolve(strict=True)


def safe_child(out_dir: Path, name: str) -> Path:
    """Return out_dir/name, guaranteeing it stays inside out_dir."""
    if not name or "/" in name or "\\" in name or name in (".", "..") or "\x00" in name:
        raise UnsafePathError(f"invalid output file name: {name!r}")
    child = (out_dir / name)
    if child.is_symlink():
        raise UnsafePathError(f"refusing to overwrite symlink: {child}")
    return child


def load_json(raw: str | os.PathLike, max_bytes: int = MAX_JSON_BYTES):
    path = safe_input_file(raw, max_bytes)
    # utf-8-sig tolerates the BOM PowerShell 5.1 writes by default
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return json.load(fh)


def write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
