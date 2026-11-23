#!/usr/bin/env python3
"""Analyse a process minidump / raw memory region dump, static, never executed.

  python -I scan_dump.py --dump proc-x-4321.dmp [--out-dir case/procmem] [--carve]

What it does
  * Minidump (MDMP) parsing: module list (paths, sizes), memory-region count, thread count
  * ASCII + UTF-16LE string extraction with IOC classification
    (URLs, IP:port, domains, .onion, mutex-like names, user-agents, crypto wallets, registry Run paths,
     PowerShell, credential-store paths, ransom text, miner pool strings, Discord/Telegram exfil)
  * Embedded PE detection (MZ…PE\\0\\0), with --carve, writes carved candidates as <offset>.bin.carved
  * YARA (yara-python or yara CLI) using skills/references/yara/*.yar
  * Scores everything into one argus.triage/1-style result
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
import struct
import sys
from collections import Counter
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        ROOT = _p
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import indicators as I  # noqa: E402
from argus.safeio import safe_child, safe_input_file, safe_output_dir, write_json  # noqa: E402
from argus.scoring import severity_for  # noqa: E402
from argus.triage import run_yara  # noqa: E402

MAX_DUMP = 64 * 1024 ** 3
ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
CLASSES = [
    ("url", re.compile(r"\b(?:https?|ftp)://[\w.-]+(?::\d+)?(?:/[\w./%?=&+#~-]*)?", re.I), 3),
    ("ip_port", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"), 8),
    ("onion", re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I), 25),
    ("user_agent", re.compile(r"Mozilla/\d\.\d \([^)]{5,120}\)", re.I), 2),
    ("btc_wallet", re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), 10),
    ("eth_wallet", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), 8),
    ("xmr_wallet", re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), 20),
    ("run_key", re.compile(r"software\\microsoft\\windows\\currentversion\\run", re.I), 10),
    ("powershell", re.compile(r"powershell(?:\.exe)?\s+-(?:e|enc|nop|w|ep)\b|frombase64string|downloadstring", re.I), 15),
    ("credential_store", re.compile(r"\\(?:login data|local state|cookies)|logins\.json|key4\.db|wallet\.dat|\\exodus\\|\\electrum\\", re.I), 20),
    ("lsass_dump", re.compile(r"seku(?:rlsa)|lsad(?:ump)|minidump(?:writedump)|comsvcs\.dll.{0,10}minidump", re.I), 25),
    ("ransom_text", re.compile(r"your\s+(?:files|documents|network)\s+(?:have\s+been|are|has\s+been)\s+encrypted|decrypt(?:ion)?\s+key|bitcoin.{0,40}(?:pay|send)", re.I), 30),
    ("recovery_delete", re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.{0,30}recoveryenabled", re.I), 30),
    ("miner", re.compile(r"stratum\+(?:tcp|ssl)://|xmrig|--donate-level|randomx", re.I), 25),
    ("messaging_exfil", re.compile(r"discord(?:app)?\.com/api/webhooks/\d+|api\.telegram\.org/bot\d+", re.I), 25),
    ("amsi_bypass", re.compile(r"amsi(?:scanbuffer|initfailed|utils)", re.I), 20),
    ("mutex_like", re.compile(r"\b(?:Global|Local)\\[\w.{}-]{6,64}\b"), 3),
    ("pdb_path", re.compile(r"[a-z]:\\[^\"<>|]{3,200}\.pdb", re.I), 3),
]


def parse_minidump(mm) -> dict | None:
    if mm[:4] != b"MDMP":
        return None
    try:
        n_streams, dir_rva = struct.unpack_from("<II", mm, 8)
        info = {"streams": n_streams, "modules": [], "threads": None, "memory64_ranges": None}
        for i in range(min(n_streams, 256)):
            stype, size, rva = struct.unpack_from("<III", mm, dir_rva + i * 12)
            if stype == 4:  # ModuleListStream
                count = struct.unpack_from("<I", mm, rva)[0]
                for j in range(min(count, 4096)):
                    off = rva + 4 + j * 108
                    base, msize = struct.unpack_from("<QI", mm, off)
                    name_rva = struct.unpack_from("<I", mm, off + 20)[0]
                    nlen = struct.unpack_from("<I", mm, name_rva)[0]
                    name = bytes(mm[name_rva + 4:name_rva + 4 + min(nlen, 1024)]).decode("utf-16-le", "replace")
                    info["modules"].append({"base": hex(base), "size": msize, "path": name})
            elif stype == 3:  # ThreadListStream
                info["threads"] = struct.unpack_from("<I", mm, rva)[0]
            elif stype == 9:  # Memory64ListStream
                info["memory64_ranges"] = struct.unpack_from("<Q", mm, rva)[0]
        return info
    except struct.error:
        return {"error": "truncated or malformed minidump"}


def iter_strings(mm, limit_bytes: int):
    view = mm[: min(len(mm), limit_bytes)]
    for m in ASCII_RE.finditer(view):
        yield m.start(), m.group(0).decode("ascii", "replace")
    for m in UTF16_RE.finditer(view):
        yield m.start(), m.group(0).decode("utf-16-le", "replace")


def find_pes(mm, max_hits=200):
    hits = []
    for m in re.finditer(rb"MZ", mm):
        o = m.start()
        if o + 0x40 > len(mm):
            break
        e = struct.unpack_from("<I", mm, o + 0x3C)[0]
        if 0x40 <= e <= 0x1000 and mm[o + e:o + e + 4] == b"PE\0\0":
            hits.append(o)
            if len(hits) >= max_hits:
                break
    return hits


def main():
    ap = argparse.ArgumentParser(description="ARGUS process-memory analysis (static)")
    ap.add_argument("--dump", required=True)
    ap.add_argument("--out-dir")
    ap.add_argument("--carve", action="store_true", help="write embedded PE candidates (first 4 MiB each)")
    ap.add_argument("--max-scan-mb", type=int, default=4096)
    a = ap.parse_args()
    path = safe_input_file(a.dump, MAX_DUMP)
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
    signals, iocs = [], {k: Counter() for k, _, _ in CLASSES}

    def sig(n, w, d=""):
        signals.append({"name": n, "weight": w, "detail": str(d)[:200]})

    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        md = parse_minidump(mm)
        if md and md.get("modules"):
            for mod in md["modules"]:
                n, w = I.path_risk(mod["path"])
                if w >= 15:
                    sig("module_from_" + n, w, mod["path"])
        for _, s in iter_strings(mm, a.max_scan_mb * 1024 * 1024):
            for name, rx, _w in CLASSES:
                for m in rx.finditer(s):
                    iocs[name][m.group(0)[:300]] += 1
        pes = find_pes(mm)
        carved = []
        if a.carve and a.out_dir and pes:
            out = safe_output_dir(a.out_dir)
            for o in pes[1:51]:  # skip offset of the main image if dump starts with it
                p = safe_child(out, f"{o:012x}.bin.carved")
                p.write_bytes(bytes(mm[o:o + 4 * 1024 * 1024]))
                carved.append(str(p))
    for name, rx, w in CLASSES:
        if iocs[name]:
            sig("strings_" + name, w, next(iter(iocs[name])))
    if len(pes) > 3:
        sig("multiple_embedded_pe_images", 10 if not md else 5, str(len(pes)))
    yara_hits = run_yara(path, ROOT / "skills" / "references" / "yara")
    for h in yara_hits:
        if not h.startswith("("):
            sig("yara_" + h, 35)
    score = max(0, min(100, sum(s["weight"] for s in signals)))
    res = {
        "schema": "argus.procmem/1", "dump": str(path), "sha256": sha.hexdigest(), "size": path.stat().st_size,
        "minidump": md, "embedded_pe_offsets": [hex(x) for x in pes[:50]], "carved": carved if a.carve else [],
        "iocs": {k: [v for v, _ in c.most_common(50)] for k, c in iocs.items() if c},
        "yara": yara_hits, "signals": signals, "score": score, "severity": severity_for(score),
        "note": "Static analysis of a memory dump. Strings are leads; confirm against disk/network evidence.",
    }
    if a.out_dir:
        out = safe_output_dir(a.out_dir)
        write_json(safe_child(out, f"procmem-{sha.hexdigest()[:16]}.json"), res)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 2 if res["severity"] in ("high", "critical") else 0


if __name__ == "__main__":
    sys.exit(main())
