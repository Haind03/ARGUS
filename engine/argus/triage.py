"""Static malware triage of a single file. NEVER executes the sample.

Reads bytes only: hashes, magic, PE header/sections/imports (minimal parser,
no third-party deps), entropy, strings of interest, optional YARA.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from .indicators import shannon_entropy
from .safeio import MAX_SAMPLE_BYTES, safe_input_file

SUSPICIOUS_IMPORTS = {
    "virtualallocex": ("process_injection_api", 15), "writeprocessmemory": ("process_injection_api", 15),
    "createremotethread": ("process_injection_api", 20), "ntunmapviewofsection": ("process_hollowing_api", 20),
    "queueuserapc": ("apc_injection_api", 15), "setwindowshookexa": ("keyboard_hook_api", 10),
    "setwindowshookexw": ("keyboard_hook_api", 10), "getasynckeystate": ("keylogging_api", 15),
    "isdebuggerpresent": ("anti_debug_api", 5), "checkremotedebuggerpresent": ("anti_debug_api", 5),
    "cryptencrypt": ("crypto_api", 5), "bcryptencrypt": ("crypto_api", 5),
    "internetopenurla": ("network_api", 5), "urldownloadtofilea": ("download_api", 15),
    "urldownloadtofilew": ("download_api", 15), "winhttpopen": ("network_api", 5),
    "adjusttokenprivileges": ("token_privilege_api", 5), "minidumpwritedump": ("minidump_api", 25),
    "openprocess": ("open_process_api", 2),
}
STRING_PATTERNS = (
    (re.compile(rb"https?://[\x21-\x7e]{6,200}"), "url", 5),
    (re.compile(rb"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}"), "ip_port", 10),
    (re.compile(rb"(?i)powershell(?:\.exe)?\s+-(?:e|enc|nop|w)"), "powershell_cmd", 15),
    (re.compile(rb"(?i)vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.+recoveryenabled"), "ransomware_recovery_delete", 35),
    (re.compile(rb"(?i)\\(?:login data|local state)|logins\.json|key4\.db|wallet\.dat|\\exodus\\|metamask"), "stealer_targets", 25),
    (re.compile(rb"(?i)seku(?:rlsa)|lsad(?:ump)|mimi(?:katz)"), "credential_tool_strings", 30),
    (re.compile(rb"(?i)software\\microsoft\\windows\\currentversion\\run"), "run_key_persistence", 10),
    (re.compile(rb"(?i)api\.telegram\.org|discord(?:app)?\.com/api/webhooks"), "messaging_c2_exfil", 25),
    (re.compile(rb"(?i)stratum\+tcp|xmrig"), "miner_strings", 30),
    (re.compile(rb"(?i)your\s+files\s+(?:have\s+been|are)\s+encrypted|\.onion\b"), "ransom_note_strings", 30),
    (re.compile(rb"(?i)amsi(?:scanbuffer|\.dll)"), "amsi_reference", 15),
)


def _hashes(data: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def parse_pe(data: bytes) -> dict[str, Any] | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"valid": False}
    machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    pe32p = magic == 0x20B
    sections = []
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\0").decode("latin-1", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        sch = struct.unpack_from("<I", data, o + 36)[0]
        raw = data[rptr:rptr + rsize] if rptr < len(data) else b""
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize, "rsize": rsize, "rptr": rptr,
                         "entropy": round(shannon_entropy(raw), 3), "executable": bool(sch & 0x20000000),
                         "writable": bool(sch & 0x80000000)})
    imports = _parse_imports(data, opt, pe32p, sections)
    return {"valid": True, "machine": hex(machine), "timestamp": ts, "is_dll": bool(chars & 0x2000),
            "pe32_plus": pe32p, "sections": sections, "imports": imports,
            "overlay_bytes": max(0, len(data) - max((s["rptr"] + s["rsize"] for s in sections), default=len(data)))}


def _rva_to_off(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return rva - s["vaddr"] + s["rptr"]
    return None


def _cstr(data: bytes, off: int, n: int = 256) -> str:
    end = data.find(b"\0", off, off + n)
    return data[off:end if end != -1 else off + n].decode("latin-1", "replace")


def _parse_imports(data: bytes, opt: int, pe32p: bool, sections: list[dict]) -> dict[str, list[str]]:
    try:
        dd = opt + (112 if pe32p else 96)
        imp_rva = struct.unpack_from("<I", data, dd + 8)[0]
        off = _rva_to_off(imp_rva, sections)
        out: dict[str, list[str]] = {}
        if off is None:
            return out
        for _ in range(512):
            if off + 20 > len(data):
                break
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
            if not (oft or name_rva or ft):
                break
            noff = _rva_to_off(name_rva, sections)
            dll = _cstr(data, noff).lower() if noff is not None else "?"
            funcs = []
            toff = _rva_to_off(oft or ft, sections)
            step, fmt, flag = (8, "<Q", 1 << 63) if pe32p else (4, "<I", 1 << 31)
            for _ in range(4096):
                if toff is None or toff + step > len(data):
                    break
                v = struct.unpack_from(fmt, data, toff)[0]
                if v == 0:
                    break
                if not v & flag:
                    hn = _rva_to_off(v & 0x7FFFFFFF, sections)
                    if hn is not None:
                        funcs.append(_cstr(data, hn + 2, 128))
                toff += step
            out[dll] = funcs
            off += 20
        return out
    except struct.error:
        return {}


def run_yara(path: Path, rules_dir: Path) -> list[str]:
    """Match the vendored Exhume+Unveil bundle plus local starter rules (yara-python, in memory).
    Falls back to the yara CLI with local starter rules only (the bundle is never written to disk)."""
    rule_files = sorted(p for p in rules_dir.glob("*.yar") if p.is_file() and not p.is_symlink())
    root = rules_dir.parent.parent.parent
    try:
        from .yara_bundle import compile_all
        rules, n = compile_all(root, rule_files)
        if rules is not None:
            return sorted({m.rule for m in rules.match(str(path), timeout=120)})
    except Exception as exc:  # broken bundle must not break triage
        return [f"(yara bundle error: {type(exc).__name__})"]
    exe = shutil.which("yara64") or shutil.which("yara")
    if not exe or not rule_files:
        return ["(yara-python not installed; vendored rules skipped)"]
    hits = []
    for rf in rule_files:
        try:
            r = subprocess.run([exe, "-w", str(rf), str(path)], capture_output=True, text=True, timeout=120)
            hits += [line.split(" ", 1)[0] for line in r.stdout.splitlines() if line.strip()]
        except (OSError, subprocess.SubprocessError):
            continue
    return hits


def triage(raw_path: str, rules_dir: Path | None = None) -> dict[str, Any]:
    path = safe_input_file(raw_path, MAX_SAMPLE_BYTES)
    data = path.read_bytes()
    signals: list[dict[str, Any]] = []

    def sig(name, w, detail=""):
        signals.append({"name": name, "weight": w, "detail": detail})

    ent = shannon_entropy(data)
    if ent > 7.2:
        sig("high_file_entropy_packed_or_encrypted", 15, f"{ent:.2f}")
    pe = parse_pe(data)
    if pe and pe.get("valid"):
        names = {s["name"].lower() for s in pe["sections"]}
        if names & {"upx0", "upx1", ".aspack", ".themida", ".vmp0", ".vmp1", ".mpress1", ".petite", ".enigma1"}:
            sig("packer_section_names", 20, ",".join(sorted(names)))
        for s in pe["sections"]:
            if s["executable"] and s["writable"]:
                sig("rwx_section", 15, s["name"])
            if s["entropy"] > 7.0 and s["executable"]:
                sig("high_entropy_code_section", 15, f"{s['name']}={s['entropy']}")
        all_imp = {f.lower() for fs in pe["imports"].values() for f in fs}
        if pe["imports"] and len(all_imp) < 10:
            sig("very_few_imports", 10, str(len(all_imp)))
        if not pe["imports"]:
            sig("no_import_table", 10)
        seen = set()
        for f in all_imp:
            if f in SUSPICIOUS_IMPORTS and SUSPICIOUS_IMPORTS[f][0] not in seen:
                n, w = SUSPICIOUS_IMPORTS[f]
                seen.add(n)
                sig(n, w, f)
        if pe["overlay_bytes"] > 1024 * 1024:
            sig("large_overlay", 10, str(pe["overlay_bytes"]))
        if pe["timestamp"] == 0 or pe["timestamp"] > 2_000_000_000:
            sig("anomalous_compile_timestamp", 5, str(pe["timestamp"]))
    head = data[: 32 * 1024 * 1024]
    strings: dict[str, list[str]] = {}
    for rx, name, w in STRING_PATTERNS:
        ms = rx.findall(head)
        if ms:
            strings[name] = sorted({m.decode("latin-1", "replace") for m in ms})[:25]
            sig("strings_" + name, w, strings[name][0][:120])
    yara_hits = run_yara(path, rules_dir) if rules_dir else []
    for h in yara_hits:
        if not h.startswith("("):
            sig("yara_" + h, 30)
    score = max(0, min(100, sum(s["weight"] for s in signals)))
    from .scoring import severity_for
    return {
        "schema": "argus.triage/1", "file": str(path), "size": len(data), "hashes": _hashes(data),
        "magic": data[:4].hex(), "entropy": round(ent, 3), "pe": pe, "strings_of_interest": strings,
        "yara": yara_hits, "signals": signals, "score": score, "severity": severity_for(score),
        "note": "Static only; sample was never executed. Hash lookups online are opt-in (threat-intel-enrichment).",
    }
