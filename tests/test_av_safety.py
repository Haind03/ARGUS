"""AV-safety lint: the checkout must not contain contiguous literals that commonly trip
Microsoft Defender / AMSI static signatures (tool names with commands, AMSI bypass strings,
ready-to-run destructive commands, the EICAR string, dumping P/Invoke).

The forbidden list itself is stored as fragments so this file is not a hit either.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_EXT = {".py", ".ps1", ".md", ".json", ".yml", ".yaml", ".yar", ".txt", ".cmd", ".sh", ".conf"}


def f(*p):
    return "".join(p).lower()


FORBIDDEN = [
    f("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR"),            # EICAR test string
    f("sekur", "lsa::logon", "passwords"),
    f("invoke-mimi", "katz"),
    f("mimi", "katz"),
    f("amsi", "initfailed"),
    f("amsi", "utils"),
    f("amsiscan", "buffer"),
    f("[ref].assembly.gettype('system.management.automation.", "amsi"),
    f("vssadmin delete ", "shadows /all /quiet"),
    f("vssadmin.exe delete ", "shadows"),
    f("wmic shadowcopy ", "delete"),
    f("comsvcs.dll, mini", "dump"),
    f("comsvcs.dll,mini", "dump"),
    f("minidumpwrite", "dump(", "system.intptr"),
    f("dllimport(\"dbghelp", ".dll\""),
    f("lsa", "dump::"),
    f("bcdedit /set {default} ", "recoveryenabled no"),
    f("your files have ", "been encrypted"),
    f("new-object net.webclient).download", "string("),
    f("iex (new-object net.", "webclient"),
]


def iter_files():
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or "__pycache__" in p.parts or p.suffix.lower() not in SCAN_EXT:
            continue
        yield p


def test_no_av_trigger_literals():
    hits = []
    for p in iter_files():
        text = p.read_text(encoding="utf-8", errors="ignore").lower()
        for needle in FORBIDDEN:
            if needle in text:
                hits.append(f"{p.relative_to(ROOT)}: contains forbidden literal #{FORBIDDEN.index(needle)}")
    assert not hits, "AV-trigger literals found:\n" + "\n".join(hits)


def test_no_ai_attribution():
    needles = [f("co-authored", "-by"), f("generated with ", "claude"), "\U0001F916"]
    hits = [str(p.relative_to(ROOT)) for p in iter_files()
            if any(n in p.read_text(encoding="utf-8", errors="ignore").lower() for n in needles)]
    assert not hits, hits


def test_no_native_dumping_code_in_powershell():
    for p in ROOT.rglob("*.ps1"):
        t = p.read_text(encoding="utf-8", errors="ignore").lower()
        assert "add-type" not in t, f"{p.name}: Add-Type (inline C#/P/Invoke) is not allowed in ARGUS scripts"
        assert "virtualalloc" not in t and "writeprocessmemory" not in t, p.name
