#!/usr/bin/env python3
"""Score argus.artifacts/1 (execution evidence) and build a timeline. Static, read-only.

  python -I artifact_hunt.py --input artifacts.json [--out-dir case/disk]

Also accepts CSV exports from Eric Zimmerman tools via --ez-csv (AmcacheParser / AppCompatCacheParser / PECmd):
columns containing a path (Path/FullPath/ExecutableName) and a timestamp are used.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import indicators as I  # noqa: E402
from argus.safeio import load_json, safe_child, safe_input_file, safe_output_dir, write_json  # noqa: E402
from argus.scoring import Finding, Signal  # noqa: E402

TOOL_NAMES = {"mimi" "katz.exe", "procdump.exe", "procdump64.exe", "psexec.exe", "psexec64.exe", "rclone.exe",
              "advanced_ip_scanner.exe", "netscan.exe", "lazagne.exe", "nanodump.exe", "rubeus.exe",
              "sharphound.exe", "adfind.exe", "nltest.exe", "anydesk.exe", "ngrok.exe", "chisel.exe",
              "plink.exe", "xmrig.exe", "7za.exe", "winscp.exe", "megasync.exe", "processhacker.exe",
              "gmer.exe", "pchunter64.exe", "defendercontrol.exe", "dcontrol.exe", "powertool.exe"}


def exec_entries(a: dict):
    for p in a.get("prefetch") or []:
        yield "prefetch", (p.get("exe") or "").lower(), "", p.get("last_run_approx") or p.get("created")
    for b in a.get("bam") or []:
        yield "bam", I.basename(b.get("path")), I.norm_path(b.get("path")), b.get("last_exec")
    for u in a.get("userassist") or []:
        yield "userassist", I.basename(u.get("name")), I.norm_path(u.get("name")), u.get("last_run")
    for l in a.get("lnk") or []:
        yield "lnk", I.basename(l.get("target")), I.norm_path(l.get("target")), l.get("modified")
    for e in a.get("_ez") or []:
        yield e["source"], I.basename(e["path"]), I.norm_path(e["path"]), e["time"]


def load_ez(paths):
    out = []
    for p in paths or []:
        f = safe_input_file(p, 1 << 30)
        with open(f, encoding="utf-8-sig", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                path = next((row[k] for k in row if k and k.lower() in ("path", "fullpath", "executablename",
                                                                         "sourcefilename", "keypath")), "")
                t = next((row[k] for k in row if k and ("lastmodified" in k.lower() or "lastrun" in k.lower()
                                                        or "timestamp" in k.lower())), "")
                if path:
                    out.append({"source": f"ez:{f.stem}", "path": path, "time": t})
    return out


def hunt(a: dict) -> tuple[list[Finding], list[dict]]:
    findings, timeline, seen = [], [], set()
    for src, name, path, t in exec_entries(a):
        timeline.append({"time": t, "source": src, "name": name, "path": path})
        sigs = []
        n, w = I.path_risk(path)
        if w >= 15:
            sigs.append(Signal("executed_from_" + n, w, path))
        if name in TOOL_NAMES:
            sigs.append(Signal("attacker_tool_executed", 40, name))
        if name in I.TUNNEL_TOOLS or name in I.EXFIL_TOOLS:
            sigs.append(Signal("tunnel_or_exfil_tool_executed", 25, name))
        typo = name in ("svch0st.exe", "scvhost.exe", "lsas.exe", "csrsss.exe", "expl0rer.exe")
        if typo or (name in I.SYSTEM_BINARY_PATHS and path and path not in I.SYSTEM_BINARY_PATHS[name]):
            sigs.append(Signal("system_binary_name_wrong_path", 50, path or name))
        if src == "prefetch" and name.endswith((".tmp", ".dat")):
            sigs.append(Signal("non_exe_extension_executed", 25, name))
        key = f"art|{src}|{path or name}"
        if sigs and key not in seen:
            seen.add(key)
            f = Finding("ARG-DF-001", "Execution evidence of suspicious binary", "TA0002", "T1204.002",
                        {"source": src, "name": name, "path": path, "time": t}, key, sigs,
                        "Recover the binary (or confirm it was deleted, check recycle/USN) and triage it.").finalize()
            if f.score >= 20:
                findings.append(f)
    for r in a.get("recycle") or []:
        p = I.norm_path(r.get("original_path"))
        if p.endswith((".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".hta", ".scr")):
            f = Finding("ARG-DF-002", "Executable/script deleted to Recycle Bin", "TA0005", "T1070.004",
                        {"original_path": p, "deleted": r.get("deleted"), "size": r.get("size")}, f"rb|{p}",
                        [Signal("deleted_executable", 20)] + ([Signal("from_" + I.path_risk(p)[0], I.path_risk(p)[1])] if I.path_risk(p)[1] else []),
                        "Recover the $R file from the Recycle Bin for triage (copy, do not run).").finalize()
            if f.score >= 20:
                findings.append(f)
    timeline.sort(key=lambda x: str(x.get("time") or ""))
    return findings, timeline


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--ez-csv", nargs="*")
    ap.add_argument("--out-dir")
    a = ap.parse_args()
    data = load_json(a.input)
    data["_ez"] = load_ez(a.ez_csv)
    findings, timeline = hunt(data)
    res = {"schema": "argus.findings/1", "source": "disk-forensics", "mode": "detect-only",
           "summary": {"total": len(findings), "timeline_events": len(timeline)},
           "findings": [f.to_dict() for f in sorted(findings, key=lambda f: -f.score)],
           "collection_gaps": data.get("collection_errors") or []}
    if a.out_dir:
        out = safe_output_dir(a.out_dir)
        write_json(safe_child(out, "disk-findings.json"), res)
        write_json(safe_child(out, "execution-timeline.json"), timeline)
    print(json.dumps(res["summary"]))
    for f in res["findings"][:30]:
        print(f"{f['score']:>3} {f['severity']:<8} {f['artifact'].get('path') or f['artifact'].get('original_path') or f['artifact'].get('name')}")


if __name__ == "__main__":
    main()
