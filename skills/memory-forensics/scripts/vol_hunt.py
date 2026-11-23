#!/usr/bin/env python3
"""Volatility 3 hunt: run (or load saved) plugin JSON and score it into argus.findings/1.

  python -I vol_hunt.py --image mem.raw --out-dir case/mem [--profile quick|full] [--yara]
  python -I vol_hunt.py --vol-json-dir case/mem/raw --out-dir case/mem

Profiles
  quick : pslist psscan pstree cmdline netscan malfind
  full  : quick + dlllist ldrmodules handles svcscan driverscan modules ssdt callbacks getsids
          privileges envars hollowprocesses registry.printkey(Run keys) filescan
  --yara: windows.vadyarascan with ARGUS starter rules (skills/references/yara)

Read-only analysis of an image; nothing from the image is executed.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        ROOT = _p
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import indicators as I  # noqa: E402
from argus.rules import cmdline_signals  # noqa: E402
from argus.safeio import safe_child, safe_input_file, safe_output_dir, write_json  # noqa: E402
from argus.scoring import Finding, Signal  # noqa: E402

QUICK = ["windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline", "windows.netscan", "windows.malfind"]
FULL = QUICK + ["windows.dlllist", "windows.ldrmodules", "windows.handles", "windows.svcscan", "windows.driverscan",
                "windows.modules", "windows.ssdt", "windows.callbacks", "windows.getsids", "windows.privileges",
                "windows.envars", "windows.hollowprocesses", "windows.filescan"]
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
JIT_PROCS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "msedgewebview2.exe",
             "teams.exe", "ms-teams.exe", "code.exe", "discord.exe", "slack.exe", "spotify.exe",
             "powershell.exe", "pwsh.exe", "searchapp.exe", "searchhost.exe", "msmpeng.exe"}
SYSTEM_PROCS = {"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
                "lsaiso.exe", "spoolsv.exe"}


# ---------------------------------------------------------------------------- io
def _flatten(rows):
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        kids = r.pop("__children", []) or []
        out.append(r)
        out += _flatten(kids)
    return out


def vol_exe():
    return shutil.which("vol") or shutil.which("vol.py") or shutil.which("volatility3")


def run_plugin(vol, image: Path, raw_dir: Path, plugin: str, extra: list[str] | None = None, tag: str | None = None):
    name = tag or plugin
    print(f"[vol] {name} ...", file=sys.stderr)
    try:
        r = subprocess.run([vol, "-q", "-r", "json", "-f", str(image), plugin, *(extra or [])],
                           capture_output=True, text=True, timeout=7200)
        (raw_dir / f"{name}.json").write_text(r.stdout if r.stdout.strip() else "[]", encoding="utf-8")
        if r.returncode != 0:
            (raw_dir / f"{name}.err").write_text(r.stderr[-4000:], encoding="utf-8")
    except (OSError, subprocess.SubprocessError) as e:
        (raw_dir / f"{name}.err").write_text(repr(e), encoding="utf-8")


def acquire_json(image: Path, raw_dir: Path, profile: str, yara: bool):
    vol = vol_exe()
    if not vol:
        sys.exit("volatility3 not found (pip install volatility3), or pass --vol-json-dir")
    raw_dir.mkdir(parents=True, exist_ok=True)
    for p in (FULL if profile == "full" else QUICK):
        run_plugin(vol, image, raw_dir, p)
    if profile == "full":
        run_plugin(vol, image, raw_dir, "windows.registry.printkey", ["--key", RUN_KEY], tag="printkey_run")
    if yara:
        rules = sorted((ROOT / "skills" / "references" / "yara").glob("*.yar"))
        for rf in rules:
            run_plugin(vol, image, raw_dir, "windows.vadyarascan", ["--yara-file", str(rf)], tag=f"vadyarascan_{rf.stem}")


def load(raw_dir: Path, name: str):
    p = raw_dir / f"{name}.json"
    if not p.is_file() or p.is_symlink():
        return []
    try:
        return _flatten(json.loads(p.read_text(encoding="utf-8", errors="replace") or "[]"))
    except json.JSONDecodeError:
        return []


def g(r: dict, *keys, default=""):
    for k in keys:
        if k in r and r[k] not in (None, ""):
            return r[k]
    return default


# ------------------------------------------------------------------------ scoring
class Hunt:
    def __init__(self, raw: Path):
        self.raw = raw
        self.f: list[Finding] = []
        self.pslist = load(raw, "windows.pslist")
        self.psscan = load(raw, "windows.psscan")
        self.name = {}
        self.ppid = {}
        for r in self.pslist + self.psscan:
            self.name[r.get("PID")] = str(g(r, "ImageFileName")).lower()
            self.ppid[r.get("PID")] = r.get("PPID")
        self.path = {}
        for r in load(raw, "windows.cmdline"):
            args = str(g(r, "Args"))
            exe = I.extract_exe_path(args)
            if exe:
                self.path[r.get("PID")] = I.norm_path(exe)

    def add(self, rid, title, tactic, tech, art, key, sigs, action):
        f = Finding(rid, title, tactic, tech, art, key, sigs, action).finalize()
        if f.score >= 20:
            self.f.append(f)

    def pname(self, pid):
        return self.name.get(pid, "")

    def run(self):
        for m in (self.hidden, self.tree, self.cmdline, self.malfind, self.netscan, self.dlls, self.ldr, self.handles,
                  self.services, self.drivers, self.ssdt, self.callbacks, self.sids, self.privs, self.envars,
                  self.hollow, self.runkeys, self.files, self.yara):
            try:
                m()
            except Exception as e:  # one broken plugin output must not stop the rest
                self.add("ARG-MEM-ERR", f"Parser error in {m.__name__}", "TA0005", "T1055", {"error": repr(e)},
                         f"err|{m.__name__}", [Signal("parser_error", 20)], "Inspect raw plugin JSON manually.")
        return self.f

    # --- individual checks -------------------------------------------------
    def hidden(self):
        listed = {r.get("PID") for r in self.pslist}
        for r in self.psscan:
            if r.get("PID") not in listed and not g(r, "ExitTime"):
                self.add("ARG-MEM-001", "Process in psscan but not pslist (unlinked/hidden, DKOM)", "TA0005", "T1564",
                         {"pid": r.get("PID"), "name": g(r, "ImageFileName"), "offset": g(r, "Offset(V)", "Offset")},
                         f"mem|hidden|{r.get('PID')}", [Signal("hidden_process", 55)],
                         "Dump it: vol -f img windows.pslist --pid <PID> --dump (or psscan --dump); triage statically.")

    def tree(self):
        for pid, name in self.name.items():
            exp = I.EXPECTED_PARENT.get(name)
            par = self.pname(self.ppid.get(pid))
            if exp and par and par not in exp:
                self.add("ARG-MEM-002", "System process with unexpected parent", "TA0005", "T1036.005",
                         {"pid": pid, "name": name, "parent": par}, f"mem|tree|{name}|{par}",
                         [Signal("unexpected_parent", 45, par)], "Compare against a known-good process tree.")
            if name in ("lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe"):
                same = [p for p, n in self.name.items() if n == name]
                if len(same) > 1 and pid == max(same):
                    self.add("ARG-MEM-003", f"Multiple {name} instances", "TA0005", "T1036.005",
                             {"name": name, "pids": same}, f"mem|dup|{name}", [Signal("duplicate_singleton_process", 50)],
                             "Only one instance should exist; dump and triage the extra one.")
        for pid, p in self.path.items():
            n = I.basename(p)
            exp = I.SYSTEM_BINARY_PATHS.get(n)
            if exp and p not in exp and not p.startswith("\\systemroot\\") and "\\device\\" not in p:
                self.add("ARG-MEM-004", "System binary name running from unexpected path (memory)", "TA0005", "T1036.005",
                         {"pid": pid, "path": p}, f"mem|path|{p}", [Signal("system_binary_wrong_path", 55)],
                         "Dump and hash; compare with System32 copy.")

    def cmdline(self):
        for r in load(self.raw, "windows.cmdline"):
            args = str(g(r, "Args"))
            sigs = cmdline_signals(args)
            n, w = I.path_risk(I.extract_exe_path(args))
            if w >= 25:
                sigs.append(Signal("image_in_" + n, w))
            if sigs:
                self.add("ARG-MEM-010", "Suspicious command line in memory", "TA0002", "T1059",
                         {"pid": r.get("PID"), "process": g(r, "Process"), "cmdline": args[:1500]},
                         f"mem|cmd|{r.get('PID')}", sigs, "Decode payload; correlate with disk/persistence findings.")

    def malfind(self):
        per_pid = defaultdict(list)
        for r in load(self.raw, "windows.malfind"):
            per_pid[r.get("PID")].append(r)
        for pid, regions in per_pid.items():
            pname = str(g(regions[0], "Process", default=self.pname(pid))).lower()
            sigs = []
            mz = [x for x in regions if str(g(x, "Hexdump")).replace(" ", "").replace("\n", "").lower().startswith("4d5a")
                  or re.search(r"\bMZ", str(g(x, "Hexdump"))[:120])]
            rwx = [x for x in regions if "EXECUTE_READWRITE" in str(g(x, "Protection"))]
            if rwx:
                sigs.append(Signal("rwx_private_memory", 20, f"{len(rwx)} region(s)"))
            if mz:
                sigs.append(Signal("pe_header_in_private_memory", 40, f"{len(mz)} region(s)"))
            if pname in SYSTEM_PROCS or pname in ("explorer.exe", "rundll32.exe", "dllhost.exe", "notepad.exe"):
                sigs.append(Signal("injected_into_common_target", 15, pname))
            if pname in JIT_PROCS:
                sigs.append(Signal("jit_heavy_process", -25, pname))
            self.add("ARG-MEM-011", "Injected / unbacked executable memory (malfind)", "TA0005", "T1055",
                     {"pid": pid, "process": pname, "regions": [str(g(x, "Start VPN")) for x in regions][:20]},
                     f"mem|malfind|{pid}|{pname}", sigs,
                     "Dump regions (windows.malfind --pid <PID> --dump) and YARA-scan offline; check with vadyarascan.")

    def netscan(self):
        for r in load(self.raw, "windows.netscan"):
            rip = str(g(r, "ForeignAddr"))
            owner = str(g(r, "Owner")).lower()
            if not I.is_public_ip(rip):
                continue
            sigs = []
            if owner in I.SCRIPTISH:
                sigs.append(Signal("script_host_socket", 35, owner))
            p = self.path.get(r.get("PID"), "")
            n, w = I.path_risk(p)
            if w:
                sigs.append(Signal("socket_from_" + n, w + 10, p))
            try:
                if int(g(r, "ForeignPort", default=0)) in I.SUSPICIOUS_PORTS:
                    sigs.append(Signal("suspicious_remote_port", 25, str(g(r, "ForeignPort"))))
            except (TypeError, ValueError):
                pass
            if sigs:
                self.add("ARG-MEM-012", "Suspicious network socket in memory", "TA0011", "T1071",
                         {"pid": r.get("PID"), "owner": owner, "remote": rip, "rport": g(r, "ForeignPort"),
                          "state": g(r, "State")}, f"mem|net|{owner}|{rip}", sigs,
                         "Check remote reputation (opt-in); correlate with DNS/proxy logs.")

    def dlls(self):
        for r in load(self.raw, "windows.dlllist"):
            p = I.norm_path(g(r, "Path"))
            pname = str(g(r, "Process")).lower()
            n, w = I.path_risk(p)
            if w >= 15 and (pname in SYSTEM_PROCS or pname in ("explorer.exe", "lsass.exe")):
                self.add("ARG-MEM-013", "DLL from user-writable path loaded into system process", "TA0005", "T1574.002",
                         {"pid": r.get("PID"), "process": pname, "dll": p}, f"mem|dll|{pname}|{p}",
                         [Signal("system_process_loads_user_path_dll", 45), Signal(n, w)],
                         "Dump DLL (windows.dlllist --pid --dump); triage; check side-loading pair on disk.")

    def ldr(self):
        for r in load(self.raw, "windows.ldrmodules"):
            inload, ininit, inmem = (g(r, "InLoad"), g(r, "InInit"), g(r, "InMem"))
            mapped = I.norm_path(g(r, "MappedPath"))
            if inload is False and inmem is False and mapped.endswith((".dll", ".exe")) and \
                    not mapped.endswith((".mui", ".nls")) and str(g(r, "Process")).lower() not in JIT_PROCS:
                self.add("ARG-MEM-014", "Module unlinked from PEB lists (ldrmodules)", "TA0005", "T1055.001",
                         {"pid": r.get("PID"), "process": g(r, "Process"), "mapped": mapped},
                         f"mem|ldr|{r.get('PID')}|{mapped}", [Signal("unlinked_module", 40)],
                         "Possible reflective/hidden DLL; dump VAD and triage.")
            elif not mapped and inload is False and inmem is False:
                self.add("ARG-MEM-015", "Executable image mapping with no file path", "TA0005", "T1055",
                         {"pid": r.get("PID"), "process": g(r, "Process"), "base": g(r, "Base")},
                         f"mem|ldrnopath|{r.get('PID')}|{g(r, 'Base')}", [Signal("image_without_backing_file", 30)],
                         "Dump region; possible process hollowing / doppelganging.")

    def handles(self):
        lsass = {p for p, n in self.name.items() if n == "lsass.exe"}
        allow = {"csrss.exe", "lsass.exe", "svchost.exe", "msmpeng.exe", "wininit.exe", "services.exe", "lsm.exe",
                 "mrt.exe", "vmtoolsd.exe", "system", "wmiprvse.exe", "taskmgr.exe"}
        for r in load(self.raw, "windows.handles"):
            if str(g(r, "Type")) != "Process":
                continue
            nm = str(g(r, "Name")).lower()
            if "lsass.exe" not in nm and not any(f"pid {x}" in nm for x in lsass):
                continue
            owner = self.pname(r.get("PID"))
            if owner in allow or r.get("PID") in lsass:
                continue
            self.add("ARG-MEM-016", "Non-system process holds a handle to LSASS", "TA0006", "T1003.001",
                     {"pid": r.get("PID"), "process": owner, "access": g(r, "GrantedAccess")},
                     f"mem|lsasshandle|{owner}", [Signal("lsass_handle", 45, str(g(r, "GrantedAccess")))],
                     "Treat credentials as exposed; dump and triage the owning process.")

    def services(self):
        for r in load(self.raw, "windows.svcscan"):
            binp = str(g(r, "Binary", "Binary (Registry)"))
            n, w = I.path_risk(I.extract_exe_path(binp))
            sigs = [Signal("service_" + n, w + 10, binp)] if w else []
            if re.search(r"(cmd|powershell)(\.exe)?\s+/?[ck]|%comspec%", binp, re.I):
                sigs.append(Signal("service_runs_shell", 35))
            if sigs:
                self.add("ARG-MEM-017", "Suspicious service in memory (svcscan)", "TA0003", "T1543.003",
                         {"name": g(r, "Name"), "binary": binp, "state": g(r, "State")}, f"mem|svc|{g(r, 'Name')}",
                         sigs, "Compare with registry service config; check 7045 on disk.")

    def drivers(self):
        mods = {I.basename(g(r, "Path", "FullDllName")) for r in load(self.raw, "windows.modules")}
        for r in load(self.raw, "windows.driverscan"):
            dn = str(g(r, "Driver Name", "Name")).lower()
            svc = I.basename(g(r, "Service Key")) or ""
            base = dn.rsplit("\\", 1)[-1] + ".sys"
            sigs = []
            if base in I.VULN_DRIVERS:
                sigs.append(Signal("known_vulnerable_driver", 60, base))
            if mods and base not in mods and svc and svc + ".sys" not in mods and g(r, "Size", default=1) not in (0, "0"):
                sigs.append(Signal("driver_object_without_module", 20))
            if sigs:
                self.add("ARG-MEM-018", "Suspicious kernel driver (driverscan/modules)", "TA0004", "T1068",
                         {"driver": dn, "service": svc}, f"mem|drv|{dn}", sigs,
                         "Hash the .sys on disk; check loldrivers; enable vulnerable driver blocklist.")
        for r in load(self.raw, "windows.modules"):
            p = I.norm_path(g(r, "Path", "FullDllName"))
            if I.basename(p) in I.VULN_DRIVERS:
                self.add("ARG-MEM-019", "Known vulnerable driver loaded (modules)", "TA0004", "T1068",
                         {"path": p}, f"mem|mod|{p}", [Signal("known_vulnerable_driver", 60)],
                         "BYOVD lead, often precedes EDR/AV killing.")

    def ssdt(self):
        bad = [r for r in load(self.raw, "windows.ssdt")
               if str(g(r, "Module")).lower() not in ("ntoskrnl", "ntoskrnl.exe", "win32k", "win32k.sys", "win32kfull",
                                                       "win32kfull.sys", "win32kbase", "win32kbase.sys", "")]
        for r in bad[:50]:
            self.add("ARG-MEM-020", "SSDT entry pointing outside the kernel (rootkit hook)", "TA0005", "T1014",
                     {"index": g(r, "Index"), "symbol": g(r, "Symbol"), "module": g(r, "Module")},
                     f"mem|ssdt|{g(r, 'Index')}", [Signal("ssdt_hook", 55, str(g(r, "Module")))],
                     "Strong rootkit indicator (PatchGuard normally prevents this on x64), consider rebuild.")

    def callbacks(self):
        known = re.compile(r"ntoskrnl|wdfilter|wdboot|wd|ksecdd|cng|fltmgr|tcpip|ndis|cldflt|ci\.dll|peauth|"
                           r"mssecflt|sysmon|sysmondrv|klif|ehdrv|avgsp|aswsp|sophos|crowdstrike|csagent|sentinel|"
                           r"vm|nvlddmkm|amdkmdag|iorate|volsnap|dxgkrnl|mmcss|ahcache|bam|rdyboost|wof|fileinfo", re.I)
        for r in load(self.raw, "windows.callbacks"):
            mod = str(g(r, "Module"))
            if mod in ("", "UNKNOWN", "-") or not known.search(mod):
                self.add("ARG-MEM-021", "Kernel callback registered by unknown/unbacked module", "TA0005", "T1014",
                         {"type": g(r, "Type"), "callback": g(r, "Callback"), "module": mod or "UNKNOWN"},
                         f"mem|cb|{g(r, 'Type')}|{mod}", [Signal("unknown_kernel_callback", 40 if mod in ("", "UNKNOWN") else 20)],
                         "Identify the driver; unknown modules registering process/image callbacks are rootkit-like.")

    def sids(self):
        for r in load(self.raw, "windows.getsids"):
            sid = str(g(r, "SID"))
            pid = r.get("PID")
            if sid == "S-1-5-18":
                p = self.path.get(pid, "")
                n, w = I.path_risk(p)
                if w >= 15:
                    self.add("ARG-MEM-022", "SYSTEM-token process running from user-writable path", "TA0004", "T1134",
                             {"pid": pid, "process": self.pname(pid), "path": p}, f"mem|sid|{p}",
                             [Signal("system_token_user_path", 45)], "Escalation lead; find how it was launched.")

    def privs(self):
        for r in load(self.raw, "windows.privileges"):
            if str(g(r, "Privilege")) != "SeDebugPrivilege":
                continue
            attrs = str(g(r, "Attributes")).lower()
            pname = self.pname(r.get("PID")) or str(g(r, "Process")).lower()
            if "enabled" in attrs and "default" not in attrs and pname not in SYSTEM_PROCS | {"msmpeng.exe", "taskmgr.exe", "procexp64.exe", "system"}:
                self.add("ARG-MEM-023", "SeDebugPrivilege explicitly enabled", "TA0004", "T1134",
                         {"pid": r.get("PID"), "process": pname}, f"mem|sedebug|{pname}",
                         [Signal("sedebug_enabled", 30)], "Typical of credential dumpers and injectors.")

    def envars(self):
        for r in load(self.raw, "windows.envars"):
            var = str(g(r, "Variable")).lower()
            val = str(g(r, "Value"))
            if var in ("comspec", "path") and I.path_risk(val.split(";")[0])[1] >= 25:
                self.add("ARG-MEM-024", "Hijacked environment variable", "TA0005", "T1574.007",
                         {"pid": r.get("PID"), "process": g(r, "Process"), "variable": var, "value": val[:300]},
                         f"mem|env|{var}|{val[:80]}", [Signal("env_path_hijack", 40)], "Check registry Environment keys.")

    def hollow(self):
        for r in load(self.raw, "windows.hollowprocesses"):
            self.add("ARG-MEM-025", "Process hollowing indicators (hollowprocesses)", "TA0005", "T1055.012",
                     {"pid": r.get("PID"), "process": g(r, "Process"), "notes": g(r, "Notes")},
                     f"mem|hollow|{r.get('PID')}", [Signal("process_hollowing", 55)],
                     "Dump process image and compare with on-disk binary.")

    def runkeys(self):
        for r in load(self.raw, "printkey_run"):
            data = str(g(r, "Data"))
            n, w = I.path_risk(I.extract_exe_path(data))
            sigs = cmdline_signals(data) + ([Signal(n, w)] if w else [])
            if sigs:
                self.add("ARG-MEM-026", "Suspicious Run key in in-memory registry hive", "TA0003", "T1547.001",
                         {"key": g(r, "Key"), "name": g(r, "Name"), "data": data}, f"mem|run|{g(r, 'Name')}", sigs,
                         "Compare with on-disk autoruns (live collector), a difference implies tampering.")

    def files(self):
        hits = defaultdict(list)
        for r in load(self.raw, "windows.filescan"):
            n = I.norm_path(g(r, "Name"))
            b = I.basename(n)
            if any(h in b for h in I.RANSOM_NOTE_HINTS):
                hits["ransom_note"].append(n)
            elif re.search(r"\\(temp|users\\public|programdata)\\[^\\]+\.(exe|dll|ps1|vbs|hta|bat)$", n):
                hits["user_path_exec"].append(n)
        if hits.get("ransom_note"):
            self.add("ARG-MEM-027", "Ransom-note file objects in memory", "TA0040", "T1486",
                     {"files": hits["ransom_note"][:20]}, "mem|ransomnote", [Signal("ransom_note_in_memory", 55)],
                     "ISOLATE the host; keep it powered on; follow incident-response.")
        if len(hits.get("user_path_exec", [])) >= 1:
            self.add("ARG-MEM-028", "Executables opened from Temp/Public/ProgramData (filescan)", "TA0002", "T1204.002",
                     {"files": hits["user_path_exec"][:30]}, "mem|filescan|userexec",
                     [Signal("user_path_executables_open", 20 + min(20, 2 * len(hits["user_path_exec"])))],
                     "Extract with windows.dumpfiles and triage statically.")

    def yara(self):
        for p in sorted(self.raw.glob("vadyarascan_*.json")):
            for r in load(self.raw, p.stem):
                rule = str(g(r, "Rule"))
                self.add("ARG-MEM-030", f"YARA hit in process memory: {rule}", "TA0005", "T1055",
                         {"pid": r.get("PID"), "process": g(r, "Process", default=self.pname(r.get("PID"))),
                          "rule": rule, "offset": g(r, "Offset")}, f"mem|yara|{r.get('PID')}|{rule}",
                         [Signal("yara_memory_hit", 50, rule)], "Dump the VAD at the offset and triage.")


def main():
    ap = argparse.ArgumentParser(description="ARGUS Volatility 3 hunt (detect-only)")
    ap.add_argument("--image")
    ap.add_argument("--vol-json-dir")
    ap.add_argument("--profile", choices=["quick", "full"], default="full")
    ap.add_argument("--yara", action="store_true")
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()
    out = safe_output_dir(a.out_dir)
    if a.vol_json_dir:
        raw = Path(a.vol_json_dir).resolve(strict=True)
    elif a.image:
        img = safe_input_file(a.image, max_bytes=1 << 40)
        raw = out / "raw"
        acquire_json(img, raw, a.profile, a.yara)
    else:
        sys.exit("need --image or --vol-json-dir")
    findings = sorted(Hunt(raw).run(), key=lambda f: -f.score)
    errs = sorted(p.name for p in raw.glob("*.err"))
    res = {"schema": "argus.findings/1", "source": "memory-forensics", "mode": "detect-only", "profile": a.profile,
           "summary": {"total": len(findings)}, "collection_gaps": [f"plugin failed: {e}" for e in errs],
           "findings": [f.to_dict() for f in findings]}
    write_json(safe_child(out, "memory-findings.json"), res)
    print(json.dumps({"findings": len(findings), "plugin_errors": len(errs), "out": str(out / "memory-findings.json")}))


if __name__ == "__main__":
    main()
