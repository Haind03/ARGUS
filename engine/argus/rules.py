"""Heuristic detection rules mapped to MITRE ATT&CK Enterprise.

Each rule is a generator: rule(ctx) -> yields Candidate.  Rules are
read-only over the telemetry dict; they never touch the live system.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator

from . import indicators as I
from .scoring import Signal

TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development",
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0011": "Command and Control", "TA0010": "Exfiltration",
    "TA0040": "Impact",
}
TACTIC_SHORTNAME = {
    "TA0043": "reconnaissance", "TA0042": "resource-development", "TA0001": "initial-access",
    "TA0002": "execution", "TA0003": "persistence", "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion", "TA0006": "credential-access", "TA0007": "discovery",
    "TA0008": "lateral-movement", "TA0009": "collection", "TA0011": "command-and-control",
    "TA0010": "exfiltration", "TA0040": "impact",
}


@dataclass
class Candidate:
    artifact: dict[str, Any]
    key: str
    signals: list[Signal]
    technique: str | None = None  # override rule default (sub-technique)


@dataclass
class Rule:
    rule_id: str
    tactic: str
    technique: str
    title: str
    action: str
    fn: Callable[["Context"], Iterable[Candidate]]
    min_signals: int = 1
    tags: tuple = field(default_factory=tuple)


RULES: list[Rule] = []


def rule(rule_id, tactic, technique, title, action, min_signals=1, tags=()):
    def deco(fn):
        RULES.append(Rule(rule_id, tactic, technique, title, action, fn, min_signals, tuple(tags)))
        return fn
    return deco


# ---------------------------------------------------------------------------
class Context:
    """Normalised, read-only view over a telemetry document."""

    def __init__(self, tel: dict[str, Any]):
        self.tel = tel if isinstance(tel, dict) else {}
        self._procs: list[dict] | None = None

    def section(self, name: str) -> list[dict]:
        v = self.tel.get(name) or []
        if isinstance(v, dict):
            v = [v]
        return [x for x in v if isinstance(x, dict)]

    def obj(self, name: str) -> dict:
        v = self.tel.get(name) or {}
        return v if isinstance(v, dict) else {}

    def events(self, ids: Iterable[int] = (), log_contains: str = "") -> Iterator[dict]:
        ids = set(ids)
        for ev in self.section("events"):
            try:
                eid = int(ev.get("id", -1))
            except (TypeError, ValueError):
                continue
            if ids and eid not in ids:
                continue
            if log_contains and log_contains.lower() not in str(ev.get("log", "")).lower():
                continue
            yield ev

    def procs(self) -> list[dict]:
        """Live processes + process-creation events (4688, Sysmon 1)."""
        if self._procs is not None:
            return self._procs
        out: list[dict] = []
        by_pid = {}
        for p in self.section("processes"):
            r = {
                "pid": p.get("pid"), "ppid": p.get("ppid"),
                "name": (p.get("name") or I.basename(p.get("path"))).lower(),
                "path": I.norm_path(p.get("path")), "cmdline": p.get("cmdline") or "",
                "user": p.get("user") or "", "signed": p.get("signed"),
                "signer": p.get("signer") or "", "sha256": p.get("sha256") or "",
                "parent_name": (p.get("parent_name") or "").lower(),
                "parent_path": I.norm_path(p.get("parent_path")),
                "start_time": p.get("start_time") or "", "source": "live",
            }
            out.append(r)
            by_pid[r["pid"]] = r
        for r in out:
            if not r["parent_name"] and r["ppid"] in by_pid:
                r["parent_name"] = by_pid[r["ppid"]]["name"]
                r["parent_path"] = by_pid[r["ppid"]]["path"]
        for ev in self.events((1,), "sysmon"):
            d = ev.get("data") or {}
            out.append({
                "pid": d.get("ProcessId"), "ppid": d.get("ParentProcessId"),
                "name": I.basename(d.get("Image")), "path": I.norm_path(d.get("Image")),
                "cmdline": d.get("CommandLine") or "", "user": d.get("User") or "",
                "signed": None, "signer": "", "sha256": _sysmon_hash(d.get("Hashes")),
                "parent_name": I.basename(d.get("ParentImage")),
                "parent_path": I.norm_path(d.get("ParentImage")),
                "start_time": ev.get("time") or "", "source": "sysmon:1",
            })
        for ev in self.events((4688,), "security"):
            d = ev.get("data") or {}
            out.append({
                "pid": d.get("NewProcessId"), "ppid": d.get("ProcessId"),
                "name": I.basename(d.get("NewProcessName")), "path": I.norm_path(d.get("NewProcessName")),
                "cmdline": d.get("CommandLine") or "", "user": d.get("SubjectUserName") or "",
                "signed": None, "signer": "", "sha256": "",
                "parent_name": I.basename(d.get("ParentProcessName")),
                "parent_path": I.norm_path(d.get("ParentProcessName")),
                "start_time": ev.get("time") or "", "source": "security:4688",
            })
        self._procs = out
        return out


TRUSTED_ROOTS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\",
                 "c:\\program files\\", "c:\\program files (x86)\\", "c:\\programdata\\microsoft\\windows defender\\")


def _trusted_system_image(path: str, names: tuple) -> bool:
    """Allow-list by name ONLY when the image lives in a protected system/program directory
    (a renamed svchost.exe in %TEMP% must not inherit trust)."""
    if I.basename(path) not in names:
        return False
    if I.path_risk(path)[1] > 0:
        return False
    return path.startswith(TRUSTED_ROOTS) and "\\temp\\" not in path


def _sysmon_hash(h: str | None) -> str:
    m = re.search(r"SHA256=([A-Fa-f0-9]{64})", h or "")
    return m.group(1).lower() if m else ""


def _pkey(p: dict) -> str:
    return f"proc|{p['path'] or p['name']}|{_norm_cmd(p['cmdline'])}"


def _norm_cmd(c: str) -> str:
    """Strip volatile tokens (GUIDs, pids, temp names) so baselines stay stable."""
    c = (c or "").lower()
    c = re.sub(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "<guid>", c)
    c = re.sub(r"\b\d{3,}\b", "<n>", c)
    return c[:400]


def _signature_signals(signed, signer: str) -> list[Signal]:
    if signed is True and "microsoft" in (signer or "").lower():
        return [Signal("signed_microsoft", -20, signer)]
    if signed is True:
        return [Signal("signed_third_party", -10, signer)]
    if signed is False:
        return [Signal("unsigned_binary", 15)]
    return []


def _proc_art(p: dict) -> dict:
    return {k: p.get(k) for k in ("pid", "ppid", "name", "path", "cmdline", "parent_name",
                                  "user", "sha256", "signed", "signer", "source", "start_time")}


def cmdline_signals(cmd: str) -> list[Signal]:
    sigs: list[Signal] = []
    for rx, name, w in I.PS_PATTERNS:
        if rx.search(cmd or ""):
            sigs.append(Signal(name, w))
    decoded = I.try_decode_ps_encoded(cmd or "")
    if decoded:
        for rx, name, w in I.PS_PATTERNS:
            if rx.search(decoded) and name != "ps_encoded_command":
                sigs.append(Signal("decoded_" + name, w // 2, decoded[:160]))
    if I.URL_RE.search(cmd or ""):
        sigs.append(Signal("url_in_cmdline", 10, I.URL_RE.search(cmd).group(0)[:200]))
    if len(cmd or "") > 1000:
        sigs.append(Signal("very_long_cmdline", 10, str(len(cmd))))
    return sigs


# ===========================================================================
# TA0001 Initial Access
# ===========================================================================
@rule("ARG-IA-001", "TA0001", "T1566.001", "Office/PDF/mail client spawned a script host or LOLBin",
      "Identify the document opened just before; pull it from Outlook/Downloads for static triage. Do not open it.")
def office_child(ctx):
    for p in ctx.procs():
        if p["parent_name"] in I.OFFICE and p["name"] in I.SCRIPTISH:
            sigs = [Signal("office_parent_script_child", 45, f"{p['parent_name']} -> {p['name']}")]
            sigs += cmdline_signals(p["cmdline"])
            yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-IA-002", "TA0001", "T1189", "Browser spawned a script host or LOLBin (possible drive-by / fake update)",
      "Review browser history around the process start time; check Downloads for the dropped file and its Zone.Identifier.")
def browser_child(ctx):
    for p in ctx.procs():
        if p["parent_name"] in I.BROWSERS and p["name"] in (I.SCRIPTISH - {"cmd.exe"}):
            sigs = [Signal("browser_parent_script_child", 35, f"{p['parent_name']} -> {p['name']}")]
            sigs += cmdline_signals(p["cmdline"])
            yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-IA-003", "TA0001", "T1204.002", "Recently downloaded executable/script (Mark-of-the-Web) present or running",
      "Verify the publisher and the download source (ZoneId HostUrl). Submit hash to intel only if online enrichment is enabled.")
def motw_exec(ctx):
    running = {p["path"] for p in ctx.procs() if p["path"]}
    for f in ctx.section("files"):
        path = I.norm_path(f.get("path"))
        zone = str(f.get("zone_id") or "")
        if not path or zone not in ("3", "4"):
            continue
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext not in (".exe", ".scr", ".msi", ".dll", ".iso", ".img", ".vhd", ".vhdx") + I.SCRIPT_EXT:
            continue
        sigs = [Signal("mark_of_the_web_internet_zone", 15, f.get("host_url") or "")]
        if ext in (".iso", ".img", ".vhd", ".vhdx", ".lnk", ".hta", ".js", ".jse", ".vbs", ".wsf", ".scr", ".cpl"):
            sigs.append(Signal("high_risk_delivery_extension", 20, ext))
        if path in running:
            sigs.append(Signal("downloaded_file_is_running", 25))
        sigs += _signature_signals(f.get("signed"), f.get("signer") or "")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|lnk|hta)$", path):
            sigs.append(Signal("double_extension", 35))
        yield Candidate({"path": path, "sha256": f.get("sha256"), "host_url": f.get("host_url"),
                         "zone_id": zone, "signed": f.get("signed")}, f"file|{path}|{f.get('sha256','')}", sigs)


@rule("ARG-IA-004", "TA0001", "T1091", "Process executed from removable media",
      "Confirm the USB device is the user's; image the device read-only before further analysis.")
def removable_exec(ctx):
    drives = {str(d).lower().rstrip("\\").rstrip(":") for d in (ctx.obj("host").get("removable_drives") or [])}
    for p in ctx.procs():
        if p["path"][:1] and p["path"][:1] in drives and p["path"][1:2] == ":":
            sigs = [Signal("exec_from_removable_drive", 35, p["path"][:2])]
            sigs += _signature_signals(p["signed"], p["signer"])
            yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-IA-005", "TA0001", "T1133", "Inbound remote logon (RDP/network) from a public IP",
      "Check whether RDP should be exposed at all; review 4624/4625 around that time and enforce NLA + MFA or disable RDP.")
def public_remote_logon(ctx):
    seen = Counter()
    for ev in ctx.events((4624,), "security"):
        d = ev.get("data") or {}
        lt = str(d.get("LogonType", ""))
        ip = d.get("IpAddress") or ""
        if lt in ("10", "3") and I.is_public_ip(ip):
            seen[(ip, lt, d.get("TargetUserName", ""))] += 1
    for (ip, lt, user), n in seen.items():
        sigs = [Signal("public_ip_remote_logon", 40 if lt == "10" else 25, f"type {lt}, {n}x")]
        yield Candidate({"ip": ip, "logon_type": lt, "user": user, "count": n}, f"logon|{ip}|{lt}|{user}", sigs)


# ===========================================================================
# TA0002 Execution
# ===========================================================================
@rule("ARG-EX-001", "TA0002", "T1059.001", "Suspicious PowerShell command line (encoded / cradle / obfuscation)",
      "Decode the command, extract URLs/IPs as IOCs, and pull PowerShell 4104 script-block logs for the same time window.",
      min_signals=1)
def powershell_susp(ctx):
    for p in ctx.procs():
        if p["name"] not in ("powershell.exe", "pwsh.exe", "powershell_ise.exe"):
            continue
        sigs = cmdline_signals(p["cmdline"])
        if not sigs:
            continue
        if p["parent_name"] in I.OFFICE | I.BROWSERS | {"wscript.exe", "cscript.exe", "mshta.exe", "wmiprvse.exe"}:
            sigs.append(Signal("suspicious_parent", 15, p["parent_name"]))
        yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-EX-002", "TA0002", "T1059.001", "Malicious PowerShell script block (Event 4104)",
      "Export the full script block (all fragments by ScriptBlockId) as evidence; hunt the same IOCs across the host.")
def ps_scriptblock(ctx):
    for ev in ctx.events((4104,), "powershell"):
        d = ev.get("data") or {}
        text = d.get("ScriptBlockText") or ""
        sigs = [s for s in cmdline_signals(text) if s.name != "very_long_cmdline"]
        if str(ev.get("level", "")).lower() == "warning":
            sigs.append(Signal("ps_logged_as_suspicious_by_windows", 15))
        if not sigs:
            continue
        sid = d.get("ScriptBlockId") or ""
        yield Candidate({"script_block_id": sid, "path": d.get("Path"), "time": ev.get("time"),
                         "excerpt": text[:300]}, f"sb|{sid or hash(text)}", sigs)


@rule("ARG-EX-003", "TA0002", "T1059.005", "Windows Script Host running a script from a user-writable location",
      "Collect the script file (copy, do not execute); look for its persistence (Run key / task / startup).")
def wsh_script(ctx):
    for p in ctx.procs():
        if p["name"] not in ("wscript.exe", "cscript.exe"):
            continue
        sigs = []
        m = re.search(r"[\"']?([a-z]:\\[^\"']+?\.(?:vbs|vbe|js|jse|wsf|wsh))", p["cmdline"], re.I)
        if m:
            name, w = I.path_risk(m.group(1))
            if w:
                sigs.append(Signal("script_in_" + name, w + 10, m.group(1)))
        if re.search(r"\.(jse|vbe)\b", p["cmdline"], re.I):
            sigs.append(Signal("encoded_script_extension", 20))
        if p["parent_name"] in ("explorer.exe",) and sigs:
            sigs.append(Signal("user_double_click", 5))
        if p["parent_name"] in I.OFFICE | {"svchost.exe", "taskeng.exe", "wmiprvse.exe"}:
            sigs.append(Signal("non_interactive_parent", 15, p["parent_name"]))
        if sigs:
            yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-EX-004", "TA0002", "T1218", "LOLBin proxy execution with suspicious arguments",
      "Confirm whether an installer/IT tool legitimately did this; otherwise collect referenced payload and scan with YARA.")
def lolbin_proxy(ctx):
    patterns = {
        "mshta.exe": [(r"https?://|javascript:|vbscript:", "mshta_remote_or_inline", 40, "T1218.005")],
        "rundll32.exe": [(r"javascript:|mshtml,runhtmlapplication", "rundll32_inline_script", 45, "T1218.011"),
                         (r"\\(?:appdata|temp|users\\public|programdata)\\[^,]+\.(?:dll|dat|tmp|png|jpg|bin)\b", "rundll32_user_path_dll", 30, "T1218.011"),
                         (r"comsvcs(?:\.dll)?[, ]+#?(?:minidump|24)", "rundll32_comsvcs_minidump", 70, "T1003.001"),
                         (r"^\"?[^\"]*rundll32(?:\.exe)?\"?\s*$", "rundll32_no_arguments", 30, "T1218.011")],
        "regsvr32.exe": [(r"/i:\s*https?://|scrobj\.dll", "regsvr32_squiblydoo", 55, "T1218.010"),
                         (r"\\(?:appdata|temp|users\\public)\\", "regsvr32_user_path", 25, "T1218.010")],
        "certutil.exe": [(r"-urlcache|-verifyctl|-ping", "certutil_download", 45, "T1105"),
                         (r"-decode(?:hex)?\b", "certutil_decode", 30, "T1140")],
        "bitsadmin.exe": [(r"/transfer|/addfile|/setnotifycmdline", "bitsadmin_transfer", 35, "T1197")],
        "msbuild.exe": [(r"\\(?:appdata|temp|users\\public|downloads)\\|\.xml\b|\.csproj\b", "msbuild_inline_task", 35, "T1127.001")],
        "installutil.exe": [(r"/u\b|/logfile=", "installutil_uninstall_trick", 35, "T1218.004")],
        "regasm.exe": [(r"/u\b", "regasm_unregister_trick", 30, "T1218.009")],
        "cmstp.exe": [(r"/s\b.*\.inf|/au\b", "cmstp_inf", 40, "T1218.003")],
        "msiexec.exe": [(r"/q.*https?://|https?://.*/q", "msiexec_remote_quiet", 40, "T1218.007")],
        "hh.exe": [(r"https?://|\\(?:temp|downloads)\\", "hh_chm", 30, "T1218.001")],
        "wmic.exe": [(r"process\s+call\s+create", "wmic_process_create", 35, "T1047"),
                     (r"/format:\s*[\"']?(?:https?://|.*\.xsl)", "wmic_xsl", 45, "T1220")],
        "forfiles.exe": [(r"/c\s+.*(?:cmd|powershell)", "forfiles_indirect_exec", 25, "T1202")],
        "curl.exe": [(r"-o\s+.*\\(?:temp|public|appdata|programdata)\\|--output", "curl_drop_to_user_path", 20, "T1105")],
        "esentutl.exe": [(r"/y\s+.*/d|/vss", "esentutl_copy", 25, "T1003.003")],
        "odbcconf.exe": [(r"regsvr|/a\s*\{", "odbcconf_dll", 35, "T1218.008")],
    }
    for p in ctx.procs():
        for rx, name, w, tech in patterns.get(p["name"], []):
            if re.search(rx, p["cmdline"] or "", re.I):
                sigs = [Signal(name, w)] + [s for s in cmdline_signals(p["cmdline"]) if s.name == "url_in_cmdline"]
                if p["parent_name"] in I.OFFICE | I.BROWSERS:
                    sigs.append(Signal("suspicious_parent", 20, p["parent_name"]))
                yield Candidate(_proc_art(p), _pkey(p), sigs, technique=tech)


@rule("ARG-EX-005", "TA0002", "T1047", "WMI provider host spawned a shell (remote/WMI execution)",
      "Check WMI-Activity/Operational and 4624 type 3 for the source; correlate with WMI subscriptions (persistence).")
def wmiprvse_child(ctx):
    for p in ctx.procs():
        if p["parent_name"] == "wmiprvse.exe" and p["name"] in I.SCRIPTISH:
            yield Candidate(_proc_art(p), _pkey(p), [Signal("wmiprvse_spawned_shell", 40)] + cmdline_signals(p["cmdline"]))


@rule("ARG-EX-006", "TA0002", "T1059", "Process running from a high-risk user-writable directory",
      "Hash and triage the binary statically; check its parent chain and any persistence pointing at it.")
def userpath_exec(ctx):
    for p in ctx.procs():
        name, w = I.path_risk(p["path"])
        if w < 25:
            continue
        sigs = [Signal(name, w, p["path"])] + _signature_signals(p["signed"], p["signer"])
        if p["parent_name"] in I.SCRIPTISH:
            sigs.append(Signal("spawned_by_script_host", 15, p["parent_name"]))
        yield Candidate(_proc_art(p), _pkey(p), sigs)


# ===========================================================================
# TA0003 Persistence
# ===========================================================================
def _command_risk(command: str) -> list[Signal]:
    sigs: list[Signal] = []
    exe = I.extract_exe_path(command)
    name, w = I.path_risk(exe)
    if w:
        sigs.append(Signal(name, w, exe))
    b = I.basename(exe)
    if b in I.SCRIPTISH:
        sigs.append(Signal("launches_script_host_or_lolbin", 20, b))
    if re.search(r"\.(?:ps1|vbs|vbe|js|jse|hta|bat|cmd|wsf)\b", command or "", re.I):
        sigs.append(Signal("launches_script_file", 15))
    sigs += [s for s in cmdline_signals(command) if s.name != "very_long_cmdline"]
    return sigs


@rule("ARG-PE-001", "TA0003", "T1547.001", "Suspicious Run/RunOnce/Startup-folder autostart entry",
      "Record the value (registry export) as evidence, triage the target binary, then decide on removal via incident-response (opt-in).")
def run_keys(ctx):
    for a in ctx.section("autoruns"):
        loc = str(a.get("location") or "")
        lloc = loc.lower()
        if not any(k in lloc for k in ("\\run", "startup", "runonce", "policies\\explorer\\run", "load", "runservices")):
            continue
        cmd = str(a.get("value") or a.get("command") or "")
        sigs = _command_risk(cmd) + _signature_signals(a.get("signed"), a.get("signer") or "")
        if not sigs or all(s.weight <= 0 for s in sigs):
            continue
        tech = "T1547.001"
        yield Candidate({"location": loc, "name": a.get("name"), "value": cmd, "signed": a.get("signed")},
                        f"autorun|{lloc}|{a.get('name','')}|{_norm_cmd(cmd)}", sigs, technique=tech)


@rule("ARG-PE-002", "TA0003", "T1053.005", "Scheduled task executing a script/LOLBin or binary from a user path",
      "Export the task XML (schtasks /query /xml) as evidence; check author/creation time vs. user activity.")
def sched_tasks(ctx):
    for t in ctx.section("scheduled_tasks"):
        path = str(t.get("path") or "") + str(t.get("name") or "")
        actions = t.get("actions") or []
        if isinstance(actions, str):
            actions = [actions]
        cmd = " ; ".join(str(x) for x in actions)
        sigs = _command_risk(cmd)
        if not sigs:
            continue
        if t.get("hidden"):
            sigs.append(Signal("task_hidden", 15))
        if not str(t.get("path") or "\\").lower().startswith("\\microsoft\\") and str(t.get("author") or "") == "":
            sigs.append(Signal("task_no_author", 5))
        if re.fullmatch(r"\\?[{(]?[0-9a-f-]{16,}[})]?", str(t.get("name") or ""), re.I):
            sigs.append(Signal("task_random_name", 10))
        if str(t.get("path") or "").lower().startswith("\\microsoft\\windows\\") and any(s.weight >= 20 for s in sigs):
            sigs.append(Signal("masquerades_in_microsoft_folder", 15))
        yield Candidate({"task": path, "actions": actions, "author": t.get("author"), "hidden": t.get("hidden"),
                         "run_as": t.get("run_as")}, f"task|{path.lower()}|{_norm_cmd(cmd)}", sigs)


@rule("ARG-PE-003", "TA0003", "T1543.003", "Windows service with suspicious binary path",
      "Export the service config (sc qc) and binary hash; check 7045/4697 for install time and installing account.")
def services(ctx):
    for s in ctx.section("services"):
        bin_path = str(s.get("path") or s.get("binary_path") or "")
        sigs = _command_risk(bin_path) + _signature_signals(s.get("signed"), s.get("signer") or "")
        if not sigs or all(x.weight <= 0 for x in sigs):
            continue
        if str(s.get("account") or "").lower() in ("localsystem", "nt authority\\system") and any(x.weight >= 15 for x in sigs):
            sigs.append(Signal("runs_as_system", 10))
        yield Candidate({"service": s.get("name"), "display": s.get("display"), "path": bin_path,
                         "start_mode": s.get("start_mode"), "account": s.get("account")},
                        f"svc|{str(s.get('name','')).lower()}|{_norm_cmd(bin_path)}", sigs)


@rule("ARG-PE-004", "TA0003", "T1543.003", "New service installed (Event 7045/4697)",
      "Validate the installer; PsExec-like random names or cmd/powershell image paths are high-priority.")
def new_service_event(ctx):
    for ev in list(ctx.events((7045,), "system")) + list(ctx.events((4697,), "security")):
        d = ev.get("data") or {}
        img = d.get("ImagePath") or d.get("ServiceFileName") or ""
        name = d.get("ServiceName") or ""
        sigs = [Signal("new_service_installed", 10, name)] + _command_risk(img)
        if re.search(r"(?:cmd|powershell)(?:\.exe)?\s+/?[ckc]|%comspec%", img, re.I):
            sigs.append(Signal("service_runs_shell_inline", 35))
        if re.fullmatch(r"[A-Za-z0-9]{8,16}", name) and not re.search(r"[aeiou]{2}", name.lower()):
            sigs.append(Signal("random_service_name", 15))
        if "psexesvc" in (name + img).lower():
            sigs.append(Signal("psexec_service", 30))
        yield Candidate({"service": name, "image_path": img, "time": ev.get("time"), "event_id": ev.get("id")},
                        f"svcevt|{name.lower()}|{_norm_cmd(img)}", sigs)


@rule("ARG-PE-005", "TA0003", "T1546.003", "WMI event subscription (filter-to-consumer binding)",
      "Export the __EventFilter / consumer / binding objects; legitimate ones on home PCs are rare (SCM Event Log Consumer is default).")
def wmi_subs(ctx):
    for w in ctx.section("wmi_subscriptions"):
        ctype = str(w.get("consumer_type") or "")
        name = str(w.get("consumer") or w.get("name") or "")
        if name.lower() in ("scm event log consumer", "bvtconsumer") and ctype.lower().startswith("ntevent"):
            continue
        cmd = str(w.get("command") or w.get("script") or "")
        sigs = [Signal("wmi_subscription_present", 30, ctype)]
        if ctype.lower() in ("commandlineeventconsumer", "activescripteventconsumer"):
            sigs.append(Signal("executing_consumer_type", 25, ctype))
        sigs += _command_risk(cmd)
        yield Candidate({"consumer": name, "type": ctype, "filter": w.get("filter"), "command": cmd},
                        f"wmi|{name.lower()}|{_norm_cmd(cmd)}", sigs)


@rule("ARG-PE-006", "TA0003", "T1546.012", "Image File Execution Options debugger / SilentProcessExit hijack",
      "Export the IFEO key; a Debugger value on a common binary is almost never legitimate on personal PCs.")
def ifeo(ctx):
    for a in ctx.section("autoruns"):
        loc = str(a.get("location") or "").lower()
        if "image file execution options" in loc or "silentprocessexit" in loc:
            val = str(a.get("value") or "")
            sigs = [Signal("ifeo_debugger_set", 45, a.get("name") or "")] + _command_risk(val)
            target = str(a.get("name") or "").lower()
            if target in ("sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe"):
                sigs.append(Signal("accessibility_binary_backdoor", 35, target))
                yield Candidate({"location": a.get("location"), "target": target, "value": val},
                                f"ifeo|{target}|{val.lower()}", sigs, technique="T1546.008")
                continue
            yield Candidate({"location": a.get("location"), "target": target, "value": val},
                            f"ifeo|{target}|{val.lower()}", sigs)


@rule("ARG-PE-007", "TA0003", "T1547.004", "Winlogon Shell/Userinit/Notify modified",
      "Compare against defaults (explorer.exe / C:\\Windows\\system32\\userinit.exe,). Export the key as evidence.")
def winlogon(ctx):
    w = ctx.obj("registry").get("winlogon") or {}
    shell = str(w.get("Shell") or "explorer.exe").strip().lower()
    userinit = str(w.get("Userinit") or "c:\\windows\\system32\\userinit.exe,").strip().lower()
    if shell not in ("explorer.exe", "explorer.exe,"):
        yield Candidate({"value": "Shell", "data": shell}, f"winlogon|shell|{shell}",
                        [Signal("winlogon_shell_modified", 55, shell)])
    ui = [x.strip() for x in userinit.split(",") if x.strip()]
    if any(x not in ("c:\\windows\\system32\\userinit.exe", "userinit.exe", "userinit") for x in ui):
        yield Candidate({"value": "Userinit", "data": userinit}, f"winlogon|userinit|{userinit}",
                        [Signal("winlogon_userinit_appended", 55, userinit)])


@rule("ARG-PE-008", "TA0003", "T1546.010", "AppInit_DLLs / AppCertDlls configured",
      "Record the DLL path and hash; AppInit is disabled under Secure Boot but still a strong signal of tampering.")
def appinit(ctx):
    reg = ctx.obj("registry")
    for key in ("appinit_dlls", "appinit_dlls_wow64", "appcert_dlls"):
        val = str(reg.get(key) or "").strip()
        if val:
            tech = "T1546.009" if key == "appcert_dlls" else "T1546.010"
            yield Candidate({"value": key, "data": val}, f"reg|{key}|{val.lower()}",
                            [Signal(f"{key}_set", 50, val)] + _command_risk(val), technique=tech)


@rule("ARG-PE-009", "TA0003", "T1197", "BITS job with remote URL or notify command",
      "List with Get-BitsTransfer -AllUsers; a notify command-line is a persistence primitive.")
def bits_jobs(ctx):
    for b in ctx.section("bits_jobs"):
        notify = str(b.get("notify_cmd") or "")
        url = str(b.get("url") or "")
        sigs = []
        if notify:
            sigs += [Signal("bits_notify_cmdline", 40, notify)] + _command_risk(notify)
        if url and not re.search(r"(windowsupdate|microsoft|msedge|office|adobe|google)\.(com|net)", url, re.I):
            sigs.append(Signal("bits_non_vendor_url", 20, url[:200]))
        name, w = I.path_risk(b.get("file"))
        if w:
            sigs.append(Signal(name, w, str(b.get("file"))))
        if sigs:
            yield Candidate(dict(b), f"bits|{str(b.get('name','')).lower()}|{url.lower()}", sigs)


@rule("ARG-PE-010", "TA0003", "T1136.001", "Local account created / added to Administrators",
      "Confirm with the user; unknown local admins on a personal PC are high-priority.")
def new_account(ctx):
    for ev in ctx.events((4720,), "security"):
        d = ev.get("data") or {}
        yield Candidate({"user": d.get("TargetUserName"), "by": d.get("SubjectUserName"), "time": ev.get("time")},
                        f"acct|{d.get('TargetUserName','')}", [Signal("local_account_created", 35)])
    for ev in ctx.events((4732,), "security"):
        d = ev.get("data") or {}
        if "admin" in str(d.get("TargetUserName", "")).lower():
            yield Candidate({"member": d.get("MemberSid") or d.get("MemberName"), "group": d.get("TargetUserName"),
                             "by": d.get("SubjectUserName"), "time": ev.get("time")},
                            f"grp|{d.get('MemberSid','')}|admins", [Signal("added_to_administrators", 40)],
                            technique="T1098")


@rule("ARG-PE-011", "TA0003", "T1546.015", "COM object hijack in HKCU (InprocServer32 / LocalServer32)",
      "Compare the HKCU CLSID with its HKLM counterpart; HKCU overrides pointing to user paths are suspicious.")
def com_hijack(ctx):
    for c in ctx.section("com_hijacks"):
        val = str(c.get("value") or "")
        sigs = [Signal("hkcu_clsid_override", 25, c.get("clsid") or "")] + _command_risk(val)
        if len(sigs) > 1:
            yield Candidate(dict(c), f"com|{str(c.get('clsid','')).lower()}|{val.lower()}", sigs)


@rule("ARG-PE-012", "TA0003", "T1176", "Browser extension with high-risk permissions installed outside the store",
      "Review extension ID in the vendor store; remove via the browser UI if unknown.")
def browser_ext(ctx):
    for e in ctx.section("browser_extensions"):
        perms = {str(x).lower() for x in (e.get("permissions") or [])}
        sigs = []
        risky = perms & {"<all_urls>", "webrequest", "webrequestblocking", "cookies", "nativemessaging",
                         "debugger", "proxy", "declarativenetrequest", "clipboardread", "management"}
        if len(risky) >= 3:
            sigs.append(Signal("many_high_risk_permissions", 20, ",".join(sorted(risky))))
        if e.get("from_webstore") is False:
            sigs.append(Signal("sideloaded_extension", 25))
        if e.get("developer_mode"):
            sigs.append(Signal("unpacked_developer_mode", 15))
        if sigs:
            yield Candidate(dict(e), f"ext|{e.get('browser','')}|{e.get('id','')}", sigs)


# ===========================================================================
# TA0004 Privilege Escalation
# ===========================================================================
@rule("ARG-PR-001", "TA0004", "T1548.002", "UAC bypass pattern (auto-elevating binary spawning a shell / hijacked handler key)",
      "Check HKCU\\Software\\Classes\\ms-settings|mscfile|Folder shell\\open\\command; export and remove via IR only after evidence capture.")
def uac_bypass(ctx):
    for p in ctx.procs():
        if p["parent_name"] in I.UAC_BYPASS_HOSTS and p["name"] in I.SCRIPTISH:
            yield Candidate(_proc_art(p), _pkey(p), [Signal("autoelevate_parent_spawned_shell", 55, p["parent_name"])])
    for a in ctx.section("autoruns"):
        loc = str(a.get("location") or "").lower()
        if re.search(r"hkcu\\software\\classes\\(ms-settings|mscfile|exefile|folder|launcher\.systemsettings|"
                     r"apppathcompat)\\.*shell\\open\\command", loc):
            val = str(a.get("value") or "")
            yield Candidate({"location": a.get("location"), "value": val}, f"uac|{loc}|{val.lower()}",
                            [Signal("hkcu_handler_hijack", 55)] + _command_risk(val))


@rule("ARG-PR-002", "TA0004", "T1068", "Known vulnerable / abused kernel driver loaded (BYOVD)",
      "Record driver hash; check against loldrivers.io offline list; enable Microsoft Vulnerable Driver Blocklist.")
def byovd(ctx):
    extra = {x.lower() for x in (ctx.tel.get("_ioc_vuln_drivers") or [])}
    for d in ctx.section("drivers"):
        name = I.basename(d.get("path")) or str(d.get("name") or "").lower()
        if not name.endswith(".sys"):
            name = name + ".sys" if name else name
        sigs = []
        if name in I.VULN_DRIVERS or name in extra:
            sigs.append(Signal("known_vulnerable_driver", 60, name))
        if d.get("signed") is False:
            sigs.append(Signal("unsigned_driver", 30))
        pname, w = I.path_risk(d.get("path"))
        if w:
            sigs.append(Signal("driver_in_" + pname, w + 10, I.norm_path(d.get("path"))))
        if sigs:
            yield Candidate({"driver": name, "path": d.get("path"), "signed": d.get("signed"), "sha256": d.get("sha256")},
                            f"drv|{name}|{d.get('sha256','')}", sigs)


@rule("ARG-PR-003", "TA0004", "T1574.009", "Unquoted service path with spaces in a writable-looking location",
      "Quote the ImagePath; check the candidate hijack paths (e.g. C:\\Program.exe) for unexpected binaries.")
def unquoted_svc(ctx):
    for s in ctx.section("services"):
        p = str(s.get("path") or "")
        if not p or p.startswith('"'):
            continue
        exe = re.split(r"\.exe", p, maxsplit=1, flags=re.I)[0]
        if " " in exe and not exe.lower().startswith("c:\\windows\\"):
            yield Candidate({"service": s.get("name"), "path": p, "account": s.get("account")},
                            f"unq|{str(s.get('name','')).lower()}", [Signal("unquoted_service_path_with_space", 20)])


@rule("ARG-PR-004", "TA0004", "T1574.001", "DLL in user-writable dir next to a signed executable (search-order hijack)",
      "Triage the DLL statically; side-loading pairs are common in PlugX/QakBot-style loaders.")
def dll_sideload(ctx):
    by_dir = defaultdict(list)
    for f in ctx.section("files"):
        p = I.norm_path(f.get("path"))
        if p:
            by_dir[p.rsplit("\\", 1)[0]].append((p, f))
    for d, items in by_dir.items():
        _, w = I.path_risk(d + "\\")
        if not w:
            continue
        exes = [f for p, f in items if p.endswith(".exe") and f.get("signed") is True]
        dlls = [(p, f) for p, f in items if p.endswith(".dll") and f.get("signed") is False]
        if exes and dlls:
            for p, f in dlls:
                yield Candidate({"dll": p, "sha256": f.get("sha256"), "signed_exe": exes[0].get("path")},
                                f"sideload|{p}", [Signal("unsigned_dll_beside_signed_exe", 35), Signal("user_writable_dir", w)])


# ===========================================================================
# TA0005 Defense Evasion
# ===========================================================================
@rule("ARG-DE-001", "TA0005", "T1562.001", "Microsoft Defender disabled or weakened (real-time off / exclusions / tamper off)",
      "Ask the user whether they configured this; unexplained exclusions are a classic malware step. Re-enable via Windows Security.")
def defender(ctx):
    d = ctx.obj("defender")
    if not d:
        return
    sigs = []
    if d.get("realtime_enabled") is False:
        sigs.append(Signal("realtime_protection_off", 45))
    if d.get("antivirus_enabled") is False:
        sigs.append(Signal("antivirus_disabled", 30))
    if d.get("tamper_protection") is False:
        sigs.append(Signal("tamper_protection_off", 15))
    if d.get("behavior_monitor_enabled") is False:
        sigs.append(Signal("behavior_monitoring_off", 20))
    if sigs:
        yield Candidate({k: d.get(k) for k in ("realtime_enabled", "antivirus_enabled", "tamper_protection",
                                               "behavior_monitor_enabled")}, "defender|state", sigs)
    for kind in ("exclusions_path", "exclusions_process", "exclusions_extension"):
        for ex in d.get(kind) or []:
            exs = str(ex)
            w = 30
            if re.fullmatch(r"[a-z]:\\?", exs, re.I) or exs in ("*", ".exe", "exe", ".dll", ".ps1"):
                w = 55
            elif I.path_risk(exs + "\\")[1]:
                w = 40
            yield Candidate({"exclusion_type": kind, "value": exs}, f"defx|{kind}|{exs.lower()}",
                            [Signal("defender_exclusion_" + kind.split("_")[1], w, exs)])


@rule("ARG-DE-002", "TA0005", "T1070.001", "Event log cleared (1102 Security / 104 System)",
      "Note the account and time; treat everything before that time as possibly incomplete.")
def log_cleared(ctx):
    for ev in list(ctx.events((1102,), "security")) + list(ctx.events((104,), "system")):
        d = ev.get("data") or {}
        yield Candidate({"event_id": ev.get("id"), "time": ev.get("time"), "by": d.get("SubjectUserName") or d.get("SubjectUserName")},
                        f"clr|{ev.get('id')}|{ev.get('time')}", [Signal("event_log_cleared", 60)])


@rule("ARG-DE-003", "TA0005", "T1036.005", "System binary name running from unexpected path or with unexpected parent",
      "Hash the binary and compare with the genuine System32 copy; masquerading is high-confidence when the path is wrong.")
def masquerade(ctx):
    for p in ctx.procs():
        exp = I.SYSTEM_BINARY_PATHS.get(p["name"])
        if exp and p["path"] and p["path"] not in exp and not p["path"].startswith(("c:\\windows\\winsxs\\",)):
            sigs = [Signal("system_binary_wrong_path", 60, p["path"])] + _signature_signals(p["signed"], p["signer"])
            yield Candidate(_proc_art(p), _pkey(p), sigs)
            continue
        par = I.EXPECTED_PARENT.get(p["name"])
        if par and p["parent_name"] and p["parent_name"] not in par:
            yield Candidate(_proc_art(p), _pkey(p) + "|parent",
                            [Signal("system_binary_unexpected_parent", 40, p["parent_name"])], technique="T1036")
    # near-miss names (svch0st, lsas, scvhost...)
    typos = re.compile(r"^(svch0st|scvhost|svchosts|svhost|lsas|lsasss|isass|csrsss|expl0rer|explore|winlogin|"
                       r"servics|smsss|dllh0st|rundl32|taskhost32)\.exe$")
    for p in ctx.procs():
        if typos.match(p["name"]):
            yield Candidate(_proc_art(p), _pkey(p) + "|typo", [Signal("typosquatted_system_binary_name", 60, p["name"])])


@rule("ARG-DE-004", "TA0005", "T1055", "Remote thread / process access into another process (Sysmon 8)",
      "Check source image; injection into explorer/svchost/browser from a user-path binary is high-priority. Consider memory capture.")
def injection(ctx):
    benign_names = ("csrss.exe", "wininit.exe", "msmpeng.exe", "svchost.exe", "explorer.exe", "mssense.exe")
    for ev in ctx.events((8,), "sysmon"):
        d = ev.get("data") or {}
        src = I.norm_path(d.get("SourceImage"))
        tgt = I.norm_path(d.get("TargetImage"))
        if _trusted_system_image(src, benign_names):
            continue
        sigs = [Signal("create_remote_thread", 35, f"{I.basename(src)} -> {I.basename(tgt)}")]
        n, w = I.path_risk(src)
        if w:
            sigs.append(Signal("source_" + n, w))
        if d.get("StartModule") in (None, "", "-"):
            sigs.append(Signal("thread_start_unbacked_memory", 20))
        yield Candidate({"source": src, "target": tgt, "start_address": d.get("StartAddress"), "time": ev.get("time")},
                        f"inj|{src}|{tgt}", sigs)


@rule("ARG-DE-005", "TA0005", "T1562.004", "Windows Firewall profile disabled",
      "Re-enable unless the user knowingly uses a third-party firewall.")
def firewall_off(ctx):
    for prof in ctx.section("firewall_profiles"):
        if prof.get("enabled") is False:
            yield Candidate({"profile": prof.get("name")}, f"fw|{prof.get('name')}",
                            [Signal("firewall_profile_disabled", 30, str(prof.get("name")))])


@rule("ARG-DE-006", "TA0005", "T1564.001", "Hidden/system-attributed executable in user profile",
      "Inspect with `attrib`; hidden executables in AppData are uncommon for legitimate software.")
def hidden_exe(ctx):
    for f in ctx.section("files"):
        p = I.norm_path(f.get("path"))
        if f.get("hidden") and re.search(r"\.(exe|dll|scr|ps1|vbs|js)$", p):
            sigs = [Signal("hidden_executable", 25)]
            n, w = I.path_risk(p)
            if w:
                sigs.append(Signal(n, w))
            yield Candidate({"path": p, "sha256": f.get("sha256")}, f"hid|{p}", sigs)


@rule("ARG-DE-007", "TA0005", "T1112", "Security-relevant registry policy weakened",
      "Restore policy; check who changed it (Sysmon 13) and when.")
def reg_policy(ctx):
    reg = ctx.obj("registry")
    checks = {
        "disable_antispyware": ("defender_disableantispyware_policy", 45),
        "disable_realtime_policy": ("defender_realtime_policy_disabled", 45),
        "enable_lua": ("uac_disabled", 40),
        "disable_task_mgr": ("taskmgr_disabled_policy", 35),
        "ps_scriptblock_logging_off": ("ps_logging_disabled", 20),
        "wdigest_use_logon_credential": ("wdigest_plaintext_enabled", 45),
        "lsa_run_as_ppl_off": ("lsa_protection_off", 5),
    }
    for key, (sig, w) in checks.items():
        v = reg.get(key)
        bad = (v is True) if key != "enable_lua" else (v is False or v == 0)
        if key == "wdigest_use_logon_credential":
            bad = v in (1, True)
        if bad:
            tech = "T1003.001" if key == "wdigest_use_logon_credential" else "T1112"
            yield Candidate({"setting": key, "value": v}, f"regpol|{key}", [Signal(sig, w)], technique=tech)


# ===========================================================================
# TA0006 Credential Access
# ===========================================================================
@rule("ARG-CA-001", "TA0006", "T1003.001", "LSASS memory access / dump tooling",
      "Assume credentials on this host are exposed: plan password resets after containment. Preserve the dump file if found.")
def lsass(ctx):
    for p in ctx.procs():
        c = p["cmdline"].lower()
        sigs = []
        if re.search(r"procdump(?:64)?(?:\.exe)?\s.*(?:-ma|-mm)?\s.*lsass", c):
            sigs.append(Signal("procdump_lsass", 70))
        if re.search(r"comsvcs(?:\.dll)?[, ]+#?(?:minidump|24)", c):
            sigs.append(Signal("comsvcs_minidump", 70))
        # grouped alternations keep tool names non-contiguous on disk (AV-safe), same matching
        if re.search(r"seku(?:rlsa)|lsad(?:ump)|mimi(?:katz)|logonp(?:asswords)|nanod(?:ump)|pypyk(?:atz)|handlek(?:atz)", c) or \
                p["name"] in ("mimi" "katz.exe", "nano" "dump.exe"):
            sigs.append(Signal("credential_tool_keyword", 70))
        if re.search(r"createdump(?:\.exe)?\s.*-f", c) and "lsass" in c:
            sigs.append(Signal("createdump_lsass", 60))
        if sigs:
            yield Candidate(_proc_art(p), _pkey(p), sigs)
    for ev in ctx.events((10,), "sysmon"):
        d = ev.get("data") or {}
        if not I.norm_path(d.get("TargetImage")).endswith("\\lsass.exe"):
            continue
        src = I.norm_path(d.get("SourceImage"))
        if _trusted_system_image(src, ("msmpeng.exe", "csrss.exe", "wininit.exe", "svchost.exe", "lsm.exe",
                                       "wmiprvse.exe", "taskmgr.exe", "mrt.exe", "vmtoolsd.exe", "mssense.exe")):
            continue
        mask = str(d.get("GrantedAccess") or "").lower()
        sigs = [Signal("lsass_handle_opened", 25, f"{I.basename(src)} {mask}")]
        if mask in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x40", "0x1418"):
            sigs.append(Signal("lsass_read_access_mask", 35, mask))
        if "dbghelp" in str(d.get("CallTrace", "")).lower() or "dbgcore" in str(d.get("CallTrace", "")).lower():
            sigs.append(Signal("minidump_calltrace", 30))
        n, w = I.path_risk(src)
        if w:
            sigs.append(Signal("source_" + n, w))
        yield Candidate({"source": src, "granted_access": mask, "time": ev.get("time")}, f"lsassacc|{src}|{mask}", sigs)


@rule("ARG-CA-002", "TA0006", "T1003.002", "SAM/SYSTEM/SECURITY hive export or shadow-copy hive access",
      "Locate the output files and treat them as credential material; reset local account passwords.")
def sam_dump(ctx):
    for p in ctx.procs():
        c = p["cmdline"].lower()
        if re.search(r"reg(?:\.exe)?\s+(?:save|export)\s+hklm\\(?:sam|system|security)\b", c):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("reg_save_credential_hive", 60)])
        elif re.search(r"harddiskvolumeshadowcopy\d*\\windows\\system32\\config\\(?:sam|system|security)", c):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("shadowcopy_hive_access", 60)])
        elif re.search(r"ntdsutil.*ifm|\\ntds\.dit", c):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("ntds_access", 60)], technique="T1003.003")


@rule("ARG-CA-003", "TA0006", "T1555.003", "Non-browser process touching browser credential stores",
      "Identify the process; infostealers (RedLine/Lumma/Vidar style) read Login Data / logins.json / Local State. Rotate saved passwords.")
def browser_creds(ctx):
    rx = re.compile(r"login data|logins\.json|key4\.db|local state|cookies\.sqlite|\\network\\cookies|web data", re.I)
    for p in ctx.procs():
        if p["name"] in I.BROWSERS:
            continue
        if rx.search(p["cmdline"]):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("browser_credential_store_reference", 50)] + _signature_signals(p["signed"], p["signer"]))
    for ev in ctx.events((11, 23, 26), "sysmon"):
        d = ev.get("data") or {}
        img = I.norm_path(d.get("Image"))
        if I.basename(img) in I.BROWSERS or not rx.search(str(d.get("TargetFilename") or "")):
            continue
        yield Candidate({"image": img, "target": d.get("TargetFilename"), "time": ev.get("time")},
                        f"bcred|{img}", [Signal("browser_store_file_activity_by_non_browser", 45)])


@rule("ARG-CA-004", "TA0006", "T1552.001", "Credential hunting in files (findstr/Select-String for passwords)",
      "Review what files matched; move plaintext secrets into a password manager.")
def cred_search(ctx):
    rx = re.compile(r"(findstr|select-string|grep).{0,60}(password|passwd|pwd|credential|secret|apikey|token)", re.I)
    for p in ctx.procs():
        if rx.search(p["cmdline"]):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("password_string_search", 30)])
        if re.search(r"cmdkey\s+/list|vaultcmd\s+/list|credentialmanager", p["cmdline"], re.I):
            yield Candidate(_proc_art(p), _pkey(p) + "|vault", [Signal("credential_manager_enum", 25)], technique="T1555.004")


@rule("ARG-CA-005", "TA0006", "T1110", "Brute force: many failed logons",
      "If the source is remote, block it and disable exposed RDP/SMB; if local, check for credential-stuffing malware.")
def brute(ctx):
    fails = Counter()
    for ev in ctx.events((4625,), "security"):
        d = ev.get("data") or {}
        fails[(d.get("IpAddress") or "-", d.get("TargetUserName") or "-")] += 1
    by_ip = Counter()
    for (ip, _u), n in fails.items():
        by_ip[ip] += n
    for ip, n in by_ip.items():
        if n >= 20:
            users = sorted({u for (i, u) in fails if i == ip})
            sigs = [Signal("failed_logons_burst", 30 if n < 100 else 45, str(n))]
            if len(users) >= 5:
                sigs.append(Signal("password_spray_many_users", 20, str(len(users))))
            if I.is_public_ip(ip):
                sigs.append(Signal("from_public_ip", 15, ip))
            yield Candidate({"source_ip": ip, "failures": n, "users": users[:20]}, f"bf|{ip}", sigs)


# ===========================================================================
# TA0007 Discovery
# ===========================================================================
@rule("ARG-DI-001", "TA0007", "T1082", "Burst of host/user/network discovery commands from one parent",
      "Reconstruct the parent process tree; discovery bursts from a script host or unknown binary often follow initial access.")
def discovery_burst(ctx):
    groups = defaultdict(set)
    proc_by_parent = {}
    for p in ctx.procs():
        c = (p["name"] + " " + p["cmdline"]).lower()
        for k in I.DISCOVERY_CMDS:
            if k in c:
                gk = (p["ppid"], p["parent_name"])
                groups[gk].add(k)
                proc_by_parent[gk] = p
    for (ppid, pname), cmds in groups.items():
        if len(cmds) < 4:
            continue
        sigs = [Signal("discovery_command_burst", 20 + 5 * min(len(cmds), 8), ",".join(sorted(cmds)))]
        if pname in I.SCRIPTISH or pname in I.OFFICE:
            sigs.append(Signal("discovery_from_script_host", 15, pname))
        if pname == "explorer.exe":
            sigs.append(Signal("interactive_user_parent", -15))
        yield Candidate({"parent_pid": ppid, "parent": pname, "commands": sorted(cmds)},
                        f"disc|{pname}|{','.join(sorted(cmds))}", sigs)


@rule("ARG-DI-002", "TA0007", "T1518.001", "Security software discovery (SecurityCenter2 / AV process enumeration)",
      "Correlate with defense-evasion findings shortly afterwards.")
def av_discovery(ctx):
    rx = re.compile(r"securitycenter2|antivirusproduct|get-mpcomputerstatus|tasklist.*(?:msmpeng|avp|ekrn|bdagent)|"
                    r"wmic.*/namespace:\\\\root\\securitycenter", re.I)
    for p in ctx.procs():
        if rx.search(p["cmdline"]):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("security_product_enumeration", 30)])


# ===========================================================================
# TA0008 Lateral Movement
# ===========================================================================
@rule("ARG-LM-001", "TA0008", "T1021.002", "PsExec-style / admin-share remote execution",
      "Identify the remote source (4624 type 3 + 5145); on a home PC inbound admin-share execution is rarely legitimate.")
def psexec(ctx):
    for p in ctx.procs():
        if p["name"] in ("psexesvc.exe", "paexec.exe", "remcomsvc.exe", "csexecsvc.exe") or \
                re.search(r"\\\\[^\\]+\\(?:admin|c|ipc)\$", p["cmdline"], re.I):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("admin_share_or_psexec", 45)])
    for ev in ctx.events((5145,), "security"):
        d = ev.get("data") or {}
        share = str(d.get("ShareName") or "")
        if re.search(r"\\(admin|c)\$$", share, re.I) and re.search(r"\.(exe|dll|bat|ps1)$", str(d.get("RelativeTargetName", "")), re.I):
            yield Candidate({"share": share, "file": d.get("RelativeTargetName"), "ip": d.get("IpAddress")},
                            f"share|{d.get('IpAddress')}|{d.get('RelativeTargetName')}", [Signal("executable_written_to_admin_share", 50)])


@rule("ARG-LM-002", "TA0008", "T1021.006", "WinRM remote shell (wsmprovhost spawned processes)",
      "Confirm whether WinRM should be enabled (Get-Service WinRM); disable if not used.")
def winrm(ctx):
    for p in ctx.procs():
        if p["parent_name"] == "wsmprovhost.exe":
            yield Candidate(_proc_art(p), _pkey(p), [Signal("winrm_remote_child", 35)] + cmdline_signals(p["cmdline"]))


@rule("ARG-LM-003", "TA0008", "T1021.001", "Inbound RDP session (logon type 10) from another host",
      "Validate the source and account; disable RDP if the user does not use it.")
def rdp_in(ctx):
    for ev in ctx.events((4624,), "security"):
        d = ev.get("data") or {}
        ip = d.get("IpAddress") or ""
        if str(d.get("LogonType")) == "10" and ip not in ("", "-", "127.0.0.1", "::1") and not I.is_public_ip(ip):
            yield Candidate({"ip": ip, "user": d.get("TargetUserName"), "time": ev.get("time")},
                            f"rdp|{ip}|{d.get('TargetUserName','')}", [Signal("inbound_rdp_internal", 20)])


# ===========================================================================
# TA0009 Collection
# ===========================================================================
@rule("ARG-CO-001", "TA0009", "T1560.001", "Archiver creating password-protected / staged archive",
      "Locate the archive; check what was collected and whether it left the host (exfil hunting).")
def archive(ctx):
    for p in ctx.procs():
        c = p["cmdline"].lower()
        if p["name"] in I.ARCHIVERS or re.search(r"compress-archive", c):
            sigs = []
            if re.search(r"\s-p\S*|\s-hp\S*|-mhe=on", c):
                sigs.append(Signal("password_protected_archive", 30))
            if re.search(r"\\(?:temp|public|programdata|appdata)\\", c):
                sigs.append(Signal("staged_in_user_writable_dir", 15))
            if re.search(r"\\(?:documents|desktop|pictures|onedrive)\\|\*\.(?:docx?|xlsx?|pdf|kdbx|wallet)", c):
                sigs.append(Signal("collects_user_documents", 20))
            if p["parent_name"] in I.SCRIPTISH:
                sigs.append(Signal("archiver_from_script_host", 15))
            if sigs:
                yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-CO-002", "TA0009", "T1074.001", "Large archive staged in temp/public directory",
      "Inspect archive listing (7z l) without extracting executables; correlate with exfil tools.")
def staged_archives(ctx):
    for f in ctx.section("files"):
        p = I.norm_path(f.get("path"))
        try:
            size = int(f.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if re.search(r"\.(zip|7z|rar|tar|gz|cab)$", p) and size >= 50 * 1024 * 1024:
            n, w = I.path_risk(p)
            if w >= 25:
                yield Candidate({"path": p, "size": size}, f"stage|{p}", [Signal("large_archive_in_" + n, 30, str(size))])


@rule("ARG-CO-003", "TA0009", "T1056.001", "Keylogger / screen / clipboard capture tooling indicators",
      "Triage the binary; hooks via SetWindowsHookEx are visible in memory forensics (malfind / windows.hooks).")
def capture(ctx):
    rx = re.compile(r"getasynckeystate|setwindowshookex|keylog|get-clipboard|screenshot|copyfromscreen|"
                    r"system\.windows\.forms\.screen", re.I)
    for p in ctx.procs():
        if rx.search(p["cmdline"]):
            tech = "T1113" if re.search(r"screen", p["cmdline"], re.I) else (
                "T1115" if "clipboard" in p["cmdline"].lower() else "T1056.001")
            yield Candidate(_proc_art(p), _pkey(p), [Signal("capture_api_or_keyword", 35)], technique=tech)


# ===========================================================================
# TA0011 Command and Control
# ===========================================================================
def _net(ctx):
    return ctx.section("network")


@rule("ARG-C2-001", "TA0011", "T1071.001", "Outbound connection from a binary in a user-writable path or unsigned",
      "Resolve the remote IP/domain (DNS cache), check reputation offline/opt-in online, capture a pcap if still active.")
def c2_userpath(ctx):
    procs = {p["pid"]: p for p in ctx.procs() if p["source"] == "live"}
    for c in _net(ctx):
        rip = c.get("remote") or c.get("remote_address")
        if not I.is_public_ip(rip):
            continue
        p = procs.get(c.get("pid")) or {}
        path = I.norm_path(c.get("process_path") or p.get("path"))
        n, w = I.path_risk(path)
        sigs = []
        if w:
            sigs.append(Signal("network_from_" + n, w + 10, path))
        sigs += _signature_signals(p.get("signed"), p.get("signer") or "")
        name = I.basename(path) or str(c.get("process") or "").lower()
        if name in I.SCRIPTISH and name not in ("curl.exe",):
            sigs.append(Signal("script_host_network_connection", 30, name))
        try:
            rport = int(c.get("rport") or c.get("remote_port") or 0)
        except (TypeError, ValueError):
            rport = 0
        if rport in I.SUSPICIOUS_PORTS:
            sigs.append(Signal("suspicious_remote_port", 25, str(rport)))
        if sigs and any(s.weight > 0 for s in sigs):
            yield Candidate({"process": name, "path": path, "pid": c.get("pid"), "remote": rip, "rport": rport,
                             "state": c.get("state")}, f"net|{path or name}|{rip}|{rport}", sigs)


@rule("ARG-C2-002", "TA0011", "T1105", "Ingress tool transfer via built-in downloaders",
      "Retrieve the downloaded file path from the command line and triage it; block the source URL.")
def ingress(ctx):
    rx = re.compile(r"(certutil.*-urlcache.*-f|bitsadmin.*/transfer|invoke-webrequest.*-outfile|iwr.*-o(?:utfile)?\s|"
                    r"curl(?:\.exe)?\s.*(?:-o|--output)\s|wget(?:\.exe)?\s|start-bitstransfer|downloadfile\()", re.I)
    for p in ctx.procs():
        if rx.search(p["cmdline"]):
            sigs = [Signal("builtin_download_to_disk", 30)]
            if re.search(r"\\(?:temp|public|appdata|programdata)\\[^\s\"']+\.(?:exe|dll|ps1|bat|vbs|zip|bin)", p["cmdline"], re.I):
                sigs.append(Signal("payload_to_user_writable_path", 20))
            if I.IPV4_RE.search(I.URL_RE.search(p["cmdline"]).group(0) if I.URL_RE.search(p["cmdline"]) else ""):
                sigs.append(Signal("url_uses_raw_ip", 20))
            yield Candidate(_proc_art(p), _pkey(p), sigs)


@rule("ARG-C2-003", "TA0011", "T1572", "Tunneling / reverse-proxy tool present (ngrok, cloudflared, chisel...)",
      "Ask the user if they use it (developers often do); otherwise treat as covert channel and capture its config file.")
def tunnels(ctx):
    for p in ctx.procs():
        if p["name"] in I.TUNNEL_TOOLS or re.search(r"\b(ngrok|cloudflared)\b.*\b(tcp|tunnel|http)\b|chisel.*client|"
                                                    r"-r\s+\d+:|plink.*-r\s", p["cmdline"], re.I):
            sigs = [Signal("tunneling_tool", 35, p["name"])]
            n, w = I.path_risk(p["path"])
            if w:
                sigs.append(Signal(n, w))
            yield Candidate(_proc_art(p), _pkey(p), sigs, technique="T1572")


@rule("ARG-C2-004", "TA0011", "T1219", "Remote access software running",
      "Low-confidence by itself; confirm the user installed it. Unattended-access RMM on a personal PC is a scam/intrusion indicator.")
def rmm(ctx):
    seen = set()
    for p in ctx.procs():
        if p["name"] in I.REMOTE_ACCESS_TOOLS and p["name"] not in seen:
            seen.add(p["name"])
            sigs = [Signal("remote_access_tool_running", 20, p["name"])]
            n, w = I.path_risk(p["path"])
            if w:
                sigs.append(Signal("rmm_" + n, w))
            if p["parent_name"] in I.SCRIPTISH:
                sigs.append(Signal("rmm_started_by_script", 25))
            yield Candidate(_proc_art(p), f"rmm|{p['name']}|{p['path']}", sigs)


@rule("ARG-C2-005", "TA0011", "T1568.002", "Possible DGA domain in DNS cache / Sysmon 22",
      "Pull the querying process (Sysmon 22 Image); a single high-entropy domain is weak, many is strong.")
def dga(ctx):
    names = []
    for d in ctx.section("dns_cache"):
        names.append((str(d.get("name") or ""), ""))
    for ev in ctx.events((22,), "sysmon"):
        dd = ev.get("data") or {}
        names.append((str(dd.get("QueryName") or ""), I.norm_path(dd.get("Image"))))
    hits = [(n, img, I.dga_score(n)[1]) for n, img in names if I.dga_score(n)[0]]
    uniq = {}
    for n, img, e in hits:
        uniq.setdefault(n.lower(), (img, e))
    for n, (img, e) in uniq.items():
        sigs = [Signal("high_entropy_domain", 15, f"entropy={e}")]
        if len(uniq) >= 10:
            sigs.append(Signal("many_dga_like_domains", 25, str(len(uniq))))
        if img and I.path_risk(img)[1]:
            sigs.append(Signal("queried_by_user_path_binary", 20, img))
        yield Candidate({"domain": n, "image": img}, f"dga|{n}", sigs)


@rule("ARG-C2-006", "TA0011", "T1102", "Non-browser process contacting web-service C2 / paste / webhook domains",
      "Capture the full URL from command line / DNS; Discord/Telegram webhooks are widely abused by stealers.")
def web_service(ctx):
    for p in ctx.procs():
        if p["name"] in I.BROWSERS:
            continue
        low = p["cmdline"].lower()
        hit = next((d for d in I.WEB_C2_DOMAINS if d in low), None)
        if hit:
            yield Candidate(_proc_art(p), _pkey(p), [Signal("web_service_domain_in_cmdline", 35, hit)])
    for ev in ctx.events((22,), "sysmon"):
        d = ev.get("data") or {}
        img = I.norm_path(d.get("Image"))
        q = str(d.get("QueryName") or "").lower()
        if I.basename(img) in I.BROWSERS:
            continue
        hit = next((x for x in I.WEB_C2_DOMAINS if x.split("/")[0] in q), None)
        if hit:
            sigs = [Signal("non_browser_dns_web_service", 30, q)]
            if I.path_risk(img)[1]:
                sigs.append(Signal("querying_binary_in_user_path", 20, img))
            yield Candidate({"image": img, "query": q, "time": ev.get("time")}, f"webc2|{img}|{q}", sigs)


@rule("ARG-C2-007", "TA0011", "T1071", "Hosts file tampering (redirects for security/vendor domains)",
      "Restore C:\\Windows\\System32\\drivers\\etc\\hosts; malware blocks AV/update domains or redirects banking sites.")
def hosts_file(ctx):
    for line in ctx.tel.get("hosts_file") or []:
        s = str(line).strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2 or parts[1].lower() in ("localhost", "localhost.localdomain"):
            continue
        sigs = [Signal("hosts_entry", 10, s[:120])]
        if re.search(r"microsoft|windowsupdate|virustotal|kaspersky|eset|avast|avg|bitdefender|malwarebytes|"
                     r"symantec|norton|mcafee|sophos|defender", s, re.I):
            sigs.append(Signal("security_domain_redirect", 40))
        if re.search(r"bank|paypal|google|facebook|apple|amazon", s, re.I) and not parts[0].startswith(("0.0.0.0", "127.")):
            sigs.append(Signal("high_value_domain_redirect", 40))
        if len(sigs) > 1:
            yield Candidate({"line": s}, f"hosts|{s.lower()}", sigs, technique="T1565.001")


# ===========================================================================
# TA0010 Exfiltration
# ===========================================================================
@rule("ARG-EF-001", "TA0010", "T1567.002", "Cloud-storage exfil tooling (rclone/mega) or upload command",
      "Recover rclone.conf (remote + credentials) as evidence; revoke the cloud token. Data likely already left.")
def exfil(ctx):
    for p in ctx.procs():
        c = p["cmdline"].lower()
        sigs = []
        if p["name"] in I.EXFIL_TOOLS:
            sigs.append(Signal("exfil_capable_tool", 25, p["name"]))
        if re.search(r"\b(copy|sync|move)\b.*\b[a-z0-9_-]+:[\w/\\.-]*", c) and ("rclone" in c or p["name"] == "rclone.exe"):
            sigs.append(Signal("rclone_copy_to_remote", 40))
        if re.search(r"--(?:bwlimit|transfers|no-check-certificate|max-age)", c) and "rclone" in c:
            sigs.append(Signal("rclone_operator_flags", 15))
        if re.search(r"curl(?:\.exe)?\s.*(?:-t\s|--upload-file|-f\s+[\"']?\w+=@|--data-binary\s+@)", c):
            sigs.append(Signal("curl_file_upload", 35))
        if re.search(r"invoke-(?:webrequest|restmethod).*-method\s+(?:post|put).*-infile", c):
            sigs.append(Signal("ps_file_upload", 35))
        if p["name"] in I.EXFIL_TOOLS and I.path_risk(p["path"])[1]:
            sigs.append(Signal("tool_in_user_writable_path", 15))
        if sigs:
            tech = "T1567.002" if any(s.name.startswith(("rclone", "exfil")) for s in sigs) else "T1048"
            yield Candidate(_proc_art(p), _pkey(p), sigs, technique=tech)


@rule("ARG-EF-002", "TA0010", "T1041", "Process with high outbound byte count (if collector recorded bytes)",
      "Validate the process (backup/sync clients are common FPs); review destination.")
def exfil_bytes(ctx):
    for c in _net(ctx):
        try:
            sent = int(c.get("bytes_sent") or 0)
        except (TypeError, ValueError):
            sent = 0
        if sent >= 500 * 1024 * 1024 and I.is_public_ip(c.get("remote")):
            name = str(c.get("process") or "").lower()
            if name in I.BROWSERS or name in ("onedrive.exe", "dropbox.exe", "googledrivesync.exe", "backblaze.exe"):
                continue
            yield Candidate({"process": name, "remote": c.get("remote"), "bytes_sent": sent},
                            f"bytes|{name}|{c.get('remote')}", [Signal("large_outbound_volume", 30, str(sent))])


# ===========================================================================
# TA0040 Impact
# ===========================================================================
@rule("ARG-IM-001", "TA0040", "T1490", "Inhibit system recovery (shadow copy / backup / boot recovery deletion)",
      "RANSOMWARE PRECURSOR: isolate network immediately (pull cable / disable Wi-Fi), then consult incident-response skill.")
def inhibit_recovery(ctx):
    rx = (
        (r"vssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)", "vssadmin_delete_shadows", 70),
        (r"wmic(?:\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.*delete|get-ciminstance\s+win32_shadowcopy.*remove", "wmi_shadowcopy_delete", 70),
        (r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)", "wbadmin_delete", 60),
        (r"bcdedit(?:\.exe)?.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", "bcdedit_disable_recovery", 60),
        (r"reagentc(?:\.exe)?\s+/disable", "winre_disabled", 45),
        (r"diskshadow.*delete\s+shadows", "diskshadow_delete", 60),
    )
    for p in ctx.procs():
        for pat, name, w in rx:
            if re.search(pat, p["cmdline"], re.I):
                yield Candidate(_proc_art(p), _pkey(p), [Signal(name, w)])
                break
    vss = ctx.tel.get("shadow_copies")
    prev = ctx.tel.get("_baseline_shadow_copies")
    if isinstance(vss, int) and isinstance(prev, int) and prev > 0 and vss == 0:
        yield Candidate({"shadow_copies": vss, "baseline": prev}, "vss|count",
                        [Signal("all_shadow_copies_gone_since_baseline", 50)])


@rule("ARG-IM-002", "TA0040", "T1486", "Ransomware artefacts: ransom notes or mass-renamed files with unknown extension",
      "ISOLATE the host now. Do not reboot (keys may be in memory); capture memory if possible, then follow incident-response.")
def ransom(ctx):
    files = ctx.section("files")
    notes = [I.norm_path(f.get("path")) for f in files
             if any(h in I.basename(f.get("path")) for h in I.RANSOM_NOTE_HINTS)]
    if notes:
        yield Candidate({"ransom_notes": notes[:20], "count": len(notes)}, "ransom|notes",
                        [Signal("ransom_note_filenames", 45 if len(notes) < 3 else 70, str(len(notes)))])
    ext = Counter()
    for f in files:
        b = I.basename(f.get("path"))
        if "." in b:
            e = "." + b.rsplit(".", 1)[-1]
            if e not in I.KNOWN_BENIGN_EXT and 3 <= len(e) <= 12:
                ext[e] += 1
    for e, n in ext.most_common(3):
        if n >= 50:
            yield Candidate({"extension": e, "count": n}, f"ransom|ext|{e}",
                            [Signal("mass_unknown_extension", 40 if n < 200 else 65, f"{e} x{n}")])


@rule("ARG-IM-003", "TA0040", "T1489", "Mass stop/disable of security, backup or database services",
      "Check which services stopped (7036/7040); combined with T1490 this is a ransomware pre-encryption pattern.")
def svc_stop(ctx):
    rx = re.compile(r"(?:net|sc)(?:\.exe)?\s+(?:stop|config\s+\S+\s+start=\s*disabled)\s+\"?(\S+)|"
                    r"stop-service\s+(?:-name\s+)?\"?(\S+)|taskkill.*?/im\s+(\S+)", re.I)
    targets = defaultdict(list)
    for p in ctx.procs():
        for m in rx.finditer(p["cmdline"]):
            t = next(g for g in m.groups() if g)
            targets[(p["ppid"], p["parent_name"])].append(t.lower().strip('"'))
    sensitive = re.compile(r"vss|sql|backup|veeam|sophos|defend|windefend|msmpeng|mbam|malware|wbengine|"
                           r"mysql|oracle|exchange|acronis|shadow|eset|kaspersky|avast|bitdefender", re.I)
    for (ppid, pname), ts in targets.items():
        hits = [t for t in ts if sensitive.search(t)]
        if len(hits) >= 2 or len(ts) >= 5:
            yield Candidate({"parent": pname, "parent_pid": ppid, "targets": ts[:30]}, f"svcstop|{pname}|{','.join(sorted(set(ts)))[:200]}",
                            [Signal("mass_service_stop", 30 + 5 * min(len(hits), 6), ",".join(hits[:10]))])


@rule("ARG-IM-004", "TA0040", "T1496", "Cryptominer indicators (resource hijacking)",
      "Kill only via incident-response opt-in; find how it persists (tasks/services) first.")
def miner(ctx):
    for p in ctx.procs():
        low = (p["name"] + " " + p["cmdline"]).lower()
        hits = [h for h in I.MINER_HINTS if h in low]
        if hits:
            sigs = [Signal("miner_keyword", 45, ",".join(hits))]
            if I.path_risk(p["path"])[1]:
                sigs.append(Signal("miner_in_user_path", 15))
            yield Candidate(_proc_art(p), _pkey(p), sigs)
    for c in _net(ctx):
        try:
            rport = int(c.get("rport") or 0)
        except (TypeError, ValueError):
            continue
        if rport in (3333, 7777, 14444, 45700) and I.is_public_ip(c.get("remote")):
            yield Candidate({"process": c.get("process"), "remote": c.get("remote"), "rport": rport},
                            f"minerport|{c.get('process')}|{c.get('remote')}", [Signal("mining_pool_port", 20, str(rport))])


@rule("ARG-IM-005", "TA0040", "T1485", "Data destruction commands (cipher /w, sdelete, format, mass del)",
      "Check what path was targeted; cipher /w after encryption is used to wipe free space.")
def destruction(ctx):
    rx = re.compile(r"cipher(?:\.exe)?\s+/w:|sdelete(?:64)?(?:\.exe)?\s|format(?:\.com)?\s+[a-z]:\s*/q|"
                    r"del\s+/[sfq].*\s+[a-z]:\\\*|remove-item.*-recurse.*-force.*[a-z]:\\\s*$", re.I)
    for p in ctx.procs():
        if rx.search(p["cmdline"]):
            yield Candidate(_proc_art(p), _pkey(p), [Signal("destructive_command", 45)])


# ---------------------------------------------------------------------------
def covered_techniques() -> dict[str, set[str]]:
    """technique -> set(tactics) for every technique a rule can emit (approx: default + overrides in source)."""
    out: dict[str, set[str]] = defaultdict(set)
    for r in RULES:
        out[r.technique].add(r.tactic)
    for tech, tac in _EXTRA_EMITS:
        out[tech].add(tac)
    return out


# sub-techniques emitted via Candidate.technique overrides
_EXTRA_EMITS = [
    ("T1218.005", "TA0005"), ("T1218.011", "TA0005"), ("T1218.010", "TA0005"), ("T1105", "TA0011"),
    ("T1140", "TA0005"), ("T1197", "TA0005"), ("T1127.001", "TA0005"), ("T1218.004", "TA0005"),
    ("T1218.009", "TA0005"), ("T1218.003", "TA0005"), ("T1218.007", "TA0005"), ("T1218.001", "TA0005"),
    ("T1220", "TA0005"), ("T1202", "TA0005"), ("T1003.003", "TA0006"), ("T1218.008", "TA0005"),
    ("T1546.008", "TA0003"), ("T1546.009", "TA0003"), ("T1098", "TA0003"), ("T1036", "TA0005"),
    ("T1555.004", "TA0006"), ("T1113", "TA0009"), ("T1115", "TA0009"), ("T1565.001", "TA0040"),
    ("T1048", "TA0010"),
]
