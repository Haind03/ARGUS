"""Action guard, the fail-closed safety core of the ARGUS harness.

Classifies a shell command (PowerShell / cmd / bash) as:
  read        : inspection only                              -> allow
  collect     : writes only ARGUS output (case dir, reports)  -> allow
  egress      : sends data off-host (intel lookups, uploads)  -> ask unless ARGUS_INTEL_ONLINE=1
  config      : changes logging/visibility config (opt-in)    -> ask
  destructive : kills/deletes/quarantines/changes security    -> DENY unless a valid IR opt-in exists,
                                                                 then ASK (a human still confirms each one)
Fail-closed: anything unparsable that touches a destructive verb is treated as destructive.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path

DESTRUCTIVE = [
    (r"\bremove-item\b|\brm\s+-|\brmdir\b|\bdel\s|\berase\s|\brd\s+/s", "file deletion"),
    (r"\bstop-process\b|\btaskkill\b|\bkill\s+-?\d|\bpkill\b", "process termination"),
    (r"\breg(?:\.exe)?\s+(?:delete|add|import)\b|\bremove-itemproperty\b|\bset-itemproperty\b|\bnew-itemproperty\b", "registry change"),
    (r"\bsc(?:\.exe)?\s+(?:delete|stop|config)\b|\bstop-service\b|\bset-service\b|\bremove-service\b", "service change"),
    (r"\bschtasks(?:\.exe)?\s+/(?:delete|change)\b|\bunregister-scheduledtask\b|\bdisable-scheduledtask\b", "scheduled task change"),
    (r"\bset-mppreference\b|\badd-mppreference\b|\bremove-mppreference\b", "Defender configuration change"),
    (r"\bnetsh\b.*\b(?:advfirewall|firewall)\b.*\b(?:set|add|delete)\b|\bset-netfirewall\w*\b|\bnew-netfirewallrule\b", "firewall change"),
    (r"\bdisable-netadapter\b|\bnetsh\s+interface\s+set\b", "network isolation"),
    (r"\bvssadmin\b.*\b(?:delete|resize|create)\b|\bwbadmin\b.*\b(?:delete|start)\b|\bbcdedit\b.*/(?:set|delete|deletevalue|import)\b|"
     r"\breagentc\b.*/(?:disable|enable)\b|\bcipher(?:\.exe)?\s+/w\b|\bformat(?:\.com)?\s+[a-z]:", "recovery/disk change"),
    (r"\bremove-wmiobject\b|\bremove-ciminstance\b|\bwmic\b.*\bdelete\b", "WMI object deletion"),
    (r"\bmove-item\b.*\bquarantine\b|\binvoke-argusresponse\b.*-execute\b", "ARGUS incident-response action"),
    (r"\bremove-localuser\b|\bdisable-localuser\b|\bnet\s+user\s+\S+\s+/(?:delete|active:no)\b", "account change"),
    (r"\bshutdown(?:\.exe)?\b|\brestart-computer\b|\bstop-computer\b", "power state change"),
    (r"\bicacls\b.*\s/(?:deny|remove|grant|setowner|reset|inheritance)\b|\btakeown\b", "ACL change"),
    (r"\bgit\s+push\b.*--force|\bgit\s+reset\s+--hard\b", "destructive git"),
]
EGRESS = [
    (r"virustotal\.com|mb-api\.abuse\.ch|threatfox|urlhaus|hybrid-analysis|any\.run|triage\.ge", "threat-intel lookup"),
    (r"\binvoke-(?:webrequest|restmethod)\b.*-method\s+(?:post|put)|"
     r"\bcurl(?:\.exe)?\b.*(?:\s-t\s|--upload-file|\s-f\s|--data|--form)", "upload"),
    (r"(?:^|\s)--online\b", "ARGUS online enrichment"),
]
# NOTE: input is lower-cased before matching; never put \b directly before '-' or '/'.
CONFIG = [
    (r"\bauditpol\b.*\s/set\b|\bwevtutil\s+sl\b|enable-arguslogging\.ps1.*-apply|sysmon(?:64)?(?:\.exe)?\s+-(?:i|c|u)\b", "logging configuration"),
    (r"register-argusscheduledscan\.ps1.*-register|register-scheduledtask", "scheduled scan registration"),
    (r"invoke-argusmemorydump\.ps1.*-acquire|start-arguspacketcapture\.ps1.*-capture", "acquisition (writes large sensitive files)"),
]


def classify(command: str) -> tuple[str, str]:
    c = (command or "").lower()
    if "-whatif" in c and not re.search(r"-whatif:\s*\$?false", c):
        return ("read", "dry run (-WhatIf)")
    for rx, why in DESTRUCTIVE:
        if re.search(rx, c):
            # ARGUS-owned output housekeeping is allowed (case dir / reports retention)
            if why == "file deletion" and re.search(r"argus[\\/](?:telemetry|reports|cases)[\\/]", c) and ".." not in c:
                return ("collect", "ARGUS output housekeeping")
            return ("destructive", why)
    for rx, why in EGRESS:
        if re.search(rx, c):
            return ("egress", why)
    for rx, why in CONFIG:
        if re.search(rx, c):
            return ("config", why)
    return ("read", "no state-changing verb detected")


def _ir_optin(case_dir: Path | None) -> dict | None:
    if not case_dir:
        return None
    p = case_dir / "case.json"
    if not p.is_file() or p.is_symlink():
        return None
    try:
        case = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    opt = case.get("ir_optin") or {}
    exp = opt.get("expires_at")
    try:
        if not exp or _dt.datetime.fromisoformat(exp) < _dt.datetime.now(_dt.timezone.utc):
            return None
    except ValueError:
        return None
    return opt


def decide(command: str, case_dir: Path | None = None) -> tuple[str, str]:
    """Return (decision, reason) where decision in allow|ask|deny."""
    kind, why = classify(command)
    if kind in ("read", "collect"):
        return ("allow", f"{kind}: {why}")
    if kind == "egress":
        if os.environ.get("ARGUS_INTEL_ONLINE") == "1":
            return ("ask", f"egress ({why}): online intel is enabled, confirm only SHA-256 hashes are sent")
        return ("ask", f"egress ({why}): ARGUS is offline-by-default; user must opt in explicitly")
    if kind == "config":
        return ("ask", f"config change ({why}): opt-in action, confirm with the user")
    opt = _ir_optin(case_dir)
    if not opt:
        return ("deny", f"DETECT-ONLY: blocked {why}. Remediation requires an IR opt-in "
                        f"(`argus case optin --case <dir> --minutes 60 --reason ...`) and then per-action confirmation.")
    return ("ask", f"IR opt-in active (by {opt.get('by')}, until {opt.get('expires_at')}): confirm this {why}. "
                   "Capture evidence first (evidence-discipline).")
