#!/usr/bin/env python3
"""Event-log forensics over argus.telemetry/1 'events' (from Export-ArgusEvents.ps1 or the main collector).

  python -I evtx_hunt.py --input events.json --out-dir case/evtx

1. Runs every ARGUS engine rule that consumes events (process creation, 4104, 7045, 1102, Sysmon 8/10/22...).
2. Adds log-specific analytics: logon summary, explicit-credential logons (4648), scheduled-task creation (4698/4702), audit-policy change (4719),
   account changes (4722/4724/4738/4740), Defender detections & tamper (1116/1117/5001/5007/5010/5012),
   WMI persistence (5861), RDP sessions (TS 21/22/25), BITS jobs (59/60), Kerberos anomalies (4769 RC4).
3. Writes a merged findings file + a UTC timeline.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import indicators as I  # noqa: E402
from argus.hunt import run_rules  # noqa: E402
from argus.rules import cmdline_signals  # noqa: E402
from argus.safeio import load_json, safe_child, safe_output_dir, write_json  # noqa: E402
from argus.scoring import Finding, Signal  # noqa: E402

SYSTEM_ACCOUNTS = re.compile(r"^(system|local service|network service|dwm-\d+|umfd-\d+|.*\$)$", re.I)


def ev(events, log_sub, *ids):
    for e in events:
        try:
            if int(e.get("id", -1)) in ids and log_sub.lower() in str(e.get("log", "")).lower():
                yield e, e.get("data") or {}
        except (TypeError, ValueError):
            continue


def analytics(events: list[dict]) -> tuple[list[Finding], dict]:
    F: list[Finding] = []

    def add(rid, title, tac, tech, art, key, sigs, action):
        f = Finding(rid, title, tac, tech, art, key, sigs, action).finalize()
        if f.score >= 20:
            F.append(f)

    logons = Counter()
    for e, d in ev(events, "security", 4624):
        logons[(d.get("TargetUserName"), str(d.get("LogonType")), d.get("IpAddress") or "-")] += 1
    summary = {"logons": [{"user": u, "type": t, "source": s, "count": n} for (u, t, s), n in logons.most_common(50)]}

    for e, d in ev(events, "security", 4648):
        tgt = str(d.get("TargetServerName") or "")
        proc = I.basename(d.get("ProcessName"))
        if tgt.lower() not in ("localhost", "", "-") and proc not in ("lsass.exe", "svchost.exe", "consent.exe"):
            add("ARG-EL-001", "Explicit-credential logon to another host (4648)", "TA0008", "T1078",
                {"user": d.get("SubjectUserName"), "as": d.get("TargetUserName"), "target": tgt, "process": proc,
                 "time": e.get("time")}, f"4648|{d.get('TargetUserName')}|{tgt}|{proc}",
                [Signal("runas_to_remote_host", 25, tgt)] + ([Signal("by_script_host", 15, proc)] if proc in I.SCRIPTISH else []),
                "Check whether the user ran runas/net use; credential reuse is a lateral-movement sign.")
    for e, d in ev(events, "security", 4698, 4702):
        xml = str(d.get("TaskContent") or d.get("TaskContentNew") or "")
        cmds = re.findall(r"<Command>(.*?)</Command>", xml, re.S)
        args_ = re.findall(r"<Arguments>(.*?)</Arguments>", xml, re.S)
        cmd = " ".join(cmds + args_).strip()
        n, w = I.path_risk(I.extract_exe_path(cmd))
        sigs = [Signal("task_created_or_updated", 10, d.get("TaskName"))] + cmdline_signals(cmd)
        if w:
            sigs.append(Signal("task_action_" + n, w))
        if re.search(r"powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32", cmd, re.I):
            sigs.append(Signal("task_runs_script_host", 20))
        add("ARG-EL-003", "Scheduled task created/updated (4698/4702)", "TA0003", "T1053.005",
            {"task": d.get("TaskName"), "by": d.get("SubjectUserName"), "command": cmd[:500], "time": e.get("time")},
            f"4698|{d.get('TaskName')}|{cmd[:120]}", sigs, "Export task XML; check the action binary.")
    for e, d in ev(events, "security", 4719):
        add("ARG-EL-004", "Audit policy changed (4719)", "TA0005", "T1562.002",
            {"by": d.get("SubjectUserName"), "subcategory": d.get("SubcategoryGuid"), "changes": d.get("AuditPolicyChanges"),
             "time": e.get("time")}, f"4719|{e.get('time')}", [Signal("audit_policy_changed", 35)],
            "Logging may have been reduced to hide activity; compare with auditpol /get /category:*.")
    for e, d in ev(events, "security", 4722, 4724, 4738):
        add("ARG-EL-005", "Account enabled / password reset / account changed", "TA0003", "T1098",
            {"event": e.get("id"), "target": d.get("TargetUserName"), "by": d.get("SubjectUserName"), "time": e.get("time")},
            f"acct|{e.get('id')}|{d.get('TargetUserName')}", [Signal("account_modified", 20)],
            "Confirm with the user (Guest/Administrator enable is a classic backdoor).")
    fails = Counter(d.get("TargetUserName") for e, d in ev(events, "security", 4740))
    for u, n in fails.items():
        add("ARG-EL-006", "Account lockout (4740)", "TA0006", "T1110", {"user": u, "count": n}, f"4740|{u}",
            [Signal("account_lockout", 20 + min(20, n * 5))], "Correlate with 4625 sources.")
    for e, d in ev(events, "security", 4769):
        if str(d.get("TicketEncryptionType", "")).lower() in ("0x17", "0x18") and not str(d.get("ServiceName", "")).endswith("$"):
            add("ARG-EL-007", "Kerberos service ticket with RC4 (possible Kerberoasting)", "TA0006", "T1558.003",
                {"service": d.get("ServiceName"), "user": d.get("TargetUserName"), "ip": d.get("IpAddress")},
                f"4769|{d.get('ServiceName')}|{d.get('TargetUserName')}", [Signal("rc4_service_ticket", 35)],
                "Domain-joined PCs only; check the requesting process.")
    for e, d in ev(events, "defender", 1116, 1117, 1006, 1007):
        add("ARG-EL-010", "Microsoft Defender detection", "TA0002", "T1204",
            {"threat": d.get("Threat Name"), "path": d.get("Path"), "action": d.get("Action Name"),
             "severity": d.get("Severity Name"), "time": e.get("time")},
            f"def|{d.get('Threat Name')}|{d.get('Path')}",
            [Signal("defender_detection", 40 if e.get("id") in (1116, 1006) else 25, d.get("Threat Name"))],
            "Check whether remediation succeeded (1117/1008) and hunt for what dropped it.")
    for e, d in ev(events, "defender", 5001, 5010, 5012):
        add("ARG-EL-011", "Defender protection component disabled", "TA0005", "T1562.001",
            {"event": e.get("id"), "time": e.get("time")}, f"defoff|{e.get('id')}|{e.get('time')}",
            [Signal("defender_component_disabled", 45)], "Who disabled it? Correlate with process events at that time.")
    for e, d in ev(events, "defender", 5007):
        new = str(d.get("New Value") or "")
        if re.search(r"\\exclusions\\|disable|tamper", new, re.I):
            add("ARG-EL-012", "Defender configuration changed (exclusion / disable)", "TA0005", "T1562.001",
                {"new": new[:300], "old": str(d.get("Old Value") or "")[:300], "time": e.get("time")},
                f"def5007|{new[:120]}", [Signal("defender_config_weakened", 40)], "Verify the user made this change.")
    for e, d in ev(events, "wmi", 5861):
        add("ARG-EL-013", "WMI permanent event consumer registered (5861)", "TA0003", "T1546.003",
            {"details": str(d)[:600], "time": e.get("time")}, f"5861|{e.get('time')}",
            [Signal("wmi_consumer_registered", 45)], "Export root\\subscription objects.")
    for e, d in ev(events, "terminalservices", 21, 25):
        src = str(d.get("Address") or "")
        if src and src not in ("LOCAL", "127.0.0.1", "::1"):
            add("ARG-EL-014", "RDP session logon/reconnect", "TA0008", "T1021.001",
                {"user": d.get("User"), "source": src, "time": e.get("time")}, f"ts|{d.get('User')}|{src}",
                [Signal("rdp_session", 20 + (20 if I.is_public_ip(src) else 0), src)], "Confirm the user expected it.")
    for e, d in ev(events, "bits", 59, 60):
        url = str(d.get("url") or d.get("Url") or "")
        if url and not re.search(r"(microsoft|windowsupdate|msedge|office|google|adobe|mozilla)\.(com|net)", url, re.I):
            add("ARG-EL-015", "BITS transfer from non-vendor URL", "TA0011", "T1197",
                {"job": d.get("name"), "url": url[:300], "time": e.get("time")}, f"bits|{url[:150]}",
                [Signal("bits_non_vendor_url", 30)], "Check destination file; BITS is a stealthy downloader.")
    return F, summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out-dir")
    a = ap.parse_args()
    tel = load_json(a.input)
    events = [e for e in (tel.get("events") or []) if isinstance(e, dict)]
    engine = run_rules({"events": events, "host": tel.get("host", {})}, {"min_score": 20})
    extra, summary = analytics(events)
    allf = sorted(engine + extra, key=lambda f: -f.score)
    timeline = sorted(({"time": e.get("time"), "log": e.get("log"), "id": e.get("id")} for e in events),
                      key=lambda x: str(x["time"]))
    by_id = Counter(f"{e.get('log')}/{e.get('id')}" for e in events)
    res = {"schema": "argus.findings/1", "source": "eventlog-forensics", "mode": "detect-only",
           "summary": {"events": len(events), "total": len(allf), "event_counts": dict(by_id.most_common(60)), **summary},
           "collection_gaps": tel.get("collection_errors") or [], "findings": [f.to_dict() for f in allf]}
    if a.out_dir:
        out = safe_output_dir(a.out_dir)
        write_json(safe_child(out, "eventlog-findings.json"), res)
        write_json(safe_child(out, "eventlog-timeline.json"), timeline)
    print(json.dumps({"events": len(events), "findings": len(allf)}))
    for f in res["findings"][:40]:
        print(f"{f['score']:>3} {f['severity']:<8} {f['rule_id']} {f['title']}")


if __name__ == "__main__":
    main()
