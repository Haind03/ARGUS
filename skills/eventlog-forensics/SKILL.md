---
name: eventlog-forensics
description: Use when you need deep analysis of Windows EVENT LOGS on the user's own PC (live channels or exported .evtx), logons/RDP, explicit credentials, account changes, scheduled-task creation, audit-policy tampering, Defender detections and disablement, WMI persistence, BITS, Sysmon, PowerShell 4103/4104, scored and placed on a UTC timeline.
---

# Event-log forensics

> **Scope:** logs of the user's own, authorised machine. Export is read-only. Logs may contain user names,
> command lines and script content, keep exports in the case folder.

## Run
```powershell
# live, last 7 days (elevated for Security/Sysmon)
.\skills\eventlog-forensics\scripts\Export-ArgusEvents.ps1 -Hours 168 -OutFile E:\case01\events.json
# offline .evtx (copied from C:\Windows\System32\winevt\Logs or another disk)
.\skills\eventlog-forensics\scripts\Export-ArgusEvents.ps1 -EvtxPath E:\case01\evtx\*.evtx -OutFile E:\case01\events.json
```
```bash
python -I skills/eventlog-forensics/scripts/evtx_hunt.py --input E:\case01\events.json --out-dir E:\case01\evtx
```
Runs all engine rules that consume events **plus** log analytics `ARG-EL-001…015`. Outputs
`eventlog-findings.json`, `eventlog-timeline.json`, logon summary and per-ID event counts
(missing IDs = logging gap → report it).

References: [event-id-cheatsheet.md](references/event-id-cheatsheet.md) · Sigma rules for these IDs live in
`skills/references/sigma/` (convert with sigma-cli if you run a SIEM; ARGUS itself evaluates the Python rules).
