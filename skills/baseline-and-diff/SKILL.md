---
name: baseline-and-diff
description: Use when creating a known-good baseline of the user's own PC, comparing a new scan against it to surface new autoruns/tasks/services/drivers/WMI/Defender exclusions/admins, reducing false positives in scheduled scans, or installing the ARGUS scheduled scan in Windows Task Scheduler.
---

# Baseline & diff (data layer)

> **Scope:** the user's own, authorised machine only. Creating a baseline and registering a scheduled
> scan are explicit user actions — never do either silently.

## Why
Heuristics alone are noisy on a real PC. A baseline captured when the machine is believed clean lets
scheduled scans (1) down-weight known findings (score × 0.3, still visible) and (2) flag **new**
persistence-class artefacts even when no heuristic fires.

## Create a baseline (after a reviewed, clean hunt)
```bash
python -I engine/argus_cli.py hunt --input telemetry.json --preset new-machine-baseline
# analyst reviews every finding; only if nothing is malicious:
python -I engine/argus_cli.py baseline --input telemetry.json --out-dir %ProgramData%\ARGUS\baseline
```
**Never baseline a host with open high/critical findings** — you would whitelist the intrusion.

## Diff
```bash
python -I engine/argus_cli.py diff --baseline baseline.json --input new-telemetry.json
python -I engine/argus_cli.py hunt --input new-telemetry.json --baseline baseline.json --preset quick
```
Inventory categories: autoruns, scheduled_tasks, services, drivers, wmi_subscriptions, listening_ports,
local_admins, browser_extensions, process_images, defender_exclusions. See [references/baseline-model.md](references/baseline-model.md).

## Scheduled scan (Task Scheduler)
```powershell
# dry run shows the task definition; -Register creates it (elevated)
powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\baseline-and-diff\scripts\Register-ArgusScheduledScan.ps1 -Preset quick -Time 12:30 -Register
```
The task runs `scripts/Invoke-ArgusScan.ps1` as SYSTEM: collect → hunt with baseline → write reports to
`%ProgramData%\ARGUS\reports` → Windows toast/event log entry on high/critical. Detect-only; it never remediates.
Details: [references/scheduled-scan.md](references/scheduled-scan.md).
