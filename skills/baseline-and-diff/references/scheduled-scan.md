# Scheduled scan design

```
Task "ARGUS\ScheduledHunt" (SYSTEM, highest privileges, daily + at logon +15 min)
  └─ powershell -NoProfile -ExecutionPolicy RemoteSigned -File Invoke-ArgusScan.ps1 -Preset quick
       1. Collect-Telemetry.ps1   (read-only)            → %ProgramData%\ARGUS\telemetry
       2. python -I argus_cli.py hunt --baseline latest  → %ProgramData%\ARGUS\reports  (JSON, MD, Navigator)
       3. exit code 2 (high/critical) → Application event log source "ARGUS" id 4100 + optional toast
       4. retention: keep last 30 telemetry files / 90 reports
```

- Python discovery: `py -3` launcher, then `python`. Python must be installed for all users (SYSTEM).
- `%ProgramData%\ARGUS` ACL: Administrators + SYSTEM full, Users read — telemetry contains command lines.
- Online intel stays **off** in scheduled mode unless the user sets `ARGUS_INTEL_ONLINE=1` machine-wide
  *and* provides keys; the scan logs which hashes (if any) were sent.
- Remove: `Unregister-ScheduledTask -TaskName ScheduledHunt -TaskPath \ARGUS\`.
