---
description: Create (or refresh) the known-good baseline of this PC and optionally register the scheduled scan
argument-hint: "[--schedule HH:MM]"
---

# /hunt.baseline

1. `scope-discipline` + `baseline-and-diff`.
2. Collect full telemetry (read-only), then review every finding:
   `python -I engine/argus_cli.py hunt --input <telemetry.json> --preset new-machine-baseline`
3. **Only if** the user confirms nothing is malicious (no open high/critical):
   `python -I engine/argus_cli.py baseline --input <telemetry.json> --out-dir "%ProgramData%\ARGUS\baseline" --name baseline-<yyyymmdd>.json`
4. If `$ARGUMENTS` contains `--schedule`, show the dry run, then (user approval) register:
   `powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\baseline-and-diff\scripts\Register-ArgusScheduledScan.ps1 -Preset quick -Time <HH:MM> -Register`

Never baseline a machine with unresolved high/critical findings.

Arguments: $ARGUMENTS
