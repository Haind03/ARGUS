---
description: Quick detect-only sweep (execution, persistence, defense evasion, C2, impact), medium+ findings only
argument-hint: "[telemetry.json]"
---

# /hunt.quick

1. `scope-discipline`: confirm this is the user's own PC.
2. Collect if no telemetry given: `powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\telemetry-collection\scripts\Collect-Telemetry.ps1 -Sections host,processes,autoruns,scheduled_tasks,services,wmi,network,dns,defender,registry -EventHours 24`
3. Score: `python -I engine/argus_cli.py hunt --input <telemetry.json> --preset quick [--baseline <latest baseline>] --out-dir argus-reports`
4. Summarise the top findings in plain language with severity, ATT&CK ID and the recommended analyst action.
   State collection gaps. Offer `/hunt.full` if anything is high/critical.

Arguments: $ARGUMENTS
