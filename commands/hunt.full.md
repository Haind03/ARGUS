---
description: Full hypothesis-driven ATT&CK hunt of this PC (all host-observable tactics) via the ARGUS harness
argument-hint: "[telemetry.json] [--baseline baseline.json]"
---

# /hunt.full

Run a full, detect-only hunt of the user's **own** Windows PC through `workflows/full-hunt.yml`.

1. Load `using-argus`, then `scope-discipline` — confirm ownership; stop if not confirmed.
2. Load `hunt-methodology`.
3. If no telemetry path was given in `$ARGUMENTS`, collect it (read-only; elevated prompt recommended):
   `powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\telemetry-collection\scripts\Collect-Telemetry.ps1 -Sections all -EventHours 168 -HashProcesses`
4. Open a case and run the workflow:
   ```
   python -I engine/argus_cli.py case init --name <host-yyyymmdd> --i-own-this-machine
   python -I engine/argus_cli.py case run --case argus-cases/<host-yyyymmdd> --input <telemetry.json> --workflow full-hunt [--baseline <baseline.json>]
   ```
5. For each phase with `supported — investigate`, load that phase's skill and validate the top findings
   (`false-positive-discipline`); go deeper with analysis skills per `hunt-methodology` depth triggers.
6. Dispose every high/critical finding (`case dispose`), then `/hunt.report`.
7. Never remediate. If the user wants containment, explain `incident-response` (opt-in) and stop.

Arguments: $ARGUMENTS
