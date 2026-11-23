---
description: Hunt persistence (TA0003) — Run keys, Startup, tasks, services, WMI, IFEO, Winlogon, AppInit, BITS, COM, accounts, extensions
argument-hint: "[telemetry.json] [--baseline baseline.json]"
---

# /hunt.persistence

1. `scope-discipline`, then load `persistence-hunting` (and `baseline-and-diff` if a baseline exists).
2. Collect if needed: `powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\persistence-hunting\scripts\Collect-Persistence.ps1`
3. Detect: `python -I skills/persistence-hunting/scripts/hunt_persistence_hunting.py --input <telemetry.json> [--baseline <b.json>]`
4. Also run `python -I engine/argus_cli.py diff --baseline <b.json> --input <telemetry.json>` for anything new since baseline.
5. Validate each entry with the matching `references/T*.md`; report entries with location, target, signer, ATT&CK ID.
   Removal only through `incident-response` (opt-in).

Arguments: $ARGUMENTS
