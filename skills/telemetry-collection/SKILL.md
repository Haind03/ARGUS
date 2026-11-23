---
name: telemetry-collection
description: Use when you need raw host telemetry from the user's own Windows PC before any hunt — processes, autoruns, tasks, services, WMI, network, DNS, Defender, registry policy, event logs (Security/Sysmon/PowerShell), recent files — or need to enable Sysmon/PowerShell logging or use osquery cross-platform.
---

# Telemetry collection (data layer)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. The collector is
> **read-only** — it never writes registry, stops services or deletes files. Output stays local.

## When to use
First step of every hunt (`/hunt.quick`, `/hunt.full`, `/hunt.baseline`) or when a finding needs fresh data.

## Collect
```powershell
# elevated prompt recommended (Security log, Sysmon, WMI subscriptions, Defender exclusions, BITS)
powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\telemetry-collection\scripts\Collect-Telemetry.ps1 -Sections all -EventHours 168 -HashProcesses
```
Output: `%ProgramData%\ARGUS\telemetry\telemetry-<HOST>-<ts>.json` (or `%LOCALAPPDATA%` if not elevated),
schema `argus.telemetry/1` — see [references/telemetry-schema.md](references/telemetry-schema.md).
Rights problems are recorded in `collection_errors`; **always report them as collection gaps**.

## Improve visibility (recommended, user opt-in — changes system config)
| Source | Why | Reference |
|---|---|---|
| Sysmon (SwiftOnSecurity / olafhartong modular config) | process tree w/ hashes, network, LSASS access, DNS | [sysmon-setup.md](references/sysmon-setup.md) |
| PowerShell Script Block Logging (4104) | decoded PowerShell | [windows-logging-setup.md](references/windows-logging-setup.md) |
| Process creation auditing 4688 + command line | fallback when no Sysmon | same |
| osquery | cross-platform (macOS/Linux) collection | [osquery.md](references/osquery.md), `scripts/osquery_to_argus.py` |

These change logging configuration, so suggest them — do not apply them silently.

## Scripts
- `scripts/Collect-Telemetry.ps1` — main collector (PowerShell 5.1+, no dependencies).
- `scripts/Enable-ArgusLogging.ps1` — opt-in: enables 4688 cmdline + 4104 logging (`-WhatIf` default).
- `scripts/osquery_to_argus.py` — convert `osqueryi --json` results to the ARGUS schema (`python -I`).
- `scripts/argus-osquery-pack.conf` — osquery pack with the same artefact coverage.
