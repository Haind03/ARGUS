---
name: persistence-hunting
description: Use when you need to find how malware SURVIVES REBOOT: Run keys, Startup folder, scheduled tasks, services, WMI subscriptions, IFEO/accessibility backdoors, Winlogon, AppInit, BITS, COM hijack, new accounts, browser extensions on the user's own Windows PC (MITRE ATT&CK TA0003 Persistence).
---

# Persistence hunting (TA0003)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find how malware SURVIVES REBOOT: Run keys, Startup folder, scheduled tasks, services, WMI subscriptions, IFEO/accessibility backdoors, Winlogon, AppInit, BITS, COM hijack, new accounts, browser extensions. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\persistence-hunting\scripts\Collect-Persistence.ps1
   ```
   (wraps `telemetry-collection` with sections: `autoruns,scheduled_tasks,services,wmi,registry,bits,users,browser,com,events`)
2. **Detect / score**:
   ```bash
   python -I skills/persistence-hunting/scripts/hunt_persistence_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1547.001` | Boot or Logon Autostart: Registry Run Keys / Startup Folder | [T1547.001-boot-or-logon-autostart-registry-run-keys-startup-folder.md](references/T1547.001-boot-or-logon-autostart-registry-run-keys-startup-folder.md) | ARG-PE-001 |
| `T1053.005` | Scheduled Task/Job: Scheduled Task | [T1053.005-scheduled-task-job-scheduled-task.md](references/T1053.005-scheduled-task-job-scheduled-task.md) | ARG-PE-002 |
| `T1543.003` | Create or Modify System Process: Windows Service | [T1543.003-create-or-modify-system-process-windows-service.md](references/T1543.003-create-or-modify-system-process-windows-service.md) | ARG-PE-003, ARG-PE-004 |
| `T1546.003` | Event Triggered Execution: WMI Event Subscription | [T1546.003-event-triggered-execution-wmi-event-subscription.md](references/T1546.003-event-triggered-execution-wmi-event-subscription.md) | ARG-PE-005 |
| `T1546.012` | Event Triggered Execution: Image File Execution Options Injection | [T1546.012-event-triggered-execution-image-file-execution-options-injec.md](references/T1546.012-event-triggered-execution-image-file-execution-options-injec.md) | ARG-PE-006 |
| `T1546.008` | Event Triggered Execution: Accessibility Features | [T1546.008-event-triggered-execution-accessibility-features.md](references/T1546.008-event-triggered-execution-accessibility-features.md) | ARG-PE-006 |
| `T1547.004` | Boot or Logon Autostart: Winlogon Helper DLL | [T1547.004-boot-or-logon-autostart-winlogon-helper-dll.md](references/T1547.004-boot-or-logon-autostart-winlogon-helper-dll.md) | ARG-PE-007 |
| `T1546.010` | Event Triggered Execution: AppInit DLLs (and T1546.009 AppCert DLLs) | [T1546.010-event-triggered-execution-appinit-dlls-and-t1546-009-appcert.md](references/T1546.010-event-triggered-execution-appinit-dlls-and-t1546-009-appcert.md) | ARG-PE-008 |
| `T1197` | BITS Jobs | [T1197-bits-jobs.md](references/T1197-bits-jobs.md) | ARG-PE-009 |
| `T1136.001` | Create Account: Local Account (+T1098 admin group add) | [T1136.001-create-account-local-account-t1098-admin-group-add.md](references/T1136.001-create-account-local-account-t1098-admin-group-add.md) | ARG-PE-010 |
| `T1546.015` | Event Triggered Execution: Component Object Model Hijacking | [T1546.015-event-triggered-execution-component-object-model-hijacking.md](references/T1546.015-event-triggered-execution-component-object-model-hijacking.md) | ARG-PE-011 |
| `T1176` | Browser Extensions | [T1176-browser-extensions.md](references/T1176-browser-extensions.md) | ARG-PE-012 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
