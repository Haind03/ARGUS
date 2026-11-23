---
name: execution-hunting
description: Use when you need to find malicious code EXECUTION: obfuscated/encoded PowerShell, script hosts (VBS/JS/HTA), LOLBin proxy execution, WMI execution, or binaries running from Temp/AppData on the user's own Windows PC (MITRE ATT&CK TA0002 Execution).
---

# Execution hunting (TA0002)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find malicious code EXECUTION: obfuscated/encoded PowerShell, script hosts (VBS/JS/HTA), LOLBin proxy execution, WMI execution, or binaries running from Temp/AppData. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\execution-hunting\scripts\Collect-Execution.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,events`)
2. **Detect / score**:
   ```bash
   python -I skills/execution-hunting/scripts/hunt_execution_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1059.001` | Command and Scripting Interpreter: PowerShell | [T1059.001-command-and-scripting-interpreter-powershell.md](references/T1059.001-command-and-scripting-interpreter-powershell.md) | ARG-EX-001, ARG-EX-002 |
| `T1059.003` | Command and Scripting Interpreter: Windows Command Shell | [T1059.003-command-and-scripting-interpreter-windows-command-shell.md](references/T1059.003-command-and-scripting-interpreter-windows-command-shell.md) | ARG-IA-001, ARG-C2-002 |
| `T1059.005` | Command and Scripting Interpreter: Visual Basic | [T1059.005-command-and-scripting-interpreter-visual-basic.md](references/T1059.005-command-and-scripting-interpreter-visual-basic.md) | ARG-EX-003 |
| `T1218` | System Binary Proxy Execution | [T1218-system-binary-proxy-execution.md](references/T1218-system-binary-proxy-execution.md) | ARG-EX-004 |
| `T1047` | Windows Management Instrumentation | [T1047-windows-management-instrumentation.md](references/T1047-windows-management-instrumentation.md) | ARG-EX-005, ARG-EX-004 |
| `T1053.005` | Scheduled Task/Job: Scheduled Task (execution) | [T1053.005-scheduled-task-job-scheduled-task-execution.md](references/T1053.005-scheduled-task-job-scheduled-task-execution.md) | ARG-PE-002 |
| `T1204` | User Execution (from Temp/AppData) | [T1204-user-execution-from-temp-appdata.md](references/T1204-user-execution-from-temp-appdata.md) | ARG-EX-006 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
