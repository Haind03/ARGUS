---
name: privesc-hunting
description: Use when you need to find PRIVILEGE ESCALATION on the PC: UAC bypasses, vulnerable drivers (BYOVD), unquoted service paths, DLL search-order hijacking, or abuse of elevated persistence on the user's own Windows PC (MITRE ATT&CK TA0004 Privilege Escalation).
---

# Privilege Escalation hunting (TA0004)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find PRIVILEGE ESCALATION on the PC: UAC bypasses, vulnerable drivers (BYOVD), unquoted service paths, DLL search-order hijacking, or abuse of elevated persistence. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\privesc-hunting\scripts\Collect-Privesc.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,autoruns,services,drivers,files,events`)
2. **Detect / score**:
   ```bash
   python -I skills/privesc-hunting/scripts/hunt_privesc_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1548.002` | Abuse Elevation Control Mechanism: Bypass UAC | [T1548.002-abuse-elevation-control-mechanism-bypass-uac.md](references/T1548.002-abuse-elevation-control-mechanism-bypass-uac.md) | ARG-PR-001 |
| `T1068` | Exploitation for Privilege Escalation (BYOVD) | [T1068-exploitation-for-privilege-escalation-byovd.md](references/T1068-exploitation-for-privilege-escalation-byovd.md) | ARG-PR-002 |
| `T1574.009` | Hijack Execution Flow: Path Interception by Unquoted Path | [T1574.009-hijack-execution-flow-path-interception-by-unquoted-path.md](references/T1574.009-hijack-execution-flow-path-interception-by-unquoted-path.md) | ARG-PR-003 |
| `T1574.001` | Hijack Execution Flow: DLL Search Order Hijacking / Side-Loading (T1574.002) | [T1574.001-hijack-execution-flow-dll-search-order-hijacking-side-loadin.md](references/T1574.001-hijack-execution-flow-dll-search-order-hijacking-side-loadin.md) | ARG-PR-004 |
| `T1543.003` | Create or Modify System Process: Windows Service (as SYSTEM) | [T1543.003-create-or-modify-system-process-windows-service-as-system.md](references/T1543.003-create-or-modify-system-process-windows-service-as-system.md) | ARG-PE-003, ARG-PE-004 |
| `T1546.008` | Accessibility features (SYSTEM at logon screen) | [T1546.008-accessibility-features-system-at-logon-screen.md](references/T1546.008-accessibility-features-system-at-logon-screen.md) | ARG-PE-006 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
