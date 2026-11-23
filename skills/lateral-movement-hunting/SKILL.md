---
name: lateral-movement-hunting
description: Use when you need to find LATERAL MOVEMENT into or out of the PC: PsExec/admin-share execution, WinRM remote shells, inbound RDP from other LAN hosts, or remote service creation on the user's own Windows PC (MITRE ATT&CK TA0008 Lateral Movement).
---

# Lateral Movement hunting (TA0008)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find LATERAL MOVEMENT into or out of the PC: PsExec/admin-share execution, WinRM remote shells, inbound RDP from other LAN hosts, or remote service creation. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\lateral-movement-hunting\scripts\Collect-LateralMovement.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,events,services`)
2. **Detect / score**:
   ```bash
   python -I skills/lateral-movement-hunting/scripts/hunt_lateral_movement_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1021.002` | Remote Services: SMB/Windows Admin Shares | [T1021.002-remote-services-smb-windows-admin-shares.md](references/T1021.002-remote-services-smb-windows-admin-shares.md) | ARG-LM-001, ARG-PE-004 |
| `T1021.006` | Remote Services: Windows Remote Management | [T1021.006-remote-services-windows-remote-management.md](references/T1021.006-remote-services-windows-remote-management.md) | ARG-LM-002 |
| `T1021.001` | Remote Services: Remote Desktop Protocol | [T1021.001-remote-services-remote-desktop-protocol.md](references/T1021.001-remote-services-remote-desktop-protocol.md) | ARG-LM-003, ARG-IA-005 |
| `T1570` | Lateral Tool Transfer | [T1570-lateral-tool-transfer.md](references/T1570-lateral-tool-transfer.md) | ARG-LM-001 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
