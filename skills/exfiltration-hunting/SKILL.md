---
name: exfiltration-hunting
description: Use when you need to find DATA EXFILTRATION: rclone/MEGA uploads, curl/PowerShell file uploads, large outbound transfers, or exfil over web services on the user's own Windows PC (MITRE ATT&CK TA0010 Exfiltration).
---

# Exfiltration hunting (TA0010)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find DATA EXFILTRATION: rclone/MEGA uploads, curl/PowerShell file uploads, large outbound transfers, or exfil over web services. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\exfiltration-hunting\scripts\Collect-Exfiltration.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,network,files`)
2. **Detect / score**:
   ```bash
   python -I skills/exfiltration-hunting/scripts/hunt_exfiltration_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1567.002` | Exfiltration Over Web Service: Exfiltration to Cloud Storage | [T1567.002-exfiltration-over-web-service-exfiltration-to-cloud-storage.md](references/T1567.002-exfiltration-over-web-service-exfiltration-to-cloud-storage.md) | ARG-EF-001 |
| `T1048` | Exfiltration Over Alternative Protocol | [T1048-exfiltration-over-alternative-protocol.md](references/T1048-exfiltration-over-alternative-protocol.md) | ARG-EF-001 |
| `T1041` | Exfiltration Over C2 Channel | [T1041-exfiltration-over-c2-channel.md](references/T1041-exfiltration-over-c2-channel.md) | ARG-EF-002 |
| `T1567` | Exfiltration Over Web Service (webhooks) | [T1567-exfiltration-over-web-service-webhooks.md](references/T1567-exfiltration-over-web-service-webhooks.md) | ARG-C2-006 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic, never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
