---
name: impact-hunting
description: Use when you need to find DESTRUCTIVE IMPACT or its precursors: ransomware (shadow-copy deletion, recovery disabled, mass service stop, ransom notes, mass renamed files), wipers, or cryptominers on the user's own Windows PC (MITRE ATT&CK TA0040 Impact).
---

# Impact hunting (TA0040)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find DESTRUCTIVE IMPACT or its precursors: ransomware (shadow-copy deletion, recovery disabled, mass service stop, ransom notes, mass renamed files), wipers, or cryptominers. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\impact-hunting\scripts\Collect-Impact.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,files,events,shadow_copies,services,network`)
2. **Detect / score**:
   ```bash
   python -I skills/impact-hunting/scripts/hunt_impact_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1490` | Inhibit System Recovery | [T1490-inhibit-system-recovery.md](references/T1490-inhibit-system-recovery.md) | ARG-IM-001 |
| `T1486` | Data Encrypted for Impact | [T1486-data-encrypted-for-impact.md](references/T1486-data-encrypted-for-impact.md) | ARG-IM-002 |
| `T1489` | Service Stop | [T1489-service-stop.md](references/T1489-service-stop.md) | ARG-IM-003 |
| `T1496` | Resource Hijacking (cryptomining) | [T1496-resource-hijacking-cryptomining.md](references/T1496-resource-hijacking-cryptomining.md) | ARG-IM-004 |
| `T1485` | Data Destruction | [T1485-data-destruction.md](references/T1485-data-destruction.md) | ARG-IM-005 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
