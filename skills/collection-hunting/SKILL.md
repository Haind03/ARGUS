---
name: collection-hunting
description: Use when you need to find DATA COLLECTION / STAGING: password-protected archives of documents, large archives in Temp/Public, keylogging, screen or clipboard capture on the user's own Windows PC (MITRE ATT&CK TA0009 Collection).
---

# Collection hunting (TA0009)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find DATA COLLECTION / STAGING: password-protected archives of documents, large archives in Temp/Public, keylogging, screen or clipboard capture. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\collection-hunting\scripts\Collect-Collection.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,files`)
2. **Detect / score**:
   ```bash
   python -I skills/collection-hunting/scripts/hunt_collection_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1560.001` | Archive Collected Data: Archive via Utility | [T1560.001-archive-collected-data-archive-via-utility.md](references/T1560.001-archive-collected-data-archive-via-utility.md) | ARG-CO-001 |
| `T1074.001` | Data Staged: Local Data Staging | [T1074.001-data-staged-local-data-staging.md](references/T1074.001-data-staged-local-data-staging.md) | ARG-CO-002 |
| `T1056.001` | Input Capture: Keylogging (+T1113 Screen Capture, T1115 Clipboard Data) | [T1056.001-input-capture-keylogging-t1113-screen-capture-t1115-clipboar.md](references/T1056.001-input-capture-keylogging-t1113-screen-capture-t1115-clipboar.md) | ARG-CO-003 |
| `T1005` | Data from Local System | [T1005-data-from-local-system.md](references/T1005-data-from-local-system.md) | ARG-CO-001 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic, never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
