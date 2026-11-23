---
name: initial-access-hunting
description: Use when you need to find HOW malware first landed on the PC: malicious attachments, drive-by / fake-update downloads, ISO/LNK/HTA delivery, USB execution, or exposed RDP on the user's own Windows PC (MITRE ATT&CK TA0001 Initial Access).
---

# Initial Access hunting (TA0001)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find HOW malware first landed on the PC: malicious attachments, drive-by / fake-update downloads, ISO/LNK/HTA delivery, USB execution, or exposed RDP. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\initial-access-hunting\scripts\Collect-InitialAccess.ps1
   ```
   (wraps `telemetry-collection` with sections: `host,processes,events,files`)
2. **Detect / score**:
   ```bash
   python -I skills/initial-access-hunting/scripts/hunt_initial_access_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1566.001` | Phishing: Spearphishing Attachment | [T1566.001-phishing-spearphishing-attachment.md](references/T1566.001-phishing-spearphishing-attachment.md) | ARG-IA-001 |
| `T1566.002` | Phishing: Spearphishing Link | [T1566.002-phishing-spearphishing-link.md](references/T1566.002-phishing-spearphishing-link.md) | ARG-IA-003 |
| `T1189` | Drive-by Compromise | [T1189-drive-by-compromise.md](references/T1189-drive-by-compromise.md) | ARG-IA-002 |
| `T1204.002` | User Execution: Malicious File | [T1204.002-user-execution-malicious-file.md](references/T1204.002-user-execution-malicious-file.md) | ARG-IA-003 |
| `T1091` | Replication Through Removable Media | [T1091-replication-through-removable-media.md](references/T1091-replication-through-removable-media.md) | ARG-IA-004 |
| `T1133` | External Remote Services | [T1133-external-remote-services.md](references/T1133-external-remote-services.md) | ARG-IA-005, ARG-CA-005 |
| `T1195.002` | Supply Chain Compromise: Compromise Software Supply Chain | [T1195.002-supply-chain-compromise-compromise-software-supply-chain.md](references/T1195.002-supply-chain-compromise-compromise-software-supply-chain.md) | ARG-EX-006 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic, never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
