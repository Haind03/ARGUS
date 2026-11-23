---
name: discovery-hunting
description: Use when you need to find post-compromise RECONNAISSANCE ON THE HOST: bursts of whoami/systeminfo/ipconfig/net/nltest, security product enumeration, or network/share discovery by malware on the user's own Windows PC (MITRE ATT&CK TA0007 Discovery).
---

# Discovery hunting (TA0007)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find post-compromise RECONNAISSANCE ON THE HOST: bursts of whoami/systeminfo/ipconfig/net/nltest, security product enumeration, or network/share discovery by malware. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\discovery-hunting\scripts\Collect-Discovery.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,events`)
2. **Detect / score**:
   ```bash
   python -I skills/discovery-hunting/scripts/hunt_discovery_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1082` | System Information Discovery (+T1016, T1033, T1087, T1069, T1049) | [T1082-system-information-discovery-t1016-t1033-t1087-t1069-t1049.md](references/T1082-system-information-discovery-t1016-t1033-t1087-t1069-t1049.md) | ARG-DI-001 |
| `T1518.001` | Software Discovery: Security Software Discovery | [T1518.001-software-discovery-security-software-discovery.md](references/T1518.001-software-discovery-security-software-discovery.md) | ARG-DI-002 |
| `T1135` | Network Share Discovery / T1018 Remote System Discovery | [T1135-network-share-discovery-t1018-remote-system-discovery.md](references/T1135-network-share-discovery-t1018-remote-system-discovery.md) | ARG-DI-001 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
