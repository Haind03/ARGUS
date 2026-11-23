---
name: defense-evasion-hunting
description: Use when you need to find DEFENSE EVASION: Defender disabled/excluded, logs cleared, masquerading system binaries, process injection, LOLBin proxy execution, hidden files, weakened security policy or firewall on the user's own Windows PC (MITRE ATT&CK TA0005 Defense Evasion).
---

# Defense Evasion hunting (TA0005)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find DEFENSE EVASION: Defender disabled/excluded, logs cleared, masquerading system binaries, process injection, LOLBin proxy execution, hidden files, weakened security policy or firewall. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\defense-evasion-hunting\scripts\Collect-DefenseEvasion.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,defender,registry,events,firewall,files`)
2. **Detect / score**:
   ```bash
   python -I skills/defense-evasion-hunting/scripts/hunt_defense_evasion_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1562.001` | Impair Defenses: Disable or Modify Tools | [T1562.001-impair-defenses-disable-or-modify-tools.md](references/T1562.001-impair-defenses-disable-or-modify-tools.md) | ARG-DE-001, ARG-DE-007 |
| `T1070.001` | Indicator Removal: Clear Windows Event Logs | [T1070.001-indicator-removal-clear-windows-event-logs.md](references/T1070.001-indicator-removal-clear-windows-event-logs.md) | ARG-DE-002 |
| `T1036.005` | Masquerading: Match Legitimate Name or Location | [T1036.005-masquerading-match-legitimate-name-or-location.md](references/T1036.005-masquerading-match-legitimate-name-or-location.md) | ARG-DE-003 |
| `T1055` | Process Injection | [T1055-process-injection.md](references/T1055-process-injection.md) | ARG-DE-004 |
| `T1218` | System Binary Proxy Execution (evasion) | [T1218-system-binary-proxy-execution-evasion.md](references/T1218-system-binary-proxy-execution-evasion.md) | ARG-EX-004 |
| `T1562.004` | Impair Defenses: Disable or Modify System Firewall | [T1562.004-impair-defenses-disable-or-modify-system-firewall.md](references/T1562.004-impair-defenses-disable-or-modify-system-firewall.md) | ARG-DE-005 |
| `T1564.001` | Hide Artifacts: Hidden Files and Directories | [T1564.001-hide-artifacts-hidden-files-and-directories.md](references/T1564.001-hide-artifacts-hidden-files-and-directories.md) | ARG-DE-006 |
| `T1112` | Modify Registry (security policy) | [T1112-modify-registry-security-policy.md](references/T1112-modify-registry-security-policy.md) | ARG-DE-007 |
| `T1140` | Deobfuscate/Decode Files or Information | [T1140-deobfuscate-decode-files-or-information.md](references/T1140-deobfuscate-decode-files-or-information.md) | ARG-EX-004, ARG-EX-001 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic, never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
