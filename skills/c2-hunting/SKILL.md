---
name: c2-hunting
description: Use when you need to find COMMAND-AND-CONTROL / beaconing: outbound connections from Temp/unsigned binaries, suspicious ports, DGA domains, web-service C2 (Discord/Telegram/Pastebin), tunnelling tools, RMM tools, built-in downloaders, hosts-file tampering on the user's own Windows PC (MITRE ATT&CK TA0011 Command and Control).
---

# Command and Control hunting (TA0011)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find COMMAND-AND-CONTROL / beaconing: outbound connections from Temp/unsigned binaries, suspicious ports, DGA domains, web-service C2 (Discord/Telegram/Pastebin), tunnelling tools, RMM tools, built-in downloaders, hosts-file tampering. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\c2-hunting\scripts\Collect-C2.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,network,dns,hosts,events`)
2. **Detect / score**:
   ```bash
   python -I skills/c2-hunting/scripts/hunt_c2_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1071.001` | Application Layer Protocol: Web Protocols | [T1071.001-application-layer-protocol-web-protocols.md](references/T1071.001-application-layer-protocol-web-protocols.md) | ARG-C2-001 |
| `T1105` | Ingress Tool Transfer | [T1105-ingress-tool-transfer.md](references/T1105-ingress-tool-transfer.md) | ARG-C2-002, ARG-EX-004 |
| `T1572` | Protocol Tunneling (+T1090 Proxy) | [T1572-protocol-tunneling-t1090-proxy.md](references/T1572-protocol-tunneling-t1090-proxy.md) | ARG-C2-003 |
| `T1219` | Remote Access Software | [T1219-remote-access-software.md](references/T1219-remote-access-software.md) | ARG-C2-004 |
| `T1568.002` | Dynamic Resolution: Domain Generation Algorithms | [T1568.002-dynamic-resolution-domain-generation-algorithms.md](references/T1568.002-dynamic-resolution-domain-generation-algorithms.md) | ARG-C2-005 |
| `T1102` | Web Service | [T1102-web-service.md](references/T1102-web-service.md) | ARG-C2-006 |
| `T1571` | Non-Standard Port | [T1571-non-standard-port.md](references/T1571-non-standard-port.md) | ARG-C2-001 |
| `T1565.001` | Hosts file tampering (DNS redirection) | [T1565.001-hosts-file-tampering-dns-redirection.md](references/T1565.001-hosts-file-tampering-dns-redirection.md) | ARG-C2-007 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic — never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
