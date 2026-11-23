---
name: credential-access-hunting
description: Use when you need to find CREDENTIAL THEFT: LSASS dumping, SAM/SYSTEM hive export, browser password/cookie stealing (infostealers), credential file searches, WDigest downgrade, or brute force on the user's own Windows PC (MITRE ATT&CK TA0006 Credential Access).
---

# Credential Access hunting (TA0006)

> **Scope:** run only on a machine you own or are explicitly authorised to examine. This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal goes through `incident-response` and requires explicit opt-in.

## When to use
Use when you need to find CREDENTIAL THEFT: LSASS dumping, SAM/SYSTEM hive export, browser password/cookie stealing (infostealers), credential file searches, WDigest downgrade, or brute force. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\credential-access-hunting\scripts\Collect-CredentialAccess.ps1
   ```
   (wraps `telemetry-collection` with sections: `processes,events,registry`)
2. **Detect / score**:
   ```bash
   python -I skills/credential-access-hunting/scripts/hunt_credential_access_hunting.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
| `T1003.001` | OS Credential Dumping: LSASS Memory | [T1003.001-os-credential-dumping-lsass-memory.md](references/T1003.001-os-credential-dumping-lsass-memory.md) | ARG-CA-001, ARG-EX-004, ARG-DE-007 |
| `T1003.002` | OS Credential Dumping: Security Account Manager | [T1003.002-os-credential-dumping-security-account-manager.md](references/T1003.002-os-credential-dumping-security-account-manager.md) | ARG-CA-002 |
| `T1555.003` | Credentials from Password Stores: Credentials from Web Browsers | [T1555.003-credentials-from-password-stores-credentials-from-web-browse.md](references/T1555.003-credentials-from-password-stores-credentials-from-web-browse.md) | ARG-CA-003 |
| `T1552.001` | Unsecured Credentials: Credentials In Files (+T1555.004 Windows Credential Manager) | [T1552.001-unsecured-credentials-credentials-in-files-t1555-004-windows.md](references/T1552.001-unsecured-credentials-credentials-in-files-t1555-004-windows.md) | ARG-CA-004 |
| `T1110` | Brute Force (password guessing/spraying) | [T1110-brute-force-password-guessing-spraying.md](references/T1110-brute-force-password-guessing-spraying.md) | ARG-CA-005 |

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic, never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
