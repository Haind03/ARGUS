---
name: using-argus
description: Use when starting ANY threat-hunting, malware-check, forensics or incident task on the user's own Windows PC, establishes how to route to the right ARGUS skill before acting (including before collecting data, answering "am I infected?", triaging a file, or writing a report).
---

<SUBAGENT-STOP>
If you were dispatched as a subagent for one specific task, skip this dispatcher and do that task.
</SUBAGENT-STOP>

# Using ARGUS (dispatcher)

ARGUS is a **defensive, detect-only** threat-hunting toolkit for the user's **own** machine.
If there is even a small chance a skill applies, load it with the Skill tool **before** acting, and
announce: "Using <skill> to <purpose>".

## Non-negotiables (the user cannot waive 1-3)
1. **Scope**, only the user's own / explicitly authorised machine (`scope-discipline`).
2. **Detect-only**, never kill, delete, quarantine, change Defender/firewall/registry/services unless the
   user opted in through `incident-response`. The PreToolUse guard enforces this.
3. **Privacy**, offline by default; online intel sends SHA-256 only, only with explicit opt-in + API keys.
4. **Evidence before change**, **validation before verdict**: scores are leads, not conclusions.
5. **No AV exclusions**, never suggest excluding ARGUS or anything else from Defender.

## Priority
1. Discipline first: `scope-discipline` → `hunt-methodology` → (`evidence-discipline`, `false-positive-discipline`) → `reporting-discipline`.
2. Then domain skills.

## Routing
| User says / situation | Skill(s) |
|---|---|
| "Is my PC infected?", "scan my laptop", full check | `hunt-methodology` → `/hunt.full` (workflows/full-hunt.yml) |
| Quick check, scheduled scan, "something feels off" | `/hunt.quick`, `baseline-and-diff` |
| New / freshly installed PC | `/hunt.baseline` (`baseline-and-diff`, preset new-machine-baseline) |
| Need raw data / logging is weak | `telemetry-collection` |
| Suspicious file / attachment / download | `malware-triage` (`/hunt.triage <file>`), `threat-intel-enrichment` (opt-in) |
| Ransom note, files renamed, shadow copies gone | `impact-hunting` + workflows/ransomware-response.yml, `incident-response` advice |
| Passwords/accounts stolen, stealer suspected | `credential-access-hunting`, `browser-forensics` |
| Weird network, beaconing, unknown connections | `c2-hunting`, `network-forensics` |
| Startup items, things coming back after reboot | `persistence-hunting` (`/hunt.persistence`) |
| Fileless / injection / rootkit suspicion | `memory-acquisition` → `memory-forensics`, `process-memory-analysis` |
| "What ran and when?", deleted malware | `disk-forensics`, `eventlog-forensics` |
| Infection came from browser / fake update | `initial-access-hunting`, `browser-forensics` |
| Per tactic | `initial-access-hunting` TA0001 · `execution-hunting` TA0002 · `persistence-hunting` TA0003 · `privesc-hunting` TA0004 · `defense-evasion-hunting` TA0005 · `credential-access-hunting` TA0006 · `discovery-hunting` TA0007 · `lateral-movement-hunting` TA0008 · `collection-hunting` TA0009 · `c2-hunting` TA0011 · `exfiltration-hunting` TA0010 · `impact-hunting` TA0040 |
| Write a detection rule | `yara-sigma-authoring` |
| User wants to remove / contain a confirmed threat | `incident-response` (opt-in, time-boxed) |
| Write the report | `reporting-discipline` (`/hunt.report`) |
| Add or edit an ARGUS skill | `writing-defensive-skills` |

## Harness (prefer over ad-hoc commands)
```bash
python -I engine/argus_cli.py case init --name <pc-date> --i-own-this-machine
python -I engine/argus_cli.py case run --case argus-cases/<pc-date> --input <telemetry.json> --workflow full-hunt
python -I engine/argus_cli.py case findings --case ...      # then validate + dispose each high/critical
python -I engine/argus_cli.py case report --case ... --input <telemetry.json>
```
Always run Python with `-I`. Collectors are PowerShell, read-only. Outputs: JSON + Markdown + ATT&CK Navigator layer.

## Red flags: stop and re-check
| Thought | Reality |
|---|---|
| "I'll just delete this suspicious file" | detect-only; evidence first; IR opt-in required |
| "Score 90, so it's malware" | heuristic lead, validate (false-positive-discipline) |
| "No findings, the PC is clean" | check collection gaps; absence of evidence ≠ evidence of absence |
| "Upload the sample to VirusTotal" | uploads make files public; hash-only, opt-in only |
| "Add a Defender exclusion so ARGUS runs" | never; report the false positive instead |
| "Scan the neighbour's / company machine too" | out of scope |
