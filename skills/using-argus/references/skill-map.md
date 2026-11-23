# ARGUS skill map

| Layer | Skills |
|---|---|
| Discipline | using-argus, scope-discipline, hunt-methodology, evidence-discipline, false-positive-discipline, reporting-discipline, writing-defensive-skills |
| Data | telemetry-collection, baseline-and-diff |
| Tactic hunting (ATT&CK) | initial-access (TA0001), execution (TA0002), persistence (TA0003), privesc (TA0004), defense-evasion (TA0005), credential-access (TA0006), discovery (TA0007), lateral-movement (TA0008), collection (TA0009), c2 (TA0011), exfiltration (TA0010), impact (TA0040) |
| Analysis / forensics | malware-triage, memory-acquisition, memory-forensics, process-memory-analysis, disk-forensics, eventlog-forensics, network-forensics, browser-forensics, threat-intel-enrichment, yara-sigma-authoring |
| Response (opt-in) | incident-response |

TA0043 Reconnaissance and TA0042 Resource Development are not host-observable; they enter ARGUS only as
threat-intel IOCs (`skills/references/ioc/`).

Live list: `python -I skills/using-argus/scripts/list_skills.py`
