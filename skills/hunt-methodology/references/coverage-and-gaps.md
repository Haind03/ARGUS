# Coverage & gaps

ATT&CK coverage claims must be honest:
- **Tactic coverage**: all 12 host-observable Enterprise tactics have rules and a skill; TA0043/TA0042 are
  out-of-host (intel only).
- **Technique coverage**: ~70 techniques/sub-techniques have heuristics (`skills/references/ttp-index.json`);
  Enterprise has hundreds more. Generate the Navigator layer: `python -I engine/argus_cli.py coverage`.
- **Data coverage** determines real coverage: without Sysmon, many rules only see live processes at
  collection time (no history); without 4104, PowerShell content is invisible.

Report gaps explicitly (`collection_gaps` in every result):
| Gap | Effect | Fix (opt-in) |
|---|---|---|
| not elevated | no Security log, WMI subs, Defender exclusions, BITS | run collector as admin |
| no Sysmon | no process history, no LSASS access, no DNS per process | telemetry-collection/sysmon-setup |
| no 4688 cmdline | no historical command lines | Enable-ArgusLogging.ps1 -Apply |
| no 4104 | no PowerShell content | Enable-ArgusLogging.ps1 -Apply |
| short log retention | early intrusion stages lost | increase log sizes |
| no baseline | more FPs, no "new since" signal | baseline-and-diff |
