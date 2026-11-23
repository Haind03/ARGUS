# T1047 — Windows Management Instrumentation

| Field | Value |
|---|---|
| ATT&CK | [T1047](https://attack.mitre.org/techniques/T1047/) |
| Tactic | TA0002 Execution |
| ARGUS rules | `ARG-EX-005`, `ARG-EX-004` |

## Data sources needed
Process with parent wmiprvse.exe; WMI-Activity 5861

## Hunt hypothesis
Malware or a remote operator uses WMI to spawn processes.

## Detection logic
parent = wmiprvse.exe AND child IN shells/LOLBins; wmic process call create.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0002
python -I engine/argus_cli.py rules --tactic TA0002
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block) — path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`) — was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Management agents and some AV products spawn via WMI.

## Rationalizations to reject
- "It's signed, so it's fine." — signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it." — low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe." — destroys evidence; detect-only until the user opts in.
