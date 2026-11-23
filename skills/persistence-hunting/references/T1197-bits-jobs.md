# T1197 — BITS Jobs

| Field | Value |
|---|---|
| ATT&CK | [T1197](https://attack.mitre.org/techniques/T1197/) |
| Tactic | TA0003 Persistence |
| ARGUS rules | `ARG-PE-009` |

## Data sources needed
Get-BitsTransfer -AllUsers; Microsoft-Windows-Bits-Client/Operational 59/60

## Hunt hypothesis
A BITS job downloads a payload and runs it through SetNotifyCmdLine.

## Detection logic
Notify cmdline present; non-vendor URL; destination in user path.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0003
python -I engine/argus_cli.py rules --tactic TA0003
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block) — path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`) — was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Windows Update, Edge, Office, Chrome updaters.

## Rationalizations to reject
- "It's signed, so it's fine." — signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it." — low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe." — destroys evidence; detect-only until the user opts in.
