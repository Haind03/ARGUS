# T1055 — Process Injection

| Field | Value |
|---|---|
| ATT&CK | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Tactic | TA0005 Defense Evasion |
| ARGUS rules | `ARG-DE-004` |

## Data sources needed
Sysmon 8 CreateRemoteThread (StartModule empty); Sysmon 10; memory forensics malfind

## Hunt hypothesis
A user-path binary injects into explorer/svchost/browser.

## Detection logic
Sysmon 8 from non-allow-listed source; unbacked start address; source in user path.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0005
python -I engine/argus_cli.py rules --tactic TA0005
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block) — path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`) — was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
AV/EDR, accessibility tools, game overlays (Discord, Steam, NVIDIA).

## Rationalizations to reject
- "It's signed, so it's fine." — signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it." — low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe." — destroys evidence; detect-only until the user opts in.
