# T1489 — Service Stop

| Field | Value |
|---|---|
| ATT&CK | [T1489](https://attack.mitre.org/techniques/T1489/) |
| Tactic | TA0040 Impact |
| ARGUS rules | `ARG-IM-003` |

## Data sources needed
Process cmdline (net stop, sc config start= disabled, Stop-Service, taskkill /im); System 7036/7040

## Hunt hypothesis
Ransomware stops AV/backup/DB services to release file locks.

## Detection logic
≥2 sensitive services or ≥5 services stopped by one parent.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0040
python -I engine/argus_cli.py rules --tactic TA0040
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block) — path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`) — was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Installers/updaters stopping their own services.

## Rationalizations to reject
- "It's signed, so it's fine." — signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it." — low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe." — destroys evidence; detect-only until the user opts in.
