# T1041, Exfiltration Over C2 Channel

| Field | Value |
|---|---|
| ATT&CK | [T1041](https://attack.mitre.org/techniques/T1041/) |
| Tactic | TA0010 Exfiltration |
| ARGUS rules | `ARG-EF-002` |

## Data sources needed
Per-connection byte counters (if collector supports, e.g. Sysmon/ETW or netstat -e per process)

## Hunt hypothesis
Large outbound volume from a non-sync process.

## Detection logic
bytes_sent ≥ 500 MB to public IP, excluding browsers/sync clients.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0010
python -I engine/argus_cli.py rules --tactic TA0010
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Video calls, games, backup software.

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
