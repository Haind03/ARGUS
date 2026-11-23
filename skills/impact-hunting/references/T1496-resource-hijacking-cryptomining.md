# T1496, Resource Hijacking (cryptomining)

| Field | Value |
|---|---|
| ATT&CK | [T1496](https://attack.mitre.org/techniques/T1496/) |
| Tactic | TA0040 Impact |
| ARGUS rules | `ARG-IM-004` |

## Data sources needed
Process cmdline / names; network ports

## Hunt hypothesis
A miner (XMRig-style) runs persistently, often from AppData.

## Detection logic
Miner keywords (stratum+tcp, xmrig, --donate-level); mining-pool ports.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0040
python -I engine/argus_cli.py rules --tactic TA0040
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
User's own mining software.

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
