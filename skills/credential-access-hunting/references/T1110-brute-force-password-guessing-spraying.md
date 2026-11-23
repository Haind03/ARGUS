# T1110, Brute Force (password guessing/spraying)

| Field | Value |
|---|---|
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) |
| Tactic | TA0006 Credential Access |
| ARGUS rules | `ARG-CA-005` |

## Data sources needed
Security 4625 by IpAddress/TargetUserName

## Hunt hypothesis
Exposed RDP/SMB is being brute-forced.

## Detection logic
≥20 failures per source; ≥5 users = spray; public source aggravates.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0006
python -I engine/argus_cli.py rules --tactic TA0006
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
User mistyping passwords; stale mapped drive creds.

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
