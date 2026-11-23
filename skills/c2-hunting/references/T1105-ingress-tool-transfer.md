# T1105, Ingress Tool Transfer

| Field | Value |
|---|---|
| ATT&CK | [T1105](https://attack.mitre.org/techniques/T1105/) |
| Tactic | TA0011 Command and Control |
| ARGUS rules | `ARG-C2-002`, `ARG-EX-004` |

## Data sources needed
Process cmdline (certutil -urlcache, bitsadmin /transfer, iwr -OutFile, curl -o)

## Hunt hypothesis
Second stage downloaded with built-in tools.

## Detection logic
download-to-disk regex; payload ext in user path; raw IP URL.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0011
python -I engine/argus_cli.py rules --tactic TA0011
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Admin scripts, package managers (choco uses iwr).

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
