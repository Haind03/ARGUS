# T1218, System Binary Proxy Execution

| Field | Value |
|---|---|
| ATT&CK | [T1218](https://attack.mitre.org/techniques/T1218/) |
| Tactic | TA0002 Execution |
| ARGUS rules | `ARG-EX-004` |

## Data sources needed
Process cmdline for mshta, rundll32, regsvr32, certutil, msbuild, installutil, cmstp, msiexec, hh, odbcconf

## Hunt hypothesis
Attackers proxy execution through signed Microsoft binaries to evade allow-listing.

## Detection logic
Per-binary argument patterns: mshta http/javascript:, rundll32 javascript:/user-path DLL/no args, regsvr32 /i:http scrobj, msbuild with user-path project, msiexec /q http.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0002
python -I engine/argus_cli.py rules --tactic TA0002
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Legit rundll32 usage is extremely common, only argument patterns are scored, never the binary alone.

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
