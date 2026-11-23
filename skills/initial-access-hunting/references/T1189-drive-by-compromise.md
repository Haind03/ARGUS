# T1189, Drive-by Compromise

| Field | Value |
|---|---|
| ATT&CK | [T1189](https://attack.mitre.org/techniques/T1189/) |
| Tactic | TA0001 Initial Access |
| ARGUS rules | `ARG-IA-002` |

## Data sources needed
Process creation with browser parent; Sysmon 11 file create under Downloads/Temp

## Hunt hypothesis
A browser exploit or fake browser-update (SocGholish-style) made the browser spawn a script host.

## Detection logic
parent IN browsers AND child IN (wscript, cscript, mshta, powershell, rundll32, regsvr32), cmd.exe excluded because native messaging hosts use it.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0001
python -I engine/argus_cli.py rules --tactic TA0001
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Browser native-messaging hosts (password managers) launching via cmd/powershell; enterprise SSO helpers.

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
