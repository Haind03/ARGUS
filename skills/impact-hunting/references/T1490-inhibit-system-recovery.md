# T1490, Inhibit System Recovery

| Field | Value |
|---|---|
| ATT&CK | [T1490](https://attack.mitre.org/techniques/T1490/) |
| Tactic | TA0040 Impact |
| ARGUS rules | `ARG-IM-001` |

## Data sources needed
Process cmdline (vssadmin, wmic shadowcopy, wbadmin, bcdedit, reagentc, diskshadow); Win32_ShadowCopy count vs baseline

## Hunt hypothesis
Ransomware deletes shadow copies/backups right before encryption.

## Detection logic
Command regexes (high base score); shadow copy count dropped to 0 since baseline.

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
Disk cleanup / storage tools resizing shadow storage (vssadmin resize).

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
