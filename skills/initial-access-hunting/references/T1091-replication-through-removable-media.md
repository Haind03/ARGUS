# T1091 — Replication Through Removable Media

| Field | Value |
|---|---|
| ATT&CK | [T1091](https://attack.mitre.org/techniques/T1091/) |
| Tactic | TA0001 Initial Access |
| ARGUS rules | `ARG-IA-004` |

## Data sources needed
Win32_LogicalDisk DriveType=2, process image path, Sysmon 1

## Hunt hypothesis
A worm (Raspberry Robin-style LNK on USB) executed from a removable drive.

## Detection logic
Process image path on a removable drive letter; LNK on USB launching cmd/msiexec with remote URL.

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics TA0001
python -I engine/argus_cli.py rules --tactic TA0001
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block) — path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`) — was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
Portable apps run from USB by the user.

## Rationalizations to reject
- "It's signed, so it's fine." — signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it." — low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe." — destroys evidence; detect-only until the user opts in.
