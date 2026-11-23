# T1133 — External Remote Services

| Field | Value |
|---|---|
| ATT&CK | [T1133](https://attack.mitre.org/techniques/T1133/) |
| Tactic | TA0001 Initial Access |
| ARGUS rules | `ARG-IA-005`, `ARG-CA-005` |

## Data sources needed
Security 4624 (LogonType 10/3) with IpAddress; firewall/RDP configuration

## Hunt hypothesis
RDP (or another remote service) is exposed and an attacker logged in from the Internet.

## Detection logic
4624 LogonType IN (10,3) AND IpAddress is public. Correlate with 4625 bursts (brute force) before success.

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
User's own remote access from a mobile hotspot / travel; VPN egress IPs.

## Rationalizations to reject
- "It's signed, so it's fine." — signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it." — low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe." — destroys evidence; detect-only until the user opts in.
