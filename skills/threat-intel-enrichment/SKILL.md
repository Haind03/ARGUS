---
name: threat-intel-enrichment
description: Use when you want to check hashes, domains or IPs from ARGUS findings against threat intelligence — local offline IOC lists by default, and VirusTotal v3 / MalwareBazaar (abuse.ch) ONLY when the user explicitly opts in with API keys.
---

# Threat-intel enrichment (hybrid opt-in)

> **Scope:** indicators from the user's own, authorised machine. Lookups are passive (no probing of attacker infrastructure).

> **Privacy default: OFFLINE.** Nothing leaves the machine unless the user opts in.

## Modes
| Mode | How | Sends |
|---|---|---|
| Offline (default) | local lists in `skills/references/ioc/` | nothing |
| Online (opt-in) | `ARGUS_INTEL_ONLINE=1` **or** `--online`, **and** `VT_API_KEY` / `ABUSECH_AUTH_KEY` env vars | **SHA-256 only** |

Never send: file contents, file paths, usernames, hostnames, command lines, IPs of the user's own network.
Uploading a sample to VirusTotal makes it **public to VT subscribers** — this toolkit never uploads files; if the
user wants that, they do it themselves knowingly.

## Use
```bash
# offline enrichment is automatic inside `hunt`
python -I engine/argus_cli.py hunt --input t.json
# opt-in online (PowerShell): $env:VT_API_KEY='...'; $env:ABUSECH_AUTH_KEY='...'
python -I engine/argus_cli.py hunt --input t.json --online
python -I skills/threat-intel-enrichment/scripts/enrich.py --findings report.json --online   # re-enrich a report
```
Before going online, **tell the user exactly which hashes will be sent** (the result records `hashes_sent`).

## Scoring impact
local hash IOC +40 · local domain/IP IOC +35 · VT ≥5 malicious +30 · MalwareBazaar known sample +30.
"Not found" online is **not** evidence of benign — new/targeted samples are often unknown.

## Local IOC lists
`skills/references/ioc/{hashes_sha256,domains,ips,vuln_drivers}.txt` — one per line, `#` comments.
Update offline from exports (abuse.ch ThreatFox/URLhaus/MalwareBazaar CSV, loldrivers.io) via
`scripts/update_iocs.py --from-file <export.csv>` (no network access in the script).
References: [references/providers.md](references/providers.md).
