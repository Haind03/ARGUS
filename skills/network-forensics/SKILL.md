---
name: network-forensics
description: Use when you need to analyse NETWORK behaviour of the user's own PC — beaconing (regular C2 intervals), DGA and DNS tunnelling, web-service/tunnel C2 domains (Discord, Telegram, ngrok, pastebin), suspicious ports, raw-IP HTTP, large uploads — from a pktmon/Wireshark capture (via tshark fields) or from repeated ARGUS telemetry snapshots.
---

# Network forensics

> **Scope:** traffic of the user's own, authorised machine only — never capture other people's traffic
> on shared networks. Capture is **opt-in** and time-boxed; captures contain private data.

## Options
| Data | Get it | Analyse |
|---|---|---|
| Connection snapshots (no capture) | scheduled scans already store `network` + `dns_cache` | `network_hunt.py --telemetry t1.json t2.json ...` (beaconing across snapshots) |
| Packet capture | `Start-ArgusPacketCapture.ps1 -Minutes 15 -OutDir E:\case01\net -Capture` (pktmon) or Wireshark | tshark field export → `network_hunt.py --tshark-csv flows.csv` |
| Per-app bytes history | SRUM (disk-forensics) | exfil volume per process |

```bash
python -I skills/network-forensics/scripts/network_hunt.py --tshark-csv E:\case01\net\flows.csv --out-dir E:\case01\net
```
Detections `ARG-NF-001…007` — see [network-hunt-reference.md](references/network-hunt-reference.md).
Process attribution: pktmon has no PIDs; correlate dst IP with `Get-NetTCPConnection`/Sysmon 3 from the same time.
