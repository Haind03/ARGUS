# Network hunt reference

| Rule | Hypothesis | Logic | ATT&CK | FP |
|---|---|---|---|---|
| ARG-NF-001 | implant beacons on a timer | ≥8 connections to dst:port, mean gap ≥5 s, coefficient of variation < 0.25 (jitter-tolerant) | T1071 | NTP, update checks, chat/push keep-alives, telemetry |
| ARG-NF-002 | DGA resolution | label ≥12, entropy ≥3.6, low vowel / high digit ratio | T1568.002 | CDN hashes, AV cloud lookups |
| ARG-NF-003 | web-service C2/exfil | SNI/Host/DNS ∈ paste/webhook/tunnel list | T1102, T1567 | developers, Discord client |
| ARG-NF-004 | non-standard C2 port | dst port ∈ {4444, 1337, 31337, 8888, 9001, 9050...} | T1571 | games, P2P, Tor browser |
| ARG-NF-005 | bulk exfil | ≥200 MB (tunable) to one public IP | T1041 | backups, cloud sync, video calls |
| ARG-NF-006 | downloader to raw IP | HTTP Host header is a public IPv4 | T1071.001 | IoT devices, some updaters |
| ARG-NF-007 | DNS tunnelling | label >50 chars or ≥50 unique subdomains under one parent | T1071.004, T1048.003 | CDNs (allow-listed parents) |

## Jitter
Commodity C2 frameworks add 10-50 % jitter; CV < 0.25 catches low-jitter beacons. For high jitter,
look at long-run frequency (connections/hour stable over a day of snapshots).

## TLS without decryption
SNI, certificate subject/issuer (self-signed, Let's Encrypt on fresh domains), JA3/JA4 fingerprints
(`-e tls.handshake.ja3` in newer tshark builds) are usable without breaking encryption.
