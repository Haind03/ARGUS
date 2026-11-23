---
description: Hunt command-and-control (TA0011), suspicious outbound connections, beaconing, DGA, web-service C2, tunnels, RMM
argument-hint: "[telemetry.json ...] [--pcap-csv flows.csv]"
---

# /hunt.c2

1. `scope-discipline`, load `c2-hunting` and `network-forensics`.
2. Snapshot detection: `python -I skills/c2-hunting/scripts/hunt_c2_hunting.py --input <telemetry.json>`
3. Beaconing across scheduled snapshots: `python -I skills/network-forensics/scripts/network_hunt.py --telemetry <t1.json> <t2.json> ...`
4. If the user agrees to a short capture (opt-in): `Start-ArgusPacketCapture.ps1 -Minutes 15 -OutDir <case>\net -Capture`,
   export with tshark, then `network_hunt.py --tshark-csv flows.csv`.
5. Map each suspicious destination to a process; check local IOCs; online reputation only with opt-in.
   Never connect to, scan or probe the remote infrastructure.

Arguments: $ARGUMENTS
