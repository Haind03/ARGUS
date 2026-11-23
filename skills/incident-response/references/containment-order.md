# Containment order

1. **Decide with the user**, what is confirmed, what will change, what may break.
2. **Volatile evidence**: memory (memory-acquisition), network state, process list, before killing anything.
3. **Isolate** the network (stops C2/exfil/spreading), `Isolate`, or physically unplug / disable Wi-Fi.
4. **Persistence first, then processes**: disable tasks/services/Run values/WMI bindings so a killed process cannot respawn.
5. **Kill** malicious processes.
6. **Quarantine** binaries (never delete, quarantine is reversible and keeps samples).
7. **Re-hunt** (`/hunt.quick` with baseline) to confirm nothing re-appears; check every tactic, not only the one you fixed.
8. **Credentials**: reset from a clean device (credential-access or infostealer findings).
9. **Unisolate** only after re-hunt is clean; keep monitoring with scheduled scans.
10. **Report** with what was changed (response-log.jsonl) and residual risk.
