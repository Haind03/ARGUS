# Rebuild vs clean

**Rebuild (reinstall Windows from trusted media) when any of:**
- kernel-level compromise (rootkit, unknown driver/callback, SSDT hook, BYOVD used)
- ransomware executed
- attacker had interactive/admin access for unknown duration (RMM, RDP, tunnels)
- Defender/EDR was tampered with and you cannot tell what ran meanwhile
- multiple persistence mechanisms or memory-only components

**Clean (targeted removal) may be acceptable when all of:**
- single commodity sample (adware, miner) with known behaviour
- timeline is complete (initial access → persistence → no further stages)
- no credential theft or C2 interaction beyond the sample
- re-hunt with baseline is clean for 7+ days of scheduled scans

Either way: reset passwords from a clean device and review cloud account sessions.
