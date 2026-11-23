# Config & IOC extraction from process memory

| IOC class | Weight | Malware relevance | FP in |
|---|---|---|---|
| `onion` | 25 | ransomware negotiation / Tor C2 | Tor browser |
| `ransom_text` | 30 | ransomware note template in memory | security blogs open in a browser |
| `recovery_delete` | 30 | ransomware pre-encryption commands | admin tools |
| `lsass_dump` | 25 | credential dumper strings | AV signatures in AV process memory |
| `credential_store` | 20 | infostealer target paths | browsers themselves, password managers |
| `messaging_exfil` | 25 | Discord webhook / Telegram bot exfil | Discord client |
| `miner` | 25 | cryptominer config | — |
| `xmr_wallet` / `btc_wallet` / `eth_wallet` | 20/10/8 | miners, clippers (clipboard hijack), ransom | wallet apps, browsers |
| `amsi_bypass` | 20 | in-memory AMSI patch | AV |
| `powershell` | 15 | stagers | PowerShell host itself |
| `ip_port` | 8 | hard-coded C2 | many |
| `run_key` | 10 | persistence code | installers |
| `mutex_like`, `pdb_path`, `user_agent`, `url` | 2-3 | pivots for YARA/intel | everywhere |

## Pivot workflow
1. Take the rarest strings (mutex, PDB path, odd user-agent, IP:port) → write a YARA rule (`yara-sigma-authoring`).
2. Search the live host for them: `Select-String -Path C:\Users\*\AppData\* -Pattern '<mutex>' -SimpleMatch -List`.
3. IP/domain → DNS cache, firewall, browser history; opt-in intel.
4. Embedded PEs → carve → `triage` → hash → opt-in intel.

## Family config extractors (offline, optional)
CAPE/`malduck`/MWCP-style extractors can parse known families from dumps; run them only inside an isolated VM.
