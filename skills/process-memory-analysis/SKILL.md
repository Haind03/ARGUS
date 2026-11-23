---
name: process-memory-analysis
description: Use when you have a single PROCESS DUMP (minidump from memory-acquisition, ProcDump, Task Manager, WER crash dump) or a region/VAD/DLL dumped by Volatility and need to extract IOCs and malware config — URLs, C2 IP:port, wallets, mutexes, stealer targets, ransom text — find embedded/injected PE images, and YARA-scan it, all statically.
---

# Process memory analysis (static)

> **Scope:** dumps from the user's own, authorised machine. A process dump may contain the user's
> secrets (browser dumps contain cookies/passwords) — keep it in the case folder, never upload it.

## Why process memory
Packed/encrypted malware is only readable **after** it unpacks in memory: C2 URLs, configs, mutexes and
second-stage PEs that never touch disk show up here.

## Run
```bash
python -I skills/process-memory-analysis/scripts/scan_dump.py --dump E:\case01\proc-evil-4321.dmp --out-dir E:\case01\procmem
python -I skills/process-memory-analysis/scripts/scan_dump.py --dump pid.4321.vad.0x1a0000.dmp --carve --out-dir case/carved
python -I engine/argus_cli.py triage case/carved/000000012000.bin.carved     # triage carved PEs
```
Output (`argus.procmem/1`): minidump modules (user-path modules flagged), IOC classes, embedded PE offsets,
optional carved PEs, YARA hits, signals → score.

## Interpreting
- [config-extraction.md](references/config-extraction.md) — what each IOC class means and how to pivot
- [dump-sources.md](references/dump-sources.md) — where dumps come from and their limits
- C2 candidates → `threat-intel-enrichment` (opt-in) and local `ioc/` lists; families → `yara-sigma-authoring`.
- Strings appear in benign processes too (browsers hold every URL visited). Weight by process type.
