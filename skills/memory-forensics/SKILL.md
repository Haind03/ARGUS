---
name: memory-forensics
description: Use when analysing a RAM image of the user's own PC with Volatility 3, hidden/unlinked processes, process-tree anomalies, injected code (malfind, ldrmodules, hollowing), LSASS handles, suspicious services/drivers, SSDT hooks and kernel callbacks (rootkits), SYSTEM tokens and SeDebug, in-memory Run keys, ransom notes, YARA in process memory, scored into ARGUS findings.
---

# Memory forensics (Volatility 3)

> **Scope:** memory of the user's own, authorised machine. A RAM image contains **passwords, keys,
> session cookies**, store it encrypted, never upload it. Analysis is read-only.

## When
Fileless malware (PowerShell/WMI with nothing on disk), injection (ARG-DE-004), LSASS access (ARG-CA-001),
suspected rootkit/BYOVD (ARG-PR-002), or live ransomware (**do not reboot**, keys may be in RAM).
No image yet → `memory-acquisition` first.

## Run
```bash
python -m venv .vol && .vol/Scripts/pip install volatility3 yara-python     # once, outside the live host if possible
python -I skills/memory-forensics/scripts/vol_hunt.py --image mem.raw --out-dir case/mem --profile full --yara
python -I skills/memory-forensics/scripts/vol_hunt.py --vol-json-dir case/mem/raw --out-dir case/mem   # re-score saved JSON
```

| Profile | Plugins |
|---|---|
| quick | pslist, psscan, pstree, cmdline, netscan, malfind |
| full | quick + dlllist, ldrmodules, handles, svcscan, driverscan, modules, ssdt, callbacks, getsids, privileges, envars, hollowprocesses, registry.printkey (Run), filescan |
| `--yara` | windows.vadyarascan with `skills/references/yara/*.yar` |

Findings `ARG-MEM-001…030` → `memory-findings.json` (`argus.findings/1`). Plugins that fail are listed
in `collection_gaps` (symbol download issues are common offline, see references).

## Analysis playbooks
- [volatility-plugins.md](references/volatility-plugins.md), plugin → ATT&CK → FP table
- [memory-hunt-playbook.md](references/memory-hunt-playbook.md), ordered hunt (processes → injection → network → kernel → persistence)
- [rootkit-and-kernel.md](references/rootkit-and-kernel.md), SSDT, callbacks, DKOM, BYOVD
- [extraction.md](references/extraction.md), dumping processes/DLLs/VADs/files from the image for `malware-triage` / `process-memory-analysis`
