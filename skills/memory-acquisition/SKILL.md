---
name: memory-acquisition
description: Use when you need to DUMP MEMORY from the user's own Windows PC, full physical RAM (WinPmem/DumpIt/Magnet), a single suspicious process (minidump), or offline sources (hiberfil.sys, pagefile.sys, crash dumps), with explicit opt-in, hashing and chain of custody, before memory-forensics or process-memory-analysis.
---

# Memory acquisition (opt-in)

> **Scope:** the user's own, authorised machine. Dumping memory is **an action, not a read**: it writes
> large files that contain passwords, keys and session cookies. Ask the user, explain the risk, then run.
> Default is **dry run**.

## Decide what to capture
| Situation | Capture | Why |
|---|---|---|
| Fileless / injection / rootkit suspicion | **Full RAM** | Volatility needs the whole kernel + all processes |
| One suspicious process (unknown binary, odd network) | **Process minidump** | small, fast, enough for strings/YARA/config extraction |
| Ransomware still running | **Full RAM first, do not reboot** | encryption keys may be resident |
| Machine already off | hiberfil.sys / pagefile.sys / MEMORY.DMP | offline remnants, see references |

Order of volatility: RAM → network state (`Collect-Telemetry -Sections network,dns`) → processes → disk.

## Run
ARGUS ships **no dumping code of its own**, it validates and launches vendor-signed tools you download
yourself (WinPmem, Sysinternals ProcDump), recording their hash and signer. This keeps the toolkit from
looking like a credential dumper to antivirus and keeps provenance clean.
```powershell
# plan only (default)
.\skills\memory-acquisition\scripts\Invoke-ArgusMemoryDump.ps1 -Mode FullRam -ToolPath E:\tools\winpmem_mini_x64.exe -OutDir E:\case01
# acquire (elevated)
.\skills\memory-acquisition\scripts\Invoke-ArgusMemoryDump.ps1 -Mode FullRam -ToolPath E:\tools\winpmem_mini_x64.exe -OutDir E:\case01 -Acquire
.\skills\memory-acquisition\scripts\Invoke-ArgusMemoryDump.ps1 -Mode Process -ProcessId 4321 -ToolPath E:\tools\procdump64.exe -OutDir E:\case01 -Acquire
```
Guards: refuses the system drive (unless `-AllowSystemDrive`), **always refuses LSASS and other
protected/credential/AV processes** (use full RAM + `memory-forensics` instead), checks free space ≥ RAM,
records tool hash/signer, appends `chain-of-custody.json`.

Then: full RAM → `memory-forensics`; process dump → `process-memory-analysis`.

References: [acquisition-tools.md](references/acquisition-tools.md) · [offline-memory-sources.md](references/offline-memory-sources.md)
