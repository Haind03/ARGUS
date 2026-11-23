# Offline memory sources

| Source | Location | Tooling |
|---|---|---|
| Hibernation file | `C:\hiberfil.sys` (locked while running) | copy from offline/VSS; Vol3 `layerwriter` or Hibr2Bin → raw |
| Page file | `C:\pagefile.sys` | strings/YARA only (no structure) |
| Swap file | `C:\swapfile.sys` (UWP apps) | strings/YARA |
| Full/kernel crash dump | `C:\Windows\MEMORY.DMP`, `C:\Windows\Minidump\*.dmp` | Vol3 / WinDbg |
| WER process dumps | `%LOCALAPPDATA%\CrashDumps`, `C:\ProgramData\Microsoft\Windows\WER` | process-memory-analysis |
| VM snapshot | `.vmem`/`.vmsn` (VMware), `.vsv/.bin` (Hyper-V), `.sav` (VirtualBox) | Vol3 directly |

Copy locked files from a Volume Shadow Copy (read-only) or from WinPE/offline boot. Hash on copy.
Fast startup (hybrid shutdown) means hiberfil.sys often holds the kernel session even after "shutdown".
