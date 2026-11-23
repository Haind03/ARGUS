# Volatility 3 plugins → ATT&CK

| Plugin | Look for | ATT&CK | FP |
|---|---|---|---|
| `windows.pslist` vs `windows.psscan` | processes in psscan but not pslist (unlinked / exited) | T1564, T1055 | processes that exited between scans |
| `windows.pstree` | wrong parents (svchost not under services) | T1036.005 | n/a |
| `windows.cmdline` | encoded PowerShell, LOLBin args | T1059.001, T1218 | admin tools |
| `windows.malfind` | `PAGE_EXECUTE_READWRITE` private memory, `MZ` header in VAD | T1055 | .NET/JIT, browsers, AV |
| `windows.netscan` | sockets owned by user-path processes to public IPs | T1071 | portable apps |
| `windows.handles --pid <lsass>` | handles to lsass from unexpected processes | T1003.001 | AV/EDR |
| `windows.dlllist` | DLLs from Temp/AppData in system processes | T1574.002 | n/a |
| `windows.svcscan` | services with no registry key / odd binaries | T1543.003 | n/a |
| `windows.registry.printkey` (Run keys) | in-memory persistence | T1547.001 | n/a |
| `windows.ssdt`, `windows.driverscan` | rootkit hooks / unknown drivers | T1014, T1068 | AV kernel drivers |

malfind regions in browsers and Electron apps are routinely JIT, weight them only when combined with
other signals (user-path process, network to public IP, MZ header).
