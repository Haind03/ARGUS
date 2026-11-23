# Memory hunt playbook (hypothesis order)

| # | Hypothesis | Plugins | ARGUS rule | ATT&CK |
|---|---|---|---|---|
| 1 | A process is hiding | psscan vs pslist, psxview-style cross-view | ARG-MEM-001 | T1564 / T1014 |
| 2 | A process masquerades | pstree, cmdline (path) | ARG-MEM-002/003/004 | T1036.005 |
| 3 | Malicious command line is resident | cmdline, envars | ARG-MEM-010/024 | T1059, T1574.007 |
| 4 | Code was injected | malfind, ldrmodules, hollowprocesses, vadyarascan | ARG-MEM-011/014/015/025/030 | T1055.* |
| 5 | Side-loaded DLL in a system process | dlllist | ARG-MEM-013 | T1574.002 |
| 6 | Credentials are being stolen | handles (lsass), privileges (SeDebug) | ARG-MEM-016/023 | T1003.001, T1134 |
| 7 | C2 socket exists | netscan | ARG-MEM-012 | T1071 |
| 8 | Persistence lives in memory/registry | svcscan, printkey Run | ARG-MEM-017/026 | T1543.003, T1547.001 |
| 9 | Kernel is compromised | ssdt, callbacks, driverscan, modules | ARG-MEM-018/019/020/021 | T1014, T1068 |
| 10 | Escalated process from user path | getsids | ARG-MEM-022 | T1134 |
| 11 | Ransomware/impact | filescan (notes), cmdline (vssadmin) | ARG-MEM-027/010 | T1486, T1490 |

## Correlate with disk
For every memory finding, look for the disk counterpart in the live hunt (`argus-*.json`): same PID/path/hash.
**Memory-only** artefacts (no disk file, no autorun) → fileless; record that explicitly in the report.

## Pivot commands (manual)
```bash
vol -f mem.raw windows.pstree --pid <PID>
vol -f mem.raw windows.malfind --pid <PID> --dump -o case/mem/dump
vol -f mem.raw windows.dlllist --pid <PID> --dump -o case/mem/dump
vol -f mem.raw windows.memmap --pid <PID> --dump -o case/mem/dump
vol -f mem.raw windows.dumpfiles --virtaddr <ADDR> -o case/mem/files
vol -f mem.raw windows.vadyarascan --yara-rules "rule x { strings: $a = \"stratum+tcp\" condition: $a }"
```
