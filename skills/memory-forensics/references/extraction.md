# Extracting artefacts from a memory image

All extracted files are potential malware: write to a case folder excluded from sync/AV auto-delete
(or let AV quarantine and note it), rename to `<sha256>.bin`, never execute.

| Goal | Command |
|---|---|
| Process executable | `vol -f mem.raw windows.pslist --pid <PID> --dump -o out/` |
| All DLLs of a process | `vol -f mem.raw windows.dlllist --pid <PID> --dump -o out/` |
| Injected regions | `vol -f mem.raw windows.malfind --pid <PID> --dump -o out/` |
| Whole process address space | `vol -f mem.raw windows.memmap --pid <PID> --dump -o out/` |
| File object (script, doc, note) | `vol -f mem.raw windows.filescan` → `windows.dumpfiles --virtaddr <addr> -o out/` |
| Registry hive | `vol -f mem.raw windows.registry.hivelist --dump -o out/` |

Then:
```bash
python -I engine/argus_cli.py triage out/<file>                               # static triage (PE/strings/YARA)
python -I skills/process-memory-analysis/scripts/scan_dump.py --dump out/pid.<PID>.dmp   # strings/IOC/YARA/carving
```
Dumped PEs are rebuilt from memory: section entropy and import tables may differ from the disk file — expected.
