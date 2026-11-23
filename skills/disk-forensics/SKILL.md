---
name: disk-forensics
description: Use when you need to prove WHAT RAN and WHEN on the user's own Windows PC, even after malware deleted itself — Prefetch, BAM/DAM, UserAssist, Amcache, ShimCache, LNK/Jump Lists, Recycle Bin, USB history, SRUM, $MFT/USN journal — and build an execution timeline.
---

# Disk & execution-artefact forensics

> **Scope:** the user's own, authorised machine. Collection is **read-only**. Parsing of locked hives
> ($MFT, Amcache, SRUM) is done on **copies** (VSS or offline), never in place.

## Live quick pass
```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\disk-forensics\scripts\Collect-ExecutionArtifacts.ps1 -OutFile E:\case01\artifacts.json
```
```bash
python -I skills/disk-forensics/scripts/artifact_hunt.py --input E:\case01\artifacts.json --out-dir E:\case01\disk
# with Eric Zimmerman tool CSVs (AmcacheParser, AppCompatCacheParser, PECmd, MFTECmd):
python -I skills/disk-forensics/scripts/artifact_hunt.py --input artifacts.json --ez-csv amcache.csv shimcache.csv pecmd.csv --out-dir case/disk
```
Findings: `ARG-DF-001` execution of suspicious binary (user path, attacker tool names, wrong-path system names),
`ARG-DF-002` deleted executable in Recycle Bin. Output also `execution-timeline.json`.

## Deep pass (offline parsers)
[artifact-catalog.md](references/artifact-catalog.md) — what each artefact proves, location, parser, retention.
[timeline-method.md](references/timeline-method.md) — super-timeline + pivoting around the first malicious event.
