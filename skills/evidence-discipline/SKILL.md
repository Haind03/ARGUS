---
name: evidence-discipline
description: Use when about to change anything on a possibly compromised PC and whenever collecting artefacts, hashing and copying files read-only into the case, chain of custody, order of volatility, protecting sensitive evidence (memory, browser data), and keeping the hunt reproducible.
---

# Evidence discipline

> **Scope:** evidence from the user's own, authorised machine; handling is read-only on the source.

**Iron law: preserve before you change.** Every artefact that supports a finding is hashed and copied
into the case before any response action.

## Do
```bash
python -I skills/evidence-discipline/scripts/evidence_hash.py --case argus-cases/pc1 --file "C:\Users\bob\AppData\Local\Temp\x.exe" --note "ARG-EX-006 F-1a2b3c4d5e"
python -I engine/argus_cli.py case verify --case argus-cases/pc1      # audit chain integrity
```
- Copies are read-only on the source, stored as `evidence/<sha256>.bin` (no executable extension), with
  `custody.jsonl` (who/when/where-from/hash).
- Order of volatility: memory → network connections → processes → temp files → logs → disk.
- Record time zone (UTC everywhere), host name, tool versions (collector/engine version in outputs).
- Sensitive evidence (RAM, browser DBs, Security log): keep on encrypted storage (BitLocker To Go / VeraCrypt), never upload.

## Don't
- Open, run, or "check" a sample by double-clicking.
- Copy samples into synced folders (OneDrive/Dropbox upload them).
- Let cleaners run before collection.
- Overwrite telemetry, every collection is a new timestamped file.

Reference: [chain-of-custody.md](references/chain-of-custody.md)
