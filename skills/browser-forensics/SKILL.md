---
name: browser-forensics
description: Use when the infection vector may be the web browser on the user's own PC, risky downloads (EXE/ISO/LNK/JS, double extensions, fake browser updates, raw-IP or paste/tunnel hosts), visits to malicious infrastructure, rogue extensions, or infostealer exposure of saved passwords/cookies, for Chrome, Edge, Brave, Vivaldi, Opera and Firefox.
---

# Browser forensics

> **Scope:** the user's own browser profiles, with their consent, history is personal data. The
> script copies the SQLite DBs into the case folder and reads the copies **read-only**; only flagged
> rows and counts go into findings.

## Run
```bash
python -I skills/browser-forensics/scripts/browser_hunt.py --out-dir E:\case01\browser --days 30
```
Findings: `ARG-BR-001` risky download (raw IP / paste-tunnel host / double extension / container or
script / fake-update name; vendor domains mitigate), `ARG-BR-002` visits to paste/tunnel/fake-update infra.
Extensions are covered by the main collector (`ARG-PE-012`).

## If an infostealer is confirmed
Saved passwords, cookies (session tokens) and autofill must be considered stolen:
[infostealer-response.md](references/infostealer-response.md). Artefact locations: [browser-artifacts.md](references/browser-artifacts.md).
