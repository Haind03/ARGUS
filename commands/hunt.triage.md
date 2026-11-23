---
description: Static triage of a suspicious file (never executed), hashes, PE, entropy, strings, YARA, offline IOCs
argument-hint: "<path-to-file> [--online]"
---

# /hunt.triage

1. `scope-discipline` (file comes from the user's own machine), `evidence-discipline`:
   `python -I skills/evidence-discipline/scripts/evidence_hash.py --file "$1"` (add `--case <dir>` if a case is open).
2. `malware-triage`: `python -I engine/argus_cli.py triage "$1" --out-dir argus-reports/triage`
   Do **not** open, run, unzip-and-run or upload the file.
3. If the user passed `--online` **and** has `VT_API_KEY`/`ABUSECH_AUTH_KEY` set, tell them exactly which SHA-256
   will be sent, then re-run with `--online` (`threat-intel-enrichment`).
4. Explain the signals (static-triage-playbook) and give a verdict with confidence, plus next steps
   (`process-memory-analysis` if it is running, `yara-sigma-authoring` to write a rule).

Arguments: $ARGUMENTS
