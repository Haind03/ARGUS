---
name: false-positive-discipline
description: Use when about to call ANY ARGUS finding malicious or benign, validating heuristic scores against signer, path, parent, timing, baseline and known software; recording dispositions; and tuning suppressions so scheduled scans stay quiet without hiding real threats.
---

# False-positive discipline

> **Scope:** findings from the user's own, authorised machine. Validation is read-only (detect-only).

**Iron law: no verdict without validation.** A score is a lead. "Benign" needs a reason as much as "malicious" does.

## Validate every high/critical finding
| Question | Check |
|---|---|
| Who signed it? | `Get-AuthenticodeSignature`, valid + expected vendor? revoked? |
| Where does it live? | vendor folder vs Temp/Public/random AppData folder |
| Who started it? | parent chain (explorer/services vs Office/script host) |
| When did it appear? | baseline diff, file creation time vs user activity, install logs |
| Is it explainable? | user installed it? matches [false-positive-catalog](../references/false-positive-catalog.md)? |
| Independent corroboration? | second tactic hit (persistence + C2 on the same binary) raises confidence |

## Record
```bash
python -I engine/argus_cli.py case dispose --case <dir> --key F-xxxxxxxxxx --verdict false_positive \
       --note "Logitech G HUB updater, signed Logitech Inc, present in baseline since 2026-10"
```
Verdicts: `true_positive`, `false_positive`, `benign_expected`, `needs_more_data`. FP/benign require a ≥10-char reason.

## Tune (without blinding yourself)
`python -I skills/false-positive-discipline/scripts/fp_tune.py --case <dir> --out suppress.json` exports
FP/benign keys → `argus hunt --suppress suppress.json` down-weights exactly those artefacts (× 0.3), the
same binary at a **new path or with a new command line** produces a new key and alerts again.
Never disable a whole rule because of one FP; never suppress by name alone.

## Rationalizations to reject
- "It's signed by Microsoft" → LOLBins are signed by Microsoft.
- "It's been there for months" → so has plenty of malware; check the baseline date and origin.
- "Too many findings, suppress them all" → dispose individually; tune the rule if a class is noisy.
