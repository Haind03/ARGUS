---
name: reporting-discipline
description: Use when writing or reviewing an ARGUS hunt / incident report — structure, confidence language (confirmed vs suspected), ATT&CK mapping and Navigator layer, collection gaps, recommended actions, privacy of personal data, and the gate that blocks FINAL reports with undispositioned high/critical findings.
---

# Reporting discipline

**Iron law: say only what the evidence supports.** "Confirmed" requires a `true_positive` disposition
with validation notes; everything else is "suspected", "lead" or "not observed (with gaps)".

## Produce
```bash
python -I engine/argus_cli.py case report --case argus-cases/pc1 --input telemetry.json   # FINAL (gate enforced)
python -I engine/argus_cli.py case report --case ... --draft                               # DRAFT, clearly labelled
python -I skills/reporting-discipline/scripts/report_lint.py argus-cases/pc1/reports/argus-case-pc1.md
```
Outputs: JSON (`argus.findings/1`), Markdown, ATT&CK Navigator layer (import at
https://mitre-attack.github.io/attack-navigator/ → Open Existing Layer → Upload).

## Structure
1. Executive summary (plain language: is the PC compromised? what should the user do now?)
2. Scope & method (machine, time window, preset/workflow, baseline, online intel on/off)
3. Findings by severity — technique, evidence, confidence, disposition, recommended action
4. ATT&CK view (Navigator layer) — covered vs observed
5. Timeline (if incident)
6. Collection gaps & limitations
7. Actions taken (only with IR opt-in, from response-log) and next steps

## Language
| Evidence | Wording |
|---|---|
| TP disposition + validation | "confirmed" |
| high score, not validated | "suspicious — requires validation" |
| no findings, gaps present | "not observed in available data (gaps: …)" |
| no findings, good coverage | "no indicators found for the tested hypotheses" |

## Privacy
Redact other people's names/emails, browsing history details, and secrets found in command lines
before sharing a report. Never include RAM excerpts with credentials.

Template: [report-template.md](references/report-template.md)
