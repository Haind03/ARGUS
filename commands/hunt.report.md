---
description: Build the final hunt report (JSON + Markdown + ATT&CK Navigator layer) with the disposition gate
argument-hint: "[case-dir] [--draft]"
---

# /hunt.report

1. Load `reporting-discipline`.
2. List open findings: `python -I engine/argus_cli.py case findings --case <case-dir>`
   — every high/critical needs a disposition (`false-positive-discipline`); ask the user where judgement is needed.
3. Build: `python -I engine/argus_cli.py case report --case <case-dir> --input <telemetry.json>` (add `--draft` only if the user accepts a DRAFT).
4. Lint: `python -I skills/reporting-discipline/scripts/report_lint.py <case-dir>/reports/argus-case-<name>.md`
5. Give the user: executive summary, top findings with confidence, what to do now, and where the Navigator layer is
   (import at https://mitre-attack.github.io/attack-navigator/).

Arguments: $ARGUMENTS
