---
name: writing-defensive-skills
description: Use when creating or editing an ARGUS skill, reference, collector or detector — frontmatter conventions ("Use when..."), mandatory scope/detect-only statements, ATT&CK-referenced technique files, read-only collectors, `python -I` detectors with safe path handling, AV-safe content, tests, and regenerating skills-lock.json.
---

# Writing defensive skills

## Skill layout
```
skills/<name>/
  SKILL.md          frontmatter: name (= dir), description starting "Use when ..."
  references/       one file per technique/topic; ATT&CK ID, data sources, hypothesis, logic, FPs
  scripts/          collectors (PowerShell, read-only, JSON out) + detectors (Python, run with -I)
```
Per-tactic skills are **generated**: edit `tools/techdata.py`, run `python -I tools/gen_tactic_skills.py`.

## Mandatory content
- Scope line: own/authorised machine only; detect-only (or, for IR, opt-in + dry-run default).
- Hand-offs to other skills; "Rationalizations to reject" for discipline skills.
- References cite ATT&CK IDs (`T1234.001`) and list false positives.

## Script rules
| Rule | Why |
|---|---|
| Collectors never write outside their output file | detect-only |
| Python detectors: `python -I`, locate `engine/` by walking parents, use `argus.safeio` for every input path (no symlinks, size caps) | untrusted input, import hijack |
| Never execute, import or `eval` collected content | samples are hostile |
| State-changing scripts: dry-run default, explicit switch (`-Execute`, `-Acquire`, `-Apply`, `-Register`) | opt-in |
| No network calls except opt-in intel (SHA-256 only) | privacy |
| AV-safe: no contiguous attack-tool literals, no embedded dumping/injection/AMSI code; test data built from fragments | Defender must not flag the toolkit |
| No AI/tool attribution in code, commits, docs | project rule |

## Before committing
```bash
python -I skills/writing-defensive-skills/scripts/validate_skills.py
python -I skills/yara-sigma-authoring/scripts/validate_rules.py
python -m pytest -q
python -I tools/lock.py          # refresh skills-lock.json
```
