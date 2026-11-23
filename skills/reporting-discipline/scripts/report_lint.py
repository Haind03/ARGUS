#!/usr/bin/env python3
"""Lint an ARGUS Markdown report (and its JSON twin if present). python -I report_lint.py <report.md>

Checks: required sections, DRAFT label consistency, 'confirmed' wording only with true_positive
dispositions, collection-gaps section present, obvious secrets/PII (emails, API-key-like tokens).
Exit 1 on errors.
"""
import json
import re
import sys
from pathlib import Path

REQUIRED = ["## Executive summary", "## Findings", "## Collection gaps", "## Next steps"]
SECRET = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abp]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def main(argv):
    if len(argv) != 1:
        print("usage: report_lint.py <report.md>")
        return 2
    md = Path(argv[0])
    text = md.read_text(encoding="utf-8")
    errs, warns = [], []
    for s in REQUIRED:
        if s not in text:
            errs.append(f"missing section: {s}")
    js = md.with_suffix(".json")
    if js.is_file():
        res = json.loads(js.read_text(encoding="utf-8"))
        tp = [f for f in res.get("findings", []) if (f.get("disposition") or {}).get("verdict") == "true_positive"]
        if re.search(r"\bconfirmed\b", text, re.I) and not tp and "requires validation" not in text:
            errs.append("report says 'confirmed' but no finding has a true_positive disposition")
        if str(res.get("status", "")).startswith("DRAFT") and "DRAFT" not in text:
            errs.append("JSON status is DRAFT but Markdown is not labelled DRAFT")
    if SECRET.search(text):
        errs.append("possible secret/token in report — redact before sharing")
    if EMAIL.search(text):
        warns.append("email address present — redact third-party PII before sharing")
    for e in errs:
        print("ERROR:", e)
    for w in warns:
        print("WARN:", w)
    print("ok" if not errs else f"{len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
