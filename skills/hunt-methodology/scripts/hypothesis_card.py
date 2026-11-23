#!/usr/bin/env python3
"""Write hypothesis cards (Markdown) for each phase of a workflow into a case folder.

python -I hypothesis_card.py --case argus-cases/pc1 [--workflow full-hunt]
Fills verdicts from phases/<id>.json when the workflow has already run.
"""
import argparse
import json
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
import argus_cli  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--workflow", default="full-hunt")
    a = ap.parse_args()
    case = Path(a.case).resolve(strict=True)
    wf = argus_cli.load_workflow(a.workflow)
    lines = [f"# Hypothesis cards — {wf.get('name')}", ""]
    for ph in wf.get("phases", []):
        res = case / "phases" / f"{ph['id']}.json"
        verdict, n = "not run", "-"
        if res.is_file():
            d = json.loads(res.read_text(encoding="utf-8"))["phase"]
            verdict, n = d.get("hypothesis_verdict", "-"), d.get("findings", "-")
        lines += [f"## {ph.get('name')}", f"- **Hypothesis:** {ph.get('hypothesis')}",
                  f"- **Skills:** {', '.join(ph.get('skills', []))}", f"- **Tactics:** {', '.join(ph.get('tactics', [])) or '-'}",
                  f"- **Findings:** {n}  |  **Verdict:** {verdict}", "- **Analyst notes:** ", ""]
    out = case / "hypothesis-cards.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
