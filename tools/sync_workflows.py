#!/usr/bin/env python3
"""Regenerate workflows/*.json twins from workflows/*.yml (needs PyYAML; dev-time only). python -I tools/sync_workflows.py [--check]"""
import json
import sys
from pathlib import Path

import yaml

root = Path(__file__).resolve().parent.parent / "workflows"
check = "--check" in sys.argv
bad = 0
for y in sorted(root.glob("*.yml")):
    data = json.dumps(yaml.safe_load(y.read_text(encoding="utf-8")), indent=2, ensure_ascii=False) + "\n"
    j = y.with_suffix(".json")
    if check:
        if not j.is_file() or j.read_text(encoding="utf-8") != data:
            print(f"out of date: {j.name}")
            bad += 1
    else:
        j.write_text(data, encoding="utf-8")
        print(f"wrote {j.name}")
sys.exit(1 if bad else 0)
