#!/usr/bin/env python3
"""Re-enrich an existing argus.findings/1 JSON. Offline unless --online / ARGUS_INTEL_ONLINE=1 AND API keys set.

python -I enrich.py --findings report.json [--online] [--out enriched.json]
"""
import argparse
import json
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        ROOT = _p
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import intel  # noqa: E402
from argus.safeio import load_json  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--online", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = load_json(a.findings)
    hashes = sorted({str(f.get("artifact", {}).get("sha256") or "").lower() for f in res.get("findings", [])} - {""})
    if intel.online_enabled(a.online):
        print(f"[intel] ONLINE mode: up to {min(25, len(hashes))} SHA-256 hashes may be sent to configured providers.",
              file=sys.stderr)
    summary = intel.enrich_findings(res.get("findings", []), ROOT / "skills" / "references" / "ioc", online=a.online)
    res["intel"] = summary
    out = Path(a.out or a.findings)
    if out.is_symlink():
        sys.exit("refusing symlinked output")
    out.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
