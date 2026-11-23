#!/usr/bin/env python3
"""Regenerate the 12 per-tactic hunting skills + skills/references/ttp-index.json from tools/techdata.py.
python -I tools/gen_tactic_skills.py  (overwrites generated SKILL.md / references / wrapper scripts)"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from techdata import T

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE = ("> **Scope:** run only on a machine you own or are explicitly authorised to examine. "
         "This skill is **detect-only**: it reads artefacts and scores them. Any containment or removal "
         "goes through `incident-response` and requires explicit opt-in.")


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60]


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


index = {"schema": "argus.ttp-index/1", "techniques": {}}

for tid, skill, tname, sections, use_when, techs in T:
    d = f"{ROOT}/skills/{skill}"
    refs = []
    for (xid, name, ds, hyp, logic, fps, rules) in techs:
        fn = f"{xid}-{slug(name)}.md"
        refs.append((xid, name, fn, rules))
        index["techniques"].setdefault(xid, {"name": name, "tactics": [], "rules": [], "references": []})
        e = index["techniques"][xid]
        if tid not in e["tactics"]:
            e["tactics"].append(tid)
        e["rules"] = sorted(set(e["rules"]) | set(rules))
        e["references"].append(f"skills/{skill}/references/{fn}")
        w(f"{d}/references/{fn}", f"""# {xid}, {name}

| Field | Value |
|---|---|
| ATT&CK | [{xid}](https://attack.mitre.org/techniques/{xid.replace('.', '/')}/) |
| Tactic | {tid} {tname} |
| ARGUS rules | {', '.join('`'+r+'`' for r in rules)} |

## Data sources needed
{ds}

## Hunt hypothesis
{hyp}

## Detection logic
{logic}

Run only this tactic:

```bash
python -I engine/argus_cli.py hunt --input <telemetry.json> --tactics {tid}
python -I engine/argus_cli.py rules --tactic {tid}
```

## Manual validation steps
1. Pull the full artefact from the finding (`artifact` block), path, command line, registry value, event.
2. Hash and copy it as evidence **before** any change (evidence-discipline).
3. Check signer, creation time and parent chain; correlate ±10 min in Sysmon/Security logs.
4. Compare with the baseline (`argus diff`), was it present on the clean snapshot?
5. Decide: true positive → incident-response (opt-in) · false positive → document + tune.

## Common false positives
{fps}

## Rationalizations to reject
- "It's signed, so it's fine.", signed LOLBins and stolen certificates are the norm for this technique.
- "Score is low, skip it.", low scores are leads; correlate with other tactics before closing.
- "Delete it now to be safe.", destroys evidence; detect-only until the user opts in.
""")
    rows = "\n".join(f"| `{x}` | {n} | [{fn}](references/{fn}) | {', '.join(r)} |" for x, n, fn, r in refs)
    cname = "".join(p.capitalize() for p in skill.split("-")[:-1]) or skill
    w(f"{d}/SKILL.md", f"""---
name: {skill}
description: Use when {use_when} on the user's own Windows PC (MITRE ATT&CK {tid} {tname}).
---

# {tname} hunting ({tid})

{SCOPE}

## When to use
Use when {use_when}. Typically invoked by `hunt-methodology` as one phase of `workflows/full-hunt.yml`,
or directly when a lead points at this tactic.

## Workflow
1. **Collect** (read-only, elevated prompt recommended):
   ```powershell
   powershell -NoProfile -ExecutionPolicy RemoteSigned -File skills\\{skill}\\scripts\\Collect-{cname}.ps1
   ```
   (wraps `telemetry-collection` with sections: `{sections}`)
2. **Detect / score**:
   ```bash
   python -I skills/{skill}/scripts/hunt_{skill.replace('-', '_')}.py --input <telemetry.json> [--baseline <baseline.json>]
   ```
3. **Validate** each finding with the matching reference below + `false-positive-discipline`.
4. **Record** evidence (`evidence-discipline`) and hand off to `reporting-discipline`.

## Technique references
| ATT&CK | Technique | Reference | Rules |
|---|---|---|---|
{rows}

## Output
Each finding: `artifact`, `technique`, `signals_matched`, `score` (0-100), `severity`, `action`
(recommended analyst action). Scores are heuristic, never report a finding as confirmed without validation.

## Hand-off
- Confirmed malicious → `incident-response` (opt-in only), `malware-triage` for the binary.
- Unknown binary → `malware-triage`; online hash lookup only via `threat-intel-enrichment` (opt-in).
- Need deeper proof → `memory-acquisition` + `memory-forensics` / `process-memory-analysis`,
  `disk-forensics` (execution timeline), `eventlog-forensics`, `network-forensics`, `browser-forensics`.
- Gap in coverage → `yara-sigma-authoring`.
""")
    w(f"{d}/scripts/Collect-{cname}.ps1", f"""<#
.SYNOPSIS
  Read-only collector for {tname} ({tid}). Wraps telemetry-collection.
  Authorised use on your own machine only. Makes no system changes.
#>
param([string]$OutFile, [int]$EventHours = 72, [switch]$HashProcesses)
$collector = Join-Path $PSScriptRoot '..\\..\\telemetry-collection\\scripts\\Collect-Telemetry.ps1'
$collector = (Resolve-Path -LiteralPath $collector).Path
$args2 = @{{ Sections = '{sections}'; EventHours = $EventHours }}
if ($OutFile) {{ $args2.OutFile = $OutFile }}
if ($HashProcesses) {{ $args2.HashProcesses = $true }}
& $collector @args2
""")
    w(f"{d}/scripts/hunt_{skill.replace('-', '_')}.py", f'''#!/usr/bin/env python3
"""{tname} ({tid}) detector, thin wrapper over the ARGUS engine. Run with: python -I {skill.replace('-', '_')}.py"""
import sys
from pathlib import Path

_here = Path(__file__).resolve()
for _p in [*_here.parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
else:
    sys.exit("argus: cannot locate engine/ (keep the skill inside the ARGUS repo or ~/.claude/argus)")

import argus_cli  # noqa: E402

if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print("usage: hunt_{skill.replace('-', '_')}.py --input TELEMETRY.json [--baseline B.json] [--out-dir DIR] [--online]")
        sys.exit(0)
    sys.exit(argus_cli.main(["hunt", "--tactics", "{tid}", *argv]))
''')

# pre-compromise tactics: documented, not host-observable
index["out_of_host_scope"] = {
    "TA0043": "Reconnaissance, happens on attacker infrastructure; at most visible as inbound scans in firewall logs.",
    "TA0042": "Resource Development, attacker infrastructure; consume as threat-intel IOCs (domains/IPs) only.",
}
with open(f"{ROOT}/skills/references/ttp-index.json", "w", encoding="utf-8") as f:
    json.dump(index, f, indent=2, sort_keys=True)
print(len(index["techniques"]), "techniques")
