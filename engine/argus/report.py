"""Report writers: Markdown hunt report + MITRE ATT&CK Navigator layer."""
from __future__ import annotations

from typing import Any

from . import SIGNATURE
from .rules import TACTICS, TACTIC_SHORTNAME, covered_techniques

SEV_COLOR = {"critical": "#d7191c", "high": "#fd8d3c", "medium": "#fecc5c", "low": "#a6d96a", "info": "#e0e0e0"}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _md_escape(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ").replace("`", "'")[:300]


def markdown(result: dict[str, Any], baseline_delta: dict | None = None) -> str:
    s = result["summary"]
    sev = s["by_severity"]
    lines = [
        f"# ARGUS Hunt Report, {result.get('target_host') or 'unknown host'}",
        "",
        f"- Generated: `{result['generated_at']}`  |  Telemetry: `{result.get('telemetry_collected_at')}`",
        f"- Preset: `{result['preset']}`  |  Baseline applied: `{result['baseline_applied']}`  |  Mode: **{result['mode']}**",
        f"- Findings: **{s['total']}**, critical {sev.get('critical',0)}, high {sev.get('high',0)}, "
        f"medium {sev.get('medium',0)}, low {sev.get('low',0)}",
        "",
        "> Scope: this report covers only the user's own, authorized machine. Scores are heuristic leads, "
        "not verdicts, every finding needs analyst validation (see false-positive-discipline).",
        "",
        "## Executive summary",
        "",
    ]
    if sev.get("critical") or sev.get("high"):
        lines.append("High-priority leads exist. Validate the top findings first; if any ransomware (TA0040) or "
                     "credential-dumping (TA0006) finding is confirmed, isolate the host from the network before anything else.")
    elif s["total"]:
        lines.append("Only low/medium-confidence leads. Review them against the baseline and known software.")
    else:
        lines.append("No findings above threshold. This is not proof of a clean host, check collection gaps below.")
    lines += ["", "## Findings by tactic", "", "| Tactic | Count |", "|---|---|"]
    for tid, name in TACTICS.items():
        n = s["by_tactic"].get(tid, 0)
        if n:
            lines.append(f"| {tid} {name} | {n} |")
    lines += ["", "## Findings", "", "| # | Sev | Score | Technique | Rule | Title | Artifact |", "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(result["findings"], 1):
        art = f["artifact"]
        short = art.get("path") or art.get("cmdline") or art.get("value") or art.get("task") or art.get("service") \
            or art.get("domain") or art.get("remote") or next(iter(art.values()), "") if isinstance(art, dict) else art
        lines.append(f"| {i} | {f['severity']} | {f['score']} | {f['technique']} | {f['rule_id']} | "
                     f"{_md_escape(f['title'])} | `{_md_escape(short)}` |")
    lines += ["", "## Finding details", ""]
    for i, f in enumerate(result["findings"][:100], 1):
        lines += [f"### {i}. [{f['severity'].upper()} {f['score']}] {f['title']}",
                  f"- ATT&CK: `{f['technique']}` ({f['tactic']} {TACTICS.get(f['tactic'],'')})",
                  f"- Rule: `{f['rule_id']}`{', *known in baseline (down-weighted)*' if f.get('baseline_known') else ''}",
                  "- Signals: " + ", ".join(f"`{sg['name']}`({sg['weight']:+d}{': ' + _md_escape(sg['detail'])[:80] if sg.get('detail') else ''})"
                                           for sg in f["signals"]),
                  "- Artifact:", "", "```json"]
        import json
        lines.append(json.dumps(f["artifact"], indent=2, ensure_ascii=False, default=str)[:2000])
        lines += ["```", f"- **Recommended analyst action:** {f['action']}"]
        if f.get("intel"):
            lines.append(f"- Intel (opt-in): `{_md_escape(f['intel'])}`")
        lines.append("")
    if baseline_delta:
        lines += ["## Changes since baseline", ""]
        for cat, ch in baseline_delta.items():
            lines.append(f"**{cat}**, +{len(ch['added'])} / -{len(ch['removed'])}")
            for a in ch["added"][:25]:
                lines.append(f"- + `{_md_escape(a)}`")
            lines.append("")
    gaps = result.get("collection_gaps") or []
    lines += ["## Collection gaps", ""]
    lines += [f"- {_md_escape(g)}" for g in gaps] or ["- none reported by collector"]
    lines += ["", "## Next steps", "",
              "1. Validate top findings (evidence-discipline: hash + copy artefacts before any change).",
              "2. Mark confirmed false positives in the baseline / preset `disabled_rules`.",
              "3. Remediation is **opt-in** via the incident-response skill (`-WhatIf` first).", ""]
    lines += ["---", f"*{SIGNATURE}*", ""]
    return "\n".join(lines)


def navigator_layer(result: dict[str, Any], name: str = "ARGUS hunt") -> dict[str, Any]:
    best: dict[tuple[str, str], dict] = {}
    for f in result["findings"]:
        k = (f["technique"], f["tactic"])
        if k not in best or f["score"] > best[k]["score"]:
            best[k] = f
    techniques = []
    for tech, tactics in sorted(covered_techniques().items()):
        for tac in sorted(tactics):
            if (tech, tac) in best:
                continue
            techniques.append({"techniqueID": tech, "tactic": TACTIC_SHORTNAME[tac], "color": "#cfe2f3",
                               "comment": "Covered by ARGUS rule; no finding this run", "enabled": True,
                               "metadata": [{"name": "status", "value": "covered"}]})
    for (tech, tac), f in sorted(best.items()):
        techniques.append({"techniqueID": tech, "tactic": TACTIC_SHORTNAME.get(tac, ""), "score": f["score"],
                           "color": SEV_COLOR.get(f["severity"], "#e0e0e0"),
                           "comment": f"{f['rule_id']}: {f['title']}", "enabled": True,
                           "metadata": [{"name": "status", "value": "finding"},
                                        {"name": "severity", "value": f["severity"]}]})
    return {
        "name": name, "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{SIGNATURE}. Findings for {result.get('target_host')} at {result['generated_at']} "
                       "(light blue = covered, coloured = finding severity)",
        "filters": {"platforms": ["Windows"]}, "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False, "techniques": techniques,
        "gradient": {"colors": ["#a6d96a", "#fecc5c", "#d7191c"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": k, "color": v} for k, v in SEV_COLOR.items()] +
                       [{"label": "covered (no finding)", "color": "#cfe2f3"}],
    }


def coverage_layer() -> dict[str, Any]:
    empty = {"findings": [], "generated_at": "static", "target_host": "coverage"}
    layer = navigator_layer(empty, "ARGUS detection coverage")
    layer["description"] = "Techniques with at least one ARGUS heuristic rule"
    return layer
