"""Hunt orchestration: run rules over telemetry, apply baseline, filter by preset."""
from __future__ import annotations

import datetime as _dt
import platform
from typing import Any

from . import FINDINGS_SCHEMA, __version__
from .rules import RULES, TACTICS, Context
from .scoring import Finding, at_least


def run_rules(tel: dict[str, Any], preset: dict[str, Any] | None = None,
              baseline_keys: set[str] | None = None) -> list[Finding]:
    preset = preset or {}
    tactics = set(preset.get("tactics") or TACTICS.keys())
    disabled = set(preset.get("disabled_rules") or [])
    only = set(preset.get("only_rules") or [])
    min_score = int(preset.get("min_score", 20))
    weight_overrides: dict[str, int] = preset.get("signal_weight_overrides") or {}
    baseline_keys = baseline_keys or set()

    ctx = Context(tel)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for r in RULES:
        if r.tactic not in tactics or r.rule_id in disabled or (only and r.rule_id not in only):
            continue
        try:
            candidates = list(r.fn(ctx))
        except Exception as exc:  # a broken rule must never kill the hunt
            findings.append(Finding(rule_id=r.rule_id, title=f"Rule error: {r.title}", tactic=r.tactic,
                                    technique=r.technique, artifact={"error": repr(exc)}, key=f"err|{r.rule_id}",
                                    action="Report this rule error; telemetry shape may differ from schema.").finalize())
            continue
        for c in candidates:
            if (r.rule_id, c.key) in seen:
                continue
            seen.add((r.rule_id, c.key))
            for s in c.signals:
                if s.name in weight_overrides:
                    s.weight = int(weight_overrides[s.name])
            if sum(1 for s in c.signals if s.weight > 0) < r.min_signals:
                continue
            f = Finding(rule_id=r.rule_id, title=r.title, tactic=r.tactic, technique=c.technique or r.technique,
                        artifact=c.artifact, key=c.key, signals=c.signals, action=r.action,
                        baseline_known=c.key in baseline_keys).finalize()
            if f.score >= min_score:
                findings.append(f)
    findings.sort(key=lambda f: (-f.score, f.tactic, f.rule_id))
    return findings


def build_result(tel: dict[str, Any], findings: list[Finding], preset_name: str,
                 baseline_used: bool) -> dict[str, Any]:
    host = tel.get("host") if isinstance(tel.get("host"), dict) else {}
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    by_tactic: dict[str, int] = {}
    for f in findings:
        by_tactic[f.tactic] = by_tactic.get(f.tactic, 0) + 1
    return {
        "schema": FINDINGS_SCHEMA,
        "argus_version": __version__,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "analysis_host": platform.node(),
        "target_host": host.get("hostname"),
        "telemetry_collected_at": tel.get("collected_at"),
        "preset": preset_name,
        "baseline_applied": baseline_used,
        "mode": "detect-only",
        "summary": {"total": len(findings), "by_severity": sev, "by_tactic": by_tactic,
                    "top_score": findings[0].score if findings else 0},
        "collection_gaps": tel.get("collection_errors") or [],
        "findings": [f.to_dict() for f in findings],
    }


def filter_severity(findings: list[Finding], minimum: str) -> list[Finding]:
    return [f for f in findings if at_least(f.severity, minimum)]
