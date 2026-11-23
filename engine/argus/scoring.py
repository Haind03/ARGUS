"""Heuristic scoring model.

score = clamp(sum(signal.weight), 0, 100)
Negative weights are mitigating signals (e.g. valid Microsoft signature).
A finding whose artifact key exists in the baseline is down-weighted (x0.3)
instead of dropped, so analysts can still see it at low severity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_BANDS = ((80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "info"))
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BASELINE_FACTOR = 0.3


@dataclass
class Signal:
    name: str
    weight: int
    detail: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    tactic: str
    technique: str
    artifact: dict[str, Any]
    key: str
    signals: list[Signal] = field(default_factory=list)
    action: str = ""
    score: int = 0
    severity: str = "info"
    baseline_known: bool = False
    intel: dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> "Finding":
        self.score = compute_score(self.signals)
        if self.baseline_known:
            self.score = int(round(self.score * BASELINE_FACTOR))
        self.severity = severity_for(self.score)
        return self

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = finding_id(self.rule_id, self.key)
        d["signals_matched"] = [s.name for s in self.signals]
        return d


def finding_id(rule_id: str, key: str) -> str:
    """Short stable ID analysts can type (rule + artifact key)."""
    import hashlib
    return "F-" + hashlib.sha1(f"{rule_id}|{key}".encode()).hexdigest()[:10]


def compute_score(signals: list[Signal]) -> int:
    total = sum(int(s.weight) for s in signals)
    return max(0, min(100, total))


def severity_for(score: int) -> str:
    for floor, name in SEVERITY_BANDS:
        if score >= floor:
            return name
    return "info"


def at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)
