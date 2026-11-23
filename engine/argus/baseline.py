"""Baseline snapshot + diff.

A baseline is the set of artifact keys (autoruns, tasks, services, drivers,
WMI consumers, Defender exclusions, listening ports, ...) observed on a host
the user believes is clean.  Scheduled scans then (1) down-weight findings
already in the baseline and (2) report *new* persistence-class artifacts even
when no rule fires.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from . import BASELINE_SCHEMA
from . import indicators as I
from .hunt import run_rules
from .rules import _norm_cmd


def inventory(tel: dict[str, Any]) -> dict[str, set[str]]:
    def sec(name):
        v = tel.get(name) or []
        return [x for x in (v if isinstance(v, list) else [v]) if isinstance(x, dict)]

    inv: dict[str, set[str]] = {
        "autoruns": {f"{str(a.get('location','')).lower()}|{a.get('name','')}|{_norm_cmd(str(a.get('value','')))}"
                     for a in sec("autoruns")},
        "scheduled_tasks": {f"{str(t.get('path','')).lower()}{str(t.get('name','')).lower()}|"
                            f"{_norm_cmd(' ; '.join(map(str, t.get('actions') or [])))}" for t in sec("scheduled_tasks")},
        "services": {f"{str(s.get('name','')).lower()}|{_norm_cmd(str(s.get('path','')))}" for s in sec("services")},
        "drivers": {f"{I.basename(d.get('path')) or str(d.get('name','')).lower()}|{d.get('sha256','')}" for d in sec("drivers")},
        "wmi_subscriptions": {f"{str(w.get('consumer','')).lower()}|{_norm_cmd(str(w.get('command','')))}"
                              for w in sec("wmi_subscriptions")},
        "listening_ports": {f"{c.get('proto','tcp')}|{c.get('lport')}|{str(c.get('process','')).lower()}"
                            for c in sec("network") if str(c.get("state", "")).lower() in ("listen", "listening")},
        "local_admins": {str(x).lower() for x in (tel.get("local_admins") or [])},
        "browser_extensions": {f"{e.get('browser','')}|{e.get('id','')}" for e in sec("browser_extensions")},
        "process_images": {I.norm_path(p.get("path")) for p in sec("processes") if p.get("path")},
    }
    d = tel.get("defender") if isinstance(tel.get("defender"), dict) else {}
    inv["defender_exclusions"] = {f"{k}|{str(v).lower()}" for k in ("exclusions_path", "exclusions_process",
                                                                     "exclusions_extension") for v in (d.get(k) or [])}
    return inv


def create(tel: dict[str, Any]) -> dict[str, Any]:
    inv = inventory(tel)
    # finding keys are stored so known-noisy findings get down-weighted later
    finding_keys = sorted({f.key for f in run_rules(tel, {"min_score": 0})})
    host = tel.get("host") if isinstance(tel.get("host"), dict) else {}
    return {
        "schema": BASELINE_SCHEMA,
        "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "hostname": host.get("hostname"),
        "shadow_copies": tel.get("shadow_copies"),
        "inventory": {k: sorted(v) for k, v in inv.items()},
        "finding_keys": finding_keys,
        "note": "Baseline assumes the host was clean when captured. Re-baseline only after a clean hunt.",
    }


def diff(baseline: dict[str, Any], tel: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    cur = inventory(tel)
    old = {k: set(v) for k, v in (baseline.get("inventory") or {}).items()}
    out = {}
    for k in sorted(set(cur) | set(old)):
        added = sorted(cur.get(k, set()) - old.get(k, set()))
        removed = sorted(old.get(k, set()) - cur.get(k, set()))
        if added or removed:
            out[k] = {"added": added, "removed": removed}
    return out


def diff_findings(delta: dict[str, dict[str, list[str]]]) -> list[dict[str, Any]]:
    """Convert inventory additions in persistence-class categories into review items."""
    weights = {"autoruns": ("TA0003", "T1547.001", 30), "scheduled_tasks": ("TA0003", "T1053.005", 30),
               "services": ("TA0003", "T1543.003", 30), "drivers": ("TA0004", "T1068", 30),
               "wmi_subscriptions": ("TA0003", "T1546.003", 45), "defender_exclusions": ("TA0005", "T1562.001", 40),
               "local_admins": ("TA0003", "T1098", 40), "listening_ports": ("TA0011", "T1571", 15),
               "browser_extensions": ("TA0003", "T1176", 20)}
    items = []
    for cat, ch in delta.items():
        if cat not in weights:
            continue
        tac, tech, score = weights[cat]
        for a in ch["added"]:
            items.append({"rule_id": "ARG-BL-NEW", "title": f"New {cat.replace('_', ' ')} since baseline",
                          "tactic": tac, "technique": tech, "artifact": {"category": cat, "entry": a},
                          "key": f"bl|{cat}|{a}", "signals_matched": ["new_since_baseline"], "score": score,
                          "severity": "low" if score < 40 else "medium",
                          "action": "Confirm the user installed/changed this since the baseline date."})
    return items
