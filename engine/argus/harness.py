"""ARGUS defensive harness: case management, phase runner, gates, dispositions, audit chain.

A *case* is a directory:
  case.json          scope attestation, mode, ir_optin (expiring), workflow, created
  audit.jsonl        append-only, SHA-256 hash-chained log of every harness action
  phases/<id>.json   per-phase results (findings, hypothesis verdict, gate result)
  dispositions.json  analyst verdicts per finding key
  evidence/          hashed copies (evidence-discipline)
  reports/           final outputs (JSON / Markdown / Navigator)

Gates are fail-closed: a failed gate stops the run and says why.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from . import report as R
from .hunt import build_result, run_rules
from .rules import TACTICS
from .safeio import safe_child, safe_output_dir, write_json, write_text

VERDICTS = ("true_positive", "false_positive", "benign_expected", "needs_more_data")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------------------------- audit
def audit(case: Path, action: str, **detail) -> dict:
    log = case / "audit.jsonl"
    prev = "0" * 64
    if log.is_file():
        lines = log.read_text(encoding="utf-8").splitlines()
        if lines:
            prev = json.loads(lines[-1])["hash"]
    entry = {"time": _now(), "action": action, "detail": detail, "prev": prev}
    entry["hash"] = hashlib.sha256((prev + json.dumps(entry, sort_keys=True, default=str)).encode()).hexdigest()
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")
    return entry


def verify_audit(case: Path) -> tuple[bool, int]:
    log = case / "audit.jsonl"
    if not log.is_file():
        return (True, 0)
    prev = "0" * 64
    n = 0
    for line in log.read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        h = e.pop("hash")
        if e["prev"] != prev:
            return (False, n)
        if hashlib.sha256((prev + json.dumps(e, sort_keys=True, default=str)).encode()).hexdigest() != h:
            return (False, n)
        prev = h
        n += 1
    return (True, n)


# ------------------------------------------------------------------------------ case
def init_case(root: str, name: str, owner: str, attest_authorized: bool) -> Path:
    if not attest_authorized:
        raise ValueError("scope-discipline: you must attest that this is your own / an authorised machine "
                         "(--i-own-this-machine)")
    safe_name = "".join(ch for ch in name if ch.isalnum() or ch in "-_.") or "case"
    case = safe_output_dir(Path(root) / safe_name)
    if (case / "case.json").exists():
        raise ValueError(f"case already exists: {case}")
    for sub in ("phases", "evidence", "reports"):
        (case / sub).mkdir(exist_ok=True)
    meta = {"schema": "argus.case/1", "name": safe_name, "created": _now(), "owner": owner,
            "scope": {"target": "local machine only", "authorized_attestation": True,
                      "analysis_host": platform.node()},
            "mode": "detect-only", "ir_optin": None, "intel_online": False}
    write_json(case / "case.json", meta)
    write_json(case / "dispositions.json", {})
    audit(case, "case.init", name=safe_name, owner=owner)
    return case


def load_case(case_dir: str) -> tuple[Path, dict]:
    case = Path(case_dir).resolve(strict=True)
    p = case / "case.json"
    if p.is_symlink() or not p.is_file():
        raise ValueError("not an ARGUS case directory")
    return case, json.loads(p.read_text(encoding="utf-8"))


def set_ir_optin(case_dir: str, by: str, minutes: int, reason: str) -> dict:
    case, meta = load_case(case_dir)
    if minutes < 1 or minutes > 240:
        raise ValueError("opt-in window must be 1-240 minutes")
    if not reason.strip():
        raise ValueError("a reason is required for IR opt-in")
    exp = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=minutes)).isoformat(timespec="seconds")
    meta["ir_optin"] = {"by": by, "granted_at": _now(), "expires_at": exp, "reason": reason}
    meta["mode"] = "ir-opt-in"
    write_json(case / "case.json", meta)
    audit(case, "ir.optin", by=by, expires_at=exp, reason=reason)
    return meta["ir_optin"]


def revoke_ir_optin(case_dir: str) -> None:
    case, meta = load_case(case_dir)
    meta["ir_optin"] = None
    meta["mode"] = "detect-only"
    write_json(case / "case.json", meta)
    audit(case, "ir.revoke")


def dispose(case_dir: str, key: str, verdict: str, note: str, by: str) -> None:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    if verdict in ("false_positive", "benign_expected") and len(note.strip()) < 10:
        raise ValueError("false-positive-discipline: explain WHY it is benign (>=10 chars)")
    case, _ = load_case(case_dir)
    d = json.loads((case / "dispositions.json").read_text(encoding="utf-8"))
    d[key] = {"verdict": verdict, "note": note, "by": by, "time": _now()}
    write_json(case / "dispositions.json", d)
    audit(case, "finding.dispose", key=key, verdict=verdict)


# ------------------------------------------------------------------------------ gates
def gate_collection(tel: dict, required: list[str]) -> tuple[bool, str]:
    missing = [s for s in required if not tel.get(s)]
    if missing:
        return (False, f"telemetry missing required sections: {missing} (re-collect elevated, or mark as gap)")
    return (True, "collection ok")


def gate_dispositions(findings: list[dict], disp: dict, levels=("critical", "high")) -> tuple[bool, list[str]]:
    open_keys = [f["key"] for f in findings if f["severity"] in levels and f["key"] not in disp]
    return (not open_keys, open_keys)


# ------------------------------------------------------------------------------ runner
def run_workflow(case_dir: str, workflow: dict, tel: dict, preset: dict, baseline_keys: set[str] | None = None,
                 stop_on_gate: bool = True) -> dict[str, Any]:
    case, meta = load_case(case_dir)
    audit(case, "workflow.start", workflow=workflow.get("id"), telemetry_collected_at=tel.get("collected_at"))
    state: dict[str, Any] = {"workflow": workflow.get("id"), "phases": [], "stopped_at": None}
    all_findings = []
    for ph in workflow.get("phases", []):
        pid = ph["id"]
        rec: dict[str, Any] = {"id": pid, "name": ph.get("name"), "hypothesis": ph.get("hypothesis"),
                               "tactics": ph.get("tactics", []), "skills": ph.get("skills", [])}
        gate = ph.get("gate") or {}
        if gate.get("require_sections"):
            ok, msg = gate_collection(tel, gate["require_sections"])
            rec["gate"] = {"passed": ok, "detail": msg}
            if not ok and gate.get("blocking", True) and stop_on_gate:
                state["stopped_at"] = pid
                state["phases"].append(rec)
                audit(case, "phase.gate_failed", phase=pid, detail=msg)
                break
        if ph.get("tactics"):
            p = dict(preset)
            p["tactics"] = [t for t in ph["tactics"] if t in TACTICS]
            if ph.get("rules"):
                p["only_rules"] = ph["rules"]
            fs = [f.to_dict() for f in run_rules(tel, p, baseline_keys)]
            rec["findings"] = len(fs)
            rec["top_score"] = max((f["score"] for f in fs), default=0)
            rec["hypothesis_verdict"] = ("supported, investigate" if rec["top_score"] >= 60 else
                                         "weak leads" if fs else "not supported by available data")
            all_findings += fs
            write_json(case / "phases" / f"{pid}.json", {"phase": rec, "findings": fs})
        state["phases"].append(rec)
        audit(case, "phase.done", phase=pid, findings=rec.get("findings", 0))
    # de-duplicate across phases by (rule, key)
    seen, uniq = set(), []
    for f in sorted(all_findings, key=lambda x: -x["score"]):
        k = (f["rule_id"], f["key"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    write_json(case / "phases" / "_state.json", state)
    write_json(case / "phases" / "_findings.json", uniq)
    audit(case, "workflow.end", stopped_at=state["stopped_at"], findings=len(uniq))
    state["findings"] = len(uniq)
    return state


def build_report(case_dir: str, tel: dict, allow_open: bool = False) -> dict[str, Any]:
    case, meta = load_case(case_dir)
    fpath = case / "phases" / "_findings.json"
    if not fpath.is_file():
        raise ValueError("no workflow results yet, run `argus case run` first")
    findings = json.loads(fpath.read_text(encoding="utf-8"))
    disp = json.loads((case / "dispositions.json").read_text(encoding="utf-8"))
    ok, open_keys = gate_dispositions(findings, disp)
    if not ok and not allow_open:
        audit(case, "report.gate_failed", open=len(open_keys))
        raise ValueError(f"reporting-discipline gate: {len(open_keys)} high/critical finding(s) lack an analyst "
                         f"disposition. Use `argus case dispose` (or --draft to emit a DRAFT report).\n"
                         + "\n".join(f"  - {k}" for k in open_keys[:20]))
    for f in findings:
        if f["key"] in disp:
            f["disposition"] = disp[f["key"]]
    shown = [f for f in findings if f.get("disposition", {}).get("verdict") not in ("false_positive",)]
    res = build_result(tel, [], meta.get("name", "case"), False)
    res["findings"] = shown
    sev = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    tac: dict[str, int] = {}
    for f in shown:
        sev[f["severity"]] += 1
        tac[f["tactic"]] = tac.get(f["tactic"], 0) + 1
    res["summary"] = {"total": len(shown), "by_severity": sev, "by_tactic": tac,
                      "top_score": max((f["score"] for f in shown), default=0),
                      "false_positives_suppressed": len(findings) - len(shown)}
    res["status"] = "DRAFT (undispositioned high/critical findings)" if not ok else "FINAL"
    res["case"] = {"name": meta.get("name"), "mode": meta.get("mode"), "audit_chain_ok": verify_audit(case)[0]}
    out = safe_output_dir(case / "reports")
    stem = f"argus-case-{meta.get('name')}"
    write_json(safe_child(out, stem + ".json"), res)
    md = R.markdown(res).replace("# ARGUS Hunt Report", f"# ARGUS Case Report [{res['status']}]", 1)
    write_text(safe_child(out, stem + ".md"), md)
    write_json(safe_child(out, stem + ".navigator.json"), R.navigator_layer(res, f"ARGUS case {meta.get('name')}"))
    from .html_report import render
    write_text(safe_child(out, stem + ".html"), render(res))
    audit(case, "report.built", status=res["status"], findings=len(shown))
    return {"status": res["status"], "out": str(out / stem), "findings": len(shown)}
