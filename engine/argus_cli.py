#!/usr/bin/env python3
"""ARGUS command-line entry point. by HaiND from the Post and Telecommunication Institute of Technology.

Always run isolated:  python -I engine/argus_cli.py <command> ...
(-I ignores PYTHON* env vars, user site-packages and the CWD on sys.path,
so a planted module in the scanned directory cannot hijack imports.)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
REPO_ROOT = ENGINE_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from argus import __version__  # noqa: E402
from argus import baseline as bl  # noqa: E402
from argus import guard, harness, html_report, intel, report, triage  # noqa: E402
from argus.hunt import build_result, filter_severity, run_rules  # noqa: E402
from argus.rules import RULES, TACTICS  # noqa: E402
from argus.safeio import load_json, safe_child, safe_input_file, safe_output_dir, write_json, write_text  # noqa: E402

PRESET_DIR = REPO_ROOT / "presets"
IOC_DIR = REPO_ROOT / "skills" / "references" / "ioc"
YARA_DIR = REPO_ROOT / "skills" / "references" / "yara"


def load_preset(name_or_path: str | None) -> tuple[str, dict]:
    if not name_or_path:
        name_or_path = "full"
    cand = PRESET_DIR / f"{name_or_path}.json"
    if cand.is_file():
        return name_or_path, json.loads(cand.read_text(encoding="utf-8"))
    p = safe_input_file(name_or_path, 1024 * 1024)
    return p.stem, json.loads(p.read_text(encoding="utf-8"))


def _stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def cmd_hunt(a) -> int:
    tel = load_json(a.input)
    preset_name, preset = load_preset(a.preset)
    if a.tactics:
        preset["tactics"] = [t.strip().upper() for t in a.tactics.split(",") if t.strip()]
    base_keys: set[str] = set()
    delta = None
    base = None
    if a.baseline:
        base = load_json(a.baseline)
        base_keys = set(base.get("finding_keys") or [])
        tel["_baseline_shadow_copies"] = base.get("shadow_copies")
        delta = bl.diff(base, tel)
    if a.suppress:
        sup = load_json(a.suppress)
        base_keys |= {e["key"] for e in sup.get("suppressions", []) if isinstance(e, dict) and e.get("key")}
    tel["_ioc_vuln_drivers"] = sorted(intel.load_local_iocs(IOC_DIR)["vuln_drivers"])
    findings = run_rules(tel, preset, base_keys)
    findings = filter_severity(findings, a.min_severity or preset.get("min_severity", "low"))
    result = build_result(tel, findings, preset_name, bool(a.baseline))
    if delta:
        result["baseline_new_items"] = bl.diff_findings(delta)
    result["intel"] = intel.enrich_findings(result["findings"], IOC_DIR, online=a.online)
    result["findings"].sort(key=lambda f: -f["score"])
    out = safe_output_dir(a.out_dir)
    stem = f"argus-{(result.get('target_host') or 'host')}-{_stamp()}".replace(" ", "_")
    stem = "".join(ch for ch in stem if ch.isalnum() or ch in "-_.")
    write_json(safe_child(out, stem + ".json"), result)
    write_text(safe_child(out, stem + ".md"), report.markdown(result, delta))
    write_json(safe_child(out, stem + ".navigator.json"), report.navigator_layer(result, f"ARGUS {stem}"))
    write_text(safe_child(out, stem + ".html"), html_report.render(result))
    s = result["summary"]
    print(json.dumps({"out": str(out / stem), "total": s["total"], "by_severity": s["by_severity"],
                      "top_score": s["top_score"], "intel_online": result["intel"]["online_enabled"]}, indent=2))
    sev = s["by_severity"]
    return 2 if sev.get("critical") or sev.get("high") else (1 if s["total"] else 0)


def cmd_baseline(a) -> int:
    tel = load_json(a.input)
    b = bl.create(tel)
    out = safe_output_dir(a.out_dir)
    p = safe_child(out, a.name)
    write_json(p, b)
    print(json.dumps({"baseline": str(p), "items": {k: len(v) for k, v in b["inventory"].items()}}, indent=2))
    return 0


def cmd_diff(a) -> int:
    d = bl.diff(load_json(a.baseline), load_json(a.input))
    print(json.dumps({"delta": d, "review_items": bl.diff_findings(d)}, indent=2, ensure_ascii=False))
    return 1 if d else 0


def cmd_report(a) -> int:
    res = load_json(a.findings)
    out = safe_output_dir(a.out_dir)
    stem = Path(a.findings).name.rsplit(".json", 1)[0]
    write_text(safe_child(out, stem + ".md"), report.markdown(res))
    write_json(safe_child(out, stem + ".navigator.json"), report.navigator_layer(res))
    print(f"report written to {out}")
    return 0


def cmd_triage(a) -> int:
    res = triage.triage(a.file, YARA_DIR)
    if a.online or intel.online_enabled():
        fake = [{"artifact": {"sha256": res["hashes"]["sha256"]}, "score": res["score"]}]
        res["intel"] = intel.enrich_findings(fake, IOC_DIR, online=a.online)
        res["intel_detail"] = fake[0].get("intel")
    else:
        local = intel.load_local_iocs(IOC_DIR)
        res["local_ioc_match"] = res["hashes"]["sha256"] in local["sha256"]
    if a.out_dir:
        out = safe_output_dir(a.out_dir)
        write_json(safe_child(out, f"triage-{res['hashes']['sha256'][:16]}.json"), res)
    print(json.dumps(res, indent=2, default=str))
    return 2 if res["severity"] in ("high", "critical") else 0


def cmd_rules(a) -> int:
    for r in RULES:
        if not a.tactic or r.tactic == a.tactic.upper():
            print(f"{r.rule_id}\t{r.tactic} {TACTICS[r.tactic]}\t{r.technique}\t{r.title}")
    return 0


def cmd_coverage(a) -> int:
    out = safe_output_dir(a.out_dir)
    p = safe_child(out, "argus-coverage.navigator.json")
    write_json(p, report.coverage_layer())
    print(str(p))
    return 0


WORKFLOW_DIR = REPO_ROOT / "workflows"


def load_workflow(name_or_path: str) -> dict:
    """workflows/<name>.yml (PyYAML if installed) or its generated JSON twin workflows/<name>.json."""
    yml = WORKFLOW_DIR / f"{name_or_path}.yml"
    js = WORKFLOW_DIR / f"{name_or_path}.json"
    if yml.is_file():
        try:
            import yaml  # type: ignore
            return yaml.safe_load(yml.read_text(encoding="utf-8"))
        except ImportError:
            pass
    if js.is_file():
        return json.loads(js.read_text(encoding="utf-8"))
    p = safe_input_file(name_or_path, 4 * 1024 * 1024)
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yml", ".yaml"):
        import yaml  # type: ignore
        return yaml.safe_load(text)
    return json.loads(text)


def _who() -> str:
    import getpass
    try:
        return getpass.getuser()
    except Exception:
        return "analyst"


def cmd_case(a) -> int:
    if a.case_cmd == "init":
        c = harness.init_case(a.root, a.name, a.owner or _who(), a.i_own_this_machine)
        print(c)
        return 0
    if a.case_cmd == "run":
        tel = load_json(a.input)
        wf = load_workflow(a.workflow)
        _, preset = load_preset(a.preset)
        base_keys = set()
        if a.baseline:
            b = load_json(a.baseline)
            base_keys = set(b.get("finding_keys") or [])
            tel["_baseline_shadow_copies"] = b.get("shadow_copies")
        tel["_ioc_vuln_drivers"] = sorted(intel.load_local_iocs(IOC_DIR)["vuln_drivers"])
        st = harness.run_workflow(a.case, wf, tel, preset, base_keys)
        print(json.dumps({k: st[k] for k in ("workflow", "stopped_at", "findings")}, indent=2))
        for ph in st["phases"]:
            print(f"  {ph['id']:<22} findings={ph.get('findings', '-'):<4} {ph.get('hypothesis_verdict', '')}"
                  f"{'  GATE FAILED: ' + ph['gate']['detail'] if ph.get('gate') and not ph['gate']['passed'] else ''}")
        return 4 if st["stopped_at"] else 0
    if a.case_cmd == "findings":
        case, _ = harness.load_case(a.case)
        fs = json.loads((case / "phases" / "_findings.json").read_text(encoding="utf-8"))
        disp = json.loads((case / "dispositions.json").read_text(encoding="utf-8"))
        for f in fs:
            d = disp.get(f["key"], {}).get("verdict", "OPEN")
            print(f"{f.get('id','')} {f['score']:>3} {f['severity']:<8} {d:<16} {f['rule_id']:<11} {f['title'][:70]}")
        return 0
    if a.case_cmd == "dispose":
        key = a.key
        if key.startswith("F-"):
            case, _ = harness.load_case(a.case)
            fs = json.loads((case / "phases" / "_findings.json").read_text(encoding="utf-8"))
            match = [f["key"] for f in fs if f.get("id") == key]
            if not match:
                raise ValueError(f"no finding with id {key}")
            key = match[0]
        harness.dispose(a.case, key, a.verdict, a.note, a.by or _who())
        print("recorded")
        return 0
    if a.case_cmd == "optin":
        print(json.dumps(harness.set_ir_optin(a.case, a.by or _who(), a.minutes, a.reason), indent=2))
        return 0
    if a.case_cmd == "revoke":
        harness.revoke_ir_optin(a.case)
        print("IR opt-in revoked; case back to detect-only")
        return 0
    if a.case_cmd == "report":
        tel = load_json(a.input) if a.input else {}
        print(json.dumps(harness.build_report(a.case, tel, allow_open=a.draft), indent=2))
        return 0
    if a.case_cmd == "verify":
        case, _ = harness.load_case(a.case)
        ok, n = harness.verify_audit(case)
        print(f"audit chain {'OK' if ok else 'BROKEN'} ({n} entries verified)")
        return 0 if ok else 5
    return 3


def cmd_guard(a) -> int:
    decision, reason = guard.decide(a.command, Path(a.case) if a.case else None)
    print(json.dumps({"decision": decision, "reason": reason}))
    return {"allow": 0, "ask": 1, "deny": 2}[decision]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="argus", description=f"ARGUS defensive hunt engine {__version__} (detect-only)")
    sp = ap.add_subparsers(dest="cmd", required=True)
    h = sp.add_parser("hunt", help="score telemetry and write JSON/Markdown/Navigator outputs")
    h.add_argument("--input", required=True)
    h.add_argument("--preset", default="full")
    h.add_argument("--baseline")
    h.add_argument("--tactics", help="comma list, e.g. TA0003,TA0011")
    h.add_argument("--suppress", help="argus.suppress/1 file from fp_tune.py (exact keys, down-weighted x0.3)")
    h.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"])
    h.add_argument("--online", action="store_true", help="opt-in: send SHA-256 hashes to VT/MalwareBazaar (needs API keys)")
    h.add_argument("--out-dir", default="argus-reports")
    h.set_defaults(fn=cmd_hunt)
    b = sp.add_parser("baseline", help="create a baseline from clean-state telemetry")
    b.add_argument("--input", required=True)
    b.add_argument("--out-dir", default="argus-baseline")
    b.add_argument("--name", default="baseline.json")
    b.set_defaults(fn=cmd_baseline)
    d = sp.add_parser("diff", help="diff telemetry against a baseline")
    d.add_argument("--baseline", required=True)
    d.add_argument("--input", required=True)
    d.set_defaults(fn=cmd_diff)
    r = sp.add_parser("report", help="re-render Markdown/Navigator from findings JSON")
    r.add_argument("--findings", required=True)
    r.add_argument("--out-dir", default="argus-reports")
    r.set_defaults(fn=cmd_report)
    t = sp.add_parser("triage", help="static triage of one file (never executed)")
    t.add_argument("file")
    t.add_argument("--online", action="store_true")
    t.add_argument("--out-dir")
    t.set_defaults(fn=cmd_triage)
    rl = sp.add_parser("rules", help="list detection rules")
    rl.add_argument("--tactic")
    rl.set_defaults(fn=cmd_rules)
    c = sp.add_parser("coverage", help="write ATT&CK Navigator coverage layer")
    c.add_argument("--out-dir", default="argus-reports")
    c.set_defaults(fn=cmd_coverage)
    cs = sp.add_parser("case", help="defensive harness: case, phases, gates, dispositions, IR opt-in")
    csp = cs.add_subparsers(dest="case_cmd", required=True)
    ci = csp.add_parser("init")
    ci.add_argument("--root", default="argus-cases")
    ci.add_argument("--name", required=True)
    ci.add_argument("--owner")
    ci.add_argument("--i-own-this-machine", action="store_true", help="scope attestation (required)")
    cr = csp.add_parser("run")
    cr.add_argument("--case", required=True)
    cr.add_argument("--input", required=True)
    cr.add_argument("--workflow", default="full-hunt")
    cr.add_argument("--preset", default="full")
    cr.add_argument("--baseline")
    cf = csp.add_parser("findings")
    cf.add_argument("--case", required=True)
    cd = csp.add_parser("dispose")
    cd.add_argument("--case", required=True)
    cd.add_argument("--key", required=True, help="finding id (F-xxxxxxxxxx) or full key")
    cd.add_argument("--verdict", required=True, choices=harness.VERDICTS)
    cd.add_argument("--note", default="")
    cd.add_argument("--by")
    co = csp.add_parser("optin", help="time-boxed incident-response opt-in (still asks per action)")
    co.add_argument("--case", required=True)
    co.add_argument("--minutes", type=int, default=60)
    co.add_argument("--reason", required=True)
    co.add_argument("--by")
    cv = csp.add_parser("revoke")
    cv.add_argument("--case", required=True)
    cp = csp.add_parser("report")
    cp.add_argument("--case", required=True)
    cp.add_argument("--input")
    cp.add_argument("--draft", action="store_true")
    cy = csp.add_parser("verify")
    cy.add_argument("--case", required=True)
    cs.set_defaults(fn=cmd_case)
    g = sp.add_parser("guard", help="classify a shell command (allow/ask/deny) for the PreToolUse hook")
    g.add_argument("command")
    g.add_argument("--case")
    g.set_defaults(fn=cmd_guard)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (ValueError, OSError) as exc:
        print(f"argus: error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
