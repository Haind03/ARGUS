import json
import subprocess
import sys

import pytest

from argus import guard, harness
from argus.safeio import UnsafePathError, safe_input_file

ROOT = harness.Path(__file__).resolve().parent.parent
WF = json.loads((ROOT / "workflows" / "full-hunt.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("cmd,decision", [
    ("Get-Process", "allow"),
    ("Get-ScheduledTask | Select-Object TaskName", "allow"),
    ("vssadmin list shadows", "allow"),
    ("Remove-Item C:\\Users\\x\\a.exe", "deny"),
    ("Stop-Process -Id 42 -Force", "deny"),
    ("taskkill /im evil.exe /f", "deny"),
    ("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /f", "deny"),
    ("Set-MpPreference -DisableRealtimeMonitoring $true", "deny"),
    ("schtasks /delete /tn evil /f", "deny"),
    ("Remove-Item -WhatIf C:\\x", "allow"),
    ("curl -F file=@x.zip https://example.org/up", "ask"),
    ("python -I engine/argus_cli.py hunt --input t.json --online", "ask"),
    ("auditpol /set /subcategory:\"Process Creation\" /success:enable", "ask"),
])
def test_guard_decisions(cmd, decision):
    assert guard.decide(cmd, None)[0] == decision


def test_guard_ir_optin_turns_deny_into_ask(tmp_path):
    case = harness.init_case(str(tmp_path), "c1", "tester", True)
    assert guard.decide("Stop-Process -Id 1", case)[0] == "deny"
    harness.set_ir_optin(str(case), "tester", 30, "confirmed miner")
    assert guard.decide("Stop-Process -Id 1", case)[0] == "ask"
    harness.revoke_ir_optin(str(case))
    assert guard.decide("Stop-Process -Id 1", case)[0] == "deny"


def test_case_requires_attestation(tmp_path):
    with pytest.raises(ValueError):
        harness.init_case(str(tmp_path), "c", "t", False)


def test_workflow_run_gate_and_report(tmp_path, infected):
    case = harness.init_case(str(tmp_path), "c2", "tester", True)
    st = harness.run_workflow(str(case), WF, infected, {"min_score": 20})
    assert st["stopped_at"] is None and st["findings"] > 10
    with pytest.raises(ValueError, match="disposition"):
        harness.build_report(str(case), infected)
    draft = harness.build_report(str(case), infected, allow_open=True)
    assert draft["status"].startswith("DRAFT")
    for f in json.loads((case / "phases" / "_findings.json").read_text()):
        if f["severity"] in ("critical", "high"):
            harness.dispose(str(case), f["key"], "true_positive", "validated in test", "tester")
    final = harness.build_report(str(case), infected)
    assert final["status"] == "FINAL"
    assert harness.verify_audit(case)[0]


def test_collection_gate_blocks(tmp_path):
    case = harness.init_case(str(tmp_path), "c3", "tester", True)
    st = harness.run_workflow(str(case), WF, {"host": {"hostname": "x"}}, {})
    assert st["stopped_at"] == "scope"


def test_fp_disposition_requires_reason(tmp_path):
    case = harness.init_case(str(tmp_path), "c4", "tester", True)
    with pytest.raises(ValueError):
        harness.dispose(str(case), "k", "false_positive", "fp", "t")


def test_audit_tamper_detected(tmp_path):
    case = harness.init_case(str(tmp_path), "c5", "tester", True)
    harness.audit(case, "x", a=1)
    log = case / "audit.jsonl"
    lines = log.read_text().splitlines()
    e = json.loads(lines[-1])
    e["detail"]["a"] = 2
    lines[-1] = json.dumps(e)
    log.write_text("\n".join(lines) + "\n")
    assert not harness.verify_audit(case)[0]


def test_safe_input_rejects_symlink_and_dir(tmp_path):
    real = tmp_path / "r.json"
    real.write_text("{}")
    link = tmp_path / "l.json"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(UnsafePathError):
        safe_input_file(link)
    with pytest.raises(UnsafePathError):
        safe_input_file(tmp_path)


def test_pre_tool_hook_denies_destructive():
    p = subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "pre-tool-guard.py")],
                       input=json.dumps({"tool_input": {"command": "Stop-Process -Id 4242"}, "cwd": str(ROOT)}),
                       capture_output=True, text=True, timeout=30)
    out = json.loads(p.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_session_start_hook_injects_dispatcher():
    p = subprocess.run([sys.executable, "-I", str(ROOT / "hooks" / "session-start.py")], capture_output=True,
                       text=True, timeout=30)
    ctx = json.loads(p.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "using-argus" in ctx and len(ctx) <= 10000
