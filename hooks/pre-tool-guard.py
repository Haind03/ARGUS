"""PreToolUse hook: ARGUS action guard for Bash / PowerShell tool calls.

DEGRADATION: fail-CLOSED — any internal error yields "ask" (never a silent allow of an unknown command).
Decision source: engine/argus/guard.py (allow | ask | deny).
Active case for IR opt-in: $ARGUS_CASE, else the most recently modified case under ./argus-cases.
"""
import json
import os
import sys
from pathlib import Path


def out(decision: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": f"[ARGUS guard] {reason}"}}))
    sys.exit(0)


try:
    payload = json.loads(sys.stdin.read() or "{}")
    tool_input = payload.get("tool_input") or {}
    command = str(tool_input.get("command") or "")
    if not command:
        sys.exit(0)  # not a shell call: no opinion
    root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
    sys.path.insert(0, str(root / "engine"))
    from argus.guard import decide  # noqa: E402

    case = os.environ.get("ARGUS_CASE")
    case_dir = Path(case) if case else None
    if case_dir is None:
        cwd = Path(payload.get("cwd") or os.getcwd())
        cases = sorted((p for p in (cwd / "argus-cases").glob("*/case.json") if p.is_file()),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        case_dir = cases[0].parent if cases else None
    decision, reason = decide(command, case_dir)
    if decision == "allow":
        sys.exit(0)  # defer to normal permission flow
    out(decision, reason)
except SystemExit:
    raise
except Exception as exc:  # fail closed
    out("ask", f"guard error ({type(exc).__name__}); confirm this command manually")
