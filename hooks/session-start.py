"""SessionStart hook: inject the using-argus dispatcher.

DEGRADATION: fail-OPEN (context injection is a convenience, never a gate), always exits 0.
"""
import json
import os
import sys
from pathlib import Path

root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
try:
    dispatcher = (root / "skills" / "using-argus" / "SKILL.md").read_text(encoding="utf-8")
except OSError as e:
    dispatcher = f"(ARGUS dispatcher unavailable: {e})"

ctx = (
    "<ARGUS-DEFENSIVE-MODE>\n"
    "You are operating ARGUS, a DETECT-ONLY defensive threat-hunting toolkit for the user's OWN Windows PC.\n"
    "Destructive actions are blocked by the ARGUS PreToolUse guard unless the user opts in for incident response.\n"
    "Below is the full 'using-argus' dispatcher skill. Load every other skill with the Skill tool.\n\n"
    f"{dispatcher}\n"
    "</ARGUS-DEFENSIVE-MODE>"
)[:9500]
logo = ""
try:
    sys.path.insert(0, str(root / "engine"))
    from argus.banner import text as _banner  # noqa: E402
    logo = _banner()
except Exception:
    logo = "ARGUS\n  by HaiND from the Post and Telecommunication Institute of Technology\n"
print(json.dumps({"systemMessage": logo,
                  "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ctx}}))
sys.exit(0)
