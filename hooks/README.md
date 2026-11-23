# ARGUS hooks

| Hook | Event | Degradation | Purpose |
|---|---|---|---|
| `session-start.py` | SessionStart (startup/clear/compact) | fail-open | injects `skills/using-argus/SKILL.md` (dispatcher) |
| `pre-tool-guard.py` | PreToolUse (Bash, PowerShell) | **fail-closed** (`ask`) | classifies commands via `engine/argus/guard.py`: destructive → deny (or ask with IR opt-in), egress/config → ask |

`run-hook.cmd` is a cmd/sh polyglot: on Windows it finds `py -3` or `python`, on Unix `python3`, and runs the
hook with `-I` (isolated: no CWD or user-site imports). No Git Bash dependency.

Test locally:
```bash
echo '{"tool_input":{"command":"Stop-Process -Id 4242"}}' | python -I hooks/pre-tool-guard.py
python -I hooks/session-start.py | head -c 300
```
Manual install (no plugin): merge `hooks.json` into `~/.claude/settings.json`, replacing
`${CLAUDE_PLUGIN_ROOT}` with the absolute install path (install scripts do this).
