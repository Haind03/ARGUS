#!/usr/bin/env bash
# ARGUS manual installer (macOS/Linux/WSL/Git-Bash). Windows users: prefer install.ps1.
#   curl -fsSL https://raw.githubusercontent.com/haind03/argus/main/install.sh | bash
#   or from a checkout:  ./install.sh
# Installs:  ~/.claude/argus/        full toolkit (engine, skills, hooks, workflows, presets)
#            ~/.claude/skills/<name> full skill folders (SKILL.md + references + scripts)
#            ~/.claude/commands, ~/.claude/agents
#            hooks merged into ~/.claude/settings.json (absolute paths; existing settings kept)
set -euo pipefail
DEST="${CLAUDE_HOME:-$HOME/.claude}"
REPO="https://github.com/haind03/argus"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ ! -f "${SRC}/engine/argus_cli.py" ]; then
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  git clone --depth 1 "$REPO" "$TMP/argus"
  SRC="$TMP/argus"
fi
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "[!] Python 3 is required"; exit 1; }

echo "[*] Installing ARGUS to $DEST/argus"
mkdir -p "$DEST/argus" "$DEST/skills" "$DEST/commands" "$DEST/agents"
for d in engine skills hooks workflows presets tools; do
  rm -rf "$DEST/argus/$d"; cp -R "$SRC/$d" "$DEST/argus/$d"
done
cp "$SRC/CLAUDE.md" "$SRC/README.md" "$SRC/TERMS.md" "$SRC/LICENSE" "$SRC/skills-lock.json" "$DEST/argus/"
for s in "$SRC"/skills/*/; do
  n="$(basename "$s")"; rm -rf "$DEST/skills/$n"; cp -R "$s" "$DEST/skills/$n"
done
cp "$SRC"/commands/*.md "$DEST/commands/"
cp "$SRC"/agents/*.md "$DEST/agents/"

"$PY" -I - "$DEST" <<'PYEOF'
import json, sys
from pathlib import Path
dest = Path(sys.argv[1]); root = dest / "argus"
hooks = json.loads((root / "hooks" / "hooks.json").read_text())["hooks"]
for ev in hooks.values():
    for m in ev:
        for h in m["hooks"]:
            h["command"] = h["command"].replace("${CLAUDE_PLUGIN_ROOT}", str(root))
sp = dest / "settings.json"
s = json.loads(sp.read_text()) if sp.is_file() else {}
s.setdefault("hooks", {})
for ev, matchers in hooks.items():
    cur = [m for m in s["hooks"].get(ev, []) if "argus" not in json.dumps(m)]
    s["hooks"][ev] = cur + matchers
sp.write_text(json.dumps(s, indent=2))
print(f"[*] hooks merged into {sp}")
PYEOF
chmod +x "$DEST/argus/hooks/run-hook.cmd" 2>/dev/null || true
echo "[+] Done. Restart Claude Code, then try: /hunt.quick"
echo "    Engine: $PY -I $DEST/argus/engine/argus_cli.py rules"
