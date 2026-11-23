#!/usr/bin/env bash
# ARGUS for OpenAI Codex CLI. by HaiND from the Post and Telecommunication Institute of Technology
# Installs: toolkit -> ~/.codex/argus, skills -> ~/.agents/skills (Codex user skill dir),
#           ARGUS rules appended to ~/.codex/AGENTS.md (global guidance).
set -euo pipefail
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
CODEX="${CODEX_HOME:-$HOME/.codex}"; SK="$HOME/.agents/skills"
mkdir -p "$CODEX/argus" "$SK"
for d in engine skills hooks workflows presets tools commands; do rm -rf "$CODEX/argus/$d"; cp -R "$SRC/$d" "$CODEX/argus/$d"; done
cp "$SRC/AGENTS.md" "$SRC/README.md" "$SRC/LICENSE" "$CODEX/argus/"
for s in "$SRC"/skills/*/; do n="$(basename "$s")"; [ "$n" = references ] && continue; rm -rf "$SK/argus-$n"; cp -R "$s" "$SK/argus-$n"; done
touch "$CODEX/AGENTS.md"
if ! grep -q "ARGUS-BEGIN" "$CODEX/AGENTS.md"; then
  { echo "<!-- ARGUS-BEGIN -->"; echo "ARGUS toolkit root: $CODEX/argus (run its scripts from there)."; cat "$SRC/AGENTS.md"; echo "<!-- ARGUS-END -->"; } >> "$CODEX/AGENTS.md"
fi
echo "[+] ARGUS installed for Codex. Start codex, then: \$argus-using-argus  or  /skills"
