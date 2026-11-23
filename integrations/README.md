# ARGUS on other agents

ARGUS by HaiND from the Post and Telecommunication Institute of Technology.

| Agent | How it loads ARGUS | Safety guard |
|---|---|---|
| Claude Code (Anthropic or GLM backend) | plugin / `install.ps1` / `install.sh`: skills, commands, agents, hooks | automatic (SessionStart + PreToolUse hooks) |
| Claude Code on **GLM** (Z.ai) | same install, plus `glm/settings.glm.example.json` env block (Anthropic-compatible endpoint) | automatic (hooks still run) |
| **OpenAI Codex CLI** | `codex/install-codex.ps1` or `.sh`: skills to `~/.agents/skills/argus-*`, rules appended to `~/.codex/AGENTS.md` | AGENTS.md instructs the agent to call `argus_cli.py guard` before state-changing commands; set `approval_policy = "on-request"` (`codex/config.toml.example`) |
| Any other agent (GLM via other CLIs, Gemini CLI, Cursor...) | read `AGENTS.md` + `skills/*/SKILL.md` (standard Agent Skills format) | same manual guard; use the tool's approval mode |

Notes (verify against current vendor docs, these change often):
- Codex user skill directory per OpenAI docs is `~/.agents/skills`; invoke with `/skills` or `$argus-<skill>`.
- Codex has no PreToolUse hook equivalent here, so the guard is advisory. Keep the sandbox read-only for hunts.
- Z.ai endpoint for Claude Code: `https://api.z.ai/api/anthropic`; Z.ai advises keeping its default model mapping.
- Slash commands (`commands/hunt.*.md`) are plain Markdown instructions; on Codex/GLM tell the agent "run hunt.full" and it reads the file.
