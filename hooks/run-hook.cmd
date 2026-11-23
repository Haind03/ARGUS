: << 'CMDBLOCK'
@echo off
REM Cross-platform polyglot launcher for ARGUS hooks (Python).
REM Windows: cmd.exe runs this batch part. Unix: the shell treats ':' as a no-op and skips to the bottom.
REM Usage: run-hook.cmd <hook-name>     (runs hooks\<hook-name>.py isolated with -I)
if "%~1"=="" ( echo run-hook.cmd: missing hook name 1>&2 & exit /b 0 )
set "HOOK_DIR=%~dp0"
where py >nul 2>nul
if %ERRORLEVEL% equ 0 ( py -3 -I "%HOOK_DIR%%~1.py" & exit /b %ERRORLEVEL% )
where python >nul 2>nul
if %ERRORLEVEL% equ 0 ( python -I "%HOOK_DIR%%~1.py" & exit /b %ERRORLEVEL% )
REM No Python: session-start degrades silently; pre-tool-guard must fail CLOSED.
if /I "%~1"=="pre-tool-guard" (
  echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"ARGUS guard unavailable (Python not found): confirm this command manually."}}
)
exit /b 0
CMDBLOCK

# Unix
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
NAME="$1"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  if [ "$NAME" = "pre-tool-guard" ]; then
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"ARGUS guard unavailable (Python not found): confirm this command manually."}}'
  fi
  exit 0
fi
exec "$PY" -I "${HOOK_DIR}/${NAME}.py"
