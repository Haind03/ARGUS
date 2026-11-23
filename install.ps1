<#
.SYNOPSIS
  ARGUS installer for Windows (manual install into %USERPROFILE%\.claude). Prefer the plugin install
  (/plugin marketplace add haind03/argus) when available.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\install.ps1
#>
param([string]$Dest = (Join-Path $env:USERPROFILE '.claude'), [string]$Repo = 'https://github.com/haind03/argus')
$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
if (-not $src -or -not (Test-Path (Join-Path $src 'engine\argus_cli.py'))) {
  $tmp = Join-Path $env:TEMP ("argus-" + [guid]::NewGuid())
  git clone --depth 1 $Repo $tmp
  $src = $tmp
}
$py = Get-Command py -ErrorAction SilentlyContinue
$pyArgs = @('-3')
if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue; $pyArgs = @() }
if (-not $py) { throw 'Python 3 is required (install from python.org, "for all users" if you want scheduled scans).' }

$root = Join-Path $Dest 'argus'
New-Item -ItemType Directory -Force -Path $root, (Join-Path $Dest 'skills'), (Join-Path $Dest 'commands'), (Join-Path $Dest 'agents') | Out-Null
foreach ($d in 'engine', 'skills', 'hooks', 'workflows', 'presets', 'tools') {
  $t = Join-Path $root $d
  if (Test-Path $t) { Remove-Item -LiteralPath $t -Recurse -Force }
  Copy-Item -LiteralPath (Join-Path $src $d) -Destination $t -Recurse
}
foreach ($f in 'CLAUDE.md', 'README.md', 'TERMS.md', 'LICENSE', 'skills-lock.json') { Copy-Item -LiteralPath (Join-Path $src $f) -Destination $root -Force }
Get-ChildItem -LiteralPath (Join-Path $src 'skills') -Directory | ForEach-Object {
  $t = Join-Path (Join-Path $Dest 'skills') $_.Name
  if (Test-Path $t) { Remove-Item -LiteralPath $t -Recurse -Force }
  Copy-Item -LiteralPath $_.FullName -Destination $t -Recurse
}
Copy-Item (Join-Path $src 'commands\*.md') (Join-Path $Dest 'commands') -Force
Copy-Item (Join-Path $src 'agents\*.md') (Join-Path $Dest 'agents') -Force

# Files from a git clone have no Mark-of-the-Web; a ZIP download does. Unblock ONLY ARGUS's own files so
# scripts run under -ExecutionPolicy RemoteSigned (no Bypass needed, no AV exclusions ever).
Get-ChildItem -LiteralPath $root, (Join-Path $Dest 'skills') -Recurse -File -Include *.ps1, *.py, *.cmd | Unblock-File

$merge = @'
import json, sys
from pathlib import Path
dest = Path(sys.argv[1]); root = dest / "argus"
hooks = json.loads((root / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
for ev in hooks.values():
    for m in ev:
        for h in m["hooks"]:
            h["command"] = h["command"].replace("${CLAUDE_PLUGIN_ROOT}", str(root).replace("\\", "/"))
sp = dest / "settings.json"
s = json.loads(sp.read_text(encoding="utf-8")) if sp.is_file() else {}
s.setdefault("hooks", {})
for ev, matchers in hooks.items():
    cur = [m for m in s["hooks"].get(ev, []) if "argus" not in json.dumps(m)]
    s["hooks"][ev] = cur + matchers
sp.write_text(json.dumps(s, indent=2), encoding="utf-8")
print("[*] hooks merged into", sp)
'@
$tmpPy = Join-Path $env:TEMP ("argus-merge-" + [guid]::NewGuid() + '.py')
Set-Content -LiteralPath $tmpPy -Value $merge -Encoding UTF8
& $py.Source @pyArgs -I $tmpPy $Dest
Remove-Item -LiteralPath $tmpPy -Force
Write-Host "[+] ARGUS installed to $root. Restart Claude Code, then run /hunt.quick"
Write-Host "    Scheduled scan (optional): powershell -NoProfile -ExecutionPolicy RemoteSigned -File `"$root\skills\baseline-and-diff\scripts\Register-ArgusScheduledScan.ps1`""
