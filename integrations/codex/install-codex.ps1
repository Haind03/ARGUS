<#
  ARGUS for OpenAI Codex CLI (Windows). by HaiND from the Post and Telecommunication Institute of Technology
  Toolkit -> %USERPROFILE%\.codex\argus, skills -> %USERPROFILE%\.agents\skills, rules -> %USERPROFILE%\.codex\AGENTS.md
#>
$ErrorActionPreference = 'Stop'
$src = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$codex = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
$sk = Join-Path $env:USERPROFILE '.agents\skills'
New-Item -ItemType Directory -Force -Path (Join-Path $codex 'argus'), $sk | Out-Null
foreach ($d in 'engine', 'skills', 'hooks', 'workflows', 'presets', 'tools', 'commands') {
  $t = Join-Path $codex "argus\$d"; if (Test-Path $t) { Remove-Item -LiteralPath $t -Recurse -Force }
  Copy-Item -LiteralPath (Join-Path $src $d) -Destination $t -Recurse
}
foreach ($f in 'AGENTS.md', 'README.md', 'LICENSE') { Copy-Item (Join-Path $src $f) (Join-Path $codex 'argus') -Force }
Get-ChildItem (Join-Path $src 'skills') -Directory | Where-Object Name -ne 'references' | ForEach-Object {
  $t = Join-Path $sk ("argus-" + $_.Name); if (Test-Path $t) { Remove-Item -LiteralPath $t -Recurse -Force }
  Copy-Item -LiteralPath $_.FullName -Destination $t -Recurse
}
Get-ChildItem (Join-Path $codex 'argus'), $sk -Recurse -File -Include *.ps1, *.py | Unblock-File
$ag = Join-Path $codex 'AGENTS.md'; if (-not (Test-Path $ag)) { New-Item $ag | Out-Null }
if (-not (Select-String -LiteralPath $ag -Pattern 'ARGUS-BEGIN' -Quiet)) {
  Add-Content $ag "<!-- ARGUS-BEGIN -->`nARGUS toolkit root: $codex\argus (run its scripts from there).`n"
  Get-Content (Join-Path $src 'AGENTS.md') | Add-Content $ag
  Add-Content $ag '<!-- ARGUS-END -->'
}
Write-Host '[+] ARGUS installed for Codex. Start codex, then use /skills or $argus-using-argus'
