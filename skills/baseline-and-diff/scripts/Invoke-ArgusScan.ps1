<#
  ARGUS by HaiND from the Post and Telecommunication Institute of Technology
.SYNOPSIS
  One ARGUS scan cycle: collect (read-only) -> hunt (detect-only) -> report. Used by the scheduled task.
  Authorised use on your own machine only. Never remediates.
#>
param(
  [string]$Preset = 'quick',
  [string]$ArgusRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path,
  [string]$DataRoot = (Join-Path $env:ProgramData 'ARGUS'),
  [int]$KeepTelemetry = 30
)
$__argusBanner = Join-Path $PSScriptRoot '..\..\telemetry-collection\scripts\ArgusBanner.ps1'
if (Test-Path -LiteralPath $__argusBanner) { . $__argusBanner }
$ErrorActionPreference = 'Stop'
$tel = Join-Path $DataRoot 'telemetry'; $rep = Join-Path $DataRoot 'reports'; $base = Join-Path $DataRoot 'baseline'
New-Item -ItemType Directory -Force -Path $tel, $rep, $base | Out-Null

$presetFile = Join-Path $ArgusRoot "presets\$Preset.json"
$hours = 72
if (Test-Path -LiteralPath $presetFile) { try { $hours = [int]((Get-Content -Raw $presetFile | ConvertFrom-Json).event_hours) } catch { } }
$out = Join-Path $tel ("telemetry-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
& (Join-Path $ArgusRoot 'skills\telemetry-collection\scripts\Collect-Telemetry.ps1') -Sections all -EventHours $hours -OutFile $out -HashProcesses | Out-Null

$py = $null
foreach ($c in @(@('py', '-3'), @('python'), @('python3'))) {
  if (Get-Command $c[0] -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) { throw 'Python 3 not found for this account (install for all users).' }
$cli = Join-Path $ArgusRoot 'engine\argus_cli.py'
$argsList = @()
if ($py.Count -gt 1) { $argsList += $py[1..($py.Count - 1)] }
$argsList += @('-I', $cli, 'hunt', '--input', $out, '--preset', $Preset, '--out-dir', $rep)
$latest = Get-ChildItem -LiteralPath $base -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) { $argsList += @('--baseline', $latest.FullName) }
& $py[0] @argsList
$code = $LASTEXITCODE

if ($code -eq 2) {
  try {
    if (-not [Diagnostics.EventLog]::SourceExists('ARGUS')) { New-EventLog -LogName Application -Source 'ARGUS' }
    Write-EventLog -LogName Application -Source 'ARGUS' -EventId 4100 -EntryType Warning -Message "ARGUS scheduled hunt: high/critical findings. Reports: $rep"
  } catch { }
}
Get-ChildItem -LiteralPath $tel -Filter 'telemetry-*.json' | Sort-Object LastWriteTime -Descending | Select-Object -Skip $KeepTelemetry | Remove-Item -Force
exit $code
