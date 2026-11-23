<#
.SYNOPSIS
  OPT-IN memory acquisition for the user's own machine, using external SIGNED tools only:
  full RAM via WinPmem, or one process via Sysinternals ProcDump. Default = DRY RUN.

.DESCRIPTION
  This script contains no native dumping code on purpose: it only validates and launches a tool the
  user downloaded from the vendor (signature + hash are recorded), so the toolkit itself never looks
  like - or behaves like - a credential dumper.
  - LSASS and other protected/credential processes are always refused.
  - The system drive is refused unless -AllowSystemDrive (avoid overwriting deleted-file evidence).
  - Every dump is SHA-256 hashed and appended to chain-of-custody.json.

.EXAMPLE
  .\Invoke-ArgusMemoryDump.ps1 -Mode FullRam -ToolPath E:\tools\winpmem_mini_x64.exe -OutDir E:\case01 -Acquire
.EXAMPLE
  .\Invoke-ArgusMemoryDump.ps1 -Mode Process -ProcessId 4321 -ToolPath E:\tools\procdump64.exe -OutDir E:\case01 -Acquire
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('FullRam', 'Process')][string]$Mode,
  [Parameter(Mandatory)][string]$OutDir,
  [Parameter(Mandatory)][string]$ToolPath,
  [int]$ProcessId,
  [string]$Examiner = "$env:USERDOMAIN\$env:USERNAME",
  [string]$CaseId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
  [switch]$Acquire,
  [switch]$AllowSystemDrive
)
$ErrorActionPreference = 'Stop'
$Refused = @('lsass', 'lsaiso', 'csrss', 'wininit', 'winlogon', 'smss', 'services', 'msmpeng', 'mssense', 'nissrv')

function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

$full = [IO.Path]::GetFullPath($OutDir)
if ($full.Substring(0, 2).ToUpper() -eq $env:SystemDrive.TrimEnd('\').ToUpper() -and -not $AllowSystemDrive) {
  throw "Refusing to write a memory dump to the system drive. Use external media or pass -AllowSystemDrive."
}
if (-not (Test-Path -LiteralPath $ToolPath -PathType Leaf)) { throw "Tool not found: $ToolPath" }
$sig = Get-AuthenticodeSignature -LiteralPath $ToolPath
$toolName = [IO.Path]::GetFileName($ToolPath).ToLower()
$expected = if ($Mode -eq 'FullRam') { 'winpmem' } else { 'procdump' }
if ($toolName -notlike "*$expected*") { throw "Mode $Mode expects a $expected executable, got $toolName" }
if ($sig.Status -ne 'Valid') { Write-Warning "Tool signature status: $($sig.Status). Verify you downloaded it from the vendor." }

$plan = [ordered]@{
  case_id = $CaseId; mode = $Mode; out_dir = $full; host = $env:COMPUTERNAME; examiner = $Examiner
  tool = $ToolPath; tool_sha256 = (Get-FileHash -LiteralPath $ToolPath -Algorithm SHA256).Hash.ToLower()
  tool_signer = "$($sig.SignerCertificate.Subject)"; tool_signature = "$($sig.Status)"
}
if ($Mode -eq 'FullRam') {
  $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
  $plan.expected_size_gb = [math]::Round($ram / 1GB, 1)
  $drive = Get-PSDrive -Name $full.Substring(0, 1)
  if ($drive.Free -lt $ram * 1.1) { throw "Not enough free space on target ($([math]::Round($drive.Free/1GB,1)) GB < RAM)." }
  $plan.output = Join-Path $full "mem-$env:COMPUTERNAME-$CaseId.raw"
  $toolArgs = @($plan.output)
} else {
  if (-not $ProcessId) { throw 'Process mode needs -ProcessId.' }
  $p = Get-Process -Id $ProcessId
  if ($Refused -contains $p.ProcessName.ToLower()) { throw "Refusing to dump protected/credential process '$($p.ProcessName)'. Use full RAM capture + memory-forensics instead." }
  $plan.process = "$($p.ProcessName) ($ProcessId)"; $plan.process_path = $p.Path
  $plan.output = Join-Path $full ("proc-{0}-{1}-{2}.dmp" -f $p.ProcessName, $ProcessId, $CaseId)
  $toolArgs = @('-accepteula', '-ma', "$ProcessId", $plan.output)
}

Write-Host '=== ARGUS memory acquisition plan ==='
$plan.GetEnumerator() | ForEach-Object { '{0,-18}: {1}' -f $_.Key, $_.Value } | Write-Host
if (-not $Acquire) { Write-Host "`nDRY RUN. Re-run with -Acquire (elevated) to write the dump."; return }
if (-not (Test-Admin)) { throw 'Acquisition requires an elevated prompt.' }
New-Item -ItemType Directory -Force -Path $full | Out-Null
$start = (Get-Date).ToUniversalTime().ToString('o')
& $ToolPath @toolArgs
if (-not (Test-Path -LiteralPath $plan.output)) { throw "Tool finished (exit $LASTEXITCODE) but no dump was written." }

$hash = (Get-FileHash -LiteralPath $plan.output -Algorithm SHA256).Hash.ToLower()
$rec = [ordered]@{
  case_id = $CaseId; artefact = $plan.output; sha256 = $hash; size = (Get-Item -LiteralPath $plan.output).Length
  acquired_start_utc = $start; acquired_end_utc = (Get-Date).ToUniversalTime().ToString('o')
  host = $env:COMPUTERNAME; examiner = $Examiner; method = $Mode; tool = $ToolPath; tool_sha256 = $plan.tool_sha256
  process = $plan.process; note = 'Sensitive: memory contents. Store encrypted. Do not upload.'
}
$custody = Join-Path $full 'chain-of-custody.json'
$all = @(); if (Test-Path -LiteralPath $custody) { $all = @(Get-Content -Raw -LiteralPath $custody | ConvertFrom-Json) }
$all += [pscustomobject]$rec
$all | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $custody -Encoding UTF8
Write-Host "[ARGUS] dump: $($plan.output)`n[ARGUS] sha256: $hash`n[ARGUS] custody: $custody"
