<#
.SYNOPSIS
  Register (opt-in) the ARGUS scheduled hunt in Task Scheduler. Without -Register it only prints the plan.
  Authorised use on your own machine only.
.EXAMPLE
  .\Register-ArgusScheduledScan.ps1 -Preset quick -Time 12:30 -Register
.EXAMPLE
  .\Register-ArgusScheduledScan.ps1 -Unregister
#>
param(
  [ValidateSet('quick', 'full', 'ransomware-focus')][string]$Preset = 'quick',
  [string]$Time = '12:30',
  [switch]$AtLogon,
  [switch]$Register,
  [switch]$Unregister
)
$taskPath = '\ARGUS\'; $taskName = 'ScheduledHunt'
if ($Unregister) { Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false; Write-Host 'Removed.'; return }

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$scan = Join-Path $PSScriptRoot 'Invoke-ArgusScan.ps1'
# RemoteSigned + no hidden window: the task must not look like the malware it hunts.
# install.ps1 runs Unblock-File on the toolkit so local scripts are allowed under RemoteSigned.
$arg = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$scan`" -Preset $Preset -ArgusRoot `"$root`""
Write-Host "Task      : $taskPath$taskName"
Write-Host "Runs as   : SYSTEM (highest)  daily at $Time$(if ($AtLogon) { ' + at logon' })"
Write-Host "Action    : powershell.exe $arg"
Write-Host "Mode      : detect-only (collect -> score -> report). No remediation."
if (-not $Register) { Write-Host "`nDry run. Re-run with -Register in an elevated prompt to create the task."; return }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
$triggers = @(New-ScheduledTaskTrigger -Daily -At $Time)
if ($AtLogon) { $t = New-ScheduledTaskTrigger -AtLogOn; $t.Delay = 'PT15M'; $triggers += $t }
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'ARGUS defensive threat hunt (detect-only)' -Force | Out-Null

$data = Join-Path $env:ProgramData 'ARGUS'
New-Item -ItemType Directory -Force -Path $data | Out-Null
icacls $data /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
Write-Host "Registered. Reports -> $data\reports"
