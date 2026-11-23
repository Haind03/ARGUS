<#
.SYNOPSIS
  OPT-IN: enable native logging useful for ARGUS (4688 + cmdline, 4104, 4697, 4720, larger Security log).
  Default is a dry run that only prints what would change. Pass -Apply to change configuration.
  Authorised use on your own machine only.
#>
param([switch]$Apply)
$plan = @(
  @{ d = 'Audit Process Creation (4688)'; c = { auditpol /set /subcategory:"Process Creation" /success:enable } },
  @{ d = 'Include command line in 4688'; c = { New-Item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null; Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1 -Type DWord } },
  @{ d = 'PowerShell Script Block Logging (4104)'; c = { New-Item 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1 -Type DWord } },
  @{ d = 'Audit Security System Extension (4697)'; c = { auditpol /set /subcategory:"Security System Extension" /success:enable } },
  @{ d = 'Audit User Account Management (4720/4732)'; c = { auditpol /set /subcategory:"User Account Management" /success:enable } },
  @{ d = 'Security log 256 MB'; c = { wevtutil sl Security /ms:268435456 } }
)
foreach ($p in $plan) {
  if ($Apply) { Write-Host "[APPLY] $($p.d)"; & $p.c } else { Write-Host "[WHATIF] would: $($p.d)" }
}
if (-not $Apply) { Write-Host 'Dry run only. Re-run with -Apply in an elevated prompt to make these changes.' }
