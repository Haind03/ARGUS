<#
  ARGUS by HaiND from the Post and Telecommunication Institute of Technology
.SYNOPSIS
  ARGUS incident response, OPT-IN ONLY. Default is -WhatIf (prints what would happen).

.DESCRIPTION
  Containment / eradication actions for the user's OWN machine, each evidence-preserving:
    Isolate            block all inbound/outbound traffic via a dedicated firewall policy (reversible: -Action Unisolate)
    Unisolate          remove the ARGUS isolation rules and restore profile defaults that were saved
    Quarantine         hash + copy to case evidence, then move the file to the case quarantine folder (renamed .quarantine)
    KillProcess        record process details (path, cmdline, hash), then stop the process
    DisableTask        export task XML to evidence, then disable it (not delete)
    DisableService     export service config to evidence, then set Startup=Disabled and stop it
    RemoveRunValue     export the Run key to evidence (.reg), then remove the single value
    RemoveWmiBinding   export filter/consumer/binding to evidence, then remove the binding
  Requirements (all enforced):
    * -CaseDir points at an ARGUS case whose case.json has an UNEXPIRED ir_optin (argus case optin ...)
    * -Execute is passed explicitly (otherwise dry run)
    * every action is appended to <case>\response-log.jsonl
  Never: deletes evidence, wipes, reboots, touches other machines.

.EXAMPLE
  .\Invoke-ArgusResponse.ps1 -CaseDir .\argus-cases\pc1 -Action Quarantine -Path C:\Users\bob\AppData\Local\Temp\x.exe
.EXAMPLE
  .\Invoke-ArgusResponse.ps1 -CaseDir .\argus-cases\pc1 -Action Quarantine -Path C:\Users\bob\AppData\Local\Temp\x.exe -Execute
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$CaseDir,
  [Parameter(Mandatory)][ValidateSet('Isolate', 'Unisolate', 'Quarantine', 'KillProcess', 'DisableTask', 'DisableService', 'RemoveRunValue', 'RemoveWmiBinding')][string]$Action,
  [string]$Path,
  [int]$ProcessId,
  [string]$TaskPath = '\',
  [string]$TaskName,
  [string]$ServiceName,
  [string]$RegistryKey,
  [string]$ValueName,
  [string]$ConsumerName,
  [switch]$Execute
)
$__argusBanner = Join-Path $PSScriptRoot '..\..\telemetry-collection\scripts\ArgusBanner.ps1'
if (Test-Path -LiteralPath $__argusBanner) { . $__argusBanner }
$ErrorActionPreference = 'Stop'
$case = (Resolve-Path -LiteralPath $CaseDir).Path
$meta = Get-Content -Raw -LiteralPath (Join-Path $case 'case.json') | ConvertFrom-Json
$opt = $meta.ir_optin
if (-not $opt) { throw 'DETECT-ONLY: this case has no IR opt-in. Run: argus case optin --case <dir> --minutes 60 --reason "..."' }
# cast (not ::Parse): PS7 ConvertFrom-Json already turns ISO strings into DateTime; PS5.1 keeps strings
if (([DateTimeOffset]$opt.expires_at) -lt [DateTimeOffset]::UtcNow) { throw "IR opt-in expired at $($opt.expires_at). Renew it deliberately." }
$ev = Join-Path $case 'evidence'; $qdir = Join-Path $case 'quarantine'
New-Item -ItemType Directory -Force -Path $ev, $qdir | Out-Null
$log = Join-Path $case 'response-log.jsonl'
$protected = @('C:\Windows\System32\', 'C:\Windows\SysWOW64\', 'C:\Windows\explorer.exe', 'C:\Program Files\Windows Defender\')

function Log([string]$what, $detail) {
  $o = [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('o'); action = $Action; executed = [bool]$Execute; what = $what; detail = $detail; by = "$env:USERDOMAIN\$env:USERNAME" }
  Add-Content -LiteralPath $log -Value ($o | ConvertTo-Json -Compress -Depth 5) -Encoding UTF8
}
function Step([string]$desc, [scriptblock]$do) {
  if ($Execute) { Write-Host "[DO]     $desc"; & $do } else { Write-Host "[WHATIF] $desc" }
}

switch ($Action) {
  'Isolate' {
    Step 'save firewall profile state to evidence\firewall-before.json' { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json | Set-Content (Join-Path $ev 'firewall-before.json') }
    Step 'enable all firewall profiles; default inbound+outbound = Block (group "ARGUS-Isolation")' {
      Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    }
    Step 'allow loopback only' { New-NetFirewallRule -DisplayName 'ARGUS-Isolation-Loopback' -Group 'ARGUS-Isolation' -Direction Outbound -RemoteAddress 127.0.0.1 -Action Allow | Out-Null }
    Log 'network isolation' @{ note = 'reverse with -Action Unisolate' }
  }
  'Unisolate' {
    $before = Join-Path $ev 'firewall-before.json'
    Step 'remove ARGUS-Isolation rules' { Get-NetFirewallRule -Group 'ARGUS-Isolation' -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
    Step 'restore saved profile defaults' {
      foreach ($p in (Get-Content -Raw $before | ConvertFrom-Json)) {
        Set-NetFirewallProfile -Profile $p.Name -Enabled ([bool]$p.Enabled) -DefaultInboundAction $p.DefaultInboundAction -DefaultOutboundAction $p.DefaultOutboundAction
      }
    }
    Log 'network isolation removed' @{}
  }
  'Quarantine' {
    $full = (Resolve-Path -LiteralPath $Path).Path
    foreach ($pp in $protected) { if ($full -like "$pp*") { throw "Refusing to quarantine protected OS path: $full" } }
    $h = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLower()
    Step "copy evidence -> evidence\$h.bin" { Copy-Item -LiteralPath $full -Destination (Join-Path $ev "$h.bin") }
    Step "move -> quarantine\$h.quarantine and strip execute (icacls deny RX for Everyone on the quarantined copy)" {
      $dst = Join-Path $qdir "$h.quarantine"; Move-Item -LiteralPath $full -Destination $dst
      icacls $dst /deny '*S-1-1-0:(RX)' | Out-Null
      [ordered]@{ original_path = $full; sha256 = $h; quarantined = $dst } | ConvertTo-Json | Set-Content (Join-Path $qdir "$h.json")
    }
    Log 'quarantine' @{ path = $full; sha256 = $h }
  }
  'KillProcess' {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId"
    if (-not $p) { throw "No process $ProcessId" }
    if ($p.Name -in @('lsass.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'System')) { throw "Refusing to kill critical process $($p.Name)" }
    $info = [ordered]@{ pid = $ProcessId; name = $p.Name; path = $p.ExecutablePath; cmdline = $p.CommandLine; parent = $p.ParentProcessId
      sha256 = if ($p.ExecutablePath) { (Get-FileHash -LiteralPath $p.ExecutablePath -Algorithm SHA256).Hash.ToLower() } else { '' } }
    Write-Host 'Tip: capture memory first (memory-acquisition) if the process may hold keys/config.'
    Step "record process details -> evidence\proc-$ProcessId.json" { $info | ConvertTo-Json | Set-Content (Join-Path $ev "proc-$ProcessId.json") }
    Step "stop process $($p.Name) ($ProcessId)" { Stop-Process -Id $ProcessId -Force }
    Log 'kill process' $info
  }
  'DisableTask' {
    Step "export task XML -> evidence\task-$TaskName.xml" { Export-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName | Set-Content (Join-Path $ev "task-$TaskName.xml") }
    Step "disable task $TaskPath$TaskName (not deleted)" { Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName | Out-Null }
    Log 'disable task' @{ task = "$TaskPath$TaskName" }
  }
  'DisableService' {
    Step "export service config -> evidence\svc-$ServiceName.txt" { sc.exe qc $ServiceName | Set-Content (Join-Path $ev "svc-$ServiceName.txt") }
    Step "set $ServiceName start=Disabled and stop it" { Set-Service -Name $ServiceName -StartupType Disabled; Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
    Log 'disable service' @{ service = $ServiceName }
  }
  'RemoveRunValue' {
    if ($RegistryKey -notmatch '\\(Run|RunOnce)$') { throw 'RemoveRunValue only operates on ...\Run or ...\RunOnce keys.' }
    $safe = ($RegistryKey -replace '[\\: ]', '_')
    Step "export key -> evidence\$safe.reg" { reg.exe export ($RegistryKey -replace '^HKCU:', 'HKCU' -replace '^HKLM:', 'HKLM') (Join-Path $ev "$safe.reg") /y | Out-Null }
    Step "remove value '$ValueName' from $RegistryKey" { Remove-ItemProperty -Path ($RegistryKey -replace '^(HKCU|HKLM)\\', '$1:\') -Name $ValueName }
    Log 'remove run value' @{ key = $RegistryKey; value = $ValueName }
  }
  'RemoveWmiBinding' {
    $ns = 'root\subscription'
    $b = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { $_.Consumer.Name -eq $ConsumerName }
    if (-not $b) { throw "No binding for consumer $ConsumerName" }
    Step "export binding/consumer -> evidence\wmi-$ConsumerName.json" {
      [ordered]@{ binding = ($b | Select-Object * | Out-String); consumer = (Get-CimInstance -Namespace $ns -ClassName __EventConsumer | Where-Object Name -eq $ConsumerName | Select-Object * | Out-String) } | ConvertTo-Json | Set-Content (Join-Path $ev "wmi-$ConsumerName.json")
    }
    Step "remove binding for consumer $ConsumerName (consumer/filter kept as evidence)" { $b | Remove-CimInstance }
    Log 'remove wmi binding' @{ consumer = $ConsumerName }
  }
}
if (-not $Execute) { Write-Host "`nDry run only. Re-run with -Execute to perform (IR opt-in valid until $($opt.expires_at))." }
