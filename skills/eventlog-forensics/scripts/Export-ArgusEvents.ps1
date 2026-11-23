<#
  ARGUS by HaiND from the Post and Telecommunication Institute of Technology
.SYNOPSIS
  READ-ONLY export of Windows event logs (live channels or offline .evtx files) to ARGUS JSON
  ({"schema":"argus.telemetry/1","events":[...]}), so they can be scored by evtx_hunt.py / the engine.
.EXAMPLE
  .\Export-ArgusEvents.ps1 -Hours 168 -OutFile E:\case01\events.json
.EXAMPLE
  .\Export-ArgusEvents.ps1 -EvtxPath E:\case01\evtx\*.evtx -OutFile E:\case01\events.json
#>
param(
  [int]$Hours = 168,
  [string[]]$EvtxPath,
  [int]$MaxPerId = 2000,
  [Parameter(Mandatory)][string]$OutFile
)
$__argusBanner = Join-Path $PSScriptRoot '..\..\telemetry-collection\scripts\ArgusBanner.ps1'
if (Test-Path -LiteralPath $__argusBanner) { . $__argusBanner }
$ids = @{
  'Security' = 1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4702, 4719, 4720, 4722, 4724, 4732, 4738, 4740, 4768, 4769, 4776, 5140, 5145
  'System' = 104, 7034, 7036, 7040, 7045
  'Microsoft-Windows-PowerShell/Operational' = 4103, 4104
  'Windows PowerShell' = 400, 600
  'Microsoft-Windows-Sysmon/Operational' = 1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23, 25, 26
  'Microsoft-Windows-Windows Defender/Operational' = 1006, 1007, 1116, 1117, 5001, 5004, 5007, 5010, 5012
  'Microsoft-Windows-WMI-Activity/Operational' = 5857, 5858, 5860, 5861
  'Microsoft-Windows-TaskScheduler/Operational' = 106, 140, 141, 200, 201
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 21, 22, 24, 25
  'Microsoft-Windows-Bits-Client/Operational' = 3, 59, 60
}
$start = (Get-Date).AddHours(-$Hours)
$out = New-Object System.Collections.Generic.List[object]
$errs = New-Object System.Collections.Generic.List[string]
function Add-Ev($e, $log) {
  $x = [xml]$e.ToXml(); $data = [ordered]@{}
  foreach ($d in @($x.Event.EventData.Data)) { if ($d -and $d.Name) { $data[$d.Name] = $d.'#text' } }
  foreach ($d in @($x.Event.UserData.ChildNodes)) { foreach ($c in @($d.ChildNodes)) { if ($c.Name) { $data[$c.Name] = $c.InnerText } } }
  if ($data.Contains('ScriptBlockText') -and $data.ScriptBlockText -and $data.ScriptBlockText.Length -gt 20000) { $data.ScriptBlockText = $data.ScriptBlockText.Substring(0, 20000) }
  $out.Add([ordered]@{ log = $log; id = $e.Id; time = $e.TimeCreated.ToUniversalTime().ToString('o'); level = "$($e.LevelDisplayName)"; record = $e.RecordId; data = $data })
}
if ($EvtxPath) {
  foreach ($f in (Get-ChildItem -Path $EvtxPath -File)) {
    try { Get-WinEvent -Path $f.FullName -MaxEvents 200000 -ErrorAction Stop | ForEach-Object { Add-Ev $_ $_.LogName } }
    catch { $errs.Add("$($f.Name): $_") }
  }
} else {
  foreach ($log in $ids.Keys) {
    foreach ($id in $ids[$log]) {
      try { Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $id; StartTime = $start } -MaxEvents $MaxPerId -ErrorAction Stop | ForEach-Object { Add-Ev $_ $log } }
      catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $errs.Add("${log}/${id}: $($_.Exception.Message)") } }
    }
  }
}
$doc = [ordered]@{ schema = 'argus.telemetry/1'; collector = 'Export-ArgusEvents.ps1'; collected_at = (Get-Date).ToUniversalTime().ToString('o')
  host = @{ hostname = $env:COMPUTERNAME }; events = $out.ToArray(); collection_errors = $errs.ToArray() }
[IO.File]::WriteAllText($OutFile, ($doc | ConvertTo-Json -Depth 6 -Compress), (New-Object Text.UTF8Encoding($false)))
Write-Output "$OutFile ($($out.Count) events, $($errs.Count) errors)"
