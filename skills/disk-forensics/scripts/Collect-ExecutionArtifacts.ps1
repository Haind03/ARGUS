<#
  ARGUS by HaiND from the Post and Telecommunication Institute of Technology
.SYNOPSIS
  READ-ONLY collection of Windows execution & file-activity artefacts -> argus.artifacts/1 JSON.
  Prefetch, BAM/DAM, UserAssist (ROT13-decoded), RecentDocs, LNK in Recent, Jump Lists (metadata),
  USB device history (USBSTOR), Recycle Bin ($I files), Amcache/ShimCache presence (for offline parsers).
  Authorised use on your own machine only. Nothing is modified.
#>
param([string]$OutFile, [int]$MaxItems = 5000)
$ErrorActionPreference = 'Continue'
$errs = New-Object System.Collections.Generic.List[string]
function Rot13([string]$s) {
  -join ($s.ToCharArray() | ForEach-Object {
    $c = [int]$_
    if ($c -ge 65 -and $c -le 90) { [char](((($c - 65) + 13) % 26) + 65) }
    elseif ($c -ge 97 -and $c -le 122) { [char](((($c - 97) + 13) % 26) + 97) } else { $_ } })
}
function FileTimeAt([byte[]]$b, [int]$o) { try { [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, $o)).ToString('o') } catch { '' } }

$A = [ordered]@{ schema = 'argus.artifacts/1'; host = $env:COMPUTERNAME; collected_at = (Get-Date).ToUniversalTime().ToString('o') }

# Prefetch (names + timestamps; content is MAM-compressed on Win10+, parse offline with PECmd)
try {
  $A.prefetch = @(Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -ErrorAction Stop | Select-Object -First $MaxItems | ForEach-Object {
    [ordered]@{ file = $_.Name; exe = ($_.Name -replace '-[0-9A-F]{8}\.pf$', ''); created = $_.CreationTimeUtc.ToString('o'); last_run_approx = $_.LastWriteTimeUtc.ToString('o') } })
} catch { $errs.Add("prefetch (needs admin / prefetch disabled): $_") }

# BAM / DAM (last execution per user SID)
$A.bam = @()
foreach ($root in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
  try {
    Get-ChildItem $root -ErrorAction Stop | ForEach-Object {
      $sid = $_.PSChildName; $k = Get-Item $_.PSPath
      foreach ($v in $k.GetValueNames()) {
        $d = $k.GetValue($v)
        if ($d -is [byte[]] -and $d.Length -ge 8) { $A.bam += [ordered]@{ sid = $sid; path = $v; last_exec = (FileTimeAt $d 0) } }
      }
    }
  } catch { }
}

# UserAssist (GUI launches, ROT13)
try {
  $A.userassist = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count' -ErrorAction Stop | ForEach-Object {
    $k = Get-Item $_.PSPath
    foreach ($v in $k.GetValueNames()) {
      $d = $k.GetValue($v); $run = 0; $last = ''
      if ($d -is [byte[]] -and $d.Length -ge 68) { $run = [BitConverter]::ToInt32($d, 4); $last = FileTimeAt $d 60 }
      [ordered]@{ name = (Rot13 $v); run_count = $run; last_run = $last }
    } })
} catch { $errs.Add("userassist: $_") }

# Recent LNK files + Jump Lists (metadata)
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
try {
  $sh = New-Object -ComObject WScript.Shell
  $A.lnk = @(Get-ChildItem -LiteralPath $recent -Filter *.lnk -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First $MaxItems | ForEach-Object {
    $t = ''; try { $t = $sh.CreateShortcut($_.FullName).TargetPath } catch { }
    [ordered]@{ lnk = $_.Name; target = $t; modified = $_.LastWriteTimeUtc.ToString('o') } })
  $A.jumplists = @(Get-ChildItem -LiteralPath "$recent\AutomaticDestinations", "$recent\CustomDestinations" -File -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ file = $_.Name; modified = $_.LastWriteTimeUtc.ToString('o'); size = $_.Length } })
} catch { $errs.Add("lnk: $_") }

# RecentDocs extensions summary
try {
  $A.recentdocs_ext = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -ErrorAction Stop | ForEach-Object { $_.PSChildName })
} catch { }

# USB storage history
try {
  $A.usb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction Stop | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [ordered]@{ device = $_.PSParentPath.Split('\')[-1]; serial = $_.PSChildName; friendly = $p.FriendlyName } })
} catch { $errs.Add("usbstor: $_") }

# Recycle Bin $I metadata (original path + deletion time)
$A.recycle = @()
foreach ($d in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root })) {
  $rb = Join-Path $d.Root '$Recycle.Bin'
  try {
    Get-ChildItem -LiteralPath $rb -Recurse -Force -Filter '$I*' -ErrorAction Stop | Select-Object -First $MaxItems | ForEach-Object {
      $b = [IO.File]::ReadAllBytes($_.FullName)
      if ($b.Length -ge 28) {
        $ver = [BitConverter]::ToInt64($b, 0); $size = [BitConverter]::ToInt64($b, 8); $del = FileTimeAt $b 16
        $name = if ($ver -eq 2) { [Text.Encoding]::Unicode.GetString($b, 28, $b.Length - 28).TrimEnd([char]0) } else { [Text.Encoding]::Unicode.GetString($b, 24, [Math]::Min(520, $b.Length - 24)).TrimEnd([char]0) }
        $A.recycle += [ordered]@{ original_path = $name; size = $size; deleted = $del; sid = $_.Directory.Name }
      }
    }
  } catch { }
}

# Offline-parser handoff (Eric Zimmerman tools: AmcacheParser, AppCompatCacheParser, PECmd, MFTECmd)
$A.offline_sources = [ordered]@{
  amcache = (Test-Path "$env:SystemRoot\AppCompat\Programs\Amcache.hve")
  shimcache_key = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
  srum = (Test-Path "$env:SystemRoot\System32\sru\SRUDB.dat")
  mft_usn = 'use MFTECmd on $MFT / $J from a VSS or offline copy'
}
$A.collection_errors = $errs.ToArray()

if (-not $OutFile) { $OutFile = Join-Path $env:TEMP ("artifacts-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format yyyyMMdd-HHmmss)) }
[IO.File]::WriteAllText($OutFile, ($A | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
Write-Output $OutFile
