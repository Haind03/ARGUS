<#
  ARGUS by HaiND from the Post and Telecommunication Institute of Technology
.SYNOPSIS
  ARGUS telemetry collector (READ-ONLY). Produces argus.telemetry/1 JSON.

.DESCRIPTION
  Collects host artefacts used by the ARGUS hunt engine. It never modifies
  system state: no registry writes, no service/process changes, no deletion.
  Run only on a machine you own or are explicitly authorised to examine.

  Some sections need an elevated prompt (Security log, Sysmon, all-users
  scheduled tasks, Defender preferences). Missing rights are recorded in
  "collection_errors" instead of failing.

.PARAMETER OutFile
  Output JSON path. Default: %ProgramData%\ARGUS\telemetry\telemetry-<host>-<ts>.json

.PARAMETER Sections
  Comma list or 'all'. host,processes,autoruns,scheduled_tasks,services,wmi,network,
  dns,defender,registry,events,files,drivers,bits,users,firewall,browser,hosts,shadow_copies,com

.PARAMETER EventHours
  Look-back window for event logs (default 72).

.PARAMETER HashProcesses
  Compute SHA-256 of running process images (slower).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy RemoteSigned -File Collect-Telemetry.ps1 -Sections all -HashProcesses
#>
[CmdletBinding()]
param(
  [string]$OutFile,
  [string]$Sections = 'all',
  [int]$EventHours = 72,
  [int]$MaxEventsPerId = 500,
  [int]$FileRecentDays = 7,
  [int]$MaxFiles = 20000,
  [switch]$HashProcesses
)
$__argusBanner = Join-Path $PSScriptRoot 'ArgusBanner.ps1'
if (Test-Path -LiteralPath $__argusBanner) { . $__argusBanner }

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'
$script:Errors = New-Object System.Collections.Generic.List[string]
$want = @($Sections.ToLower().Split(',') | ForEach-Object { $_.Trim() })
function Want([string]$name) { return ($want -contains 'all') -or ($want -contains $name) }
function Note-Err([string]$where, $err) { $script:Errors.Add("${where}: $($err.ToString())") }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$SigCache = @{}
function Get-Sig([string]$path) {
  if ([string]::IsNullOrWhiteSpace($path)) { return $null }
  $p = [Environment]::ExpandEnvironmentVariables($path.Trim('"'))
  if ($SigCache.ContainsKey($p)) { return $SigCache[$p] }
  $r = $null
  try {
    if (Test-Path -LiteralPath $p -PathType Leaf) {
      $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
      $signer = ''
      if ($s.SignerCertificate) { $signer = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
      $r = @{ signed = ($s.Status -eq 'Valid'); signer = $signer; status = "$($s.Status)" }
    }
  } catch { }
  $SigCache[$p] = $r
  return $r
}
function Get-Sha256([string]$path) {
  try {
    $p = [Environment]::ExpandEnvironmentVariables($path.Trim('"'))
    if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
  } catch { }
  return ''
}
function Extract-Exe([string]$cmd) {
  if ([string]::IsNullOrWhiteSpace($cmd)) { return '' }
  $c = $cmd.Trim()
  if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 0) { return $c.Substring(1, $e - 1) } }
  $m = [regex]::Match($c, '^(.+?\.(exe|dll|com|bat|cmd|ps1|vbs|js|scr))\b', 'IgnoreCase')
  if ($m.Success) { return $m.Groups[1].Value }
  return ($c -split ' ')[0]
}

$T = [ordered]@{
  schema = 'argus.telemetry/1'
  collector = 'Collect-Telemetry.ps1/0.1'
  collected_at = (Get-Date).ToUniversalTime().ToString('o')
  elevated = (Test-Admin)
}

# ---------------- host ----------------
if (Want 'host') {
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $rem = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID })
    $T.host = [ordered]@{
      hostname = $env:COMPUTERNAME; os = $os.Caption; build = $os.BuildNumber
      last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o'); user = "$env:USERDOMAIN\$env:USERNAME"
      removable_drives = $rem; ps_version = "$($PSVersionTable.PSVersion)"
      sysmon_installed = [bool](Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
    }
  } catch { Note-Err 'host' $_ }
}

# ---------------- processes ----------------
if (Want 'processes') {
  try {
    $procs = Get-CimInstance Win32_Process
    $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    $T.processes = @(foreach ($p in $procs) {
      $owner = ''
      try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop; if ($o.User) { $owner = "$($o.Domain)\$($o.User)" } } catch { }
      $sig = Get-Sig $p.ExecutablePath
      $parent = $byPid[[int]$p.ParentProcessId]
      [ordered]@{
        pid = [int]$p.ProcessId; ppid = [int]$p.ParentProcessId; name = $p.Name; path = $p.ExecutablePath
        cmdline = $p.CommandLine; user = $owner
        start_time = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { '' }
        parent_name = if ($parent) { $parent.Name } else { '' }
        parent_path = if ($parent) { $parent.ExecutablePath } else { '' }
        signed = if ($sig) { $sig.signed } else { $null }; signer = if ($sig) { $sig.signer } else { '' }
        sha256 = if ($HashProcesses -and $p.ExecutablePath) { Get-Sha256 $p.ExecutablePath } else { '' }
      }
    })
  } catch { Note-Err 'processes' $_ }
}

# ---------------- autoruns (Run keys, startup, IFEO, UAC handler keys) ----------------
if (Want 'autoruns') {
  $ar = New-Object System.Collections.Generic.List[object]
  $runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
  )
  foreach ($k in $runKeys) {
    try {
      if (Test-Path $k) {
        $item = Get-ItemProperty -Path $k
        foreach ($prop in $item.PSObject.Properties) {
          if ($prop.Name -like 'PS*') { continue }
          if ($k -like '*CurrentVersion\Windows' -and $prop.Name -notin @('Load', 'Run')) { continue }
          $v = "$($prop.Value)"; if (-not $v) { continue }
          $sig = Get-Sig (Extract-Exe $v)
          $ar.Add([ordered]@{ location = ($k -replace ':', ''); name = $prop.Name; value = $v
            signed = if ($sig) { $sig.signed } else { $null }; signer = if ($sig) { $sig.signer } else { '' } })
        }
      }
    } catch { Note-Err "autoruns $k" $_ }
  }
  $startup = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
  foreach ($d in $startup) {
    try {
      Get-ChildItem -LiteralPath $d -File -Force -ErrorAction Stop | ForEach-Object {
        $target = $_.FullName
        if ($_.Extension -eq '.lnk') {
          try { $sh = New-Object -ComObject WScript.Shell; $l = $sh.CreateShortcut($_.FullName); $target = ("$($l.TargetPath) $($l.Arguments)").Trim() } catch { }
        }
        $sig = Get-Sig (Extract-Exe $target)
        $ar.Add([ordered]@{ location = "StartupFolder:$d"; name = $_.Name; value = $target
          signed = if ($sig) { $sig.signed } else { $null }; signer = if ($sig) { $sig.signer } else { '' } })
      }
    } catch { }
  }
  try {
    Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction Stop | ForEach-Object {
      $dbg = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
      if ($dbg) { $ar.Add([ordered]@{ location = ($_.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM'); name = $_.PSChildName; value = $dbg }) }
    }
    Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object {
      $mon = (Get-ItemProperty -Path $_.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue).MonitorProcess
      if ($mon) { $ar.Add([ordered]@{ location = ($_.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM'); name = $_.PSChildName; value = $mon }) }
    }
  } catch { Note-Err 'ifeo' $_ }
  foreach ($cls in 'ms-settings', 'mscfile', 'exefile', 'Folder', 'Launcher.SystemSettings') {
    $k = "HKCU:\Software\Classes\$cls\shell\open\command"
    try {
      if (Test-Path $k) {
        $v = (Get-ItemProperty -Path $k).'(default)'
        if ($v) { $ar.Add([ordered]@{ location = "HKCU\Software\Classes\$cls\shell\open\command"; name = '(default)'; value = $v }) }
      }
    } catch { }
  }
  $T.autoruns = $ar.ToArray()
}

# ---------------- scheduled tasks ----------------
if (Want 'scheduled_tasks') {
  try {
    $T.scheduled_tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
      $acts = @($_.Actions | ForEach-Object {
        if ($_.CimClass.CimClassName -eq 'MSFT_TaskExecAction') { ("$($_.Execute) $($_.Arguments)").Trim() }
        elseif ($_.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') { "COM:$($_.ClassId) $($_.Data)" }
        else { "$($_.CimClass.CimClassName)" } })
      [ordered]@{ path = $_.TaskPath; name = $_.TaskName; actions = $acts; author = "$($_.Author)"
        enabled = ($_.State -ne 'Disabled'); hidden = [bool]$_.Settings.Hidden; run_as = "$($_.Principal.UserId)"
        date = "$($_.Date)"; triggers = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) }
    })
  } catch { Note-Err 'scheduled_tasks' $_ }
}

# ---------------- services ----------------
if (Want 'services') {
  try {
    $T.services = @(Get-CimInstance Win32_Service | ForEach-Object {
      $sig = Get-Sig (Extract-Exe $_.PathName)
      [ordered]@{ name = $_.Name; display = $_.DisplayName; path = $_.PathName; start_mode = $_.StartMode
        state = $_.State; account = $_.StartName
        signed = if ($sig) { $sig.signed } else { $null }; signer = if ($sig) { $sig.signer } else { '' } }
    })
  } catch { Note-Err 'services' $_ }
}

# ---------------- drivers ----------------
if (Want 'drivers') {
  try {
    $T.drivers = @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
      $p = $_.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
      $sig = Get-Sig $p
      [ordered]@{ name = $_.Name; path = $p; signed = if ($sig) { $sig.signed } else { $null }
        signer = if ($sig) { $sig.signer } else { '' }; sha256 = (Get-Sha256 $p) }
    })
  } catch { Note-Err 'drivers' $_ }
}

# ---------------- WMI persistence ----------------
if (Want 'wmi') {
  try {
    $filters = @{}; Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object { $filters[$_.Name] = $_.Query }
    $T.wmi_subscriptions = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
      $cons = $_.Consumer; $fil = $_.Filter
      $c = Get-CimInstance -Namespace root\subscription -ClassName $cons.CimClass.CimClassName -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $cons.Name } | Select-Object -First 1
      [ordered]@{ consumer = $cons.Name; consumer_type = $cons.CimClass.CimClassName; filter = $filters[$fil.Name]
        command = if ($c) { "$($c.CommandLineTemplate)$($c.ScriptText)" } else { '' } }
    })
  } catch { Note-Err 'wmi (needs admin)' $_ }
}

# ---------------- network ----------------
if (Want 'network') {
  try {
    $pmap = @{}; Get-CimInstance Win32_Process | ForEach-Object { $pmap[[int]$_.ProcessId] = $_ }
    $tcp = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in 'Established', 'Listen', 'SynSent', 'CloseWait' }
    $T.network = @(foreach ($c in $tcp) {
      $pp = $pmap[[int]$c.OwningProcess]
      [ordered]@{ proto = 'tcp'; local = $c.LocalAddress; lport = $c.LocalPort; remote = $c.RemoteAddress; rport = $c.RemotePort
        state = "$($c.State)"; pid = [int]$c.OwningProcess; process = if ($pp) { $pp.Name } else { '' }
        process_path = if ($pp) { $pp.ExecutablePath } else { '' } }
    })
    $T.network += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
      $pp = $pmap[[int]$_.OwningProcess]
      [ordered]@{ proto = 'udp'; local = $_.LocalAddress; lport = $_.LocalPort; state = 'Listen'; pid = [int]$_.OwningProcess
        process = if ($pp) { $pp.Name } else { '' }; process_path = if ($pp) { $pp.ExecutablePath } else { '' } }
    })
  } catch { Note-Err 'network' $_ }
}
if (Want 'dns') {
  try { $T.dns_cache = @(Get-DnsClientCache -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Entry; type = "$($_.Type)"; data = $_.Data } }) }
  catch { Note-Err 'dns' $_ }
}
if (Want 'hosts') {
  try { $T.hosts_file = @(Get-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop) } catch { Note-Err 'hosts' $_ }
}

# ---------------- Defender / firewall ----------------
if (Want 'defender') {
  try {
    $st = Get-MpComputerStatus -ErrorAction Stop
    $pr = $null; try { $pr = Get-MpPreference -ErrorAction Stop } catch { Note-Err 'defender prefs (exclusions need admin)' $_ }
    $T.defender = [ordered]@{
      realtime_enabled = $st.RealTimeProtectionEnabled; antivirus_enabled = $st.AntivirusEnabled
      behavior_monitor_enabled = $st.BehaviorMonitorEnabled; tamper_protection = $st.IsTamperProtected
      signature_age_days = $st.AntivirusSignatureAge
      exclusions_path = if ($pr) { @($pr.ExclusionPath | Where-Object { $_ -and $_ -notlike 'N/A*' }) } else { @() }
      exclusions_process = if ($pr) { @($pr.ExclusionProcess | Where-Object { $_ -and $_ -notlike 'N/A*' }) } else { @() }
      exclusions_extension = if ($pr) { @($pr.ExclusionExtension | Where-Object { $_ -and $_ -notlike 'N/A*' }) } else { @() }
    }
  } catch { Note-Err 'defender' $_ }
}
if (Want 'firewall') {
  try { $T.firewall_profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled } }) }
  catch { Note-Err 'firewall' $_ }
}

# ---------------- registry policy ----------------
if (Want 'registry') {
  function RegVal($path, $name) { try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null } }
  $T.registry = [ordered]@{
    winlogon = [ordered]@{ Shell = (RegVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell')
                           Userinit = (RegVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit') }
    appinit_dlls = (RegVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs')
    appinit_dlls_wow64 = (RegVal 'HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs')
    appcert_dlls = ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Value }) -join ';'
    wdigest_use_logon_credential = (RegVal 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential')
    disable_antispyware = ((RegVal 'HKLM:\Software\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware') -eq 1)
    disable_realtime_policy = ((RegVal 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring') -eq 1)
    enable_lua = (RegVal 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
    disable_task_mgr = ((RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableTaskMgr') -eq 1)
    lsa_run_as_ppl_off = ((RegVal 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RunAsPPL') -ne 1)
    ps_scriptblock_logging_off = ((RegVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 0)
  }
}
if (Want 'com') {
  try {
    $T.com_hijacks = @(Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction Stop | ForEach-Object {
      foreach ($sub in 'InprocServer32', 'LocalServer32') {
        $k = Join-Path $_.PSPath $sub
        if (Test-Path $k) { $v = (Get-ItemProperty $k).'(default)'; if ($v) { [ordered]@{ clsid = $_.PSChildName; server = $sub; value = $v } } }
      } })
  } catch { }
}

# ---------------- BITS ----------------
if (Want 'bits') {
  try {
    $T.bits_jobs = @(Get-BitsTransfer -AllUsers -ErrorAction Stop | ForEach-Object {
      [ordered]@{ name = $_.DisplayName; owner = $_.OwnerAccount; state = "$($_.JobState)"
        url = (@($_.FileList | ForEach-Object { $_.RemoteName }) -join ' ')
        file = (@($_.FileList | ForEach-Object { $_.LocalName }) -join ' ')
        notify_cmd = ("$($_.NotifyCmdLine)").Trim() }
    })
  } catch { Note-Err 'bits (needs admin)' $_ }
}

# ---------------- users ----------------
if (Want 'users') {
  try {
    $T.users = @(Get-LocalUser | ForEach-Object { [ordered]@{ name = $_.Name; enabled = $_.Enabled; last_logon = "$($_.LastLogon)"; created = '' } })
    $T.local_admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name })
  } catch { Note-Err 'users' $_ }
}

# ---------------- browser extensions (Chromium family) ----------------
if (Want 'browser') {
  $ext = New-Object System.Collections.Generic.List[object]
  $roots = @{ chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data"; edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"; brave = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
  foreach ($b in $roots.Keys) {
    $r = $roots[$b]; if (-not (Test-Path -LiteralPath $r)) { continue }
    Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } | ForEach-Object {
      $prefs = Join-Path $_.FullName 'Secure Preferences'
      $settings = $null
      try { $settings = (Get-Content -LiteralPath $prefs -Raw -ErrorAction Stop | ConvertFrom-Json).extensions.settings } catch { }
      if ($settings) {
        foreach ($p in $settings.PSObject.Properties) {
          $m = $p.Value.manifest; if (-not $m) { continue }
          $ext.Add([ordered]@{ browser = $b; id = $p.Name; name = "$($m.name)"; version = "$($m.version)"
            permissions = @($m.permissions) + @($m.host_permissions); from_webstore = [bool]$p.Value.from_webstore
            developer_mode = ($p.Value.location -eq 4) })
        }
      }
    }
  }
  $T.browser_extensions = $ext.ToArray()
}

# ---------------- shadow copies ----------------
if (Want 'shadow_copies') {
  try { $T.shadow_copies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop).Count } catch { Note-Err 'shadow_copies (needs admin)' $_ }
}

# ---------------- recent files in high-risk dirs (metadata only) ----------------
if (Want 'files') {
  $since = (Get-Date).AddDays(-$FileRecentDays)
  $dirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:PUBLIC", "$env:ProgramData", "$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:SystemRoot\Temp")
  $files = New-Object System.Collections.Generic.List[object]
  foreach ($d in ($dirs | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $d)) { continue }
    try {
      Get-ChildItem -LiteralPath $d -File -Recurse -Force -Depth 3 -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $since -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
        Select-Object -First $MaxFiles | ForEach-Object {
          if ($files.Count -ge $MaxFiles) { return }
          $zone = ''; $hostUrl = ''
          try { $ads = Get-Content -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction Stop
                $zone = (($ads | Where-Object { $_ -like 'ZoneId=*' }) -replace 'ZoneId=', '')
                $hostUrl = (($ads | Where-Object { $_ -like 'HostUrl=*' }) -replace 'HostUrl=', '') } catch { }
          $isExec = $_.Extension -match '^\.(exe|dll|scr|msi|ps1|vbs|js|jse|hta|bat|cmd|lnk|iso|img)$'
          $sig = if ($isExec) { Get-Sig $_.FullName } else { $null }
          $files.Add([ordered]@{ path = $_.FullName; size = $_.Length; modified = $_.LastWriteTimeUtc.ToString('o')
            created = $_.CreationTimeUtc.ToString('o'); zone_id = "$zone"; host_url = "$hostUrl"
            hidden = [bool]($_.Attributes -band [IO.FileAttributes]::Hidden)
            signed = if ($sig) { $sig.signed } else { $null }; signer = if ($sig) { $sig.signer } else { '' }
            sha256 = if ($isExec -and $_.Length -lt 100MB) { Get-Sha256 $_.FullName } else { '' } })
        }
    } catch { Note-Err "files $d" $_ }
  }
  $T.files = $files.ToArray()
}

# ---------------- event logs ----------------
if (Want 'events') {
  $start = (Get-Date).AddHours(-$EventHours)
  $queries = @(
    @{ log = 'Security'; ids = 1102, 4624, 4625, 4688, 4697, 4720, 4732, 5145 },
    @{ log = 'System'; ids = 104, 7045, 7036, 7040 },
    @{ log = 'Microsoft-Windows-PowerShell/Operational'; ids = 4104 },
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = 1, 3, 8, 10, 11, 13, 22, 23, 26 },
    @{ log = 'Microsoft-Windows-Windows Defender/Operational'; ids = 1006, 1116, 1117, 5001, 5007 },
    @{ log = 'Microsoft-Windows-WMI-Activity/Operational'; ids = 5861 },
    @{ log = 'Microsoft-Windows-TaskScheduler/Operational'; ids = 106, 141 }
  )
  $ev = New-Object System.Collections.Generic.List[object]
  foreach ($q in $queries) {
    foreach ($id in $q.ids) {
      try {
        Get-WinEvent -FilterHashtable @{ LogName = $q.log; Id = $id; StartTime = $start } -MaxEvents $MaxEventsPerId -ErrorAction Stop | ForEach-Object {
          $x = [xml]$_.ToXml(); $data = [ordered]@{}
          foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = $d.'#text' } }
          if ($id -eq 4104 -and $data.ScriptBlockText -and $data.ScriptBlockText.Length -gt 20000) { $data.ScriptBlockText = $data.ScriptBlockText.Substring(0, 20000) }
          if ($id -eq 4624 -and $data.LogonType -notin '3', '10') { return }  # keep only remote logons
          $ev.Add([ordered]@{ log = $q.log; id = $id; time = $_.TimeCreated.ToUniversalTime().ToString('o'); level = "$($_.LevelDisplayName)"; data = $data })
        }
      } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Note-Err "events $($q.log)/$id" $_ }
      }
    }
  }
  $T.events = $ev.ToArray()
}

$T.collection_errors = $script:Errors.ToArray()

if (-not $OutFile) {
  $dir = Join-Path $env:ProgramData 'ARGUS\telemetry'
  if (-not (Test-Admin)) { $dir = Join-Path $env:LOCALAPPDATA 'ARGUS\telemetry' }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $OutFile = Join-Path $dir ("telemetry-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$json = $T | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host "[ARGUS] telemetry written: $OutFile  (elevated=$($T.elevated), errors=$($script:Errors.Count))"
Write-Output $OutFile
