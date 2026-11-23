# Native Windows logging (opt-in)

Without Sysmon, these native settings give ARGUS process command lines and PowerShell content.
`scripts/Enable-ArgusLogging.ps1` applies them; it runs in **-WhatIf mode unless `-Apply` is passed**.

| Setting | Command (elevated) | Enables |
|---|---|---|
| Process creation auditing | `auditpol /set /subcategory:"Process Creation" /success:enable` | Security 4688 |
| Command line in 4688 | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1` | 4688 CommandLine |
| Script Block Logging | `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1` | PowerShell 4104 |
| Security log size | `wevtutil sl Security /ms:268435456` | longer look-back |
| Service install auditing | `auditpol /set /subcategory:"Security System Extension" /success:enable` | 4697 |
| Account management | `auditpol /set /subcategory:"User Account Management" /success:enable` | 4720 |

Privacy: Script Block Logging records full script text, which may include secrets typed into PowerShell. Tell the user.
