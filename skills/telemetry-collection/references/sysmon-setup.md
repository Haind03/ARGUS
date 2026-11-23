# Sysmon setup (opt-in, changes system configuration)

Sysmon is the single biggest visibility upgrade for a personal Windows PC. It is a free Microsoft
Sysinternals tool. Installing it is a **system change**, ask the user first.

```powershell
# Download from https://learn.microsoft.com/sysinternals/downloads/sysmon (verify signature: Microsoft Corporation)
Get-AuthenticodeSignature .\Sysmon64.exe
# Community configs (review before use):
#   https://github.com/SwiftOnSecurity/sysmon-config   (single file, lower noise)
#   https://github.com/olafhartong/sysmon-modular       (modular, more coverage)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
# update config later
.\Sysmon64.exe -c sysmonconfig.xml
```

## Events ARGUS uses
| ID | Event | Used by |
|---|---|---|
| 1 | Process create (hashes, parent, cmdline) | all process rules |
| 3 | Network connect | c2-hunting (manual) |
| 8 | CreateRemoteThread | ARG-DE-004 |
| 10 | ProcessAccess (LSASS) | ARG-CA-001 |
| 11 / 23 / 26 | File create / delete | ARG-CA-003 |
| 13 | Registry value set | persistence validation |
| 22 | DNS query | ARG-C2-005, ARG-C2-006 |

## Log size
Default 64 MB rolls over in hours on busy PCs; raise it:
`wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:536870912`

## False-positive note
Sysmon itself, Defender (MsMpEng) and game anti-cheat generate ProcessAccess to LSASS; the engine allow-lists the common ones.
