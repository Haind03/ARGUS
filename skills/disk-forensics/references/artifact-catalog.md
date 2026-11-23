# Windows execution / file-activity artefact catalog

| Artefact | Proves | Location | Parser | Notes |
|---|---|---|---|---|
| Prefetch | execution, run count, last 8 run times, files loaded | `C:\Windows\Prefetch\*.pf` | PECmd | disabled on some SSD configs; 1024 files max |
| Amcache.hve | presence + SHA-1 of executed/installed binaries | `C:\Windows\AppCompat\Programs\Amcache.hve` | AmcacheParser | SHA-1 survives file deletion, great for intel lookups |
| ShimCache (AppCompatCache) | file existed / maybe executed; ordering | `HKLM\SYSTEM\...\AppCompatCache` | AppCompatCacheParser | written at shutdown; no exec proof on Win10 |
| BAM/DAM | last execution per user | `HKLM\SYSTEM\...\Services\bam\State\UserSettings\<SID>` | collector | ~7 days retention |
| UserAssist | GUI program launches (ROT13), count, last run | `HKCU\...\Explorer\UserAssist` | collector | user-interactive only |
| LNK / Jump Lists | files/folders opened, original paths, volume serial | `%APPDATA%\Microsoft\Windows\Recent` | LECmd / JLECmd | shows opened documents from USB/network |
| ShellBags | folders browsed (incl. deleted/USB) | NTUSER.DAT / UsrClass.dat | SBECmd | n/a |
| Recycle Bin | deleted file original path + time | `$Recycle.Bin\<SID>\$I*` | collector / RBCmd | `$R*` holds content |
| SRUM | per-app network bytes, CPU, energy (30-60 days) | `C:\Windows\System32\sru\SRUDB.dat` | SrumECmd | **exfil evidence (bytes sent per app)** |
| $MFT | every file record, MACB times, deleted entries | NTFS `$MFT` | MFTECmd | timestomping: $SI vs $FN mismatch (T1070.006) |
| USN Journal | create/rename/delete history | `$Extend\$UsnJrnl:$J` | MFTECmd | ransomware mass-rename visible here |
| USBSTOR / MountedDevices | USB devices connected | SYSTEM hive | collector / USBDeviceForensics | T1091, T1052 |
| Windows Timeline | activity history | `ActivitiesCache.db` | WxTCmd | deprecated in Win11 |
| Scheduled task XML | task creation | `C:\Windows\System32\Tasks` | text | creation time via file times |

## ATT&CK links
T1204 (execution proof), T1070.004 (file deletion), T1070.006 (timestomp), T1091/T1052 (USB),
T1041/T1567 (SRUM bytes), T1486 (USN rename storm).
