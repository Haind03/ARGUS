# Hypothesis library (personal Windows PC)

| # | Hypothesis | Tactic | Primary data | Skill |
|---|---|---|---|---|
| H1 | A downloaded file (MOTW zone 3) was executed and is unsigned | TA0001 | files, processes | initial-access-hunting |
| H2 | An Office/PDF/browser process spawned a script host | TA0001/2 | process tree | initial-access / execution |
| H3 | Encoded/obfuscated PowerShell ran in the last 7 days | TA0002 | 4688/Sysmon 1, 4104 | execution-hunting |
| H4 | A new autostart points to a user-writable path since baseline | TA0003 | autoruns, tasks, services | persistence + baseline |
| H5 | A WMI permanent subscription exists | TA0003 | root\subscription, 5861 | persistence-hunting |
| H6 | A vulnerable driver is loaded | TA0004 | drivers | privesc-hunting |
| H7 | Defender was disabled or excluded without the user knowing | TA0005 | Defender status, 5001/5007 | defense-evasion-hunting |
| H8 | A system-binary name runs from the wrong path | TA0005 | processes | defense-evasion-hunting |
| H9 | A non-browser process read browser credential stores | TA0006 | Sysmon 11/10, cmdline | credential-access / browser-forensics |
| H10 | A discovery burst followed an unusual parent | TA0007 | process tree | discovery-hunting |
| H11 | Remote execution reached this PC from another host | TA0008 | 4624 type 3/10, 5145, 7045 | lateral-movement-hunting |
| H12 | Documents were archived with a password in Temp | TA0009 | cmdline, files | collection-hunting |
| H13 | A process beacons on a regular interval / uses web-service C2 | TA0011 | network, DNS | c2-hunting, network-forensics |
| H14 | rclone/MEGA/upload tooling sent data out | TA0010 | cmdline, SRUM | exfiltration-hunting |
| H15 | Shadow copies were deleted or ransom notes exist | TA0040 | cmdline, files, VSS count | impact-hunting |
| H16 | Code is injected into a trusted process | TA0005 | memory (malfind/ldrmodules) | memory-forensics |
| H17 | A cryptominer runs persistently | TA0040 | process, network | impact-hunting |
