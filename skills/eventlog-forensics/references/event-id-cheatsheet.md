# Event ID cheat-sheet (hunt-relevant)

| Log | ID | Meaning | ATT&CK | ARGUS |
|---|---|---|---|---|
| Security | 1102 | audit log cleared | T1070.001 | ARG-DE-002 |
| Security | 4624 / 4625 | logon success / failure (type 2 interactive, 3 network, 10 RDP) | T1078, T1110, T1133 | ARG-IA-005, ARG-CA-005, ARG-LM-003 |
| Security | 4648 | logon with explicit credentials | T1078 | ARG-EL-001 |
| Security | 4688 | process created (enable cmdline) | T1059 | all process rules |
| Security | 4697 / System 7045 | service installed | T1543.003 | ARG-PE-004 |
| Security | 4698 / 4702 | scheduled task created / updated | T1053.005 | ARG-EL-003 |
| Security | 4719 | audit policy changed | T1562.002 | ARG-EL-004 |
| Security | 4720 / 4722 / 4724 / 4738 | account created / enabled / pwd reset / changed | T1136.001, T1098 | ARG-PE-010, ARG-EL-005 |
| Security | 4732 | member added to local group | T1098 | ARG-PE-010 |
| Security | 4740 | account locked out | T1110 | ARG-EL-006 |
| Security | 4769 | Kerberos service ticket (RC4 = 0x17) | T1558.003 | ARG-EL-007 |
| Security | 5140 / 5145 | share accessed / file on share | T1021.002 | ARG-LM-001 |
| System | 104 | event log cleared | T1070.001 | ARG-DE-002 |
| System | 7036 / 7040 | service state / start type changed | T1489 | (timeline) |
| PowerShell/Op | 4103 / 4104 | module / script-block logging | T1059.001 | ARG-EX-002 |
| Sysmon | 1,3,8,10,11,13,22 | process, net, remote thread, process access, file, registry, DNS | many | see sysmon-setup |
| Defender/Op | 1116 / 1117 | malware detected / action taken | T1204 | ARG-EL-010 |
| Defender/Op | 5001 / 5010 / 5012 | real-time / antispyware / antivirus disabled | T1562.001 | ARG-EL-011 |
| Defender/Op | 5007 | configuration changed (exclusions!) | T1562.001 | ARG-EL-012 |
| WMI-Activity | 5861 | permanent consumer registered | T1546.003 | ARG-EL-013 |
| TS-LocalSessionManager | 21 / 25 | RDP logon / reconnect | T1021.001 | ARG-EL-014 |
| Bits-Client | 59 / 60 | BITS transfer start / stop (URL) | T1197 | ARG-EL-015 |
| TaskScheduler/Op | 106 / 140 / 141 / 200 | task registered / updated / deleted / run | T1053.005 | (timeline) |

Absence matters: a busy PC with **zero** 4688/4104 means logging is off, not that nothing ran.
