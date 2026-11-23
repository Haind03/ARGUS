# argus.telemetry/1 schema

Top-level keys (all optional — rules skip missing sections and the gap should be reported):

| Key | Type | Fields | Feeds tactics |
|---|---|---|---|
| `host` | object | hostname, os, build, last_boot, user, removable_drives[], sysmon_installed | all |
| `processes` | list | pid, ppid, name, path, cmdline, user, start_time, parent_name, parent_path, signed, signer, sha256 | TA0001-TA0040 |
| `autoruns` | list | location, name, value, signed, signer (Run/RunOnce/Startup/IFEO/SilentProcessExit/HKCU handlers) | TA0003, TA0004 |
| `scheduled_tasks` | list | path, name, actions[], author, enabled, hidden, run_as, triggers[] | TA0002, TA0003 |
| `services` | list | name, display, path, start_mode, state, account, signed, signer | TA0003, TA0004 |
| `drivers` | list | name, path, signed, signer, sha256 | TA0004 |
| `wmi_subscriptions` | list | consumer, consumer_type, filter, command | TA0003 |
| `network` | list | proto, local, lport, remote, rport, state, pid, process, process_path, bytes_sent? | TA0011, TA0010 |
| `dns_cache` | list | name, type, data | TA0011 |
| `hosts_file` | list[str] | raw lines | TA0011 |
| `defender` | object | realtime_enabled, antivirus_enabled, behavior_monitor_enabled, tamper_protection, exclusions_path/process/extension[] | TA0005 |
| `firewall_profiles` | list | name, enabled | TA0005 |
| `registry` | object | winlogon{Shell,Userinit}, appinit_dlls, appcert_dlls, wdigest_use_logon_credential, disable_antispyware, disable_realtime_policy, enable_lua, disable_task_mgr, lsa_run_as_ppl_off, ps_scriptblock_logging_off | TA0003, TA0005, TA0006 |
| `com_hijacks` | list | clsid, server, value | TA0003 |
| `bits_jobs` | list | name, owner, state, url, file, notify_cmd | TA0003 |
| `users`, `local_admins` | list | — | TA0003 |
| `browser_extensions` | list | browser, id, name, version, permissions[], from_webstore, developer_mode | TA0003 |
| `shadow_copies` | int | count | TA0040 |
| `files` | list | path, size, modified, created, zone_id, host_url, hidden, signed, signer, sha256 (metadata only — contents never read) | TA0001, TA0009, TA0040 |
| `events` | list | log, id, time, level, data{EventData fields} | all |
| `collection_errors` | list[str] | what could not be collected | report |

Event IDs collected: Security 1102 4624(type 3/10) 4625 4688 4697 4720 4732 5145 · System 104 7036 7040 7045 ·
PowerShell 4104 · Sysmon 1 3 8 10 11 13 22 23 26 · Defender 1006 1116 1117 5001 5007 · WMI-Activity 5861 · TaskScheduler 106 141.

Any producer (osquery, Velociraptor, KAPE+parsers) can feed the engine if it emits these keys.
