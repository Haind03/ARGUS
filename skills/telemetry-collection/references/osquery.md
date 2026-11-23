# osquery (cross-platform extension)

osquery exposes the OS as SQL tables and runs on Windows, macOS and Linux. ARGUS uses it as an
alternative producer for the `argus.telemetry/1` schema.

```bash
osqueryi --json "SELECT pid, parent AS ppid, name, path, cmdline FROM processes" > processes.json
osqueryi --json "SELECT * FROM startup_items" > startup.json
python -I skills/telemetry-collection/scripts/osquery_to_argus.py --dir ./osq --out telemetry.json
```

| ARGUS section | osquery table(s) |
|---|---|
| processes | `processes` (+ `authenticode` on Windows, `hash` for sha256) |
| autoruns | `startup_items`, `registry` (Run keys), `launchd` (macOS), `systemd_units`/`crontab` (Linux) |
| scheduled_tasks | `scheduled_tasks` (Windows), `crontab` |
| services | `services` (Windows), `systemd_units` |
| drivers | `drivers` (Windows), `kernel_modules` (Linux), `kernel_extensions` (macOS) |
| wmi_subscriptions | `wmi_cli_event_consumers`, `wmi_script_event_consumers`, `wmi_filter_consumer_binding` |
| network | `process_open_sockets` |
| browser_extensions | `chrome_extensions`, `firefox_addons` |
| defender | `windows_security_products` (partial) |

The pack `scripts/argus-osquery-pack.conf` schedules these queries for osqueryd. Non-Windows rules are limited:
most ARGUS heuristics are Windows-specific; on macOS/Linux treat output as inventory + baseline diff.
