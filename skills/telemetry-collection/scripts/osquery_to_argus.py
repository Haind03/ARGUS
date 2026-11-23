#!/usr/bin/env python3
"""Convert osqueryi --json outputs (one file per query) into argus.telemetry/1.

Run isolated:  python -I osquery_to_argus.py --dir <folder> --out telemetry.json
Expected file names (any subset): processes.json startup.json scheduled_tasks.json services.json
drivers.json wmi_cli.json sockets.json chrome_extensions.json
"""
import argparse
import datetime as dt
import json
import os
import socket
import stat
import sys
from pathlib import Path

MAX = 256 * 1024 * 1024


def read(d: Path, name: str):
    p = d / name
    try:
        st = os.lstat(p)
    except OSError:
        return []
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size > MAX:
        print(f"skip unsafe/oversized file: {p}", file=sys.stderr)
        return []
    with open(p, encoding="utf-8-sig") as fh:
        v = json.load(fh)
    return v if isinstance(v, list) else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    d = Path(a.dir).resolve(strict=True)
    if not d.is_dir():
        sys.exit("--dir must be a directory")
    procs = read(d, "processes.json")
    names = {str(p.get("pid")): p.get("name") for p in procs}
    tel = {
        "schema": "argus.telemetry/1", "collector": "osquery_to_argus/0.1",
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": {"hostname": socket.gethostname()},
        "processes": [{"pid": int(p.get("pid", 0)), "ppid": int(p.get("ppid", 0) or 0), "name": p.get("name"),
                       "path": p.get("path"), "cmdline": p.get("cmdline"), "sha256": p.get("sha256", ""),
                       "parent_name": names.get(str(p.get("ppid")), "")} for p in procs],
        "autoruns": [{"location": s.get("source") or s.get("type"), "name": s.get("name"),
                      "value": (s.get("path", "") + " " + (s.get("args") or "")).strip()} for s in read(d, "startup.json")],
        "scheduled_tasks": [{"path": t.get("path", ""), "name": t.get("name"), "actions": [t.get("action", "")],
                             "hidden": t.get("hidden") in ("1", 1, True)} for t in read(d, "scheduled_tasks.json")],
        "services": [{"name": s.get("name"), "display": s.get("display_name"), "path": s.get("path"),
                      "start_mode": s.get("start_type"), "state": s.get("status"), "account": s.get("user_account")}
                     for s in read(d, "services.json")],
        "drivers": [{"name": x.get("service"), "path": x.get("image"), "signed": x.get("signed") in ("1", 1, True)}
                    for x in read(d, "drivers.json")],
        "wmi_subscriptions": [{"consumer": w.get("name"), "consumer_type": "CommandLineEventConsumer",
                               "command": w.get("command_line_template")} for w in read(d, "wmi_cli.json")],
        "network": [{"proto": "tcp" if str(s.get("protocol")) == "6" else "udp", "local": s.get("local_address"),
                     "lport": s.get("local_port"), "remote": s.get("remote_address"), "rport": s.get("remote_port"),
                     "state": s.get("state"), "pid": int(s.get("pid", 0) or 0),
                     "process": names.get(str(s.get("pid")), "")} for s in read(d, "sockets.json")],
        "browser_extensions": [{"browser": e.get("browser_type"), "id": e.get("identifier"), "name": e.get("name"),
                                "permissions": [x.strip() for x in str(e.get("permissions", "")).split(",") if x.strip()],
                                "from_webstore": str(e.get("from_webstore")) in ("1", "true")}
                               for e in read(d, "chrome_extensions.json")],
        "collection_errors": ["osquery: events/defender/registry sections not collected"],
    }
    out = Path(a.out)
    if out.is_symlink():
        sys.exit("refusing symlinked output")
    out.write_text(json.dumps(tel, indent=1), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
