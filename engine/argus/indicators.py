"""Shared indicator knowledge: paths, LOLBins, regex patterns.

Everything here is generic and defensive. Tune via presets rather than
editing in place where possible.
"""
from __future__ import annotations

import base64
import math
import re
from collections import Counter

# --- path classes (lowercase, backslash-normalised) -------------------------
HIGH_RISK_DIRS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
    "\\$recycle.bin\\", "\\perflogs\\", "\\programdata\\temp\\",
    "\\appdata\\local\\microsoft\\windows\\inetcache\\",
)
MEDIUM_RISK_DIRS = (
    "\\appdata\\roaming\\", "\\appdata\\local\\", "\\programdata\\",
    "\\downloads\\", "\\desktop\\", "\\documents\\", "\\music\\", "\\videos\\",
    "\\pictures\\",
)
# well-known legit software living under AppData; mitigates path signal
APPDATA_ALLOW_HINTS = (
    "\\appdata\\local\\microsoft\\teams\\", "\\appdata\\local\\microsoft\\onedrive\\",
    "\\appdata\\local\\programs\\", "\\appdata\\local\\discord\\",
    "\\appdata\\local\\slack\\", "\\appdata\\local\\google\\chrome\\",
    "\\appdata\\local\\microsoft\\edge\\", "\\appdata\\local\\zoom\\",
    "\\appdata\\roaming\\zoom\\", "\\appdata\\local\\microsoft\\windowsapps\\",
    "\\programdata\\microsoft\\windows defender\\",
    "\\appdata\\local\\mozilla firefox\\", "\\appdata\\roaming\\spotify\\",
)

SCRIPT_EXT = (".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
              ".hta", ".bat", ".cmd", ".scr", ".pif", ".lnk", ".cpl")

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
          "msaccess.exe", "mspub.exe", "visio.exe", "wordpad.exe", "eqnedt32.exe",
          "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "thunderbird.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
            "iexplore.exe", "vivaldi.exe", "browser.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
          "mshta.exe", "bash.exe", "wsl.exe"}
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
           "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
           "regsvcs.exe", "wmic.exe", "hh.exe", "forfiles.exe", "cmstp.exe",
           "msiexec.exe", "odbcconf.exe", "pcalua.exe", "mavinject.exe",
           "control.exe", "presentationhost.exe", "scriptrunner.exe",
           "esentutl.exe", "expand.exe", "extrac32.exe", "ieexec.exe",
           "infdefaultinstall.exe", "msxsl.exe", "syncappvpublishingserver.exe",
           "curl.exe", "finger.exe", "certreq.exe", "desktopimgdownldr.exe"}
SCRIPTISH = SHELLS | LOLBINS

UAC_BYPASS_HOSTS = {"fodhelper.exe", "computerdefaults.exe", "eventvwr.exe",
                    "sdclt.exe", "slui.exe", "wsreset.exe", "changepk.exe"}

DISCOVERY_CMDS = ("whoami", "systeminfo", "ipconfig", "net user", "net group",
                  "net localgroup", "net view", "net share", "nltest", "quser",
                  "query user", "arp -a", "route print", "netstat", "tasklist",
                  "hostname", "nslookup", "wmic computersystem", "wmic os",
                  "get-computerinfo", "get-localuser", "get-netipconfiguration",
                  "dsquery", "klist", "cmdkey /list", "reg query", "sc query")

SYSTEM_BINARY_PATHS = {
    "svchost.exe": ("c:\\windows\\system32\\svchost.exe", "c:\\windows\\syswow64\\svchost.exe"),
    "lsass.exe": ("c:\\windows\\system32\\lsass.exe",),
    "csrss.exe": ("c:\\windows\\system32\\csrss.exe",),
    "smss.exe": ("c:\\windows\\system32\\smss.exe",),
    "wininit.exe": ("c:\\windows\\system32\\wininit.exe",),
    "winlogon.exe": ("c:\\windows\\system32\\winlogon.exe",),
    "services.exe": ("c:\\windows\\system32\\services.exe",),
    "lsaiso.exe": ("c:\\windows\\system32\\lsaiso.exe",),
    "explorer.exe": ("c:\\windows\\explorer.exe",),
    "taskhostw.exe": ("c:\\windows\\system32\\taskhostw.exe",),
    "spoolsv.exe": ("c:\\windows\\system32\\spoolsv.exe",),
    "conhost.exe": ("c:\\windows\\system32\\conhost.exe",),
    "dllhost.exe": ("c:\\windows\\system32\\dllhost.exe", "c:\\windows\\syswow64\\dllhost.exe"),
    "rundll32.exe": ("c:\\windows\\system32\\rundll32.exe", "c:\\windows\\syswow64\\rundll32.exe"),
    "dwm.exe": ("c:\\windows\\system32\\dwm.exe",),
    "sihost.exe": ("c:\\windows\\system32\\sihost.exe",),
    "ctfmon.exe": ("c:\\windows\\system32\\ctfmon.exe", "c:\\windows\\syswow64\\ctfmon.exe"),
}
EXPECTED_PARENT = {
    "svchost.exe": {"services.exe", "msmpeng.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "taskhostw.exe": {"svchost.exe"},
}

REMOTE_ACCESS_TOOLS = {"anydesk.exe", "teamviewer.exe", "teamviewer_service.exe",
                       "screenconnect.clientservice.exe", "connectwisecontrol.client.exe",
                       "atera_agent.exe", "ateraagent.exe", "rustdesk.exe", "splashtop.exe",
                       "srservice.exe", "netsupport.exe", "client32.exe", "tvnserver.exe",
                       "winvnc.exe", "ammyy_admin.exe", "remoteutilities.exe", "rutserv.exe",
                       "meshagent.exe", "simplehelp.exe", "logmein.exe", "action1_agent.exe"}
TUNNEL_TOOLS = {"ngrok.exe", "cloudflared.exe", "chisel.exe", "plink.exe", "frpc.exe",
                "frps.exe", "ligolo.exe", "agent.exe-ligolo", "socat.exe", "ncat.exe",
                "nc.exe", "nc64.exe", "gost.exe", "rathole.exe", "bore.exe", "pinggy.exe"}
EXFIL_TOOLS = {"rclone.exe", "megacmd.exe", "megasync.exe", "megacmdserver.exe",
               "winscp.exe", "pscp.exe", "filezilla.exe", "restic.exe", "gdrive.exe"}
MINER_HINTS = ("xmrig", "stratum+tcp", "stratum+ssl", "nicehash", "minerd", "cpuminer",
               "--donate-level", "cryptonight", "randomx", "ethminer", "nbminer", "t-rex")
ARCHIVERS = {"7z.exe", "7za.exe", "7zr.exe", "rar.exe", "winrar.exe", "makecab.exe",
             "tar.exe", "zip.exe"}

# Known-vulnerable / abused drivers (BYOVD). Short starter list; extend from
# loldrivers.io offline exports in skills/references/ioc/vuln_drivers.txt.
VULN_DRIVERS = {"rtcore64.sys", "rtcore32.sys", "dbutil_2_3.sys", "gdrv.sys",
                "asrdrv101.sys", "asrdrv102.sys", "iqvw64e.sys", "aswarpot.sys",
                "kprocesshacker.sys", "procexp152.sys", "mhyprot2.sys", "zamguard64.sys",
                "zam64.sys", "truesight.sys", "wnbios.sys", "winring0x64.sys",
                "physmem.sys", "ene.sys", "speedfan.sys", "hw64.sys", "atillk64.sys",
                "amifldrv64.sys", "glckio2.sys", "nicm.sys", "nscm.sys", "inpoutx64.sys",
                "viragt64.sys", "rwdrv.sys", "echo_driver.sys", "capcom.sys"}

SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 1234, 5555, 9001,
                    9030, 9050, 9150, 8888, 3333, 14444, 45700, 2222, 12345, 54321}
WEB_C2_DOMAINS = ("pastebin.com", "paste.ee", "hastebin", "ghostbin", "discord.com/api/webhooks",
                  "cdn.discordapp.com", "api.telegram.org", "transfer.sh", "file.io",
                  "anonfiles", "temp.sh", "raw.githubusercontent.com", "gist.githubusercontent.com",
                  "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
                  "no-ip.", "ddns.net", "hopto.org", "serveo.net", "localtonet",
                  "webhook.site", "pipedream.net", "requestbin", "mocky.io", "glitch.me",
                  "workers.dev", "pages.dev", "dropboxusercontent.com")
RANSOM_NOTE_HINTS = ("readme_decrypt", "how_to_decrypt", "how_to_recover", "decrypt_instructions",
                     "restore_files", "read_me_to_decrypt", "!!!read", "_readme.txt",
                     "recover-files", "your_files_are_encrypted", "help_decrypt", "ransom")
KNOWN_BENIGN_EXT = {".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg",
                    ".png", ".gif", ".zip", ".exe", ".dll", ".log", ".tmp", ".ini",
                    ".json", ".xml", ".csv", ".mp3", ".mp4", ".mkv", ".ppt", ".pptx",
                    ".msi", ".lnk", ".dat", ".db", ".html", ".htm", ".js", ".css",
                    ".py", ".md", ".bak", ".cab", ".7z", ".rar", ".iso", ".sys", ".bin"}

# --- PowerShell / command-line patterns ---------------------------------------
PS_PATTERNS = (
    (re.compile(r"(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}", re.I), "ps_encoded_command", 30),
    (re.compile(r"\biex\b|invoke-expression", re.I), "ps_invoke_expression", 20),
    (re.compile(r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|"
                r"net\.webclient|start-bitstransfer|invoke-restmethod|\birm\b", re.I), "ps_download_cradle", 20),
    (re.compile(r"frombase64string", re.I), "ps_base64_decode", 15),
    (re.compile(r"-w(?:indowstyle)?\s+(?:h|hid|hidden|1)\b", re.I), "ps_hidden_window", 15),
    (re.compile(r"-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)", re.I), "ps_exec_policy_bypass", 10),
    (re.compile(r"(?:^|\s)-nop(?:rofile)?\b", re.I), "ps_noprofile", 5),
    (re.compile(r"amsi(?:utils|initfailed|scanbuffer|context)", re.I), "ps_amsi_tamper", 35),
    (re.compile(r"reflection\.assembly\]::load|\[system\.reflection\.assembly\]", re.I), "ps_reflective_load", 20),
    (re.compile(r"(?:\[char\]\s*\d+\s*\+?\s*){4,}", re.I), "ps_char_obfuscation", 15),
    (re.compile(r"(?:\w`\w.*){3,}"), "ps_backtick_obfuscation", 10),
    (re.compile(r"virtualalloc|createthread|writeprocessmemory|ntprotectvirtualmemory", re.I), "ps_win32_injection_api", 30),
    (re.compile(r"set-mppreference|add-mppreference", re.I), "ps_defender_tamper", 25),
    (re.compile(r"compression\.gzipstream|io\.compression\.deflatestream", re.I), "ps_compressed_payload", 15),
)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def norm_path(p: str | None) -> str:
    if not p:
        return ""
    s = str(p).strip().strip('"').replace("/", "\\").lower()
    s = re.sub(r"^\\\\\?\\", "", s)
    s = s.replace("%systemroot%", "c:\\windows").replace("%windir%", "c:\\windows")
    s = s.replace("\\systemroot\\", "c:\\windows\\")
    if s.startswith("system32\\"):
        s = "c:\\windows\\" + s
    return s


def basename(p: str | None) -> str:
    s = norm_path(p)
    return s.rsplit("\\", 1)[-1] if s else ""


def extract_exe_path(command: str | None) -> str:
    """Best-effort extraction of the executable from a command line."""
    if not command:
        return ""
    c = command.strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        return c[1:end] if end > 0 else c[1:]
    m = re.match(r"(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|dll|scr|hta))\b", c, re.I)
    return m.group(1) if m else c.split(" ", 1)[0]


def path_risk(path: str | None) -> tuple[str, int]:
    p = norm_path(path)
    if not p:
        return ("", 0)
    if any(h in p for h in APPDATA_ALLOW_HINTS):
        return ("known_appdata_software", 0)
    for d in HIGH_RISK_DIRS:
        if d in p:
            return ("high_risk_user_writable_path", 25)
    for d in MEDIUM_RISK_DIRS:
        if d in p:
            return ("user_writable_path", 15)
    if re.match(r"^[a-z]:\\[^\\]+\.(exe|dll|scr|bat|ps1|vbs)$", p):
        return ("drive_root_binary", 15)
    return ("", 0)


def shannon_entropy(s: str | bytes) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def try_decode_ps_encoded(cmdline: str) -> str:
    m = re.search(r"(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+([a-z0-9+/=]{20,})", cmdline or "", re.I)
    if not m:
        return ""
    blob = m.group(1)
    blob += "=" * (-len(blob) % 4)
    try:
        return base64.b64decode(blob).decode("utf-16-le", errors="ignore")
    except Exception:
        return ""


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    ip = ip.strip("[]")
    if ":" in ip:  # IPv6: treat link-local/loopback/ULA as private
        low = ip.lower()
        return not (low in ("::", "::1") or low.startswith(("fe80", "fc", "fd", "::ffff:127.", "::ffff:10.", "::ffff:192.168.")))
    parts = ip.split(".")
    if len(parts) != 4 or not all(x.isdigit() for x in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 169 and b == 254:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    return True


def dga_score(domain: str) -> tuple[bool, float]:
    """Very rough DGA heuristic on the left-most registrable label."""
    d = (domain or "").lower().strip(".")
    labels = [x for x in d.split(".") if x]
    if len(labels) < 2:
        return (False, 0.0)
    label = labels[-2] if len(labels[-1]) <= 3 else labels[-1]
    if len(label) < 12:
        return (False, 0.0)
    ent = shannon_entropy(label)
    vowels = sum(ch in "aeiou" for ch in label) / len(label)
    digits = sum(ch.isdigit() for ch in label) / len(label)
    suspicious = ent >= 3.6 and (vowels < 0.25 or digits > 0.25)
    return (suspicious, round(ent, 2))
