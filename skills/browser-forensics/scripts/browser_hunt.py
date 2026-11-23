#!/usr/bin/env python3
"""Browser forensics (Chromium family + Firefox): downloads, visits, extensions. Read-only.

  python -I browser_hunt.py --out-dir case/browser [--days 30] [--profile-root <path>]

The live SQLite databases are locked by the browser, so each DB is first COPIED into the case folder
and opened read-only from the copy (`mode=ro` URI). Nothing in the profile is modified.
Privacy: history is personal data — only summaries and flagged rows go into the findings file.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import sqlite3
import sys
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import indicators as I  # noqa: E402
from argus.safeio import safe_child, safe_output_dir, write_json  # noqa: E402
from argus.scoring import Finding, Signal  # noqa: E402

CHROMIUM = {"chrome": r"Google\Chrome\User Data", "edge": r"Microsoft\Edge\User Data",
            "brave": r"BraveSoftware\Brave-Browser\User Data", "vivaldi": r"Vivaldi\User Data",
            "opera": r"..\Roaming\Opera Software\Opera Stable"}
RISKY_EXT = (".exe", ".scr", ".msi", ".js", ".jse", ".vbs", ".vbe", ".hta", ".lnk", ".iso", ".img", ".vhd",
             ".vhdx", ".bat", ".cmd", ".ps1", ".wsf", ".cpl", ".zip", ".rar", ".7z", ".dll", ".msix", ".appx")
FAKE_UPDATE = re.compile(r"(update|upgrade).*(chrome|browser|flash|edge|firefox)|(chrome|browser|edge|firefox).*(update)", re.I)
VENDOR = re.compile(r"(microsoft|windowsupdate|google|mozilla|adobe|apple|github|python|nvidia|amd|intel|"
                    r"steampowered|oracle|zoom|vivaldi|brave|opera|7-zip|videolan|libreoffice)\.(com|org|net)", re.I)


def chrome_time(us: int) -> str:
    try:
        return (dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=int(us))).isoformat()
    except (OverflowError, ValueError, TypeError):
        return ""


def copy_db(src: Path, dst_dir: Path, tag: str) -> Path | None:
    if not src.is_file() or src.is_symlink():
        return None
    dst = dst_dir / f"{tag}-{src.name}.sqlite"
    try:
        shutil.copy2(src, dst)
        for suf in ("-wal", "-journal"):
            if Path(str(src) + suf).is_file():
                shutil.copy2(str(src) + suf, str(dst) + suf)
        return dst
    except OSError:
        return None


def q(db: Path, sql: str, args=()):
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return con.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()


def profiles(local: Path):
    for b, rel in CHROMIUM.items():
        root = (local / rel).resolve()
        if root.is_dir():
            for p in root.iterdir():
                if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile ") or b == "opera"):
                    yield b, p
    ff = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
    if ff.is_dir():
        for p in ff.iterdir():
            if p.is_dir():
                yield "firefox", p


def hunt(out: Path, days: int, local: Path) -> tuple[list[Finding], dict]:
    F, stats = [], {}
    since_chrome = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days) -
                        dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds() * 1e6)
    work = out / "db-copies"
    work.mkdir(parents=True, exist_ok=True)

    def add(*a):
        f = Finding(*a).finalize()
        if f.score >= 20:
            F.append(f)

    for browser, prof in profiles(local):
        tag = f"{browser}-{prof.name.replace(' ', '_')}"
        if browser == "firefox":
            db = copy_db(prof / "places.sqlite", work, tag)
            visits = q(db, "SELECT p.url, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id "
                           "ORDER BY v.visit_date DESC LIMIT 20000") if db else []
            dls = q(db, "SELECT a.content, p.url, a.dateAdded FROM moz_annos a JOIN moz_places p ON p.id=a.place_id "
                        "WHERE a.anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI')") if db else []
            downloads = [(c, u, "") for c, u, _ in dls]
        else:
            db = copy_db(prof / "History", work, tag)
            visits = q(db, "SELECT u.url, v.visit_time FROM visits v JOIN urls u ON u.id=v.url WHERE v.visit_time > ? "
                           "ORDER BY v.visit_time DESC LIMIT 20000", (since_chrome,)) if db else []
            downloads = q(db, "SELECT target_path, tab_url, start_time FROM downloads WHERE start_time > ?", (since_chrome,)) if db else []
            downloads = [(t, u, chrome_time(s)) for t, u, s in downloads]
            ext_dir = prof / "Extensions"
            stats[f"{tag}_extensions"] = len([p for p in ext_dir.iterdir()]) if ext_dir.is_dir() else 0
        stats[f"{tag}_visits"] = len(visits)
        stats[f"{tag}_downloads"] = len(downloads)
        for target, url, when in downloads:
            target = str(target or "").replace("file:///", "")
            low = target.lower()
            if not low.endswith(RISKY_EXT):
                continue
            sigs = [Signal("risky_download_extension", 10, I.basename(target))]
            host = re.sub(r"^\w+://([^/:]+).*$", r"\1", str(url or "")).lower()
            if I.IPV4_RE.fullmatch(host or ""):
                sigs.append(Signal("downloaded_from_raw_ip", 30, host))
            if any(d.split("/")[0] in host for d in I.WEB_C2_DOMAINS):
                sigs.append(Signal("downloaded_from_paste_or_tunnel", 30, host))
            if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|lnk|hta)$", low):
                sigs.append(Signal("double_extension", 35))
            if low.endswith((".iso", ".img", ".vhd", ".vhdx", ".lnk", ".hta", ".js", ".jse", ".vbs", ".wsf")):
                sigs.append(Signal("container_or_script_delivery", 20))
            if FAKE_UPDATE.search(I.basename(target)) and not VENDOR.search(host):
                sigs.append(Signal("fake_browser_update_name", 35))
            if host and VENDOR.search(host):
                sigs.append(Signal("vendor_domain", -20, host))
            add("ARG-BR-001", "Risky file downloaded by browser", "TA0001", "T1204.002",
                {"browser": browser, "profile": prof.name, "file": target, "source_url": str(url)[:300], "time": when},
                f"dl|{browser}|{low}", sigs, "Hash and triage the downloaded file; check if it was executed (disk-forensics).")
        hits = {}
        for url, _t in visits:
            u = str(url).lower()
            for d in I.WEB_C2_DOMAINS:
                if d.split("/")[0] in u and d not in ("raw.githubusercontent.com", "gist.githubusercontent.com"):
                    hits.setdefault(d, u[:200])
            if re.search(r"/(?:wp-content|wp-includes)/.+\.(?:js|php)\?.*(?:update|chrome)", u):
                hits.setdefault("fake-update-inject", u[:200])
        for d, sample in hits.items():
            add("ARG-BR-002", "Browsing to paste / tunnel / fake-update infrastructure", "TA0001", "T1189",
                {"browser": browser, "indicator": d, "sample_url": sample}, f"visit|{browser}|{d}",
                [Signal("risky_site_visited", 20, d)], "Usually benign by itself; correlate with downloads and executions.")
    return F, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--profile-root", default=os.environ.get("LOCALAPPDATA", ""))
    a = ap.parse_args()
    out = safe_output_dir(a.out_dir)
    root = Path(a.profile_root)
    if not root.is_dir():
        sys.exit("profile root not found (set --profile-root to %LOCALAPPDATA%)")
    F, stats = hunt(out, a.days, root)
    res = {"schema": "argus.findings/1", "source": "browser-forensics", "mode": "detect-only",
           "summary": {"total": len(F), **stats}, "findings": [f.to_dict() for f in sorted(F, key=lambda f: -f.score)]}
    write_json(safe_child(out, "browser-findings.json"), res)
    print(json.dumps(res["summary"], indent=1))


if __name__ == "__main__":
    main()
