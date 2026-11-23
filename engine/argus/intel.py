"""Threat-intel enrichment, HYBRID OPT-IN.

Default: OFFLINE. Only local IOC lists are consulted.
Online lookups happen only when BOTH are true:
  1. ARGUS_INTEL_ONLINE=1 (or --online on the CLI), and
  2. the provider's API key env var is set (VT_API_KEY, ABUSECH_AUTH_KEY).
Only SHA-256 hashes are ever sent, never file contents, paths, usernames or hostnames.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HASH_RE = re.compile(r"^[a-f0-9]{64}$")
UA = "argus-defensive/0.1"


def load_local_iocs(ioc_dir: Path) -> dict[str, set[str]]:
    out = {"sha256": set(), "domains": set(), "ips": set(), "vuln_drivers": set()}
    files = {"sha256": "hashes_sha256.txt", "domains": "domains.txt", "ips": "ips.txt", "vuln_drivers": "vuln_drivers.txt"}
    for k, fn in files.items():
        p = ioc_dir / fn
        if p.is_file() and not p.is_symlink():
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                v = line.split("#", 1)[0].strip().lower()
                if v:
                    out[k].add(v)
    return out


def online_enabled(flag: bool = False) -> bool:
    return flag or os.environ.get("ARGUS_INTEL_ONLINE", "") == "1"


def _get(url: str, headers: dict[str, str], timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https endpoints)
        return json.loads(r.read(4 * 1024 * 1024).decode("utf-8", "replace"))


def _post(url: str, data: dict[str, str], headers: dict[str, str], timeout: int = 20) -> dict[str, Any]:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read(4 * 1024 * 1024).decode("utf-8", "replace"))


def vt_lookup(sha256: str) -> dict[str, Any] | None:
    key = os.environ.get("VT_API_KEY")
    if not key or not HASH_RE.match(sha256):
        return None
    try:
        j = _get(f"https://www.virustotal.com/api/v3/files/{sha256}", {"x-apikey": key})
    except urllib.error.HTTPError as e:
        return {"provider": "virustotal", "status": "not_found" if e.code == 404 else f"http_{e.code}"}
    except Exception as e:  # network errors must not break the hunt
        return {"provider": "virustotal", "status": f"error:{type(e).__name__}"}
    a = (j.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    return {"provider": "virustotal", "status": "found", "malicious": st.get("malicious", 0),
            "suspicious": st.get("suspicious", 0), "harmless": st.get("harmless", 0),
            "undetected": st.get("undetected", 0), "meaningful_name": a.get("meaningful_name"),
            "popular_threat_label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label")}


def malwarebazaar_lookup(sha256: str) -> dict[str, Any] | None:
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key or not HASH_RE.match(sha256):
        return None
    try:
        j = _post("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": sha256}, {"Auth-Key": key})
    except Exception as e:
        return {"provider": "malwarebazaar", "status": f"error:{type(e).__name__}"}
    if j.get("query_status") != "ok":
        return {"provider": "malwarebazaar", "status": j.get("query_status")}
    d = (j.get("data") or [{}])[0]
    return {"provider": "malwarebazaar", "status": "found", "signature": d.get("signature"),
            "tags": d.get("tags"), "first_seen": d.get("first_seen")}


def enrich_findings(findings: list[dict[str, Any]], ioc_dir: Path, online: bool = False,
                    max_online: int = 25, delay_s: float = 15.5) -> dict[str, Any]:
    """Annotate findings in place. Returns a summary of what was (and was not) sent."""
    iocs = load_local_iocs(ioc_dir)
    sent: list[str] = []
    do_online = online_enabled(online)
    cache: dict[str, Any] = {}
    for f in findings:
        art = f.get("artifact") or {}
        h = str(art.get("sha256") or "").lower()
        intel: dict[str, Any] = {}
        if h and h in iocs["sha256"]:
            intel["local_ioc"] = "sha256_match"
            f["score"] = min(100, f["score"] + 40)
            f.setdefault("signals_matched", []).append("local_ioc_hash_match")
        for k in ("domain", "query"):
            dom = str(art.get(k) or "").lower()
            if dom and any(dom == d or dom.endswith("." + d) for d in iocs["domains"]):
                intel["local_ioc_domain"] = dom
                f["score"] = min(100, f["score"] + 35)
        rip = str(art.get("remote") or art.get("ip") or "")
        if rip and rip in iocs["ips"]:
            intel["local_ioc_ip"] = rip
            f["score"] = min(100, f["score"] + 35)
        if do_online and h and HASH_RE.match(h) and len(sent) < max_online:
            if h not in cache:
                res = [r for r in (vt_lookup(h), malwarebazaar_lookup(h)) if r]
                cache[h] = res
                if res:
                    sent.append(h)
                    if os.environ.get("VT_API_KEY"):
                        time.sleep(delay_s)  # VT public API: 4 req/min
            intel["online"] = cache[h]
            for r in cache[h]:
                if r.get("provider") == "virustotal" and (r.get("malicious") or 0) >= 5:
                    f["score"] = min(100, f["score"] + 30)
                if r.get("provider") == "malwarebazaar" and r.get("status") == "found":
                    f["score"] = min(100, f["score"] + 30)
        if intel:
            f["intel"] = intel
            from .scoring import severity_for
            f["severity"] = severity_for(f["score"])
    return {"online_enabled": do_online, "hashes_sent": sent, "data_sent": "sha256 only" if sent else "nothing",
            "local_ioc_counts": {k: len(v) for k, v in iocs.items()}}
