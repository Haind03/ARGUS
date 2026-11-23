#!/usr/bin/env python3
"""Network forensics on tshark field exports or repeated ARGUS telemetry snapshots. Static, offline.

  python -I network_hunt.py --tshark-csv flows.csv --out-dir case/net
  python -I network_hunt.py --telemetry t1.json t2.json t3.json --out-dir case/net    # beaconing from snapshots

tshark export (one command):
  tshark -r cap.pcapng -T fields -E header=y -E separator=, -e frame.time_epoch -e ip.src -e ip.dst \
    -e tcp.dstport -e udp.dstport -e dns.qry.name -e tls.handshake.extensions_server_name -e http.host -e frame.len

Detections
  ARG-NF-001 beaconing        : regular inter-arrival times to one dst:port (low coefficient of variation, >=8 hits)
  ARG-NF-002 DGA / rare DNS   : high-entropy names; many NXDOMAIN-like unique names
  ARG-NF-003 web-service C2   : SNI/Host/DNS to paste/webhook/tunnel domains
  ARG-NF-004 suspicious ports : traffic to SUSPICIOUS_PORTS / Tor ports
  ARG-NF-005 large upload     : bytes to a single public dst above threshold
  ARG-NF-006 raw-IP HTTP      : HTTP Host header is a bare IP
  ARG-NF-007 DNS tunnelling   : very long query labels / many subdomains of one parent
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

for _p in [*Path(__file__).resolve().parents, Path.home() / ".claude" / "argus"]:
    if (_p / "engine" / "argus_cli.py").is_file():
        sys.path.insert(0, str(_p / "engine"))
        break
from argus import indicators as I  # noqa: E402
from argus.safeio import load_json, safe_child, safe_input_file, safe_output_dir, write_json  # noqa: E402
from argus.scoring import Finding, Signal  # noqa: E402


def beacon_stats(times: list[float]) -> tuple[float, float] | None:
    ts = sorted(set(times))
    if len(ts) < 8:
        return None
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
    if len(gaps) < 7:
        return None
    mean = statistics.mean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean else 99.0
    return round(mean, 1), round(cv, 3)


def read_tshark(path) -> list[dict]:
    f = safe_input_file(path, 1 << 31)
    rows = []
    with open(f, encoding="utf-8", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            try:
                t = float(r.get("frame.time_epoch") or 0)
            except ValueError:
                continue
            port = r.get("tcp.dstport") or r.get("udp.dstport") or ""
            rows.append({"t": t, "src": r.get("ip.src", ""), "dst": r.get("ip.dst", ""), "port": port.split(",")[0],
                         "dns": (r.get("dns.qry.name") or "").split(",")[0].lower(),
                         "sni": (r.get("tls.handshake.extensions_server_name") or "").lower(),
                         "host": (r.get("http.host") or "").lower(), "len": int(r.get("frame.len") or 0)})
    return rows


def rows_from_telemetry(paths) -> list[dict]:
    rows = []
    for p in paths:
        tel = load_json(p)
        import datetime as dt
        try:
            t = dt.datetime.fromisoformat(str(tel.get("collected_at")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        for c in tel.get("network") or []:
            if str(c.get("state", "")).lower().startswith("estab"):
                rows.append({"t": t, "src": c.get("local"), "dst": c.get("remote"), "port": str(c.get("rport")),
                             "dns": "", "sni": "", "host": "", "len": 0, "process": c.get("process")})
        for d in tel.get("dns_cache") or []:
            rows.append({"t": t, "src": "", "dst": "", "port": "53", "dns": str(d.get("name", "")).lower(),
                         "sni": "", "host": "", "len": 0})
    return rows


def hunt(rows: list[dict], upload_mb: int = 200) -> list[Finding]:
    F: list[Finding] = []

    def add(*a):
        f = Finding(*a).finalize()
        if f.score >= 20:
            F.append(f)

    flows = defaultdict(list)
    bytes_to = defaultdict(int)
    proc_of = {}
    for r in rows:
        if I.is_public_ip(r["dst"]):
            flows[(r["dst"], r["port"])].append(r["t"])
            bytes_to[r["dst"]] += r["len"]
            if r.get("process"):
                proc_of[(r["dst"], r["port"])] = r["process"]
    for (dst, port), ts in flows.items():
        st = beacon_stats(ts)
        if st and st[1] < 0.25 and st[0] >= 5:
            sigs = [Signal("periodic_connections", 35 if st[1] < 0.1 else 25, f"mean={st[0]}s cv={st[1]} n={len(ts)}")]
            try:
                if int(port) in I.SUSPICIOUS_PORTS:
                    sigs.append(Signal("suspicious_port", 20, port))
            except ValueError:
                pass
            add("ARG-NF-001", "Beaconing pattern (regular interval) to public host", "TA0011", "T1071",
                {"dst": dst, "port": port, "mean_interval_s": st[0], "cv": st[1], "count": len(ts),
                 "process": proc_of.get((dst, port))}, f"beacon|{dst}|{port}", sigs,
                "Identify the owning process (Get-NetTCPConnection / Sysmon 3); NTP, updaters and chat keep-alives also beacon.")
    names = {r["dns"] for r in rows if r["dns"]} | {r["sni"] for r in rows if r["sni"]} | {r["host"] for r in rows if r["host"]}
    dga = [n for n in names if I.dga_score(n)[0]]
    for n in dga[:100]:
        add("ARG-NF-002", "DGA-like domain", "TA0011", "T1568.002", {"domain": n}, f"nfdga|{n}",
            [Signal("high_entropy_domain", 15)] + ([Signal("many_dga_like", 25, str(len(dga)))] if len(dga) >= 10 else []),
            "Check which process resolved it (Sysmon 22).")
    for n in names:
        hit = next((d for d in I.WEB_C2_DOMAINS if d.split("/")[0] in n), None)
        if hit:
            add("ARG-NF-003", "Traffic to web-service / tunnel domain", "TA0011", "T1102", {"name": n}, f"nfweb|{n}",
                [Signal("web_service_c2_domain", 30, hit)], "Non-browser process? correlate with process telemetry.")
    for (dst, port), ts in flows.items():
        try:
            p = int(port)
        except ValueError:
            continue
        if p in I.SUSPICIOUS_PORTS:
            add("ARG-NF-004", "Connections to suspicious port", "TA0011", "T1571", {"dst": dst, "port": p, "count": len(ts)},
                f"nfport|{dst}|{p}", [Signal("suspicious_port", 30, str(p))], "Identify process and purpose.")
    for dst, b in bytes_to.items():
        if b >= upload_mb * 1024 * 1024:
            add("ARG-NF-005", "Large data volume to one public host", "TA0010", "T1041", {"dst": dst, "bytes": b},
                f"nfbytes|{dst}", [Signal("large_volume", 30, str(b))], "Cloud backup/sync is the common FP; check SRUM per-app bytes.")
    for r in rows:
        if r["host"] and I.IPV4_RE.fullmatch(r["host"].split(":")[0]) and I.is_public_ip(r["host"].split(":")[0]):
            add("ARG-NF-006", "HTTP to bare public IP", "TA0011", "T1071.001", {"host": r["host"], "dst": r["dst"]},
                f"nfrawip|{r['host']}", [Signal("http_raw_ip_host", 30)], "Downloader/C2 often skip DNS; fetch nothing, record IOC.")
    parents = defaultdict(set)
    for n in {r["dns"] for r in rows if r["dns"]}:
        labels = n.split(".")
        if len(labels) >= 3:
            parents[".".join(labels[-2:])].add(n)
        if any(len(x) > 50 for x in labels):
            add("ARG-NF-007", "DNS query with very long label (possible tunnelling)", "TA0011", "T1071.004", {"query": n},
                f"nftun|{n}", [Signal("long_dns_label", 30)], "Check volume of queries to the same parent domain.")
    for parent, subs in parents.items():
        if len(subs) >= 50 and parent not in ("microsoft.com", "windows.com", "akamaiedge.net", "cloudfront.net", "google.com",
                                              "googleapis.com", "azureedge.net", "office.com", "live.com", "amazonaws.com"):
            add("ARG-NF-007", "Many unique subdomains of one parent (DNS tunnelling / exfil)", "TA0010", "T1048.003",
                {"parent": parent, "unique_subdomains": len(subs)}, f"nftun|parent|{parent}",
                [Signal("many_unique_subdomains", 35, str(len(subs)))], "Inspect the subdomain payloads (base32/hex).")
    return sorted(F, key=lambda f: -f.score)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark-csv")
    ap.add_argument("--telemetry", nargs="*")
    ap.add_argument("--upload-mb", type=int, default=200)
    ap.add_argument("--out-dir")
    a = ap.parse_args()
    rows = read_tshark(a.tshark_csv) if a.tshark_csv else rows_from_telemetry(a.telemetry or [])
    if not rows:
        sys.exit("no input rows (give --tshark-csv or --telemetry ...)")
    F = hunt(rows, a.upload_mb)
    res = {"schema": "argus.findings/1", "source": "network-forensics", "mode": "detect-only",
           "summary": {"rows": len(rows), "total": len(F)}, "findings": [f.to_dict() for f in F]}
    if a.out_dir:
        write_json(safe_child(safe_output_dir(a.out_dir), "network-findings.json"), res)
    print(json.dumps(res["summary"]))
    for f in res["findings"][:40]:
        print(f"{f['score']:>3} {f['severity']:<8} {f['rule_id']} {json.dumps(f['artifact'])[:120]}")


if __name__ == "__main__":
    main()
