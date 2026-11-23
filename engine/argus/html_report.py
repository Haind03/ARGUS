"""Self-contained HTML assessment report for an ARGUS hunt (no external assets, works offline).

Editorial design, one typeface throughout: Times New Roman.
ARGUS by HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import html
import json
import math
from typing import Any

from . import SIGNATURE, __version__
from .rules import TACTICS, covered_techniques

SEV = ["critical", "high", "medium", "low", "info"]
COLORS = {"critical": "#8b1a1a", "high": "#b5542a", "medium": "#a07d1c", "low": "#4f6f3a", "info": "#8a8578"}
ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
         "TA0009", "TA0011", "TA0010", "TA0040"]
BYLINE = "by HaiND from the Post and Telecommunication Institute of Technology"


def e(x: Any) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _verdict(sev: dict) -> tuple[str, str, str]:
    if sev.get("critical"):
        return ("Compromise likely", COLORS["critical"],
                "Critical leads were found. Validate them first; isolate the network at once if ransomware or credential theft is confirmed.")
    if sev.get("high"):
        return ("Suspicious", COLORS["high"], "High-scoring leads require analyst validation before any conclusion is drawn.")
    if sev.get("medium") or sev.get("low"):
        return ("Review advised", COLORS["medium"], "Only low or medium leads. Compare them with the baseline and with software the user knows.")
    return ("No indicators", COLORS["low"], "Nothing exceeded the threshold for the tested hypotheses. Read the collection gaps before calling the host clean.")


def _risk_index(findings: list[dict]) -> int:
    w = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
    return min(100, sum(w.get(f["severity"], 0) for f in findings))


def _donut(sev: dict) -> str:
    total = sum(sev.get(k, 0) for k in SEV)
    r, c = 52, 2 * math.pi * 52
    parts, off = [], 0.0
    if total == 0:
        parts.append(f'<circle r="{r}" cx="70" cy="70" fill="none" stroke="#d9d2c3" stroke-width="14"/>')
    for k in SEV:
        n = sev.get(k, 0)
        if not n:
            continue
        ln = c * n / total
        parts.append(f'<circle r="{r}" cx="70" cy="70" fill="none" stroke="{COLORS[k]}" stroke-width="14" '
                     f'stroke-dasharray="{ln:.2f} {c - ln:.2f}" stroke-dashoffset="{-off:.2f}" transform="rotate(-90 70 70)"/>')
        off += ln
    return (f'<svg viewBox="0 0 140 140" class="donut">{"".join(parts)}'
            f'<text x="70" y="68" text-anchor="middle" class="dn">{total}</text>'
            f'<text x="70" y="88" text-anchor="middle" class="dl">findings</text></svg>')


def render(result: dict[str, Any]) -> str:
    s = result["summary"]
    sev = s.get("by_severity", {})
    findings = result.get("findings", [])
    verdict, vcolor, vtext = _verdict(sev)
    risk = _risk_index(findings)
    cov = covered_techniques()
    cov_by_tactic: dict[str, set] = {t: set() for t in TACTICS}
    for tech, tacs in cov.items():
        for t in tacs:
            cov_by_tactic[t].add(tech)
    hits: dict[str, list] = {t: [] for t in TACTICS}
    for f in findings:
        hits.setdefault(f["tactic"], []).append(f)

    legend = "".join(f'<li><i style="background:{COLORS[k]}"></i>{k.capitalize()}<b>{sev.get(k, 0)}</b></li>' for k in SEV)

    cells = []
    for i, t in enumerate(ORDER, 1):
        h = hits.get(t, [])
        if t in ("TA0043", "TA0042"):
            state, color, sub = "Intelligence only", "#bfb6a3", "not observable on the host"
        elif h:
            top = max(h, key=lambda f: f["score"])
            state, color, sub = f"{len(h)} finding{'s' if len(h) > 1 else ''}", COLORS[top["severity"]], f"highest score {top['score']}"
        else:
            state, color, sub = "Clear", "#4f6f3a", f"{len(cov_by_tactic.get(t, ()))} techniques tested"
        cells.append(f'<div class="tac"><div class="num">{i:02d}</div><div class="tid">{t}</div>'
                     f'<div class="tname">{e(TACTICS[t])}</div><div class="rule" style="background:{color}"></div>'
                     f'<div class="tstate" style="color:{color}">{e(state)}</div><div class="tsub">{e(sub)}</div></div>')

    rows = []
    for n, f in enumerate(findings[:200], 1):
        a = f.get("artifact") or {}
        short = a.get("cmdline") or a.get("path") or a.get("value") or a.get("task") or a.get("service") or \
            a.get("domain") or a.get("remote") or json.dumps(a)[:140]
        disp = (f.get("disposition") or {}).get("verdict", "open").replace("_", " ")
        sig = ", ".join(x.replace("_", " ") for x in f.get("signals_matched", [])[:4])
        rows.append(
            f'<tr><td class="n">{n}</td><td><span class="sev" style="color:{COLORS[f["severity"]]};border-color:{COLORS[f["severity"]]}">'
            f'{e(f["severity"])}</span></td><td class="sc">{f["score"]}</td><td class="tech">{e(f["technique"])}</td>'
            f'<td><div class="ft">{e(f["title"])}</div><div class="art">{e(str(short)[:170])}</div>'
            f'<div class="sig">{e(sig)}</div></td><td class="disp">{e(disp)}</td></tr>')
    gaps = result.get("collection_gaps") or []
    gaps_html = "".join(f"<li>{e(g)}</li>" for g in gaps) or "<li>None reported by the collector.</li>"
    intel = result.get("intel") or {}
    online = "online, SHA-256 only" if intel.get("online_enabled") else "offline"
    tactics_tested = len({t for v in cov.values() for t in v})

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARGUS Assessment Report</title><style>
:root{{--paper:#fbf8f1;--ink:#1d2433;--soft:#5b6170;--line:#d9d2c3;--accent:#1f3a5f;--gold:#9c7a2b}}
*{{box-sizing:border-box}}
html,body,button,input,table,pre,code{{font-family:"Times New Roman",Times,serif}}
body{{margin:0;background:var(--paper);color:var(--ink);font-size:16px;line-height:1.5}}
.wrap{{max-width:1180px;margin:0 auto;padding:44px 48px 28px}}
.mast{{text-align:center;border-bottom:3px double var(--ink);padding-bottom:22px}}
.kicker{{letter-spacing:.32em;text-transform:uppercase;font-size:12px;color:var(--soft)}}
.word{{font-size:76px;letter-spacing:.42em;margin:6px 0 2px;padding-left:.42em;font-weight:700;color:var(--accent);line-height:1}}
.byline{{font-style:italic;color:var(--gold);font-size:17px}}
.meta{{display:flex;justify-content:center;gap:28px;flex-wrap:wrap;margin-top:14px;font-size:14px;color:var(--soft)}}
.meta b{{color:var(--ink);font-weight:600}}
h2{{font-size:13px;letter-spacing:.28em;text-transform:uppercase;color:var(--soft);font-weight:600;margin:0 0 14px;
  border-bottom:1px solid var(--line);padding-bottom:6px}}
section{{margin-top:34px}}
.lead{{display:grid;grid-template-columns:1.6fr 1fr 1fr;gap:40px;align-items:start}}
.verdict{{font-size:42px;line-height:1.1;margin:2px 0 10px}}
.verdict-text{{font-size:17px;color:var(--soft);max-width:520px}}
.risk{{margin-top:16px}}.risk .track{{height:6px;background:var(--line)}}.risk .fill{{height:6px}}
.risk .lbl{{font-size:13px;color:var(--soft);margin-top:6px;letter-spacing:.06em}}
.stat .big{{font-size:56px;line-height:1}}.stat .cap{{color:var(--soft);font-size:14px;font-style:italic}}
.stat + .stat{{margin-top:18px}}
.donutbox{{display:flex;gap:18px;align-items:center}}.donut{{width:140px;height:140px}}
.dn{{font-size:30px;fill:var(--ink)}}.dl{{font-size:12px;fill:var(--soft);letter-spacing:.1em}}
.legend{{list-style:none;margin:0;padding:0;font-size:15px}}.legend li{{display:flex;align-items:center;gap:8px;margin:3px 0}}
.legend i{{width:10px;height:10px;display:inline-block}}.legend b{{margin-left:auto;padding-left:16px;font-weight:600}}
.tactics{{display:grid;grid-template-columns:repeat(7,1fr);border-top:1px solid var(--line);border-left:1px solid var(--line)}}
.tac{{padding:12px 12px 14px;border-right:1px solid var(--line);border-bottom:1px solid var(--line);min-height:150px;background:#fffdf8}}
.tac .num{{font-size:12px;color:var(--gold);letter-spacing:.1em}}.tac .tid{{font-size:12px;color:var(--soft)}}
.tac .tname{{font-size:17px;line-height:1.2;margin:4px 0 10px;min-height:42px}}.tac .rule{{height:2px;width:36px;margin-bottom:8px}}
.tac .tstate{{font-size:15px;font-weight:600}}.tac .tsub{{font-size:13px;color:var(--soft);font-style:italic}}
table{{width:100%;border-collapse:collapse}}th{{text-align:left;font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:var(--soft);
  font-weight:600;border-bottom:1px solid var(--ink);padding:8px 10px}}
td{{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
td.n{{color:var(--gold);width:34px}}td.sc{{font-size:22px;width:56px}}td.tech{{white-space:nowrap;width:96px}}
.sev{{border:1px solid;padding:1px 8px;font-size:12px;letter-spacing:.16em;text-transform:uppercase}}
.ft{{font-size:17px}}.art{{color:var(--accent);font-size:14.5px;word-break:break-all;margin-top:3px}}
.sig{{font-size:13px;color:var(--soft);font-style:italic;margin-top:3px}}td.disp{{font-style:italic;color:var(--soft);width:96px}}
.gaps li{{margin:4px 0}}
.note{{font-size:14px;color:var(--soft);font-style:italic}}
footer{{margin-top:40px;border-top:3px double var(--ink);padding-top:14px;text-align:center;font-size:14px;color:var(--soft)}}
footer .sig2{{font-style:italic;color:var(--gold);font-size:15px}}
@media print{{body{{background:#fff}}.tac{{background:#fff}}}}
</style></head><body><div class="wrap">
<header class="mast">
  <div class="kicker">Defensive threat hunting &middot; Assessment report</div>
  <div class="word">ARGUS</div>
  <div class="byline">{e(BYLINE)}</div>
  <div class="meta"><span>Host <b>{e(result.get('target_host'))}</b></span><span>Generated <b>{e(result.get('generated_at'))}</b></span>
  <span>Preset <b>{e(result.get('preset'))}</b></span><span>Baseline <b>{'applied' if result.get('baseline_applied') else 'none'}</b></span>
  <span>Mode <b>{e(result.get('mode'))}</b></span><span>Intelligence <b>{online}</b></span></div>
</header>

<section class="lead">
  <div><h2>System assessment</h2>
    <div class="verdict" style="color:{vcolor}">{verdict}</div>
    <div class="verdict-text">{e(vtext)}</div>
    <div class="risk"><div class="track"><div class="fill" style="width:{risk}%;background:{vcolor}"></div></div>
    <div class="lbl">Risk index {risk} of 100</div></div></div>
  <div><h2>Severity</h2><div class="donutbox">{_donut(sev)}<ul class="legend">{legend}</ul></div></div>
  <div><h2>Coverage</h2>
    <div class="stat"><div class="big">{len(cov)}</div><div class="cap">ATT&amp;CK techniques tested</div></div>
    <div class="stat"><div class="big">{tactics_tested}</div><div class="cap">host-observable tactics</div></div></div>
</section>

<section><h2>Kill chain, MITRE ATT&amp;CK Enterprise</h2><div class="tactics">{''.join(cells)}</div></section>

<section><h2>Findings</h2>
<p class="note">Scores are heuristic leads, not verdicts. Validate every finding before acting.</p>
<table><tr><th>#</th><th>Severity</th><th>Score</th><th>ATT&amp;CK</th><th>Finding, artefact and signals</th><th>Disposition</th></tr>
{''.join(rows) or '<tr><td colspan=6 class="note">No findings above the threshold.</td></tr>'}</table></section>

<section><h2>Collection gaps</h2><ul class="gaps">{gaps_html}</ul></section>

<footer>Detect-only report for the user's own, authorised machine. ARGUS v{e(__version__)}.<br>
<span class="sig2">{e(SIGNATURE)}</span></footer>
</div></body></html>"""
