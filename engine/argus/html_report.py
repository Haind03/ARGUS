"""Self-contained HTML dashboard for an ARGUS hunt result (no external assets, works offline).

ARGUS by HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import html
import json
from typing import Any

from . import SIGNATURE
from .rules import TACTICS, covered_techniques

SEV = ["critical", "high", "medium", "low", "info"]
COLORS = {"critical": "#d7191c", "high": "#f46d43", "medium": "#e6b800", "low": "#66bd63", "info": "#9e9e9e"}
ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
         "TA0009", "TA0011", "TA0010", "TA0040"]


def e(x: Any) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _verdict(sev: dict) -> tuple[str, str, str]:
    if sev.get("critical"):
        return ("COMPROMISE LIKELY", "#d7191c", "Critical leads found. Validate now; isolate the network if ransomware or credential theft is confirmed.")
    if sev.get("high"):
        return ("SUSPICIOUS", "#f46d43", "High-scoring leads need analyst validation before any conclusion.")
    if sev.get("medium") or sev.get("low"):
        return ("REVIEW", "#e6b800", "Only low/medium leads. Compare with the baseline and known software.")
    return ("NO INDICATORS", "#66bd63", "Nothing above threshold for the tested hypotheses. Check collection gaps.")


def _risk_index(findings: list[dict]) -> int:
    w = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
    return min(100, sum(w.get(f["severity"], 0) for f in findings))


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
    hit_by_tactic: dict[str, list] = {t: [] for t in TACTICS}
    for f in findings:
        hit_by_tactic.setdefault(f["tactic"], []).append(f)
    total = max(1, sum(sev.get(k, 0) for k in SEV))

    bars = "".join(
        f'<div class="bar"><span class="lbl">{k}</span><div class="track"><div class="fill" '
        f'style="width:{100 * sev.get(k, 0) / total:.1f}%;background:{COLORS[k]}"></div></div>'
        f'<span class="num">{sev.get(k, 0)}</span></div>' for k in SEV)

    cells = []
    for t in ORDER:
        name = TACTICS[t]
        hits = hit_by_tactic.get(t, [])
        ncov = len(cov_by_tactic.get(t, ()))
        if t in ("TA0043", "TA0042"):
            state, color, sub = "intel only", "#cfd8dc", "not host-observable"
        elif hits:
            top = max(hits, key=lambda f: f["score"])
            state, color, sub = f"{len(hits)} finding(s)", COLORS[top["severity"]], f"top score {top['score']}"
        else:
            state, color, sub = "clear", "#c8e6c9", f"{ncov} technique(s) tested"
        cells.append(f'<div class="tac" style="border-top:6px solid {color}"><div class="tid">{t}</div>'
                     f'<div class="tname">{e(name)}</div><div class="tstate">{e(state)}</div><div class="tsub">{e(sub)}</div></div>')

    rows = []
    for f in findings[:200]:
        a = f.get("artifact") or {}
        short = a.get("cmdline") or a.get("path") or a.get("value") or a.get("task") or a.get("service") or \
            a.get("domain") or a.get("remote") or json.dumps(a)[:120]
        disp = (f.get("disposition") or {}).get("verdict", "open")
        sig = ", ".join(f.get("signals_matched", [])[:5])
        rows.append(
            f'<tr><td><span class="pill" style="background:{COLORS[f["severity"]]}">{e(f["severity"])}</span></td>'
            f'<td class="sc">{f["score"]}</td><td><code>{e(f["technique"])}</code></td><td>{e(f["title"])}</td>'
            f'<td class="art"><code>{e(str(short)[:160])}</code></td><td class="sig">{e(sig)}</td><td>{e(disp)}</td></tr>')
    gaps = result.get("collection_gaps") or []
    gaps_html = "".join(f"<li>{e(g)}</li>" for g in gaps) or "<li>none reported by collector</li>"
    intel = result.get("intel") or {}
    online = "ON (SHA-256 only)" if intel.get("online_enabled") else "OFF (offline)"

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARGUS hunt dashboard</title><style>
:root{{--bg:#0f1720;--card:#16212c;--ink:#e6edf3;--mut:#8b9bb0;--line:#243241}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,sans-serif}}
header{{display:flex;justify-content:space-between;align-items:center;padding:18px 28px;border-bottom:1px solid var(--line)}}
h1{{margin:0;font-size:20px;letter-spacing:.5px}}h1 b{{color:#4fc3f7}}.meta{{color:var(--mut);font-size:12px;text-align:right}}
main{{padding:22px 28px;display:grid;gap:18px}}.grid{{display:grid;grid-template-columns:1.2fr 1fr 1fr 1fr;gap:18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}}
.card h2{{margin:0 0 10px;font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:1px}}
.verdict{{font-size:24px;font-weight:700}}.big{{font-size:40px;font-weight:700}}.mut{{color:var(--mut);font-size:12px}}
.gauge{{height:10px;background:#243241;border-radius:5px;overflow:hidden;margin-top:8px}}.gauge div{{height:100%}}
.bar{{display:flex;align-items:center;gap:8px;margin:6px 0}}.lbl{{width:62px;color:var(--mut)}}.track{{flex:1;height:12px;background:#243241;border-radius:6px;overflow:hidden}}
.fill{{height:100%}}.num{{width:28px;text-align:right}}
.tactics{{display:grid;grid-template-columns:repeat(7,1fr);gap:10px}}.tac{{background:#1b2835;border-radius:8px;padding:10px;min-height:96px}}
.tid{{font-size:11px;color:var(--mut)}}.tname{{font-weight:600;margin:2px 0 6px}}.tstate{{font-size:13px}}.tsub{{font-size:11px;color:var(--mut)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{color:var(--mut);font-weight:600}}.pill{{padding:2px 8px;border-radius:10px;color:#111;font-weight:700;font-size:11px;text-transform:uppercase}}
.sc{{font-weight:700}}.art code{{color:#ffcc80;word-break:break-all}}.sig{{color:var(--mut);font-size:12px}}code{{font-family:Consolas,monospace}}
footer{{padding:14px 28px;color:var(--mut);font-size:12px;border-top:1px solid var(--line)}}
</style></head><body>
<header><h1><b>ARGUS</b> hunt dashboard</h1><div class="meta">host <b>{e(result.get('target_host'))}</b> &middot; preset {e(result.get('preset'))}
&middot; baseline {e(result.get('baseline_applied'))}<br>generated {e(result.get('generated_at'))} &middot; mode <b>{e(result.get('mode'))}</b> &middot; intel {online}</div></header>
<main>
<div class="grid">
 <div class="card"><h2>System assessment</h2><div class="verdict" style="color:{vcolor}">{verdict}</div><div class="mut">{e(vtext)}</div>
  <div class="gauge"><div style="width:{risk}%;background:{vcolor}"></div></div><div class="mut">risk index {risk}/100</div></div>
 <div class="card"><h2>Findings</h2><div class="big">{s.get('total', 0)}</div><div class="mut">top score {s.get('top_score', 0)}</div></div>
 <div class="card"><h2>ATT&amp;CK coverage</h2><div class="big">{len(cov)}</div><div class="mut">techniques tested across {len({t for v in cov.values() for t in v})} tactics</div></div>
 <div class="card"><h2>Severity</h2>{bars}</div>
</div>
<div class="card"><h2>Kill chain (MITRE ATT&amp;CK Enterprise)</h2><div class="tactics">{''.join(cells)}</div></div>
<div class="card"><h2>Findings (validate before acting)</h2><table><tr><th>Severity</th><th>Score</th><th>ATT&amp;CK</th><th>Title</th><th>Artifact</th><th>Signals</th><th>Disposition</th></tr>
{''.join(rows) or '<tr><td colspan=7>No findings above threshold.</td></tr>'}</table></div>
<div class="card"><h2>Collection gaps</h2><ul>{gaps_html}</ul></div>
</main><footer>Detect-only report for the user's own, authorised machine. Scores are heuristic leads, not verdicts. &middot; {e(SIGNATURE)}</footer>
</body></html>"""
