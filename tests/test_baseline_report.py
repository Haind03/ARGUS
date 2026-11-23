import json

from argus import baseline as bl
from argus import report
from argus.hunt import build_result, run_rules
from argus.rules import covered_techniques


def test_baseline_downweights_known_findings(infected):
    b = bl.create(infected)
    before = {f.key: f.score for f in run_rules(infected)}
    after = run_rules(infected, {"min_score": 0}, set(b["finding_keys"]))
    assert after and all(f.baseline_known for f in after)
    for f in after:
        if f.key in before:
            assert f.score <= before[f.key]


def test_diff_detects_new_persistence(clean, infected):
    b = bl.create(clean)
    delta = bl.diff(b, infected)
    assert "autoruns" in delta and delta["autoruns"]["added"]
    items = bl.diff_findings(delta)
    assert any(i["technique"] == "T1546.003" for i in items)  # new WMI subscription
    assert any(i["technique"] == "T1562.001" for i in items)  # new Defender exclusion


def test_diff_clean_vs_itself_empty(clean):
    assert bl.diff(bl.create(clean), clean) == {}


def test_shadow_copy_drop_since_baseline(infected):
    infected["_baseline_shadow_copies"] = 3
    assert any(f.key == "vss|count" for f in run_rules(infected))


def test_markdown_and_navigator(infected):
    res = build_result(infected, run_rules(infected), "full", False)
    md = report.markdown(res)
    assert "# ARGUS Hunt Report" in md and "## Collection gaps" in md and "detect-only" in md
    layer = report.navigator_layer(res)
    assert layer["domain"] == "enterprise-attack"
    techs = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1490" in techs
    assert all("tactic" in t for t in layer["techniques"])
    json.dumps(layer)


def test_coverage_spans_tactics():
    tactics = set().union(*covered_techniques().values())
    assert len(tactics) >= 12
