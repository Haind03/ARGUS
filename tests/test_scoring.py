from argus.scoring import BASELINE_FACTOR, Finding, Signal, at_least, compute_score, finding_id, severity_for


def test_compute_score_clamps():
    assert compute_score([Signal("a", 70), Signal("b", 60)]) == 100
    assert compute_score([Signal("a", 10), Signal("signed", -30)]) == 0
    assert compute_score([]) == 0


def test_severity_bands():
    assert severity_for(100) == "critical"
    assert severity_for(80) == "critical"
    assert severity_for(79) == "high"
    assert severity_for(60) == "high"
    assert severity_for(40) == "medium"
    assert severity_for(20) == "low"
    assert severity_for(19) == "info"


def test_mitigating_signal_lowers_severity():
    f = Finding("R", "t", "TA0002", "T1059", {}, "k", [Signal("x", 50), Signal("signed_microsoft", -20)]).finalize()
    assert f.score == 30 and f.severity == "low"


def test_baseline_downweights_but_keeps():
    f = Finding("R", "t", "TA0003", "T1547.001", {}, "k", [Signal("x", 90)], baseline_known=True).finalize()
    assert f.score == round(90 * BASELINE_FACTOR)
    assert f.severity == "low"


def test_to_dict_has_required_fields():
    d = Finding("R1", "t", "TA0003", "T1547.001", {"path": "p"}, "k", [Signal("x", 30)], action="do").finalize().to_dict()
    for k in ("artifact", "technique", "signals_matched", "score", "severity", "action", "id"):
        assert k in d
    assert d["signals_matched"] == ["x"]


def test_finding_id_stable_and_short():
    assert finding_id("R", "k") == finding_id("R", "k")
    assert finding_id("R", "k") != finding_id("R", "k2")
    assert len(finding_id("R", "k")) == 12


def test_at_least():
    assert at_least("high", "medium") and not at_least("low", "medium")
