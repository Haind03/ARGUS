from argus.hunt import run_rules
from argus.indicators import dga_score, is_public_ip, path_risk, try_decode_ps_encoded
from argus.rules import RULES, TACTICS

import synthetic


def ids(findings):
    return {f.rule_id for f in findings}


def test_every_host_tactic_has_rules():
    covered = {r.tactic for r in RULES}
    for t in TACTICS:
        if t not in ("TA0043", "TA0042"):
            assert t in covered, t


def test_rule_ids_unique():
    names = [r.rule_id for r in RULES]
    assert len(names) == len(set(names))


def test_infected_detects_core_chain(infected):
    got = ids(run_rules(infected))
    expected = {"ARG-IA-001", "ARG-EX-001", "ARG-PE-001", "ARG-PE-002", "ARG-PE-005", "ARG-PE-006",
                "ARG-DE-001", "ARG-DE-002", "ARG-DE-003", "ARG-CA-001", "ARG-C2-001", "ARG-EF-001", "ARG-IM-001",
                "ARG-IM-002", "ARG-IA-003", "ARG-PE-004"}
    assert expected <= got, expected - got


def test_clean_host_has_no_findings(clean):
    assert run_rules(clean, {"min_score": 20}) == []


def test_findings_sorted_and_scored(infected):
    fs = run_rules(infected)
    assert fs == sorted(fs, key=lambda f: (-f.score, f.tactic, f.rule_id))
    assert all(0 <= f.score <= 100 for f in fs)


def test_encoded_powershell_decoded():
    cmd = "powershell -enc " + synthetic.encoded_ps("Write-Output hello")
    assert try_decode_ps_encoded(cmd) == "Write-Output hello"


def test_renamed_svchost_in_temp_is_not_trusted(infected):
    """Regression: LSASS-access allow-list must not trust a svchost.exe outside System32."""
    fs = [f for f in run_rules(infected) if f.rule_id == "ARG-CA-001"]
    assert any("lsass_handle_opened" in [s.name for s in f.signals] for f in fs)


def test_genuine_svchost_lsass_access_allowed():
    tel = {"events": [{"log": "Microsoft-Windows-Sysmon/Operational", "id": 10, "data": {
        "SourceImage": "C:\\Windows\\System32\\svchost.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1010"}}]}
    assert not [f for f in run_rules(tel) if f.rule_id == "ARG-CA-001"]


def test_signed_microsoft_mitigates():
    base = {"processes": [{"pid": 1, "ppid": 0, "name": "x.exe", "path": "C:\\Users\\Public\\x.exe"}]}
    unsigned = run_rules(base, {"min_score": 0})
    base["processes"][0].update(signed=True, signer="Microsoft Windows")
    signed = run_rules(base, {"min_score": 0})
    assert max(f.score for f in unsigned) > max((f.score for f in signed), default=0)


def test_preset_tactic_filter(infected):
    fs = run_rules(infected, {"tactics": ["TA0040"]})
    assert fs and {f.tactic for f in fs} == {"TA0040"}


def test_disabled_rule(infected):
    assert "ARG-IM-001" not in ids(run_rules(infected, {"disabled_rules": ["ARG-IM-001"]}))


def test_weight_override(infected):
    fs = [f for f in run_rules(infected, {"signal_weight_overrides": {"vssadmin_delete_shadows": 5}, "min_score": 0})
          if f.rule_id == "ARG-IM-001"]
    assert fs and fs[0].score == 5


def test_rule_exception_does_not_crash():
    fs = run_rules({"processes": "not-a-list", "network": [{"rport": "x", "remote": "8.8.8.8"}]})
    assert isinstance(fs, list)


def test_path_risk_and_allowlist():
    assert path_risk("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe")[1] == 25
    assert path_risk("C:\\Users\\a\\AppData\\Local\\Microsoft\\Teams\\Update.exe")[1] == 0
    assert path_risk("C:\\Program Files\\App\\a.exe")[1] == 0


def test_public_ip():
    assert is_public_ip("8.8.8.8") and not is_public_ip("192.168.1.1") and not is_public_ip("10.0.0.1")
    assert not is_public_ip("172.16.5.5") and not is_public_ip("127.0.0.1") and not is_public_ip("garbage")


def test_dga():
    assert dga_score("xkqjzvbwptrmnhd.com")[0]
    assert not dga_score("microsoft.com")[0]
    assert not dga_score("googleusercontent.com")[0]
