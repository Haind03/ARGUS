import json
import struct
import subprocess
import sys

from argus import triage

ROOT = triage.Path(__file__).resolve().parent.parent
CLI = [sys.executable, "-I", str(ROOT / "engine" / "argus_cli.py")]


def run(*args, **kw):
    return subprocess.run([*CLI, *args], capture_output=True, text=True, timeout=120, **kw)


def test_cli_hunt_writes_three_outputs(tmp_path, infected_file):
    r = run("hunt", "--input", str(infected_file), "--out-dir", str(tmp_path))
    assert r.returncode == 2, r.stderr  # high/critical present
    names = {p.name.split(".", 1)[1] for p in tmp_path.iterdir() if p.name.startswith("argus-")}
    assert {"json", "md", "navigator.json"} <= names
    res = json.loads(next(p for p in tmp_path.glob("argus-*[0-9].json")).read_text())
    assert res["mode"] == "detect-only" and res["intel"]["online_enabled"] is False
    assert res["intel"]["hashes_sent"] == []


def test_cli_clean_exit_zero(tmp_path):
    r = run("hunt", "--input", str(ROOT / "tests" / "fixtures" / "clean.json"), "--out-dir", str(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_rejects_missing_input(tmp_path):
    r = run("hunt", "--input", str(tmp_path / "nope.json"), "--out-dir", str(tmp_path))
    assert r.returncode == 3 and "error" in r.stderr


def test_tactic_wrapper_script(tmp_path, infected_file):
    s = ROOT / "skills" / "impact-hunting" / "scripts" / "hunt_impact_hunting.py"
    r = subprocess.run([sys.executable, "-I", str(s), "--input", str(infected_file), "--out-dir", str(tmp_path)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 2, r.stderr


def _tiny_pe(tmp_path):
    pe = bytearray(1024)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    struct.pack_into("<H", pe, 0x98, 0x10B)
    sec = 0x98 + 0xE0
    pe[sec:sec + 8] = b"UPX0\0\0\0\0"
    struct.pack_into("<IIII", pe, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", pe, sec + 36, 0xE0000020)  # RWX
    p = tmp_path / "sample.bin"
    p.write_bytes(bytes(pe))
    return p


def test_static_triage_never_executes_and_parses_pe(tmp_path):
    p = _tiny_pe(tmp_path)
    p.chmod(0o644)
    res = triage.triage(str(p), None)
    assert res["pe"]["valid"] and res["pe"]["sections"][0]["name"] == "UPX0"
    names = {s["name"] for s in res["signals"]}
    assert "packer_section_names" in names and "rwx_section" in names
    assert len(res["hashes"]["sha256"]) == 64


def test_validators_pass():
    for script in ("skills/writing-defensive-skills/scripts/validate_skills.py",
                   "skills/yara-sigma-authoring/scripts/validate_rules.py"):
        r = subprocess.run([sys.executable, "-I", str(ROOT / script)], capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stdout + r.stderr


def test_skills_lock_up_to_date():
    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "lock.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_network_beacon_detection():
    sys.path.insert(0, str(ROOT / "skills" / "network-forensics" / "scripts"))
    import network_hunt as nh
    rows = [{"t": 1000 + 60 * i, "src": "192.168.1.5", "dst": "203.0.113.7", "port": "443", "dns": "", "sni": "",
             "host": "", "len": 300} for i in range(20)]
    fs = nh.hunt(rows)
    assert any(f.rule_id == "ARG-NF-001" for f in fs)
    jitter = [{**r, "t": r["t"] + (i * 37 % 50)} for i, r in enumerate(rows)]
    assert not any(f.rule_id == "ARG-NF-001" and f.artifact["cv"] > 0.25 for f in nh.hunt(jitter))
