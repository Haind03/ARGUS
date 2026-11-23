import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "tests"))

import synthetic  # noqa: E402


@pytest.fixture
def infected():
    return synthetic.infected()


@pytest.fixture
def clean():
    return json.loads((ROOT / "tests" / "fixtures" / "clean.json").read_text(encoding="utf-8"))


@pytest.fixture
def infected_file(tmp_path, infected):
    p = tmp_path / "infected.json"
    p.write_text(json.dumps(infected), encoding="utf-8")
    return p
