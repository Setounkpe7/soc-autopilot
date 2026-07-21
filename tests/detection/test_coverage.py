import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "tools"))
import sigma_to_dettect as cov  # noqa: E402

LAYER = Path("docs/coverage/attack-navigator-layer.json")
DETTECT = Path("docs/coverage/dettect-techniques.yaml")


def test_covers_expected_techniques():
    tech = cov.collect()
    assert "T1059.001" in tech
    assert "T1003.001" in tech


def test_generation_is_deterministic():
    a = cov.navigator_layer(cov.collect())
    b = cov.navigator_layer(cov.collect())
    assert a == b


def test_committed_navigator_layer_is_up_to_date():
    """La carte committée DOIT correspondre au code — sinon elle est périmée."""
    generated = cov.navigator_layer(cov.collect())
    committed = json.loads(LAYER.read_text(encoding="utf-8"))
    assert (
        committed == generated
    ), "docs/coverage/ périmé : relance `python tools/sigma_to_dettect.py`"


def test_dettect_file_committed():
    assert DETTECT.exists()
