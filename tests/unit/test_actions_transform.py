import base64

from soc_autopilot.actions.transform import b64_decode, score
from soc_autopilot.engine import registry


def test_transform_actions_registered():
    import soc_autopilot.actions.transform  # noqa: F401

    assert "transform.b64_decode" in registry.list_actions()
    assert "transform.score" in registry.list_actions()


async def test_b64_decode_utf16le():
    """PowerShell -enc encode en UTF-16LE : le décodage doit le refléter."""
    payload = base64.b64encode("Write-Output hello".encode("utf-16-le")).decode()
    out = await b64_decode({"field": f"powershell.exe -enc {payload}"}, None)
    assert out["found"] is True
    assert out["decoded"] == "Write-Output hello"


async def test_b64_decode_no_match():
    out = await b64_decode({"field": "powershell.exe -NoProfile Get-Process"}, None)
    assert out["found"] is False
    assert out["decoded"] is None


async def test_score_applies_rendered_boosters():
    """Après render_dict, les boosters ont when='True'/'False' (chaînes)."""
    result = await score(
        {
            "base": "5",
            "boosters": [
                {"when": "True", "points": 3},
                {"when": "False", "points": 2},
            ],
        },
        None,
    )
    assert result == 8  # 5 + 3, le booster 'False' ne s'applique pas


async def test_score_caps_at_ten():
    result = await score(
        {"base": "9", "boosters": [{"when": "True", "points": 5}]}, None
    )
    assert result == 10
