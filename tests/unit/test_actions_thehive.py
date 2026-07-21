from soc_autopilot.actions.thehive import create_case
from soc_autopilot.engine import registry


class _Ctx:
    execution_id = 42

    class playbook:
        id = "PB-0001"


def test_thehive_action_registered():
    import soc_autopilot.actions.thehive  # noqa: F401

    assert "thehive.create_case" in registry.list_actions()


async def test_create_case_degrades_without_key(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.delenv("thehive_api_key", raising=False)
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()
    out = await create_case({"title": "t"}, _Ctx())
    assert out["backend"] == "local"
    assert out["case_id"].startswith("LOCAL-")
