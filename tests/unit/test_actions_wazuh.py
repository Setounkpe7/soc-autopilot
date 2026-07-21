import httpx
import respx

from soc_autopilot.engine import registry


def _env(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.setenv("wazuh_api_url", "https://wazuh:55000")
    monkeypatch.setenv("wazuh_api_user", "u")
    monkeypatch.setenv("wazuh_api_password", "p")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()


def test_wazuh_actions_registered():
    import soc_autopilot.actions.wazuh  # noqa: F401

    for name in (
        "wazuh.get_agent_context",
        "wazuh.isolate_host",
        "wazuh.unisolate_host",
    ):
        assert name in registry.list_actions()


@respx.mock
async def test_agent_id_resolves(monkeypatch):
    _env(monkeypatch)
    from soc_autopilot.actions.wazuh import WazuhClient

    respx.post("https://wazuh:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text="TOKEN")
    )
    respx.get("https://wazuh:55000/agents").mock(
        return_value=httpx.Response(
            200, json={"data": {"affected_items": [{"id": "001"}]}}
        )
    )

    client = WazuhClient()
    assert await client.agent_id("victim-win") == "001"
