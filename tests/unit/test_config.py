from soc_autopilot.config import get_settings


def test_dry_run_defaults_true(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setenv("threat_intel_url", "http://ti.local")
    get_settings.cache_clear()
    s = get_settings()
    assert s.dry_run is True
    assert "DC-01" in s.protected_assets
