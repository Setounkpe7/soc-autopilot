import hashlib
import hmac

from soc_autopilot import config as cfg
from soc_autopilot.api.routes.webhook import verify_hmac


def _env(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "s3cr3t")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    cfg.get_settings.cache_clear()


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_verify_hmac_accepts_valid(monkeypatch):
    _env(monkeypatch)
    body = b'{"rule":{"id":"550"}}'
    assert verify_hmac(body, _sign(b"s3cr3t", body)) is True


def test_verify_hmac_rejects_bad(monkeypatch):
    _env(monkeypatch)
    assert verify_hmac(b"body", "deadbeef") is False


def test_verify_hmac_rejects_missing(monkeypatch):
    _env(monkeypatch)
    assert verify_hmac(b"body", None) is False
