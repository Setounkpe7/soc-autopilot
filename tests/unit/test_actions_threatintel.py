import inspect

import httpx
import respx

from soc_autopilot.actions.threatintel import _vt_classify, extract_iocs
from soc_autopilot.engine import registry


def test_threatintel_actions_registered():
    import soc_autopilot.actions.threatintel  # noqa: F401

    for name in (
        "threatintel.extract_iocs",
        "threatintel.lookup",
        "threatintel.virustotal_lookup",
    ):
        assert name in registry.list_actions()


async def test_extract_iocs_filters_private_ips():
    text = "beacon to 8.8.8.8 and internal 192.168.56.20 hash " + "a" * 64
    out = await extract_iocs({"text": text}, None)
    assert "8.8.8.8" in out["ips"]
    assert "192.168.56.20" not in out["ips"]  # IP privée jamais envoyée à un tiers
    assert "a" * 64 in out["hashes"]


def test_vt_classify_ratio_not_count():
    assert _vt_classify(45, 0, 70) == "malicious"
    assert _vt_classify(2, 0, 70) in ("suspicious", "likely_benign")
    assert _vt_classify(0, 0, 0) == "unknown"  # absence != benign


def test_no_file_upload_path_exists():
    """Garde structurelle : aucun upload vers VirusTotal (un upload exige un POST/PUT)."""
    import soc_autopilot.actions.threatintel as ti

    src = inspect.getsource(ti)
    # Le module ne fait QUE des GET : sans POST/PUT, aucun fichier ne peut être uploadé.
    assert ".post(" not in src
    assert ".put(" not in src


async def test_iocs_non_dict_returns_error_not_clean(monkeypatch):
    """Dans les playbooks `iocs` arrive comme str (le resolver stringifie
    `{{ steps.iocs.output }}`). VT ne doit PAS crasher sur `"".get(...)`, mais il
    ne doit surtout PAS renvoyer un `unknown` qui ressemble à un scan propre : un
    échec d'enrichissement se signale par un verdict `error` explicite (leçon de
    la revue PR #3 — un état d'erreur ne doit jamais imiter un résultat bénin)."""
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.setenv("virustotal_api_key", "k")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()
    import soc_autopilot.actions.threatintel as ti

    out = await ti.virustotal_lookup({"iocs": ""}, None)
    assert out["enabled"] is True
    assert out["checked"] == 0
    assert out["worst_verdict"] == "error"  # jamais un faux "unknown"
    assert out["reason"] == "iocs_not_dict"


@respx.mock
async def test_virustotal_enriches_iocs_passed_via_template(monkeypatch):
    """Régression du flux RÉEL : PB-0001 passe `iocs: "{{ steps.iocs.output }}"`.
    Après le passthrough d'objet du resolver, VT reçoit un DICT et enrichit
    vraiment (avant : il recevait la repr stringifiée et ne vérifiait rien)."""
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.setenv("virustotal_api_key", "k")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()
    import soc_autopilot.actions.threatintel as ti
    from soc_autopilot.engine.resolver import render_dict

    ti._VT_CACHE.clear()
    h = "a" * 64
    respx.get(f"https://www.virustotal.com/api/v3/files/{h}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 40,
                            "suspicious": 0,
                            "harmless": 30,
                            "undetected": 0,
                        }
                    }
                }
            },
        )
    )
    # Le param EXACTEMENT tel qu'écrit dans PB-0001, rendu par le resolver.
    ctx = {"steps": {"iocs": {"output": {"hashes": [h], "ips": [], "domains": []}}}}
    params = render_dict({"iocs": "{{ steps.iocs.output }}"}, ctx)
    assert isinstance(params["iocs"], dict)  # le fix : dict, pas str
    out = await ti.virustotal_lookup(params, None)
    assert out["checked"] == 1  # VT a RÉELLEMENT interrogé le hash
    assert out["worst_verdict"] == "malicious"
    assert out["malicious_count"] == 1


@respx.mock
async def test_rate_limited_verdict_is_not_cached(monkeypatch):
    """Un 429 est un état client transitoire : ne jamais le cacher (sinon un IOC
    malveillant serait masqué jusqu'au TTL)."""
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.setenv("virustotal_api_key", "k")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()
    import soc_autopilot.actions.threatintel as ti

    ti._VT_CACHE.clear()
    h = "a" * 64
    respx.get(f"https://www.virustotal.com/api/v3/files/{h}").mock(
        return_value=httpx.Response(429)
    )
    out = await ti.virustotal_lookup({"iocs": {"hashes": [h]}}, None)
    assert out["results"][0]["reason"] == "rate_limited"
    assert h not in ti._VT_CACHE  # jamais mis en cache
