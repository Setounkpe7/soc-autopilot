import inspect

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
