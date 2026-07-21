import pytest

from soc_autopilot.engine.loader import PlaybookStore


def test_loads_valid_playbooks_dir():
    store = PlaybookStore("playbooks")
    assert any(pb.id == "PB-0001" for pb in store.all())


def test_invalid_playbook_fails_fast(tmp_path):
    (tmp_path / "bad.yml").write_text("id: NOT-VALID\nname: x\n")
    with pytest.raises(ValueError):
        PlaybookStore(str(tmp_path))


def test_match_by_mitre():
    store = PlaybookStore("playbooks")
    alert = {"rule": {"id": "999999", "level": 12, "mitre": {"id": ["T1059.001"]}}}
    matched = store.match(alert)
    assert any(pb.id == "PB-0001" for pb in matched)


def test_no_match_below_severity_min():
    store = PlaybookStore("playbooks")
    alert = {"rule": {"id": "100101", "level": 3, "mitre": {"id": ["T1059.001"]}}}
    assert store.match(alert) == []
