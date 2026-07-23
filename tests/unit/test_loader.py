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


def test_notify_surfaces_threat_intel_and_degrades_gracefully():
    """Le message Slack #soc-alerts porte l'enrichissement (verdict VT + KEV) et
    dégrade proprement ('n/a'/0) quand un enrichissement best-effort a échoué —
    sans jamais lever."""
    from soc_autopilot.engine.resolver import render

    store = PlaybookStore("playbooks")
    pb = next(p for p in store.all() if p.id == "PB-0001")
    tmpl = next(s for s in pb.steps if s.id == "notify").with_["text"]

    base = {"playbook": {"id": "PB-0001"}, "inputs": {"host": "VICTIM-WIN"}}

    def ctx(vt_output, intel_output):
        return {
            **base,
            "steps": {
                "case": {"output": {"case_id": "C-1"}},
                "risk": {"output": 9},
                "vt": {"output": vt_output},
                "intel": {"output": intel_output},
            },
        }

    # VT + intel ont enrichi
    out_ok = render(
        tmpl,
        ctx({"worst_verdict": "malicious", "malicious_count": 2}, {"kev_count": 3}),
    )
    assert "malicious" in out_ok
    assert "KEV gov : 3" in out_ok

    # VT + intel ont échoué (output None) → dégradé, pas de crash
    out_ko = render(tmpl, ctx(None, None))
    assert "n/a" in out_ko
    assert "0 IOC malveillant·s" in out_ko
    assert "KEV gov : 0" in out_ko
