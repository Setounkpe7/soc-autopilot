import pytest
from pydantic import ValidationError

from soc_autopilot.engine.schema import Playbook, Trigger


def _min_pb(**over):
    base = dict(
        id="PB-0001",
        name="n",
        version="1.0",
        trigger={"mitre": ["T1059.001"]},
        steps=[{"id": "s1", "action": "noop"}],
    )
    base.update(over)
    return base


def test_valid_playbook_parses():
    pb = Playbook(**_min_pb())
    assert pb.steps[0].with_ == {}
    assert pb.steps[0].destructive is False


def test_with_alias_is_accepted():
    pb = Playbook(
        **_min_pb(steps=[{"id": "s1", "action": "a", "with": {"agent": "WS-042"}}])
    )
    assert pb.steps[0].with_["agent"] == "WS-042"


def test_bad_mitre_rejected():
    with pytest.raises(ValidationError):
        Trigger(mitre=["T1059.1"])


def test_bad_pb_id_rejected():
    with pytest.raises(ValidationError):
        Playbook(**_min_pb(id="PB-1"))


def test_duplicate_step_ids_rejected():
    with pytest.raises(ValidationError):
        Playbook(
            **_min_pb(steps=[{"id": "s", "action": "a"}, {"id": "s", "action": "b"}])
        )
