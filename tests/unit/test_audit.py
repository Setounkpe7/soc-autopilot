import pytest

from soc_autopilot.audit import AuditRepository
from soc_autopilot.engine.schema import Playbook


@pytest.fixture
async def repo():
    r = AuditRepository("sqlite+aiosqlite:///:memory:")
    await r.init_schema()
    yield r
    await r.close()


def _pb():
    return Playbook(
        id="PB-0001",
        name="n",
        version="1.0",
        trigger={},
        steps=[{"id": "s1", "action": "a"}],
    )


async def test_create_then_find_by_dedup(repo):
    ex = await repo.create_execution(
        dedup_key="k1", playbook=_pb(), alert_id="a1", alert_raw={"x": 1}, dry_run=True
    )
    assert ex.id is not None
    found = await repo.find_by_dedup("k1")
    assert found is not None and found.id == ex.id


async def test_find_by_dedup_absent_returns_none(repo):
    assert await repo.find_by_dedup("nope") is None


async def test_finish_execution_sets_status(repo):
    ex = await repo.create_execution(
        dedup_key="k2", playbook=_pb(), alert_id="a2", alert_raw={}, dry_run=True
    )
    await repo.finish_execution(ex.id, status="success", outputs={"done": True})
    reloaded = await repo.get_execution(ex.id)
    assert reloaded.status == "success" and reloaded.outputs == {"done": True}
