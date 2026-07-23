from soc_autopilot.engine import registry
from soc_autopilot.engine.executor import Executor, dedup_key
from soc_autopilot.engine.schema import Playbook


def test_dedup_key_stable():
    assert dedup_key("a1", "PB-0001") == dedup_key("a1", "PB-0001")


def test_dedup_key_differs_per_playbook():
    assert dedup_key("a1", "PB-0001") != dedup_key("a1", "PB-0002")


class _FakeExec:
    def __init__(self, id):
        self.id = id


class _FakeAudit:
    """Audit en mémoire pour tester l'executor sans DB."""

    def __init__(self):
        self.steps = []
        self._n = 0
        self.seen = {}

    async def find_by_dedup(self, key):
        return self.seen.get(key)

    async def create_execution(
        self, *, dedup_key, playbook, alert_id, alert_raw, dry_run
    ):
        self._n += 1
        ex = _FakeExec(self._n)
        self.seen[dedup_key] = ex
        return ex

    async def finish_execution(self, execution_id, *, status, outputs):
        self.last = (status, outputs)

    async def set_error(self, execution_id, message):
        pass

    async def log_step(self, *a, **k):
        self.steps.append((a, k))
        return _FakeExec(len(self.steps))


async def test_destructive_step_is_dry_run_by_default(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()

    ran = {"called": False}

    @registry.action("test.destroy")
    async def _destroy(params, ctx):
        ran["called"] = True
        return {"did": "it"}

    pb = Playbook(
        id="PB-0009",
        name="n",
        version="1.0",
        trigger={},
        steps=[{"id": "s1", "action": "test.destroy", "destructive": True}],
    )
    audit = _FakeAudit()
    result = await Executor(audit).run(pb, {"id": "alert-1"})
    assert result["status"] in ("success", "partial")
    assert ran["called"] is False  # dry_run=True → action NOT executed


async def test_destructive_empty_target_is_blocked(monkeypatch):
    """Garde-fou : une étape destructive dont la cible rend "" (typo de template
    ou enrichissement manquant) est REFUSÉE — jamais exécutée, statut failed.
    Restaure la garantie « ne jamais agir silencieusement sur la mauvaise cible »
    que la tolérance ChainableUndefined du resolver, seule, ne fournit plus."""
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()

    ran = {"called": False}

    @registry.action("test.destroy_blank")
    async def _destroy_blank(params, ctx):
        ran["called"] = True
        return {"did": "it"}

    pb = Playbook(
        id="PB-0005",
        name="n",
        version="1.0",
        trigger={},
        steps=[
            {
                "id": "s1",
                "action": "test.destroy_blank",
                "destructive": True,
                "with": {"agent": "{{ inputs.absent }}"},  # rend ""
            }
        ],
    )
    audit = _FakeAudit()
    result = await Executor(audit).run(pb, {"id": "a-blank"})
    assert ran["called"] is False  # jamais exécuté sur cible vide
    assert result["status"] == "failed"
    # audité comme échec explicite, pas comme skip silencieux
    assert "failed" in [a[2] for a, _k in audit.steps]


async def test_dedup_short_circuits_second_run(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()

    pb = Playbook(
        id="PB-0008",
        name="n",
        version="1.0",
        trigger={},
        steps=[{"id": "s1", "action": "noop"}],
    )
    audit = _FakeAudit()
    ex = Executor(audit)
    first = await ex.run(pb, {"id": "same"})
    second = await ex.run(pb, {"id": "same"})
    assert second["status"] == "deduplicated"
    assert second["execution_id"] == first["execution_id"]


async def test_distinct_alerts_without_id_are_not_deduplicated(monkeypatch):
    """Sans id/timestamp, la clé dérive du contenu → alertes distinctes distinctes."""
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()

    pb = Playbook(
        id="PB-0007",
        name="n",
        version="1.0",
        trigger={},
        steps=[{"id": "s1", "action": "noop"}],
    )
    ex = Executor(_FakeAudit())
    r1 = await ex.run(pb, {"rule": {"id": "A"}})
    r2 = await ex.run(pb, {"rule": {"id": "B"}})
    assert r1["execution_id"] != r2["execution_id"]
    assert r2["status"] != "deduplicated"


async def test_integrity_error_race_returns_deduplicated(monkeypatch):
    """Course concurrente : create_execution lève IntegrityError → dédupliqué."""
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    from soc_autopilot import config as cfg

    cfg.get_settings.cache_clear()

    class _RaceAudit(_FakeAudit):
        async def create_execution(
            self, *, dedup_key, playbook, alert_id, alert_raw, dry_run
        ):
            from sqlalchemy.exc import IntegrityError

            self.seen[dedup_key] = _FakeExec(99)  # inséré par le "concurrent"
            raise IntegrityError("dup", None, Exception("unique"))

    pb = Playbook(
        id="PB-0006",
        name="n",
        version="1.0",
        trigger={},
        steps=[{"id": "s1", "action": "noop"}],
    )
    result = await Executor(_RaceAudit()).run(pb, {"id": "race"})
    assert result["status"] == "deduplicated"
    assert result["execution_id"] == 99
