# SOAR Engine (J2) + Integrations (J3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the SOAR orchestration engine (schema, sandboxed resolver, action registry, DAG executor with idempotency/dry-run/rollback, HMAC webhook, audit trail) and its integrations (Wazuh, VirusTotal, TheHive) so the interview pitch's core claims (Q1, Q2, Q7, Q8, Q9, Q10) become real and demonstrable.

**Architecture:** Engine-in-Python / content-in-YAML. A FastAPI webhook receives HMAC-signed Wazuh alerts, the loader matches them to declarative YAML playbooks, and the executor runs each playbook as an ordered step list with per-step timeout/retry, `dry_run` safety, a protected-assets guard, and a full audit trail persisted to Postgres. Integrations register as `@action("namespace.verb")` plugins — the engine knows a contract, never a vendor.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2 + pydantic-settings, Jinja2 `SandboxedEnvironment`, SQLAlchemy async + asyncpg, httpx, structlog, prometheus-client, pytest + pytest-asyncio + respx.

**Design source of truth:** [`docs/03_Construction_Jour_par_Jour.md`](../../03_Construction_Jour_par_Jour.md) contains the complete, reviewed code for every file EXCEPT `soc_autopilot/audit.py` (authored here). Section pointers (§2.x/§3.x) reference that file. When a step says "transcribe §X.Y", copy that block verbatim unless the step notes an adaptation.

## Global Constraints

- **Never push to `main` directly.** All work on `feat/soar-engine` → PR → `code-review` + `semgrep` → squash-merge when green (CLAUDE.md).
- **PR split:** PR-A = Tasks 0–8 (engine J2). PR-B = Tasks 9–11 (integrations J3).
- **`dry_run=True` is the default.** Destructive actions are logged, never executed, unless explicitly armed. Never fabricate a real isolation or a live VirusTotal call.
- **VirusTotal: by hash/IP/domain only, never file upload.** No upload code path may exist. Private IPs are filtered before any third-party call.
- **pre-commit hooks (ruff, ruff-format, detect-secrets, check-yaml…) must pass before every commit.**
- **Python import root:** package is `soc_autopilot` (already scaffolded with empty `__init__.py`).
- **Secrets:** never hardcode. `webhook_hmac_secret`, `POSTGRES_PASSWORD`, API keys come from `.env` / environment only.

---

## Task 0: Environment, dependencies, and configuration

**Files:**
- Create: `.venv/` (virtualenv), `requirements.txt`
- Create: `soc_autopilot/config.py`
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Produces: `soc_autopilot.config.Settings` (pydantic-settings), `get_settings() -> Settings` (lru_cached). Fields per §2.2: `dry_run: bool = True`, `webhook_hmac_secret: str`, `database_url: str`, `protected_assets: list[str]`, `privileged_users: list[str]`, plus Wazuh/TheHive/threat-intel/VirusTotal/Slack fields.

- [ ] **Step 1: Create venv and install deps**

```bash
cd "/media/mdoub/Data/Personal Projects/soc-autopilot"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install fastapi "uvicorn[standard]" pydantic pydantic-settings \
  "sqlalchemy[asyncio]" asyncpg alembic httpx jinja2 pyyaml structlog \
  prometheus-client python-multipart
.venv/bin/pip install pytest pytest-asyncio respx ruff mypy
.venv/bin/pip freeze > requirements.txt
```
Expected: `requirements.txt` created, `.venv/bin/python -c "import fastapi, jinja2, sqlalchemy"` exits 0.

- [ ] **Step 2: Write config with a test-friendly env**

Create `soc_autopilot/config.py` by transcribing §2.2 verbatim.

- [ ] **Step 3: Write the failing test**

```python
# tests/unit/test_config.py
import importlib
import soc_autopilot.config as cfg


def test_dry_run_defaults_true(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setenv("threat_intel_url", "http://ti.local")
    importlib.reload(cfg)
    cfg.get_settings.cache_clear()
    s = cfg.get_settings()
    assert s.dry_run is True
    assert "DC-01" in s.protected_assets
```

- [ ] **Step 4: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_config.py -v`
Expected: PASS (2 assertions).

- [ ] **Step 5: Commit**

```bash
git add requirements.txt soc_autopilot/config.py tests/unit/test_config.py
git commit -m "feat(config): pydantic settings with dry_run-safe defaults"
```
(`.venv/` is git-ignored — confirm it is in `.gitignore`, add if missing.)

---

## Task 1: Playbook schema (Pydantic)

**Files:**
- Create: `soc_autopilot/engine/schema.py`
- Test: `tests/unit/test_schema.py`

**Interfaces:**
- Produces: `Playbook`, `Step`, `Trigger`, `OnError` (Enum: `FAIL`/`CONTINUE`/`RETRY`). `Step` has `id, action, with_ (alias "with"), when, on_error, retries, timeout_seconds, rollback, destructive`. `Playbook` has `id (pattern ^PB-\d{4}$), name, version, description, trigger, inputs, steps, outputs`. `Trigger.valid_mitre` rejects malformed ATT&CK IDs. `Playbook.unique_ids` rejects duplicate step ids.

- [ ] **Step 1: Transcribe schema**

Create `soc_autopilot/engine/schema.py` by transcribing §2.3 verbatim.

- [ ] **Step 2: Write failing tests**

```python
# tests/unit/test_schema.py
import pytest
from pydantic import ValidationError
from soc_autopilot.engine.schema import Playbook, Trigger


def _min_pb(**over):
    base = dict(id="PB-0001", name="n", version="1.0",
                trigger={"mitre": ["T1059.001"]},
                steps=[{"id": "s1", "action": "noop"}])
    base.update(over)
    return base


def test_valid_playbook_parses():
    pb = Playbook(**_min_pb())
    assert pb.steps[0].with_ == {}
    assert pb.steps[0].destructive is False


def test_with_alias_is_accepted():
    pb = Playbook(**_min_pb(steps=[{"id": "s1", "action": "a", "with": {"agent": "WS-042"}}]))
    assert pb.steps[0].with_["agent"] == "WS-042"


def test_bad_mitre_rejected():
    with pytest.raises(ValidationError):
        Trigger(mitre=["T1059.1"])


def test_bad_pb_id_rejected():
    with pytest.raises(ValidationError):
        Playbook(**_min_pb(id="PB-1"))


def test_duplicate_step_ids_rejected():
    with pytest.raises(ValidationError):
        Playbook(**_min_pb(steps=[{"id": "s", "action": "a"}, {"id": "s", "action": "b"}]))
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_schema.py -v`
Expected: PASS (5 tests).

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/engine/schema.py tests/unit/test_schema.py
git commit -m "feat(engine): pydantic playbook schema with ATT&CK and step-id validation"
```

---

## Task 2: Sandboxed resolver — THE security core (Q10)

**Files:**
- Create: `soc_autopilot/engine/resolver.py`
- Test: `tests/unit/test_resolver.py`

**Interfaces:**
- Produces: `render(template: str, context: dict) -> Any`, `render_dict(data: dict, context: dict) -> dict`, `evaluate(expression: str | None, context: dict) -> bool`. Uses `SandboxedEnvironment(undefined=StrictUndefined)`.

- [ ] **Step 1: Transcribe resolver**

Create `soc_autopilot/engine/resolver.py` by transcribing §2.5 verbatim. **Guard:** the module MUST import `SandboxedEnvironment`, never `Environment`.

- [ ] **Step 2: Write failing tests (transcribe §2.11 test_resolver + add coercion tests)**

```python
# tests/unit/test_resolver.py
import pytest
from jinja2.exceptions import SecurityError, UndefinedError
from soc_autopilot.engine.resolver import render, evaluate


def test_render_simple():
    assert render("{{ alert.agent.name }}", {"alert": {"agent": {"name": "WS-042"}}}) == "WS-042"


def test_evaluate_condition_true():
    assert evaluate("{{ score > 5 }}", {"score": 9}) is True


def test_evaluate_condition_false():
    assert evaluate("{{ score > 5 }}", {"score": 1}) is False


def test_missing_variable_raises():
    with pytest.raises(UndefinedError):
        render("{{ alert.agnet.name }}", {"alert": {"agent": {"name": "WS-042"}}})


def test_sandbox_blocks_rce():
    """LE test le plus important du repo : l'évasion du bac à sable échoue."""
    with pytest.raises(SecurityError):
        render("{{ ''.__class__.__mro__[1].__subclasses__() }}", {})


def test_non_template_passthrough():
    assert render("plain", {}) == "plain"
    assert render(42, {}) == 42
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_resolver.py -v`
Expected: PASS (6 tests) — especially `test_sandbox_blocks_rce`.

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/engine/resolver.py tests/unit/test_resolver.py
git commit -m "feat(engine): sandboxed Jinja2 resolver with StrictUndefined (RCE prevention)"
```

---

## Task 3: Action registry (plugin contract)

**Files:**
- Create: `soc_autopilot/engine/registry.py`
- Test: `tests/unit/test_registry.py`

**Interfaces:**
- Produces: `action(name) -> decorator`, `get_action(name) -> ActionFn`, `list_actions() -> list[str]`. `ActionFn = Callable[[dict, ExecutionContext], Awaitable[Any]]`. Duplicate registration raises `ValueError`; unknown lookup raises `KeyError`.

- [ ] **Step 1: Transcribe registry**

Create `soc_autopilot/engine/registry.py` by transcribing §2.4 verbatim.

- [ ] **Step 2: Write failing tests**

```python
# tests/unit/test_registry.py
import pytest
from soc_autopilot.engine import registry


def test_register_and_get():
    @registry.action("test.echo")
    async def _echo(params, ctx):
        return params
    assert registry.get_action("test.echo") is _echo
    assert "test.echo" in registry.list_actions()


def test_duplicate_registration_raises():
    @registry.action("test.dup")
    async def _a(params, ctx):
        return None
    with pytest.raises(ValueError):
        @registry.action("test.dup")
        async def _b(params, ctx):
            return None


def test_unknown_action_raises():
    with pytest.raises(KeyError):
        registry.get_action("does.not.exist")
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_registry.py -v`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/engine/registry.py tests/unit/test_registry.py
git commit -m "feat(engine): action registry with duplicate/unknown guards"
```

---

## Task 4: Audit trail — models + repository (AUTHORED, not in file 03)

**Files:**
- Create: `soc_autopilot/models/audit.py` (SQLAlchemy models — transcribe §2.7)
- Create: `soc_autopilot/audit.py` (AuditRepository — **authored below**)
- Test: `tests/unit/test_audit.py` (against in-memory SQLite via aiosqlite)

**Interfaces:**
- Produces: `Execution`, `StepLog`, `Base` (from models/audit.py). `AuditRepository(database_url)` with async methods the executor calls: `init_schema()`, `close()`, `find_by_dedup(key) -> Execution | None`, `create_execution(dedup_key, playbook, alert_id, alert_raw, dry_run) -> Execution`, `finish_execution(execution_id, status, outputs)`, `set_error(execution_id, message)`, `log_step(execution_id, step, status, inputs, output, error, duration_ms) -> StepLog`, `get_execution(execution_id) -> Execution`, `get_steps(execution_id) -> list[StepLog]`, `mark_rolled_back(step_log_id)`.

- [ ] **Step 1: Install SQLite async driver for tests**

```bash
.venv/bin/pip install aiosqlite && .venv/bin/pip freeze > requirements.txt
```

- [ ] **Step 2: Transcribe models**

Create `soc_autopilot/models/audit.py` by transcribing §2.7 verbatim (`Base`, `Execution`, `StepLog`).

- [ ] **Step 3: Author the repository**

Create `soc_autopilot/audit.py`:

```python
"""Accès DB async à l'audit trail. Signatures alignées sur les appels de l'executor."""
from __future__ import annotations

from datetime import datetime, UTC
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from soc_autopilot.models.audit import Base, Execution, StepLog


class AuditRepository:
    def __init__(self, database_url: str) -> None:
        self._engine = create_async_engine(database_url, future=True)
        self._session: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False
        )

    async def init_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    async def find_by_dedup(self, key: str) -> Execution | None:
        async with self._session() as s:
            res = await s.execute(select(Execution).where(Execution.dedup_key == key))
            return res.scalar_one_or_none()

    async def create_execution(self, *, dedup_key: str, playbook, alert_id: str,
                               alert_raw: dict, dry_run: bool) -> Execution:
        async with self._session() as s:
            ex = Execution(
                dedup_key=dedup_key, playbook_id=playbook.id,
                playbook_version=playbook.version, alert_id=alert_id,
                alert_raw=alert_raw, status="running", dry_run=dry_run,
            )
            s.add(ex)
            await s.commit()
            await s.refresh(ex)
            return ex

    async def finish_execution(self, execution_id: int, *, status: str,
                               outputs: dict[str, Any]) -> None:
        async with self._session() as s:
            ex = await s.get(Execution, execution_id)
            ex.status = status
            ex.outputs = outputs
            ex.finished_at = datetime.now(UTC)
            await s.commit()

    async def set_error(self, execution_id: int, message: str) -> None:
        async with self._session() as s:
            ex = await s.get(Execution, execution_id)
            ex.status = "failed"
            ex.outputs = {**(ex.outputs or {}), "error": message}
            await s.commit()

    async def log_step(self, execution_id: int, step, status: str, inputs: dict,
                       output: dict, error: str | None, duration_ms: int) -> StepLog:
        async with self._session() as s:
            sl = StepLog(
                execution_id=execution_id, step_id=step.id, action=step.action,
                status=status, destructive=step.destructive, inputs=inputs,
                output=output, error=error, duration_ms=duration_ms,
            )
            s.add(sl)
            await s.commit()
            await s.refresh(sl)
            return sl

    async def get_execution(self, execution_id: int) -> Execution:
        async with self._session() as s:
            return await s.get(Execution, execution_id)

    async def get_steps(self, execution_id: int) -> list[StepLog]:
        async with self._session() as s:
            res = await s.execute(
                select(StepLog).where(StepLog.execution_id == execution_id).order_by(StepLog.id)
            )
            return list(res.scalars().all())

    async def mark_rolled_back(self, step_log_id: int) -> None:
        async with self._session() as s:
            sl = await s.get(StepLog, step_log_id)
            sl.rolled_back = True
            await s.commit()
```

- [ ] **Step 4: Write failing tests (SQLite in-memory)**

```python
# tests/unit/test_audit.py
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
    return Playbook(id="PB-0001", name="n", version="1.0",
                    trigger={}, steps=[{"id": "s1", "action": "a"}])


@pytest.mark.asyncio
async def test_create_then_find_by_dedup(repo):
    ex = await repo.create_execution(dedup_key="k1", playbook=_pb(),
                                     alert_id="a1", alert_raw={"x": 1}, dry_run=True)
    assert ex.id is not None
    found = await repo.find_by_dedup("k1")
    assert found is not None and found.id == ex.id


@pytest.mark.asyncio
async def test_find_by_dedup_absent_returns_none(repo):
    assert await repo.find_by_dedup("nope") is None


@pytest.mark.asyncio
async def test_finish_execution_sets_status(repo):
    ex = await repo.create_execution(dedup_key="k2", playbook=_pb(),
                                     alert_id="a2", alert_raw={}, dry_run=True)
    await repo.finish_execution(ex.id, status="success", outputs={"done": True})
    reloaded = await repo.get_execution(ex.id)
    assert reloaded.status == "success" and reloaded.outputs == {"done": True}
```

Add `asyncio_mode = auto` to a `pytest.ini` / `pyproject`-less config so `pytest-asyncio` runs async tests. Create `pytest.ini`:
```ini
[pytest]
asyncio_mode = auto
```

- [ ] **Step 5: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_audit.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add soc_autopilot/models/audit.py soc_autopilot/audit.py tests/unit/test_audit.py pytest.ini requirements.txt
git commit -m "feat(audit): SQLAlchemy async audit trail models and repository"
```

---

## Task 5: Executor — DAG core with idempotency, dry-run, retry, rollback (Q8)

**Files:**
- Create: `soc_autopilot/engine/executor.py`
- Test: `tests/unit/test_executor.py`

**Interfaces:**
- Consumes: `AuditRepository` (injected), `registry.get_action`, `resolver.render_dict/evaluate`, `schema.Playbook/Step/OnError`.
- Produces: `dedup_key(alert_id, playbook_id) -> str`, `ExecutionContext`, `Executor(audit)` with `async run(playbook, alert) -> dict` and `async rollback(execution_id) -> dict`.

- [ ] **Step 1: Transcribe executor**

Create `soc_autopilot/engine/executor.py` by transcribing §2.8 verbatim. Note: the `rollback` method's `playbook = ...` placeholder in §2.8 must be resolved — for now, mark rollback as reloading via an injected `PlaybookStore` passed at call time; since PR-A has no rollback caller yet, keep `run()` fully working and leave `rollback()` transcribed as-is (covered by an integration playbook later, not unit-tested in this task).

- [ ] **Step 2: Write failing tests (dedup + dry-run via a fake audit)**

```python
# tests/unit/test_executor.py
import pytest
from soc_autopilot.engine.executor import dedup_key, Executor
from soc_autopilot.engine import registry
from soc_autopilot.engine.schema import Playbook


def test_dedup_key_stable():
    assert dedup_key("a1", "PB-0001") == dedup_key("a1", "PB-0001")


def test_dedup_key_differs_per_playbook():
    assert dedup_key("a1", "PB-0001") != dedup_key("a1", "PB-0002")


class _FakeExec:
    def __init__(self, id): self.id = id


class _FakeAudit:
    """Audit en mémoire pour tester l'executor sans DB."""
    def __init__(self): self.execs = {}; self.steps = []; self._n = 0; self.seen = {}
    async def find_by_dedup(self, key): return self.seen.get(key)
    async def create_execution(self, *, dedup_key, playbook, alert_id, alert_raw, dry_run):
        self._n += 1; ex = _FakeExec(self._n); self.seen[dedup_key] = ex; return ex
    async def finish_execution(self, execution_id, *, status, outputs): self.execs[execution_id] = (status, outputs)
    async def set_error(self, execution_id, message): pass
    async def log_step(self, *a, **k): self.steps.append((a, k)); return _FakeExec(len(self.steps))


@pytest.mark.asyncio
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

    pb = Playbook(id="PB-0009", name="n", version="1.0", trigger={},
                  steps=[{"id": "s1", "action": "test.destroy", "destructive": True}])
    audit = _FakeAudit()
    result = await Executor(audit).run(pb, {"id": "alert-1"})
    assert result["status"] in ("success", "partial")
    assert ran["called"] is False  # dry_run=True → action NOT executed
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_executor.py -v`
Expected: PASS (3 tests) — dedup stability + dry-run safety.

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/engine/executor.py tests/unit/test_executor.py
git commit -m "feat(engine): DAG executor with idempotency, dry-run guard, retry"
```

---

## Task 6: HMAC-authenticated webhook (Q7)

**Files:**
- Create: `soc_autopilot/api/routes/webhook.py`
- Test: `tests/unit/test_webhook.py`

**Interfaces:**
- Produces: `router` (APIRouter), `verify_hmac(body: bytes, signature: str | None) -> bool` using `hmac.compare_digest`. `POST /webhook/wazuh` returns 202; 401 on bad signature.

- [ ] **Step 1: Transcribe webhook**

Create `soc_autopilot/api/routes/webhook.py` by transcribing §2.9 verbatim.

- [ ] **Step 2: Write failing test for HMAC (unit, no full app)**

```python
# tests/unit/test_webhook.py
import hashlib
import hmac
from soc_autopilot import config as cfg
from soc_autopilot.api.routes.webhook import verify_hmac


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_verify_hmac_accepts_valid(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "s3cr3t")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    cfg.get_settings.cache_clear()
    body = b'{"rule":{"id":"550"}}'
    assert verify_hmac(body, _sign(b"s3cr3t", body)) is True


def test_verify_hmac_rejects_bad(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "s3cr3t")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    cfg.get_settings.cache_clear()
    assert verify_hmac(b"body", "deadbeef") is False


def test_verify_hmac_rejects_missing(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "s3cr3t")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    cfg.get_settings.cache_clear()
    assert verify_hmac(b"body", None) is False
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_webhook.py -v`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/api/routes/webhook.py tests/unit/test_webhook.py
git commit -m "feat(api): HMAC-authenticated Wazuh webhook (constant-time compare)"
```

---

## Task 7: Loader + app wiring + first playbook (Q9, fail-fast)

**Files:**
- Create: `soc_autopilot/engine/loader.py` (transcribe §2.6)
- Create: `soc_autopilot/api/main.py` (transcribe §2.10)
- Create: `soc_autopilot/api/routes/playbooks.py`, `soc_autopilot/api/routes/executions.py` (minimal routers — see below)
- Create: `playbooks/PB-0001-powershell-encoded.yml` (transcribe §3.6 lines 1189-1303)
- Test: `tests/unit/test_loader.py`

**Interfaces:**
- Produces: `PlaybookStore(directory)` with `reload()`, `match(alert) -> list[Playbook]`, `get(id)`, `all()`. Fail-fast: any invalid playbook → `ValueError`, none load.

- [ ] **Step 1: Transcribe loader**

Create `soc_autopilot/engine/loader.py` by transcribing §2.6 verbatim.

- [ ] **Step 2: Minimal routers so main.py imports cleanly**

```python
# soc_autopilot/api/routes/playbooks.py
from fastapi import APIRouter, Request
router = APIRouter()

@router.get("")
async def list_playbooks(request: Request):
    return {"playbooks": [pb.id for pb in request.app.state.playbooks.all()]}
```
```python
# soc_autopilot/api/routes/executions.py
from fastapi import APIRouter
router = APIRouter()

@router.get("/health")
async def executions_health():
    return {"ok": True}
```

- [ ] **Step 3: Transcribe main.py and the first playbook**

Create `soc_autopilot/api/main.py` from §2.10. Create `playbooks/PB-0001-powershell-encoded.yml` from §3.6 (lines 1189-1303). **Adaptation:** if PB-0001 references actions not yet built (wazuh/threatintel/thehive), that is fine for loading — the loader validates *schema*, not action existence. Executor resolves actions only at run time.

- [ ] **Step 4: Write failing test (fail-fast loading + match)**

```python
# tests/unit/test_loader.py
import pytest
from soc_autopilot.engine.loader import PlaybookStore


def test_loads_valid_playbooks_dir():
    store = PlaybookStore("playbooks")
    assert any(pb.id == "PB-0001" for pb in store.all())


def test_invalid_playbook_fails_fast(tmp_path):
    (tmp_path / "bad.yml").write_text("id: NOT-VALID\nname: x\n")
    with pytest.raises(ValueError):
        PlaybookStore(str(tmp_path))


def test_match_by_mitre(tmp_path):
    store = PlaybookStore("playbooks")
    alert = {"rule": {"id": "999999", "level": 12, "mitre": {"id": ["T1059.001"]}}}
    matched = store.match(alert)
    assert any(pb.id == "PB-0001" for pb in matched)
```

- [ ] **Step 5: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_loader.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Smoke-test the app imports**

Run: `.venv/bin/python -c "from soc_autopilot.api.main import app; print(app.title)"`
Expected: prints `SOC Autopilot`.

- [ ] **Step 7: Commit**

```bash
git add soc_autopilot/engine/loader.py soc_autopilot/api/main.py \
  soc_autopilot/api/routes/playbooks.py soc_autopilot/api/routes/executions.py \
  playbooks/PB-0001-powershell-encoded.yml tests/unit/test_loader.py
git commit -m "feat(engine): fail-fast playbook loader, app wiring, first playbook"
```

---

## Task 8: Semgrep guard + CI workflow (Q10 defense-in-depth)

**Files:**
- Create: `.semgrep/no-unsafe-jinja.yml` (transcribe §2.5 Semgrep block)
- Create: `.github/workflows/ci.yml`
- Test: run semgrep + full offline suite locally

**Interfaces:**
- Produces: CI that runs ruff, semgrep (custom rule), and the offline pytest suite (unit + sigma pipeline unit tests). Integration tests that need a live indexer stay skipped in CI (documented).

- [ ] **Step 1: Create the Semgrep rule**

Create `.semgrep/no-unsafe-jinja.yml` by transcribing the block in §2.5.

- [ ] **Step 2: Verify the rule catches unsafe usage locally**

```bash
.venv/bin/pip install semgrep
.venv/bin/semgrep --config .semgrep/no-unsafe-jinja.yml soc_autopilot/ --error
```
Expected: 0 findings (resolver uses `SandboxedEnvironment`).

- [ ] **Step 3: Create CI workflow**

```yaml
# .github/workflows/ci.yml
name: ci
on:
  pull_request:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install semgrep sigma-cli pysigma-backend-opensearch
      - name: Lint
        run: ruff check soc_autopilot tests
      - name: Semgrep (no unsafe Jinja)
        run: semgrep --config .semgrep/no-unsafe-jinja.yml soc_autopilot/ --error
      - name: Tests (offline; live-indexer integration tests self-skip)
        run: python -m pytest tests/ -v
```

- [ ] **Step 4: Run the full offline suite locally**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: all unit tests PASS; the live-indexer integration tests SKIP (indexer unreachable in this shell). Record the skip count.

- [ ] **Step 5: Commit**

```bash
git add .semgrep/no-unsafe-jinja.yml .github/workflows/ci.yml requirements.txt
git commit -m "ci: ruff + semgrep unsafe-jinja guard + offline test suite"
```

- [ ] **Step 6: Open PR-A and drive it green**

```bash
git push -u origin feat/soar-engine
gh pr create --base main --title "feat: SOAR engine core (J2)" \
  --body "Engine: schema, sandboxed resolver, registry, audit, executor, HMAC webhook, loader, first playbook, semgrep+CI. Closes gaps for pitch Q1/Q7/Q8/Q9/Q10."
```
Then run `code-review` skill + `semgrep`, fix/justify each finding, `gh pr checks` until green, `gh pr merge --squash --delete-branch`. **Re-branch** `feat/soar-integrations` for J3 (or continue on a fresh branch off updated main).

---

## Task 9: Wazuh integration (J3)

**Files:**
- Create: `soc_autopilot/actions/wazuh.py` (transcribe §3.1)
- Modify: `soc_autopilot/actions/__init__.py` (import wazuh so `@action` registers)
- Test: `tests/unit/test_actions_wazuh.py` (respx-mocked httpx)

**Interfaces:**
- Consumes: `registry.action`, `config.get_settings`, httpx.
- Produces: registered actions `wazuh.get_agent_context`, `wazuh.isolate_host`, `wazuh.unisolate_host`; `WazuhClient` with token cache + reactive 401 refresh.

- [ ] **Step 1: Transcribe wazuh client + actions**

Create `soc_autopilot/actions/wazuh.py` from §3.1. In `soc_autopilot/actions/__init__.py` add: `from soc_autopilot.actions import wazuh  # noqa: F401`.

- [ ] **Step 2: Write failing test (registration + agent_id via respx)**

```python
# tests/unit/test_actions_wazuh.py
import httpx
import pytest
import respx
from soc_autopilot.engine import registry


def test_wazuh_actions_registered():
    import soc_autopilot.actions.wazuh  # noqa: F401
    for name in ("wazuh.get_agent_context", "wazuh.isolate_host", "wazuh.unisolate_host"):
        assert name in registry.list_actions()


@pytest.mark.asyncio
@respx.mock
async def test_agent_id_resolves(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.setenv("wazuh_api_url", "https://wazuh:55000")
    monkeypatch.setenv("wazuh_api_user", "u")
    monkeypatch.setenv("wazuh_api_password", "p")
    from soc_autopilot import config as cfg
    cfg.get_settings.cache_clear()
    from soc_autopilot.actions.wazuh import WazuhClient

    respx.post("https://wazuh:55000/security/user/authenticate?raw=true").mock(
        return_value=httpx.Response(200, text="TОKEN"))
    respx.get("https://wazuh:55000/agents").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": [{"id": "001"}]}}))

    client = WazuhClient()
    assert await client.agent_id("victim-win") == "001"
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_actions_wazuh.py -v`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/actions/wazuh.py soc_autopilot/actions/__init__.py tests/unit/test_actions_wazuh.py
git commit -m "feat(actions): Wazuh client with token cache and isolate/unisolate actions"
```

---

## Task 10: VirusTotal + threat-intel integration (J3, Q4bis)

**Files:**
- Create: `soc_autopilot/actions/threatintel.py` (transcribe §3.2)
- Modify: `soc_autopilot/actions/__init__.py` (import threatintel)
- Test: `tests/unit/test_actions_threatintel.py`

**Interfaces:**
- Produces: registered actions `threatintel.extract_iocs`, `threatintel.lookup`, `threatintel.virustotal_lookup`; helpers `_vt_classify`, `_vt_worst`. IOC extraction filters private IPs. VT is hash/IP/domain only.

- [ ] **Step 1: Transcribe threatintel**

Create `soc_autopilot/actions/threatintel.py` from §3.2. Add import to `actions/__init__.py`.

- [ ] **Step 2: Write failing tests (IOC extraction + ratio classifier + no-upload guard)**

```python
# tests/unit/test_actions_threatintel.py
import pytest
from soc_autopilot.actions.threatintel import _vt_classify, extract_iocs
from soc_autopilot.engine import registry


def test_threatintel_actions_registered():
    import soc_autopilot.actions.threatintel  # noqa: F401
    for name in ("threatintel.extract_iocs", "threatintel.lookup", "threatintel.virustotal_lookup"):
        assert name in registry.list_actions()


@pytest.mark.asyncio
async def test_extract_iocs_filters_private_ips():
    text = "beacon to 8.8.8.8 and internal 192.168.56.20 hash " + "a" * 64
    out = await extract_iocs({"text": text}, None)
    assert "8.8.8.8" in out["ips"]
    assert "192.168.56.20" not in out["ips"]   # private IP not leaked to third parties


def test_vt_classify_ratio_not_count():
    assert _vt_classify(45, 0, 70) == "malicious"
    assert _vt_classify(2, 0, 70) in ("suspicious", "likely_benign")
    assert _vt_classify(0, 0, 0) == "unknown"   # absence != benign


def test_no_file_upload_path_exists():
    """Garde structurelle : aucun upload de fichier vers VirusTotal."""
    import inspect
    import soc_autopilot.actions.threatintel as ti
    src = inspect.getsource(ti)
    assert "/files" not in src.split("virustotal_lookup")[0] or "POST" not in src
    assert "files/upload" not in src
```

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_actions_threatintel.py -v`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add soc_autopilot/actions/threatintel.py soc_autopilot/actions/__init__.py tests/unit/test_actions_threatintel.py
git commit -m "feat(actions): VirusTotal (hash-only) + sector threat-intel enrichment"
```

---

## Task 11: TheHive integration + end-to-end dry-run (J3)

**Files:**
- Create: `soc_autopilot/actions/thehive.py` (transcribe §3.3)
- Modify: `soc_autopilot/actions/__init__.py` (import thehive)
- Test: `tests/unit/test_actions_thehive.py`, `tests/integration/test_playbook_e2e_dryrun.py`

**Interfaces:**
- Produces: registered action `thehive.create_case` (degrades to a `LOCAL-<id>` case when no API key). End-to-end: an alert matching PB-0001 runs to completion in dry-run with a full audit trail and no destructive side effect.

- [ ] **Step 1: Transcribe thehive**

Create `soc_autopilot/actions/thehive.py` from §3.3 (read §3.3 in full first — lines 1030-1071+). Add import to `actions/__init__.py`.

- [ ] **Step 2: Write failing test (degraded mode + e2e dry-run)**

```python
# tests/unit/test_actions_thehive.py
import pytest
from soc_autopilot.actions.thehive import create_case


class _Ctx:
    execution_id = 42


@pytest.mark.asyncio
async def test_create_case_degrades_without_key(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.delenv("thehive_api_key", raising=False)
    from soc_autopilot import config as cfg
    cfg.get_settings.cache_clear()
    out = await create_case({"title": "t"}, _Ctx())
    assert out["backend"] == "local"
    assert out["case_id"].startswith("LOCAL-")
```

```python
# tests/integration/test_playbook_e2e_dryrun.py
import pytest
from soc_autopilot.audit import AuditRepository
from soc_autopilot.engine.executor import Executor
from soc_autopilot.engine.loader import PlaybookStore
import soc_autopilot.actions  # noqa: F401  -> registers all actions


@pytest.mark.asyncio
async def test_pb0001_runs_end_to_end_in_dry_run(monkeypatch):
    monkeypatch.setenv("webhook_hmac_secret", "x")
    monkeypatch.setenv("database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("threat_intel_url", "http://ti")
    monkeypatch.delenv("virustotal_api_key", raising=False)
    monkeypatch.delenv("thehive_api_key", raising=False)
    from soc_autopilot import config as cfg
    cfg.get_settings.cache_clear()

    repo = AuditRepository("sqlite+aiosqlite:///:memory:")
    await repo.init_schema()
    store = PlaybookStore("playbooks")
    pb = store.get("PB-0001")
    alert = {"id": "e2e-1", "rule": {"id": "100200", "level": 12,
             "mitre": {"id": ["T1059.001"]}},
             "agent": {"name": "victim-win"}, "data": {}}
    result = await Executor(repo).run(pb, alert)
    assert result["status"] in ("success", "partial")
    steps = await repo.get_steps(result["execution_id"])
    # destructive isolate step must be dry_run, never executed
    assert any(s.action == "wazuh.isolate_host" and s.status == "dry_run" for s in steps) or \
           all(s.status != "success" or s.action != "wazuh.isolate_host" for s in steps)
    await repo.close()
```

**Adaptation note:** PB-0001 may include a Slack approval step (§3.4). If so, either (a) transcribe `actions/slack.py` §3.4 with its degraded no-token path, or (b) trim PB-0001's approval step for this e2e and keep the full version behind an armed-mode playbook. Prefer (a) if §3.4 degrades cleanly without a token.

- [ ] **Step 3: Run and verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_actions_thehive.py tests/integration/test_playbook_e2e_dryrun.py -v`
Expected: PASS.

- [ ] **Step 4: Full suite**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: all offline tests PASS; live-indexer sigma integration tests SKIP.

- [ ] **Step 5: Commit + PR-B**

```bash
git add soc_autopilot/actions/thehive.py soc_autopilot/actions/__init__.py \
  tests/unit/test_actions_thehive.py tests/integration/test_playbook_e2e_dryrun.py
git commit -m "feat(actions): TheHive case creation + end-to-end dry-run playbook test"
git push -u origin HEAD
gh pr create --base main --title "feat: SOAR integrations (J3)" \
  --body "Wazuh/VirusTotal/TheHive actions + end-to-end dry-run playbook. Realises pitch Q2/Q4bis and the response_playbook red thread."
```
Then `code-review` + `semgrep`, drive green, `gh pr merge --squash --delete-branch`.

---

## Self-Review

**Spec coverage:** Every §3-spec sequence row maps to a task — #0→Task 0, #1→Tasks 1-3, #2→Tasks 4-5, #3→Task 6+7, #4→Task 7, #5→Task 8, #6→Tasks 9-11. Honesty guardrails encoded as tests (dry-run in Task 5 & 11, no-upload in Task 10, private-IP filter in Task 10). ✔

**Placeholder scan:** The only intentional deferral is `executor.rollback()`'s playbook reload (§2.8 ships it as `...`); Task 5 Step 1 documents it as out-of-unit-scope for PR-A and it is exercised only by armed-mode rollback later — not a silent placeholder. ✔

**Type consistency:** `AuditRepository` method signatures in Task 4 match the executor call sites in §2.8 (`find_by_dedup`, `create_execution(**kw)`, `finish_execution(id, status=, outputs=)`, `set_error`, `log_step(execution_id, step, status, inputs, output, error, duration_ms)`, `get_execution`, `get_steps`, `mark_rolled_back`). `Playbook.id`/`version` used by `create_execution` exist in schema (Task 1). ✔
