from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from prometheus_client import make_asgi_app

import soc_autopilot.actions  # noqa: F401  → déclenche l'enregistrement des @action
from soc_autopilot.api.routes import approvals, executions, playbooks, webhook
from soc_autopilot.audit import AuditRepository
from soc_autopilot.config import get_settings
from soc_autopilot.engine.executor import Executor
from soc_autopilot.engine.loader import PlaybookStore

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    app.state.playbooks = PlaybookStore(s.playbooks_dir)  # fail-fast si invalide
    app.state.audit = AuditRepository(s.database_url)
    await app.state.audit.init_schema()
    app.state.executor = Executor(app.state.audit)
    yield
    await app.state.audit.close()


app = FastAPI(
    title="SOC Autopilot",
    description="Moteur d'orchestration et d'automatisation SOC (SOAR)",
    version="0.3.0",
    lifespan=lifespan,
)
app.include_router(webhook.router, tags=["webhook"])
app.include_router(approvals.router, tags=["approvals"])
app.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
app.include_router(executions.router, prefix="/executions", tags=["executions"])
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "playbooks": app.state.playbooks.count()}
