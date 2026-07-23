import asyncio
import hashlib
import json
import time
from typing import Any

import structlog
from prometheus_client import Counter, Histogram
from sqlalchemy.exc import IntegrityError

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import get_action
from soc_autopilot.engine.resolver import evaluate, render_dict
from soc_autopilot.engine.schema import OnError, Playbook, Step

log = structlog.get_logger()

EXEC_TOTAL = Counter(
    "playbook_executions_total", "Exécutions de playbook", ["playbook", "status"]
)
EXEC_DURATION = Histogram(
    "playbook_duration_seconds", "Durée d'exécution", ["playbook"]
)
ACTION_TOTAL = Counter("actions_total", "Actions exécutées", ["action", "result"])


def dedup_key(alert_id: str, playbook_id: str) -> str:
    return hashlib.sha256(f"{alert_id}:{playbook_id}".encode()).hexdigest()


class ExecutionContext:
    """État partagé pendant une exécution. Passé à chaque action."""

    def __init__(
        self, alert: dict, playbook: Playbook, execution_id: int, dry_run: bool
    ):
        self.alert = alert
        self.playbook = playbook
        self.execution_id = execution_id
        self.dry_run = dry_run
        self.settings = get_settings()
        self.steps: dict[str, dict[str, Any]] = {}
        self.inputs: dict[str, Any] = {}
        self.actions_taken: list[str] = []

    def as_template_context(self) -> dict[str, Any]:
        return {
            "alert": self.alert,
            "inputs": self.inputs,
            "steps": self.steps,
            "playbook": {"id": self.playbook.id, "version": self.playbook.version},
            "trigger": self.playbook.trigger.model_dump(),
            "vars": {
                "privileged_users": self.settings.privileged_users,
                "protected_assets": self.settings.protected_assets,
            },
            "execution": {"id": self.execution_id, "actions": self.actions_taken},
        }


class Executor:
    def __init__(self, audit) -> None:
        self._audit = audit  # objet d'accès DB, injecté (testabilité)
        self._settings = get_settings()

    async def run(self, playbook: Playbook, alert: dict) -> dict[str, Any]:
        # Fallback déterministe : si l'alerte n'a ni id/_id/timestamp, on dérive
        # la clé du CONTENU. Sans ça, toutes ces alertes partageraient la clé
        # "None" et seule la première serait exécutée (idempotence effondrée).
        alert_id = str(
            alert.get("id")
            or alert.get("_id")
            or alert.get("timestamp")
            or hashlib.sha256(
                json.dumps(alert, sort_keys=True, default=str).encode()
            ).hexdigest()
        )
        key = dedup_key(alert_id, playbook.id)

        # ── IDEMPOTENCE ────────────────────────────────────────────────
        existing = await self._audit.find_by_dedup(key)
        if existing:
            log.info("execution_deduplicated", dedup_key=key, execution_id=existing.id)
            EXEC_TOTAL.labels(playbook.id, "deduplicated").inc()
            return {"execution_id": existing.id, "status": "deduplicated"}

        try:
            execution = await self._audit.create_execution(
                dedup_key=key,
                playbook=playbook,
                alert_id=alert_id,
                alert_raw=alert,
                dry_run=self._settings.dry_run,
            )
        except IntegrityError:
            # Course concurrente entre find_by_dedup et create : la contrainte
            # d'unicité sur dedup_key rejette le doublon. L'idempotence tient
            # donc même à plusieurs replicas (garantie en base, pas en mémoire).
            existing = await self._audit.find_by_dedup(key)
            log.info("execution_deduplicated_race", dedup_key=key)
            EXEC_TOTAL.labels(playbook.id, "deduplicated").inc()
            return {
                "execution_id": existing.id if existing else None,
                "status": "deduplicated",
            }

        ctx = ExecutionContext(alert, playbook, execution.id, self._settings.dry_run)

        # Résolution des inputs déclarés
        ctx.inputs = render_dict(playbook.inputs, ctx.as_template_context())

        status = "success"
        error_msg: str | None = None
        started = time.perf_counter()
        outputs: dict[str, Any] = {}
        try:
            for step in playbook.steps:
                result = await self._run_step(step, ctx)
                if result == "failed":
                    status = "failed"
                    break
                if result == "partial":
                    status = "partial"
        except Exception as exc:
            log.exception("execution_crashed", execution_id=execution.id)
            status = "failed"
            error_msg = str(exc)
        finally:
            duration = time.perf_counter() - started
            EXEC_DURATION.labels(playbook.id).observe(duration)
            EXEC_TOTAL.labels(playbook.id, status).inc()
            # Le rendu des outputs ne doit jamais masquer le statut réel ni
            # laisser l'exécution bloquée en 'running' : on isole son échec.
            try:
                outputs = render_dict(playbook.outputs, ctx.as_template_context())
            except Exception as exc:
                log.warning(
                    "outputs_render_failed", execution_id=execution.id, error=str(exc)
                )
                outputs = {}
            if error_msg:
                outputs = {**outputs, "error": error_msg}
            await self._audit.finish_execution(
                execution.id, status=status, outputs=outputs
            )

        return {
            "execution_id": execution.id,
            "status": status,
            "duration_seconds": round(duration, 2),
            "outputs": outputs,
        }

    async def _run_step(self, step: Step, ctx: ExecutionContext) -> str:
        tctx = ctx.as_template_context()

        # ── when: ──────────────────────────────────────────────────────
        if not evaluate(step.when, tctx):
            await self._audit.log_step(
                ctx.execution_id, step, "skipped", {}, {}, None, 0
            )
            ctx.steps[step.id] = {"output": None, "skipped": True}
            return "ok"

        params = render_dict(step.with_, tctx)

        # ── GARDE-FOU : actifs protégés ────────────────────────────────
        # Compare le NOM d'actif : `protected_assets` liste des noms (DC-01…)
        # et les playbooks passent `agent: "{{ alert.agent.name }}"`. Une action
        # qui ciblerait par id numérique devrait normaliser vers le nom en amont.
        if step.destructive:
            target = str(params.get("agent") or params.get("host") or "")
            # Fail-fast cible vide : l'enrichissement best-effort est tolérant
            # (le resolver rend "" plutôt que de lever), mais une action
            # DESTRUCTIVE ne doit JAMAIS s'exécuter sur une cible vide — typo de
            # template ou enrichissement manquant rendu "". On restaure ici,
            # précisément là où ça compte, la garantie « échouer bruyamment plutôt
            # qu'agir silencieusement sur la mauvaise cible » (cf. resolver.py).
            # On ne l'exige QUE si l'étape DÉCLARE une cible (agent/host) : une
            # action destructive sans cible d'hôte (rare) n'est pas concernée.
            declares_target = bool(step.with_) and (
                "agent" in step.with_ or "host" in step.with_
            )
            if declares_target and not target.strip():
                log.error("destructive_empty_target", step=step.id, params=params)
                await self._audit.log_step(
                    ctx.execution_id,
                    step,
                    "failed",
                    params,
                    {"reason": "empty_target"},
                    "cible destructive vide après rendu",
                    0,
                )
                ctx.steps[step.id] = {"output": None, "error": "empty_target"}
                return "failed"
            if target in ctx.settings.protected_assets:
                log.warning(
                    "destructive_blocked_protected_asset", target=target, step=step.id
                )
                await self._audit.log_step(
                    ctx.execution_id,
                    step,
                    "skipped",
                    params,
                    {"reason": "protected_asset"},
                    None,
                    0,
                )
                ctx.steps[step.id] = {"output": {"blocked": "protected_asset"}}
                return "partial"

        # ── DRY RUN ────────────────────────────────────────────────────
        if step.destructive and ctx.dry_run:
            log.info("dry_run_skip", step=step.id, action=step.action, params=params)
            await self._audit.log_step(
                ctx.execution_id, step, "dry_run", params, {"simulated": True}, None, 0
            )
            ctx.steps[step.id] = {"output": {"dry_run": True}}
            ctx.actions_taken.append(f"[DRY-RUN] {step.action}")
            return "ok"

        # ── EXÉCUTION avec retry + timeout ─────────────────────────────
        fn = get_action(step.action)
        attempts = step.retries + 1
        last_error: Exception | None = None
        ms = 0

        for attempt in range(1, attempts + 1):
            t0 = time.perf_counter()
            try:
                output = await asyncio.wait_for(
                    fn(params, ctx), timeout=step.timeout_seconds
                )
                ms = int((time.perf_counter() - t0) * 1000)
                ctx.steps[step.id] = {"output": output}
                ctx.actions_taken.append(step.action)
                ACTION_TOTAL.labels(step.action, "success").inc()
                await self._audit.log_step(
                    ctx.execution_id,
                    step,
                    "success",
                    params,
                    {"value": output},
                    None,
                    ms,
                )
                return "ok"
            except Exception as exc:
                last_error = exc
                ms = int((time.perf_counter() - t0) * 1000)
                log.warning(
                    "step_attempt_failed",
                    step=step.id,
                    attempt=attempt,
                    total=attempts,
                    error=str(exc),
                )
                if attempt < attempts and step.on_error == OnError.RETRY:
                    await asyncio.sleep(2**attempt)  # backoff exponentiel
                    continue
                break

        ACTION_TOTAL.labels(step.action, "failed").inc()
        await self._audit.log_step(
            ctx.execution_id, step, "failed", params, {}, str(last_error), ms
        )
        ctx.steps[step.id] = {"output": None, "error": str(last_error)}

        if step.on_error == OnError.CONTINUE:
            return "partial"
        return "failed"

    # ── ROLLBACK ───────────────────────────────────────────────────────
    async def rollback(self, execution_id: int, playbook: Playbook) -> dict:
        """Annule les actions destructives réussies, dans l'ordre inverse."""
        execution = await self._audit.get_execution(execution_id)
        ctx = ExecutionContext(
            execution.alert_raw, playbook, execution_id, execution.dry_run
        )
        steps = await self._audit.get_steps(execution_id)
        by_id = {s.id: s for s in playbook.steps}
        undone: list[str] = []
        for slog in reversed(steps):
            if slog.status != "success" or not slog.destructive or slog.rolled_back:
                continue
            step = by_id.get(slog.step_id)
            if step is None or not step.rollback:
                continue
            fn = get_action(step.rollback)
            await fn(slog.inputs, ctx)
            await self._audit.mark_rolled_back(slog.id)
            undone.append(step.rollback)
        return {"execution_id": execution_id, "rolled_back": undone}
