"""Accès DB async à l'audit trail. Signatures alignées sur les appels de l'executor."""

from __future__ import annotations

from datetime import UTC, datetime
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

    async def create_execution(
        self,
        *,
        dedup_key: str,
        playbook,
        alert_id: str,
        alert_raw: dict,
        dry_run: bool,
    ) -> Execution:
        async with self._session() as s:
            ex = Execution(
                dedup_key=dedup_key,
                playbook_id=playbook.id,
                playbook_version=playbook.version,
                alert_id=alert_id,
                alert_raw=alert_raw,
                status="running",
                dry_run=dry_run,
            )
            s.add(ex)
            await s.commit()
            await s.refresh(ex)
            return ex

    async def finish_execution(
        self, execution_id: int, *, status: str, outputs: dict[str, Any]
    ) -> None:
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

    async def log_step(
        self,
        execution_id: int,
        step,
        status: str,
        inputs: dict,
        output: dict,
        error: str | None,
        duration_ms: int,
    ) -> StepLog:
        async with self._session() as s:
            sl = StepLog(
                execution_id=execution_id,
                step_id=step.id,
                action=step.action,
                status=status,
                destructive=step.destructive,
                inputs=inputs,
                output=output,
                error=error,
                duration_ms=duration_ms,
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
                select(StepLog)
                .where(StepLog.execution_id == execution_id)
                .order_by(StepLog.id)
            )
            return list(res.scalars().all())

    async def mark_rolled_back(self, step_log_id: int) -> None:
        async with self._session() as s:
            sl = await s.get(StepLog, step_log_id)
            sl.rolled_back = True
            await s.commit()
