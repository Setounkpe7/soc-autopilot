from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Execution(Base):
    __tablename__ = "executions"
    __table_args__ = (UniqueConstraint("dedup_key", name="uq_executions_dedup"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedup_key: Mapped[str] = mapped_column(
        String(64), index=True
    )  # sha256(alert_id + pb_id)
    playbook_id: Mapped[str] = mapped_column(String(16), index=True)
    playbook_version: Mapped[str] = mapped_column(String(16))
    alert_id: Mapped[str] = mapped_column(String(128), index=True)
    alert_raw: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))  # running|success|failed|partial
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    outputs: Mapped[dict] = mapped_column(JSON, default=dict)


class StepLog(Base):
    __tablename__ = "step_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[int] = mapped_column(Integer, index=True)
    step_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # success|failed|skipped|dry_run
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    inputs: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)
