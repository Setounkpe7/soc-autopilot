import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class OnError(str, Enum):
    FAIL = "fail"  # arrête le playbook
    CONTINUE = (
        "continue"  # log et poursuit — pour les étapes best-effort (enrichissement)
    )
    RETRY = "retry"  # réessaie avec backoff


class Trigger(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    severity_min: int = 0

    @field_validator("mitre")
    @classmethod
    def valid_mitre(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                raise ValueError(f"Technique ATT&CK invalide: {t}")
        return v


class Step(BaseModel):
    id: str
    action: str  # ex. "wazuh.isolate_host"
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    when: str | None = None  # expression Jinja2 → bool
    on_error: OnError = OnError.FAIL
    retries: int = 0
    timeout_seconds: float = 30.0
    rollback: str | None = None  # action inverse
    destructive: bool = False  # exige DRY_RUN=false pour s'exécuter

    model_config = {"populate_by_name": True}


class Playbook(BaseModel):
    id: str = Field(pattern=r"^PB-\d{4}$")
    name: str
    version: str
    description: str = ""
    trigger: Trigger
    inputs: dict[str, str] = Field(default_factory=dict)
    steps: list[Step]
    outputs: dict[str, str] = Field(default_factory=dict)

    @field_validator("steps")
    @classmethod
    def unique_ids(cls, v: list[Step]) -> list[Step]:
        ids = [s.id for s in v]
        if len(ids) != len(set(ids)):
            raise ValueError("Les step.id doivent être uniques")
        return v
