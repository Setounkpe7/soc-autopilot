# SOC Autopilot — Fichier 3/5
# Construction : J1 → J7, ligne par ligne

> **Calendrier**
> | Jour | Date | Objectif | Fichier |
> |---|---|---|---|
> | J1 | Jeu 16 juil | Labo + outils | ← fichier 02 ✅ |
> | **J2** | **Ven 17** | **Le moteur SOAR** | ce fichier |
> | **J3** | **Sam 18** | **Intégrations + playbooks** | ce fichier |
> | **J4** | **Dim 19** | **Detection-as-Code (Sigma)** | ce fichier |
> | **J5** | **Lun 20** | **Tests d'attaque & validation** | → fichier 04 |
> | **J6** | **Mar 21** | **K8s + Terraform + CI/CD** | ce fichier |
> | **J7** | **Mer 22** | **Doc + démo + répétition** | ce fichier + fichier 05 |
> | 🎯 | **Jeu 23** | **ENTREVUE CAE** | fichier 05 |

**Discipline de la semaine :** commit à chaque étape qui marche, message conventionnel (`feat:`, `fix:`, `docs:`, `test:`). Les commits datés du 17 au 22 juillet sont une **preuve d'authenticité**. Un repo avec 3 gros commits le même jour crie « copié ».

---

# J2 — Vendredi 17 juillet : le moteur SOAR

**Durée : 8-9 h.** C'est la journée la plus dense. C'est aussi celle qui gagne l'entrevue.

## 2.1 Les dépendances

```bash
cd "$SOC_DIR" && source .venv/bin/activate   # SOC_DIR="/media/mdoub/Data/Personal Projects/soc-autopilot", défini dans ~/.bashrc (fichier 02, §10)
uv pip install fastapi uvicorn[standard] pydantic pydantic-settings \
  sqlalchemy[asyncio] asyncpg alembic httpx jinja2 pyyaml structlog \
  prometheus-client python-multipart
uv pip install --dev pytest pytest-asyncio pytest-cov respx ruff mypy bandit
uv pip freeze > requirements.txt
```

**Pourquoi ces choix (chaque ligne est une réponse possible) :**
| Lib | Pourquoi celle-là |
|---|---|
| **FastAPI** | Async natif (indispensable : un playbook fait 5 appels réseau), OpenAPI auto (= documentation d'intégration gratuite, et l'offre demande « API sécurisées »), validation Pydantic intégrée |
| **Pydantic v2** | Valide les playbooks YAML **au chargement**. Un playbook invalide ne démarre jamais → pas d'échec à 3 h du matin. Cœur en Rust = rapide |
| **SQLAlchemy async + asyncpg** | L'audit trail ne doit pas bloquer l'event loop |
| **Jinja2** | Le moteur de templates pour `{{ alert.agent.name }}`. **En mode sandbox obligatoire** |
| **httpx** | Client HTTP async avec timeouts et retry — `requests` est synchrone, il gèlerait le serveur |
| **structlog** | Logs JSON. Un SOAR sans logs structurés est un SOAR qu'on ne peut pas auditer. Tu l'as déjà fait sur threat-intel-api |
| **prometheus-client** | `/metrics` → MTTR, taux d'automatisation |

## 2.2 La configuration — `soc_autopilot/config.py`

```python
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Wazuh
    wazuh_api_url: str
    wazuh_api_user: str
    wazuh_api_password: str
    wazuh_verify_tls: bool = False

    # Sécurité du webhook
    webhook_hmac_secret: str

    # TheHive
    thehive_url: str | None = None
    thehive_api_key: str | None = None

    # Threat intel (mon service — priorisation sectorielle)
    threat_intel_url: str
    threat_intel_timeout: float = 5.0

    # VirusTotal (réputation d'IOC)
    virustotal_api_key: str | None = None
    virustotal_timeout: float = 10.0

    # Slack
    slack_bot_token: str | None = None
    slack_alert_channel: str = "#soc-alerts"
    slack_action_channel: str = "#soc-actions"

    # DB
    database_url: str

    # Comportement
    dry_run: bool = True
    approval_timeout_seconds: int = 900
    playbooks_dir: str = "playbooks"

    # Actifs à ne JAMAIS isoler automatiquement
    protected_assets: list[str] = Field(default_factory=lambda: ["DC-01", "SQL-PROD-01"])
    privileged_users: list[str] = Field(default_factory=lambda: ["Administrator", "svc_backup"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

> **`dry_run: bool = True` — le défaut le plus important du projet.**
> Par défaut, **aucune action destructive n'est réellement exécutée** : elle est journalisée, l'audit trail dit « aurait isolé WS-042 », mais rien ne se passe. Il faut un choix **explicite** pour armer l'outil.
> **En entrevue :** *« Un outil qui peut couper le réseau d'un poste doit être désarmé par défaut. Le défaut sûr, c'est ne rien faire. J'ai appliqué le même principe qu'à un runbook Azure de production : dry-run d'abord, exécution ensuite. »*
> **`protected_assets` :** la liste des machines qu'on n'isole jamais automatiquement, quel que soit le score. Un contrôleur de domaine isolé, c'est toute l'entreprise à l'arrêt. **C'est le genre de détail qui distingue quelqu'un qui a pensé à la production.**

## 2.3 Le schéma des playbooks — `soc_autopilot/engine/schema.py`

**La logique :** on décrit en Pydantic **exactement** à quoi ressemble un playbook valide. Tout playbook qui ne correspond pas est rejeté **au démarrage**, avec un message d'erreur précis.

```python
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator


class OnError(str, Enum):
    FAIL = "fail"          # arrête le playbook
    CONTINUE = "continue"  # log et poursuit — pour les étapes best-effort (enrichissement)
    RETRY = "retry"        # réessaie avec backoff


class Trigger(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    severity_min: int = 0

    @field_validator("mitre")
    @classmethod
    def valid_mitre(cls, v: list[str]) -> list[str]:
        import re
        for t in v:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                raise ValueError(f"Technique ATT&CK invalide: {t}")
        return v


class Step(BaseModel):
    id: str
    action: str                                  # ex. "wazuh.isolate_host"
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    when: str | None = None                      # expression Jinja2 → bool
    on_error: OnError = OnError.FAIL
    retries: int = 0
    timeout_seconds: float = 30.0
    rollback: str | None = None                  # action inverse
    destructive: bool = False                    # exige DRY_RUN=false pour s'exécuter

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
```

> **Le validateur `valid_mitre` est un petit détail qui paie gros.**
> Il empêche d'écrire `T1059.1` au lieu de `T1059.001`. **Pourquoi ça compte :** ces tags alimentent la carte de couverture ATT&CK. Une faute de frappe = une technique qui apparaît faussement couverte = un **angle mort invisible**. En entrevue : *« Je valide le format ATT&CK au chargement parce qu'une typo dans un tag crée un faux positif de couverture — et un faux positif de couverture est pire qu'un trou connu. »*
>
> **`with_` avec `alias="with"` :** `with` est un mot-clé réservé Python. On utilise l'alias Pydantic pour garder un YAML lisible. Petit, mais si on te le demande, tu sais.

## 2.4 Le registre d'actions — `soc_autopilot/engine/registry.py`

**La logique :** un dictionnaire global `nom → fonction`. Une action s'enregistre avec un décorateur. Ajouter une intégration = ajouter un fichier, **sans jamais toucher au moteur**.

```python
from collections.abc import Awaitable, Callable
from typing import Any

ActionFn = Callable[[dict[str, Any], "ExecutionContext"], Awaitable[Any]]
_REGISTRY: dict[str, ActionFn] = {}


def action(name: str) -> Callable[[ActionFn], ActionFn]:
    """Enregistre une action sous un nom canonique 'namespace.verbe'."""
    def decorator(fn: ActionFn) -> ActionFn:
        if name in _REGISTRY:
            raise ValueError(f"Action déjà enregistrée: {name}")
        _REGISTRY[name] = fn
        return fn
    return decorator


def get_action(name: str) -> ActionFn:
    if name not in _REGISTRY:
        raise KeyError(f"Action inconnue: {name}. Disponibles: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def list_actions() -> list[str]:
    return sorted(_REGISTRY)
```

> **C'est le pattern « plugin ».** Le moteur ne connaît aucune intégration ; il connaît un **contrat**.
> **⚡ Réponse d'entrevue à mémoriser :** *« Si CAE utilise CrowdStrike au lieu de Wazuh, je n'ouvre pas le moteur. J'ajoute `actions/crowdstrike.py` avec `@action("crowdstrike.contain_host")` et je change une ligne dans le playbook. Le couplage est dans le nom de l'action, pas dans le code. C'est exactement pour ça que XSOAR a des "integrations" et pas des `if vendor == ...`. »*

## 2.5 Le resolver — `soc_autopilot/engine/resolver.py`

**La logique :** transformer `{{ alert.agent.name }}` en `WS-042`. **Et le faire sans créer une faille RCE.**

```python
from typing import Any
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import StrictUndefined

# ⚠️ SandboxedEnvironment, JAMAIS Environment
_env = SandboxedEnvironment(undefined=StrictUndefined)


def render(template: str, context: dict[str, Any]) -> Any:
    """Rend un template Jinja2 en environnement sandboxé."""
    if not isinstance(template, str) or "{{" not in template:
        return template
    result = _env.from_string(template).render(**context)
    # Coercion des littéraux simples pour que `when: "{{ x > 5 }}"` retourne un bool
    low = result.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    if result.strip().lstrip("-").isdigit():
        return int(result)
    return result


def render_dict(data: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            out[k] = render(v, context)
        elif isinstance(v, dict):
            out[k] = render_dict(v, context)
        elif isinstance(v, list):
            out[k] = [render(i, context) if isinstance(i, str) else i for i in v]
        else:
            out[k] = v
    return out


def evaluate(expression: str | None, context: dict[str, Any]) -> bool:
    """Évalue une condition `when:`. Absence de condition = True."""
    if expression is None:
        return True
    return bool(render(expression, context))
```

> **🔴 LE point de sécurité du projet. Sache le défendre par cœur.**
> Un `jinja2.Environment` standard permet d'accéder aux attributs internes Python (`__class__`, `__globals__`, `__builtins__`). Un playbook contenant `{{ ''.__class__.__mro__[1].__subclasses__() }}` = **exécution de code arbitraire sur mon SOAR**. Et mon SOAR a les clés du royaume : il peut isoler des machines.
> `SandboxedEnvironment` bloque l'accès aux attributs dunder et aux appels dangereux.
> **`StrictUndefined` :** une variable manquante lève une exception au lieu de rendre une chaîne vide. Sans ça, une typo `{{ alert.agnet.name }}` isolerait l'hôte `""`. **Échouer bruyamment vaut mieux qu'agir silencieusement sur la mauvaise cible.**
> **La phrase :** *« Mon moteur de playbooks est une surface d'exécution de code. Je l'ai threat-modelé comme telle : sandbox obligatoire, StrictUndefined, et une règle Semgrep custom en CI qui fait échouer le build si quelqu'un importe `Environment` au lieu de `SandboxedEnvironment`. »*

**La règle Semgrep custom** — `.semgrep/no-unsafe-jinja.yml` :
```yaml
rules:
  - id: no-unsafe-jinja-environment
    pattern-either:
      - pattern: jinja2.Environment(...)
      - pattern: from jinja2 import Environment
    message: >
      Utiliser jinja2.sandbox.SandboxedEnvironment. Un Environment non sandboxé
      permet une RCE via les playbooks YAML.
    severity: ERROR
    languages: [python]
```

## 2.6 Le loader — `soc_autopilot/engine/loader.py`

```python
from pathlib import Path
import yaml
import structlog
from soc_autopilot.engine.schema import Playbook

log = structlog.get_logger()


class PlaybookStore:
    """Charge, valide et indexe les playbooks. Hot-reload."""

    def __init__(self, directory: str) -> None:
        self._dir = Path(directory)
        self._by_id: dict[str, Playbook] = {}
        self._by_rule: dict[str, list[Playbook]] = {}
        self._by_mitre: dict[str, list[Playbook]] = {}
        self.reload()

    def reload(self) -> None:
        by_id, by_rule, by_mitre = {}, {}, {}
        errors = []
        for path in sorted(self._dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                pb = Playbook(**raw)
            except Exception as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            if pb.id in by_id:
                errors.append(f"{path.name}: id dupliqué {pb.id}")
                continue
            by_id[pb.id] = pb
            for rid in pb.trigger.rule_ids:
                by_rule.setdefault(rid, []).append(pb)
            for tech in pb.trigger.mitre:
                by_mitre.setdefault(tech, []).append(pb)

        if errors:
            # Fail-fast : on refuse de charger une config partiellement cassée
            raise ValueError("Playbooks invalides:\n  - " + "\n  - ".join(errors))

        self._by_id, self._by_rule, self._by_mitre = by_id, by_rule, by_mitre
        log.info("playbooks_loaded", count=len(by_id), ids=sorted(by_id))

    def match(self, alert: dict) -> list[Playbook]:
        """Retourne les playbooks déclenchés par cette alerte."""
        rule_id = str(alert.get("rule", {}).get("id", ""))
        level = int(alert.get("rule", {}).get("level", 0))
        mitre = alert.get("rule", {}).get("mitre", {}).get("id", []) or []

        candidates: dict[str, Playbook] = {}
        for pb in self._by_rule.get(rule_id, []):
            candidates[pb.id] = pb
        for tech in mitre:
            for pb in self._by_mitre.get(tech, []):
                candidates[pb.id] = pb

        return [pb for pb in candidates.values() if level >= pb.trigger.severity_min]

    def get(self, pb_id: str) -> Playbook:
        return self._by_id[pb_id]

    def all(self) -> list[Playbook]:
        return list(self._by_id.values())
```

> **Deux décisions à défendre :**
> 1. **Fail-fast au chargement.** Si UN playbook est invalide, aucun ne charge. *« Un chargement partiel donne l'illusion que le SOC est couvert. Je préfère un service qui refuse de démarrer avec une erreur claire qu'un service qui tourne avec un trou silencieux. C'est le même réflexe que sur un runbook Azure : mieux vaut un échec de déploiement qu'un déploiement à moitié appliqué. »*
> 2. **Double indexation (rule_id ET mitre).** Un playbook peut se déclencher sur des IDs de règles précis **ou** sur une technique ATT&CK. Le second est plus robuste : si j'ajoute une 3ᵉ règle qui détecte T1059.001, elle déclenche automatiquement le bon playbook **sans que je touche au playbook**. **C'est le fil rouge ATT&CK en action.**

## 2.7 L'audit trail — `soc_autopilot/models/audit.py`

```python
from datetime import datetime, UTC
from sqlalchemy import String, Integer, DateTime, JSON, Boolean, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Execution(Base):
    __tablename__ = "executions"
    __table_args__ = (UniqueConstraint("dedup_key", name="uq_executions_dedup"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)   # sha256(alert_id + pb_id)
    playbook_id: Mapped[str] = mapped_column(String(16), index=True)
    playbook_version: Mapped[str] = mapped_column(String(16))
    alert_id: Mapped[str] = mapped_column(String(128), index=True)
    alert_raw: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))   # running|success|failed|partial
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=lambda: datetime.now(UTC))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outputs: Mapped[dict] = mapped_column(JSON, default=dict)


class StepLog(Base):
    __tablename__ = "step_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[int] = mapped_column(Integer, index=True)
    step_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))   # success|failed|skipped|dry_run
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    inputs: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=lambda: datetime.now(UTC))
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)
```

> **L'audit trail n'est pas un log. C'est une preuve.**
> Trois arguments, à sortir dans cet ordre :
> 1. **Forensique :** trois semaines après, on demande « pourquoi WS-042 a été isolée le 14 à 3 h 12 ? ». La réponse doit exister, complète : quelle alerte, quel playbook, quelle version du playbook, quel score, qui a approuvé, quelle sortie de chaque étape.
> 2. **Conformité :** dans une boîte de défense, une action automatisée sur un système doit être traçable. C'est du NIST 800-53 (AU-2, AU-3).
> 3. **Debug :** quand un playbook casse en prod, `step_logs` te dit exactement quelle étape et pourquoi.
>
> **Le champ `playbook_version` est le détail d'expert.** Si tu ne stockes pas la version, tu ne peux pas expliquer un comportement passé après avoir modifié le playbook. **Dis-le, c'est rare qu'un candidat y pense.**
> **Immuabilité :** en prod je révoquerais les droits UPDATE/DELETE sur ces tables au rôle applicatif — insert-only. Je le mentionne dans le threat model.

## 2.8 L'executor — le cœur — `soc_autopilot/engine/executor.py`

```python
import asyncio
import hashlib
import time
from datetime import datetime, UTC
from typing import Any

import structlog
from prometheus_client import Counter, Histogram

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import get_action
from soc_autopilot.engine.resolver import render, render_dict, evaluate
from soc_autopilot.engine.schema import Playbook, Step, OnError

log = structlog.get_logger()

EXEC_TOTAL = Counter("playbook_executions_total", "Exécutions de playbook",
                     ["playbook", "status"])
EXEC_DURATION = Histogram("playbook_duration_seconds", "Durée d'exécution", ["playbook"])
ACTION_TOTAL = Counter("actions_total", "Actions exécutées", ["action", "result"])


def dedup_key(alert_id: str, playbook_id: str) -> str:
    return hashlib.sha256(f"{alert_id}:{playbook_id}".encode()).hexdigest()


class ExecutionContext:
    """État partagé pendant une exécution. Passé à chaque action."""

    def __init__(self, alert: dict, playbook: Playbook, execution_id: int, dry_run: bool):
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
        self._audit = audit          # objet d'accès DB, injecté (testabilité)
        self._settings = get_settings()

    async def run(self, playbook: Playbook, alert: dict) -> dict[str, Any]:
        alert_id = str(alert.get("id") or alert.get("_id") or alert.get("timestamp"))
        key = dedup_key(alert_id, playbook.id)

        # ── IDEMPOTENCE ────────────────────────────────────────────────
        existing = await self._audit.find_by_dedup(key)
        if existing:
            log.info("execution_deduplicated", dedup_key=key, execution_id=existing.id)
            EXEC_TOTAL.labels(playbook.id, "deduplicated").inc()
            return {"execution_id": existing.id, "status": "deduplicated"}

        execution = await self._audit.create_execution(
            dedup_key=key, playbook=playbook, alert_id=alert_id,
            alert_raw=alert, dry_run=self._settings.dry_run,
        )
        ctx = ExecutionContext(alert, playbook, execution.id, self._settings.dry_run)

        # Résolution des inputs déclarés
        ctx.inputs = render_dict(playbook.inputs, ctx.as_template_context())

        status = "success"
        started = time.perf_counter()
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
            await self._audit.set_error(execution.id, str(exc))
        finally:
            duration = time.perf_counter() - started
            EXEC_DURATION.labels(playbook.id).observe(duration)
            EXEC_TOTAL.labels(playbook.id, status).inc()
            outputs = render_dict(playbook.outputs, ctx.as_template_context())
            await self._audit.finish_execution(execution.id, status=status, outputs=outputs)

        return {"execution_id": execution.id, "status": status,
                "duration_seconds": round(duration, 2), "outputs": outputs}

    async def _run_step(self, step: Step, ctx: ExecutionContext) -> str:
        tctx = ctx.as_template_context()

        # ── when: ──────────────────────────────────────────────────────
        if not evaluate(step.when, tctx):
            await self._audit.log_step(ctx.execution_id, step, "skipped", {}, {}, None, 0)
            ctx.steps[step.id] = {"output": None, "skipped": True}
            return "ok"

        params = render_dict(step.with_, tctx)

        # ── GARDE-FOU : actifs protégés ────────────────────────────────
        if step.destructive:
            target = str(params.get("agent") or params.get("host") or "")
            if target in ctx.settings.protected_assets:
                log.warning("destructive_blocked_protected_asset", target=target, step=step.id)
                await self._audit.log_step(ctx.execution_id, step, "skipped", params,
                                           {"reason": "protected_asset"}, None, 0)
                ctx.steps[step.id] = {"output": {"blocked": "protected_asset"}}
                return "partial"

        # ── DRY RUN ────────────────────────────────────────────────────
        if step.destructive and ctx.dry_run:
            log.info("dry_run_skip", step=step.id, action=step.action, params=params)
            await self._audit.log_step(ctx.execution_id, step, "dry_run", params,
                                       {"simulated": True}, None, 0)
            ctx.steps[step.id] = {"output": {"dry_run": True}}
            ctx.actions_taken.append(f"[DRY-RUN] {step.action}")
            return "ok"

        # ── EXÉCUTION avec retry + timeout ─────────────────────────────
        fn = get_action(step.action)
        attempts = step.retries + 1
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            t0 = time.perf_counter()
            try:
                output = await asyncio.wait_for(fn(params, ctx), timeout=step.timeout_seconds)
                ms = int((time.perf_counter() - t0) * 1000)
                ctx.steps[step.id] = {"output": output}
                ctx.actions_taken.append(step.action)
                ACTION_TOTAL.labels(step.action, "success").inc()
                await self._audit.log_step(ctx.execution_id, step, "success", params,
                                           {"value": output}, None, ms)
                return "ok"
            except Exception as exc:
                last_error = exc
                ms = int((time.perf_counter() - t0) * 1000)
                log.warning("step_attempt_failed", step=step.id, attempt=attempt,
                            total=attempts, error=str(exc))
                if attempt < attempts and step.on_error == OnError.RETRY:
                    await asyncio.sleep(2 ** attempt)   # backoff exponentiel
                    continue
                break

        ACTION_TOTAL.labels(step.action, "failed").inc()
        await self._audit.log_step(ctx.execution_id, step, "failed", params, {},
                                   str(last_error), ms)
        ctx.steps[step.id] = {"output": None, "error": str(last_error)}

        if step.on_error == OnError.CONTINUE:
            return "partial"
        return "failed"

    # ── ROLLBACK ───────────────────────────────────────────────────────
    async def rollback(self, execution_id: int) -> dict:
        """Annule les actions destructives réussies, dans l'ordre inverse."""
        execution = await self._audit.get_execution(execution_id)
        playbook = ...  # rechargé via playbook_id + version
        steps = await self._audit.get_steps(execution_id)
        undone = []
        for slog in reversed(steps):
            if slog.status != "success" or not slog.destructive or slog.rolled_back:
                continue
            step = next(s for s in playbook.steps if s.id == slog.step_id)
            if not step.rollback:
                continue
            fn = get_action(step.rollback)
            await fn(slog.inputs, ...)
            await self._audit.mark_rolled_back(slog.id)
            undone.append(step.rollback)
        return {"execution_id": execution_id, "rolled_back": undone}
```

### Ce qu'il faut savoir expliquer dans ce fichier

| Mécanisme | La question | Ta réponse |
|---|---|---|
| **Idempotence** | « Pourquoi le hash ? » | Wazuh peut renvoyer le même webhook (retry réseau), et une alerte peut matcher 2 règles. Sans clé de déduplication : 40 cas TheHive identiques, 40 notifs, et l'analyste désactive mon outil dans l'heure. La contrainte d'unicité est **en base**, pas en mémoire : si je passe à 3 replicas Kubernetes, la garantie tient toujours. **Ce dernier point est le vrai argument.** |
| **`asyncio.wait_for`** | « Pourquoi un timeout par étape ? » | VirusTotal peut mettre 30 s sous rate-limit. Sans timeout, un playbook reste bloqué et occupe un worker. Avec 300 alertes/jour et un pic, la file explose. Le timeout est **une décision de capacité**, pas une précaution cosmétique. |
| **Backoff exponentiel** | « Pourquoi 2^attempt ? » | Si le service distant est saturé, réessayer immédiatement l'achève. Le backoff lui laisse le temps de récupérer. En prod j'ajouterais du **jitter** pour éviter le troupeau tonnant (thundering herd) quand 50 playbooks retryent en même temps. |
| **`on_error: continue`** | « Pourquoi pas tout en fail ? » | Toutes les étapes n'ont pas la même criticité. L'enrichissement est du bonus : si ma threat intel est down, l'incident doit **quand même** être créé, juste avec moins de contexte. La création du cas, elle, est en `fail`. **La criticité est une propriété de l'étape, pas du moteur.** |
| **`destructive: true`** | « Comment tu sais qu'une action est dangereuse ? » | C'est **déclaré** dans le playbook, pas deviné. Le moteur applique alors trois garde-fous : liste d'actifs protégés, dry-run, et exigence d'approbation. **Explicite plutôt qu'implicite** : je ne veux pas d'une heuristique sur le nom de l'action. |
| **`protected_assets`** | — | Un DC isolé = toute l'entreprise à l'arrêt. Le garde-fou est **avant** le dry-run dans l'ordre du code, donc il s'applique même en mode armé. |
| **Rollback en ordre inverse** | « Pourquoi reversed ? » | Même logique qu'un `terraform destroy` ou qu'un rollback de déploiement : les actions ont des dépendances. On défait de la dernière à la première. **Tu fais ça depuis 4 ans chez WSP** — dis-le, c'est un pont direct avec ton expérience.

## 2.9 Le webhook — `soc_autopilot/api/routes/webhook.py`

```python
import hmac
import hashlib
from fastapi import APIRouter, Request, Header, HTTPException, BackgroundTasks
import structlog

from soc_autopilot.config import get_settings

router = APIRouter()
log = structlog.get_logger()


def verify_hmac(body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    secret = get_settings().webhook_hmac_secret.encode()
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)   # comparaison à temps constant


@router.post("/webhook/wazuh", status_code=202)
async def wazuh_webhook(request: Request, background: BackgroundTasks,
                        x_signature: str | None = Header(default=None)):
    body = await request.body()
    if not verify_hmac(body, x_signature):
        log.warning("webhook_bad_signature", ip=request.client.host)
        raise HTTPException(status_code=401, detail="Invalid signature")

    alert = await request.json()
    store = request.app.state.playbooks
    executor = request.app.state.executor

    matched = store.match(alert)
    if not matched:
        log.info("no_playbook_matched", rule_id=alert.get("rule", {}).get("id"))
        return {"matched": 0}

    for pb in matched:
        background.add_task(executor.run, pb, alert)   # 202 immédiat

    return {"matched": len(matched), "playbooks": [pb.id for pb in matched]}
```

> **Trois choses à défendre :**
> 1. **HMAC.** Mon webhook peut isoler une machine. S'il est ouvert, n'importe qui sur le réseau forge une alerte et me fait couper un serveur de prod — **le SOAR devient l'arme de l'attaquant**. Le HMAC prouve que l'alerte vient bien du manager Wazuh.
> 2. **`hmac.compare_digest`** et pas `==`. Une comparaison de chaînes normale s'arrête au premier octet différent → **timing attack**, on peut deviner la signature octet par octet. `compare_digest` est à temps constant. **Ce détail-là fait sourire un ingénieur sécu.** C'est du OWASP ASVS — tu connais, tu l'as appliqué sur threat-intel-api.
> 3. **202 + BackgroundTasks.** Wazuh a un timeout court. Si mon playbook prend 40 s, Wazuh croit que j'ai échoué et **renvoie l'alerte** → d'où l'idempotence. Je réponds « accepté » tout de suite et je travaille derrière. En prod : une vraie file (Redis/Celery/RabbitMQ) pour survivre à un redémarrage. **`BackgroundTasks` perd les tâches en cours si le pod meurt — je le sais, c'est écrit dans mes limites connues.** ⚡ **Reconnaître spontanément la limite de son propre design = signal de séniorité.**

## 2.10 L'app — `soc_autopilot/api/main.py`

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from prometheus_client import make_asgi_app
import structlog

from soc_autopilot.config import get_settings
from soc_autopilot.engine.loader import PlaybookStore
from soc_autopilot.engine.executor import Executor
from soc_autopilot.api.routes import webhook, playbooks, executions
from soc_autopilot.audit import AuditRepository
import soc_autopilot.actions  # noqa: F401  → déclenche l'enregistrement des @action

structlog.configure(processors=[
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.JSONRenderer(),
])


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    app.state.playbooks = PlaybookStore(s.playbooks_dir)   # fail-fast si invalide
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
app.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
app.include_router(executions.router, prefix="/executions", tags=["executions"])
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "playbooks": len(app.state.playbooks.all())}
```

> **`import soc_autopilot.actions  # noqa`** — c'est cette ligne qui exécute les décorateurs `@action` et remplit le registre. Sans elle, `get_action()` lève « action inconnue » et tu perds une heure. **Le `# noqa: F401` dit au linter « je sais que c'est un import inutilisé, c'est volontaire ». Si on te demande, tu sais pourquoi.**

## 2.11 Tests — commence dès J2

```python
# tests/unit/test_resolver.py
import pytest
from jinja2.exceptions import SecurityError, UndefinedError
from soc_autopilot.engine.resolver import render, evaluate


def test_render_simple():
    assert render("{{ alert.agent.name }}", {"alert": {"agent": {"name": "WS-042"}}}) == "WS-042"


def test_evaluate_condition_true():
    assert evaluate("{{ score > 5 }}", {"score": 9}) is True


def test_missing_variable_raises():
    """Une typo doit exploser, pas rendre une chaîne vide."""
    with pytest.raises(UndefinedError):
        render("{{ alert.agnet.name }}", {"alert": {"agent": {"name": "WS-042"}}})


def test_sandbox_blocks_rce():
    """Un playbook malveillant ne doit pas pouvoir sortir du bac à sable."""
    with pytest.raises(SecurityError):
        render("{{ ''.__class__.__mro__[1].__subclasses__() }}", {})
```

> **`test_sandbox_blocks_rce` est le test le plus important du repo.**
> Il ne teste pas une fonctionnalité : il **prouve** que ta décision d'architecture tient. Quand tu montreras ton repo, ouvre **ce test-là**. Un test qui prouve une propriété de sécurité, c'est ce que fait un ingénieur. Un test qui vérifie que 2+2=4, c'est ce que fait un étudiant.

```python
# tests/unit/test_executor.py
import pytest
from soc_autopilot.engine.executor import dedup_key

def test_dedup_key_stable():
    assert dedup_key("a1", "PB-0001") == dedup_key("a1", "PB-0001")

def test_dedup_key_differs_per_playbook():
    assert dedup_key("a1", "PB-0001") != dedup_key("a1", "PB-0002")
```

**Lancer :**
```bash
pytest tests/ -v --cov=soc_autopilot --cov-report=term-missing
```

**Commits de la journée :**
```bash
git add . && git commit -m "feat(engine): playbook schema, sandboxed resolver, action registry"
git commit -m "feat(engine): DAG executor with idempotency, dry-run, retry and rollback"
git commit -m "feat(api): HMAC-authenticated Wazuh webhook, health and metrics endpoints"
git commit -m "test(engine): sandbox escape prevention and dedup key stability"
```

### ✅ Fin de J2 : `curl -X POST localhost:8000/webhook/wazuh` avec une bonne signature → une exécution apparaît en base.

---

# J3 — Samedi 18 juillet : intégrations + playbooks

**Durée : 8 h.**

## 3.1 Client Wazuh — `soc_autopilot/actions/wazuh.py`

```python
import time
import httpx
import structlog
from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action

log = structlog.get_logger()


class WazuhClient:
    """Client API Wazuh avec cache et refresh anticipé du token JWT."""

    def __init__(self) -> None:
        s = get_settings()
        self._base = s.wazuh_api_url.rstrip("/")
        self._auth = (s.wazuh_api_user, s.wazuh_api_password)
        self._verify = s.wazuh_verify_tls
        self._token: str | None = None
        self._expires_at: float = 0.0

    async def _get_token(self) -> str:
        # Refresh 60 s AVANT expiration (le token Wazuh dure 900 s)
        if self._token and time.time() < self._expires_at - 60:
            return self._token
        async with httpx.AsyncClient(verify=self._verify, timeout=10.0) as c:
            r = await c.post(f"{self._base}/security/user/authenticate?raw=true", auth=self._auth)
            r.raise_for_status()
            self._token = r.text.strip()
            self._expires_at = time.time() + 900
        return self._token

    async def _request(self, method: str, path: str, **kw) -> dict:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(verify=self._verify, timeout=15.0) as c:
            r = await c.request(method, f"{self._base}{path}", headers=headers, **kw)
            if r.status_code == 401:                 # token périmé malgré le cache
                self._token = None
                token = await self._get_token()
                r = await c.request(method, f"{self._base}{path}",
                                    headers={"Authorization": f"Bearer {token}"}, **kw)
            r.raise_for_status()
            return r.json()

    async def agent_id(self, name: str) -> str:
        data = await self._request("GET", "/agents", params={"name": name})
        items = data["data"]["affected_items"]
        if not items:
            raise ValueError(f"Agent introuvable: {name}")
        return items[0]["id"]

    async def agent_context(self, name: str) -> dict:
        data = await self._request("GET", "/agents", params={"name": name})
        a = data["data"]["affected_items"][0]
        return {"id": a["id"], "ip": a.get("ip"), "os": a.get("os", {}).get("name"),
                "status": a["status"], "last_keep_alive": a.get("lastKeepAlive"),
                "groups": a.get("group", [])}

    async def active_response(self, command: str, agent_id: str, args: list[str] | None = None) -> dict:
        return await self._request("PUT", "/active-response",
                                   params={"agents_list": agent_id},
                                   json={"command": command, "arguments": args or []})


_client = WazuhClient()


@action("wazuh.get_agent_context")
async def get_agent_context(params: dict, ctx) -> dict:
    return await _client.agent_context(params["agent"])


@action("wazuh.isolate_host")
async def isolate_host(params: dict, ctx) -> dict:
    agent = params["agent"]
    aid = await _client.agent_id(agent)
    res = await _client.active_response("firewall-drop0", aid, [params.get("ip", "")])
    log.warning("host_isolated", agent=agent, agent_id=aid, execution=ctx.execution_id)
    return {"agent": agent, "agent_id": aid, "result": res.get("data", {})}


@action("wazuh.unisolate_host")
async def unisolate_host(params: dict, ctx) -> dict:
    aid = await _client.agent_id(params["agent"])
    res = await _client.active_response("firewall-drop0", aid, ["-", "delete"])
    log.warning("host_unisolated", agent=params["agent"], execution=ctx.execution_id)
    return {"agent": params["agent"], "result": res.get("data", {})}
```

> **Le refresh anticipé de 60 s.** Sans ça : ton token expire **pendant** un playbook, l'appel 401, l'action échoue — pas toujours, juste 1 fois sur 60. **Les bugs intermittents sont les pires.** Je gère les deux : refresh proactif (cache) ET réactif (retry sur 401). Ceinture et bretelles, parce qu'un token peut aussi être révoqué côté serveur.
> **`wazuh_verify_tls: false`** — assume-le : *« C'est un certificat auto-signé de labo. En production, ce serait `true` avec le CA interne monté dans le conteneur. C'est documenté dans mon threat model comme une dette de labo, pas comme un oubli. »* **Nommer sa dette technique est un signal de maturité.**

**Côté Wazuh — activer l'active response** (`/var/ossec/etc/ossec.conf` du manager) :
```xml
<command>
  <name>firewall-drop0</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
<active-response>
  <command>firewall-drop0</command>
  <location>local</location>
  <timeout>300</timeout>
</active-response>
```

## 3.2 Threat intel — `soc_autopilot/actions/threatintel.py`

```python
import asyncio
import re
import time

import httpx

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)")


@action("threatintel.extract_iocs")
async def extract_iocs(params: dict, ctx) -> dict:
    text = str(params.get("text", ""))
    ips = [i for i in set(IPV4.findall(text)) if not PRIVATE.match(i)]
    return {"ips": ips, "hashes": list(set(SHA256.findall(text))),
            "domains": list(set(DOMAIN.findall(text))), "urls": list(set(URL.findall(text)))}


@action("threatintel.lookup")
async def lookup(params: dict, ctx) -> dict:
    """Couche 2 — interroge mon threat-intel-api pour PRIORISER par profil sectoriel."""
    s = get_settings()
    profile = params.get("profile", "gov")     # CAE = défense/aéro → gov/ICS
    async with httpx.AsyncClient(timeout=s.threat_intel_timeout) as c:
        r = await c.get(f"{s.threat_intel_url}/cves",
                        params={"profile": profile, "limit": 5, "kev_only": True})
        r.raise_for_status()
        data = r.json()
    items = data.get("items", data if isinstance(data, list) else [])
    return {"profile": profile, "kev_count": len(items),
            "top": [{"cve": i.get("cve_id"), "score": i.get("sector_score")} for i in items[:5]],
            "max_severity": max((i.get("sector_score", 0) for i in items), default=0)}


# ── Couche 1 — VirusTotal : RÉPUTATION d'un IOC concret ──────────────────
# Cache en mémoire { ioc: (verdict, timestamp) }. En prod : Redis avec TTL.
_VT_CACHE: dict[str, tuple[dict, float]] = {}
_VT_CACHE_TTL = 3600                      # un verdict VT ne change pas en 1 h
_VT_SEMAPHORE = asyncio.Semaphore(4)      # respecte le plafond 4 req/min de l'API gratuite


def _vt_classify(malicious: int, suspicious: int, total: int) -> str:
    """Verdict par RATIO, jamais par compte brut. Absence ≠ innocence."""
    if total == 0:
        return "unknown"
    ratio = (malicious + suspicious) / total
    if ratio >= 0.30:
        return "malicious"
    if malicious + suspicious >= 3:
        return "suspicious"
    if total >= 5:
        return "likely_benign"            # "likely", jamais "benign" tout court
    return "unknown"


def _vt_worst(results: list[dict]) -> str:
    order = ["malicious", "suspicious", "likely_benign", "unknown", "error"]
    found = {r["verdict"] for r in results}
    return next((v for v in order if v in found), "unknown")


@action("threatintel.virustotal_lookup")
async def virustotal_lookup(params: dict, ctx) -> dict:
    """Enrichit des IOC via VirusTotal. Par hash/IP/domaine UNIQUEMENT — jamais d'upload."""
    s = get_settings()
    if not s.virustotal_api_key:
        return {"enabled": False, "reason": "no_api_key"}

    iocs = params.get("iocs", {})
    # On BORNE le nombre d'IOC pour ne pas cramer le quota sur une seule alerte
    to_check: list[tuple[str, str]] = []
    for h in iocs.get("hashes", [])[:5]:
        to_check.append(("files", h))
    for ip in iocs.get("ips", [])[:3]:
        to_check.append(("ip_addresses", ip))
    for d in iocs.get("domains", [])[:3]:
        to_check.append(("domains", d))

    results: list[dict] = []
    headers = {"x-apikey": s.virustotal_api_key}

    async with httpx.AsyncClient(timeout=s.virustotal_timeout, headers=headers) as client:
        for endpoint, ioc in to_check:
            # Cache : on ne redemande JAMAIS le même IOC (le même malware frappe plusieurs postes)
            cached = _VT_CACHE.get(ioc)
            if cached and (time.time() - cached[1]) < _VT_CACHE_TTL:
                results.append({**cached[0], "cached": True})
                continue
            try:
                async with _VT_SEMAPHORE:      # sérialise → respecte le rate limit
                    r = await client.get(
                        f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}")
                if r.status_code == 404:
                    verdict = {"ioc": ioc, "verdict": "unknown", "reason": "not_found"}
                elif r.status_code == 429:
                    # Quota épuisé : on N'ÉCHOUE PAS le playbook, on note et on passe
                    verdict = {"ioc": ioc, "verdict": "unknown", "reason": "rate_limited"}
                else:
                    r.raise_for_status()
                    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
                    total = sum(stats.values())
                    verdict = {"ioc": ioc, "verdict": _vt_classify(mal, sus, total),
                               "malicious": mal, "suspicious": sus, "total_engines": total,
                               "vt_link": f"https://www.virustotal.com/gui/search/{ioc}"}
                _VT_CACHE[ioc] = (verdict, time.time())
                results.append(verdict)
            except Exception as exc:  # noqa: BLE001 — best-effort, ne bloque jamais le cas
                results.append({"ioc": ioc, "verdict": "error", "reason": str(exc)})

    malicious = [r for r in results if r["verdict"] == "malicious"]
    return {"enabled": True, "checked": len(results),
            "malicious_count": len(malicious), "worst_verdict": _vt_worst(results),
            "results": results}
```

> **Le filtre des IP privées.** Sans lui, tu envoies `192.168.56.20` à VirusTotal — inutile, bruyant, et ça **fuite ta topologie interne vers un service tiers**. C'est un point de **confidentialité**, pas juste d'hygiène. Dans une boîte de défense, envoyer des IP internes à un service public, c'est un incident. **Dis-le exactement comme ça.**
> **`profile="gov"` :** *« Mon service de threat intel score les CVE par profil sectoriel. CAE étant en défense et aéronautique, j'utilise le profil gov/ICS — les mêmes CVE n'ont pas la même priorité selon le secteur. C'est le service que j'ai déployé en production sur Railway l'an dernier. »* ⚡ **Boucle parfaite entre tes deux projets.**

### Ce qu'il faut savoir défendre dans l'action VirusTotal

| Mécanisme | La question | Ta réponse |
|---|---|---|
| **`_VT_SEMAPHORE = Semaphore(4)`** | « Comment tu gères le rate limit ? » | L'API gratuite est à 4 req/min. Le sémaphore sérialise les appels pour ne jamais dépasser. Sans lui, la 5ᵉ requête d'une alerte à 8 IOC est rejetée en 429 et l'enrichissement casse. **Le rate limit n'est pas un détail, c'est la contrainte qui dicte le design.** |
| **`_VT_CACHE`** | « Pourquoi un cache ? » | Le même malware frappe plusieurs postes → le même hash revient. Je ne le redemande jamais dans l'heure. Ça économise le quota **et** ça accélère. En prod : Redis avec TTL, parce qu'un dict en mémoire ne survit pas à un restart de pod — limite connue. |
| **`[:5]` / `[:3]`** | « Pourquoi borner ? » | Une alerte peut contenir 50 IOC. Les envoyer tous crame 500 requêtes/jour en une alerte. Je borne aux plus pertinents. C'est un arbitrage de quota assumé. |
| **`_vt_classify` par ratio** | « Pourquoi pas juste malicious > 0 ? » | « 3 moteurs sur 70 » est souvent du faux positif de moteurs bruyants ; « 45 sur 70 » est un vrai verdict. Je raisonne en ratio et en consensus, pas en présence. |
| **404 → `unknown`, pas `benign`** | « Un hash inconnu, c'est sûr ? » | **Non.** Inconnu = jamais vu, ce qui est précisément le cas d'un malware ciblé ou tout récent. Traiter « 0 détection » comme « bénin » est l'erreur d'interprétation classique. Mon verdict le plus optimiste est `likely_benign`, jamais `benign`. |
| **429 → `unknown`, on continue** | « Et si le quota est épuisé ? » | Je ne fais **pas** échouer le playbook. Le cas est créé quand même, juste avec moins de contexte. `on_error: continue` dans le playbook + gestion du 429 dans le code = double filet. |
| **Hash uniquement, jamais de fichier** | — *(dis-le sans qu'on demande)* | Envoyer un hash = 64 caractères anonymes. Uploader un fichier = le publier. Dans un contexte défense, uploader un fichier interne est un incident. **Mon code n'a aucun chemin d'upload — c'est structurel, pas une consigne.** ⚡ |

> **⚡ Le point « hash jamais fichier » est celui qui fait lever un sourcil approbateur.** C'est le réflexe qu'on n'a que quand on a vraiment pensé au contexte d'une boîte comme CAE. Place-le, même si on ne te le demande pas.

## 3.3 TheHive — `soc_autopilot/actions/thehive.py`

```python
import httpx
from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action


@action("thehive.create_case")
async def create_case(params: dict, ctx) -> dict:
    s = get_settings()
    if not s.thehive_api_key:
        return {"case_id": f"LOCAL-{ctx.execution_id}", "backend": "local"}  # mode dégradé

    payload = {
        "title": params["title"],
        "description": params.get("description", ""),
        "severity": min(max(int(params.get("severity", 2)), 1), 4),
        "tlp": params.get("tlp", 2),
        "tags": params.get("mitre_tags", []) + [f"playbook:{ctx.playbook.id}",
                                                f"exec:{ctx.execution_id}"],
    }
    headers = {"Authorization": f"Bearer {s.thehive_api_key}"}
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(f"{s.thehive_url}/api/v1/case", json=payload, headers=headers)
        r.raise_for_status()
        case = r.json()

        for obs_type, values in (params.get("observables") or {}).items():
            for v in values:
                await c.post(f"{s.thehive_url}/api/v1/case/{case['_id']}/observable",
                             json={"dataType": obs_type, "data": [v], "tlp": 2,
                                   "ioc": True, "message": f"Auto — {ctx.playbook.id}"},
                             headers=headers)

    return {"case_id": case["_id"], "case_number": case.get("number"),
            "url": f"{s.thehive_url}/cases/{case['_id']}/details"}
```

> **Le tag `exec:{execution_id}`.** Il relie le cas TheHive à ton audit trail. Un analyste qui voit le cas peut remonter à l'exécution exacte du playbook. **La traçabilité doit être bidirectionnelle**, sinon elle ne sert à rien.
> **Le mode dégradé** (`if not thehive_api_key`) : ton système marche même sans TheHive. **Pendant la démo, si TheHive plante, tu ne perds pas la démo.** Prévoir le mode dégradé, c'est prévoir l'entrevue.

## 3.4 Slack + approbation — `soc_autopilot/actions/slack.py`

```python
import asyncio
import httpx
from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action

_PENDING: dict[str, asyncio.Future] = {}   # en prod : Redis (survit au restart du pod)


@action("slack.post")
async def post(params: dict, ctx) -> dict:
    s = get_settings()
    if not s.slack_bot_token:
        return {"posted": False, "reason": "slack_disabled"}
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post("https://slack.com/api/chat.postMessage",
                         headers={"Authorization": f"Bearer {s.slack_bot_token}"},
                         json={"channel": params.get("channel", s.slack_alert_channel),
                               "text": params["text"]})
        return {"ok": r.json().get("ok")}


@action("slack.request_approval")
async def request_approval(params: dict, ctx) -> dict:
    """Demande une approbation humaine. TIMEOUT => DENY."""
    s = get_settings()
    key = f"{ctx.execution_id}:{params.get('step_id', 'approval')}"
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    _PENDING[key] = fut

    timeout = params.get("timeout_seconds", s.approval_timeout_seconds)
    text = (f"{params['text']}\n\n"
            f"Approuver : `curl -XPOST http://<soc-autopilot>/approvals/{key} "
            f"-d '{{\"approved\":true,\"by\":\"votre.nom\"}}'`\n"
            f"⏱ Expire dans {timeout}s — *sans réponse, l'action est REFUSÉE*.")

    if s.slack_bot_token:
        async with httpx.AsyncClient(timeout=10.0) as c:
            await c.post("https://slack.com/api/chat.postMessage",
                         headers={"Authorization": f"Bearer {s.slack_bot_token}"},
                         json={"channel": params.get("channel", s.slack_action_channel),
                               "text": text})

    try:
        result = await asyncio.wait_for(fut, timeout=timeout)
        return {"approved": bool(result.get("approved")), "by": result.get("by"),
                "reason": "human_decision"}
    except asyncio.TimeoutError:
        return {"approved": False, "by": None, "reason": "timeout_denied"}   # ⚠️ FAIL-SAFE
    finally:
        _PENDING.pop(key, None)


def resolve_approval(key: str, payload: dict) -> bool:
    fut = _PENDING.get(key)
    if fut and not fut.done():
        fut.set_result(payload)
        return True
    return False
```

**La route :**
```python
# soc_autopilot/api/routes/approvals.py
from fastapi import APIRouter, HTTPException
from soc_autopilot.actions.slack import resolve_approval

router = APIRouter()

@router.post("/approvals/{key}")
async def approve(key: str, payload: dict):
    if not resolve_approval(key, payload):
        raise HTTPException(404, "Aucune approbation en attente pour cette clé")
    return {"ok": True, "key": key, "approved": payload.get("approved")}
```

> **🔴 LA question d'entrevue. Prépare-la mot pour mot.**
> *« Sur timeout, je refuse. Jamais j'approuve. Un système de sécurité doit être fail-safe, pas fail-open : en cas de doute, il ne fait rien. Le coût des deux erreurs n'est pas symétrique — un faux négatif me coûte une enquête manuelle, un faux positif destructif me coûte la confiance dans l'outil. Et un SOC qui ne fait pas confiance à son automatisation est un SOC sans automatisation. C'est le même raisonnement qu'un disjoncteur : en cas d'anomalie, il ouvre le circuit, il ne le ferme pas. »*
>
> **Et la limite, que tu donnes toi-même avant qu'on te la trouve :** *« Mes approbations en attente sont dans un dict en mémoire. Si le pod redémarre, elles sont perdues — donc refusées, ce qui est le bon comportement par défaut, mais l'analyste ne le sait pas. En production : Redis avec TTL, plus une notification d'expiration. C'est dans mes limites connues au README. »*

## 3.5 Les transformations — `soc_autopilot/actions/transform.py`

```python
import base64
import re
from soc_autopilot.engine.registry import action


@action("transform.b64_decode")
async def b64_decode(params: dict, ctx) -> dict:
    text = str(params.get("field", ""))
    pattern = params.get("pattern", r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})")
    m = re.search(pattern, text, re.I)
    if not m:
        return {"decoded": None, "found": False}
    raw = base64.b64decode(m.group(1))
    # PowerShell -enc est en UTF-16LE
    decoded = raw.decode("utf-16-le", errors="replace")
    return {"decoded": decoded, "found": True}


@action("transform.score")
async def score(params: dict, ctx) -> int:
    total = int(params.get("base", 0))
    for booster in params.get("boosters", []):
        if booster.get("when") is True or booster.get("when") == "True":
            total += int(booster.get("points", 0))
    return min(total, 10)
```

> **`utf-16-le` :** PowerShell encode ses commandes `-EncodedCommand` en UTF-16 Little Endian, pas en UTF-8. Si tu décodes en UTF-8, tu obtiens du charabia avec des octets nuls entre chaque lettre. **C'est un détail que seul quelqu'un qui l'a fait connaît.** Si tu le places naturellement en entrevue, ça vaut plus qu'une certification.

## 3.6 Les 4 playbooks

**`playbooks/PB-0001-powershell-encoded.yml`**
```yaml
id: PB-0001
name: PowerShell encodé suspect
version: "1.0"
description: >
  T1059.001 — décodage de la commande, extraction d'IOC, enrichissement sectoriel,
  ouverture de cas, isolation sous approbation humaine si le score est critique.

trigger:
  rule_ids: ["100101"]
  mitre: ["T1059.001"]
  severity_min: 8

inputs:
  host: "{{ alert.agent.name }}"
  user: "{{ alert.data.win.eventdata.user | default('unknown') }}"
  cmdline: "{{ alert.data.win.eventdata.commandLine | default('') }}"

steps:
  - id: decode
    action: transform.b64_decode
    with: { field: "{{ inputs.cmdline }}" }
    on_error: continue

  - id: iocs
    action: threatintel.extract_iocs
    with: { text: "{{ steps.decode.output.decoded }}{{ inputs.cmdline }}" }
    on_error: continue

  - id: vt
    action: threatintel.virustotal_lookup    # COUCHE 1 — réputation d'IOC
    with:
      iocs: "{{ steps.iocs.output }}"
    on_error: continue          # best-effort : ne doit jamais bloquer le cas
    timeout_seconds: 15

  - id: intel
    action: threatintel.lookup               # COUCHE 2 — priorisation sectorielle
    with: { profile: "gov" }
    on_error: continue          # best-effort : ne doit jamais bloquer le cas
    timeout_seconds: 5

  - id: context
    action: wazuh.get_agent_context
    with: { agent: "{{ inputs.host }}" }
    on_error: continue

  - id: risk
    action: transform.score
    with:
      base: "{{ alert.rule.level }}"
      boosters:
        - when: "{{ steps.vt.output.worst_verdict == 'malicious' }}"
          points: 3                            # un IOC confirmé malveillant pèse lourd
        - when: "{{ steps.decode.output.found }}"
          points: 2
        - when: "{{ inputs.user in vars.privileged_users }}"
          points: 2

  - id: case
    action: thehive.create_case
    on_error: fail              # celle-là est critique
    with:
      title: "[{{ playbook.id }}] PowerShell encodé — {{ inputs.host }}"
      description: |
        Hôte     : {{ inputs.host }} ({{ steps.context.output.ip }})
        Utilisateur : {{ inputs.user }}
        Commande : {{ inputs.cmdline }}
        Décodé   : {{ steps.decode.output.decoded }}
        Score    : {{ steps.risk.output }}/10
        VirusTotal : {{ steps.vt.output.worst_verdict }} ({{ steps.vt.output.malicious_count }} IOC malveillant(s))
        KEV secteur gov : {{ steps.intel.output.kev_count }}
      severity: 3
      tlp: 2
      mitre_tags: ["attack.t1059.001", "attack.execution"]
      observables:
        ip: "{{ steps.iocs.output.ips }}"
        domain: "{{ steps.iocs.output.domains }}"
        url: "{{ steps.iocs.output.urls }}"
        hash: "{{ steps.iocs.output.hashes }}"

  - id: approval
    action: slack.request_approval
    when: "{{ steps.risk.output >= 9 }}"
    with:
      step_id: approval
      text: "🚨 Isoler *{{ inputs.host }}* ? Score {{ steps.risk.output }}/10 — cas {{ steps.case.output.case_id }}"
      timeout_seconds: 900

  - id: isolate
    action: wazuh.isolate_host
    destructive: true
    rollback: wazuh.unisolate_host
    when: "{{ steps.approval.output.approved }}"
    with:
      agent: "{{ inputs.host }}"
      ip: "{{ steps.context.output.ip }}"

  - id: notify
    action: slack.post
    with:
      channel: "#soc-alerts"
      text: "✅ {{ playbook.id }} — {{ inputs.host }} — cas {{ steps.case.output.case_id }} (score {{ steps.risk.output }}/10)"

outputs:
  case_id: "{{ steps.case.output.case_id }}"
  score: "{{ steps.risk.output }}"
  isolated: "{{ steps.isolate.output is not none }}"
```

**Les 3 autres (même structure, périmètre réduit) :**
| Playbook | Technique | Particularité à expliquer |
|---|---|---|
| `PB-0002-lsass-dump.yml` | T1003.001 | **Pas d'approbation : isolation immédiate.** Justification : un dump de LSASS signifie que les credentials sont *déjà* volés ; chaque seconde compte pour le mouvement latéral. C'est le seul cas où j'accepte l'auto-containment — et le playbook le documente dans `description`. **⚡ Excellente question à provoquer.** |
| `PB-0003-persistence-runkey.yml` | T1547.001 | Pas d'isolation du tout (persistence ≠ urgence) → cas + enrichissement du registre + tâche d'investigation. Montre que **tout n'appelle pas la même réponse**. |
| `PB-0004-suspicious-account.yml` | T1136.001 | Création de compte → vérifie si le créateur est admin → cas + notification. Illustre le `when:` conditionnel. |

> **Pourquoi 4 playbooks avec des réponses DIFFÉRENTES et pas 4 clones ?**
> *« Un playbook qui isole toujours n'est pas un playbook, c'est un réflexe. La graduation de la réponse — enrichir seul, cas seul, cas + approbation, containment immédiat — est le vrai travail d'ingénierie de réponse. La question n'est pas "est-ce que je peux automatiser ?", c'est "**qu'est-ce qui mérite d'être automatisé, et jusqu'où**". »*
> **C'est peut-être ta meilleure phrase de toute l'entrevue.**

**Commits :**
```bash
git commit -m "feat(actions): Wazuh API client with token refresh, isolate/unisolate"
git commit -m "feat(actions): threat-intel enrichment with private-IP filtering"
git commit -m "feat(actions): VirusTotal IOC reputation with rate-limiting, cache and hash-only lookups"
git commit -m "feat(actions): TheHive case creation with observables and exec traceability"
git commit -m "feat(actions): Slack approval gate with fail-safe timeout deny"
git commit -m "feat(playbooks): 4 playbooks with graduated response by ATT&CK technique"
```

### ✅ Fin de J3 : une alerte forgée → cas TheHive créé + notif Slack, en < 5 s.

---

# J4 — Dimanche 19 juillet : Detection-as-Code

**Durée : 7 h.**

## 4.1 Anatomie d'une règle Sigma

`detections/windows/powershell_encoded_command.yml` :
```yaml
title: Commande PowerShell encodée en Base64
id: 8f3a2c1e-4d5b-4a7c-9e2f-1b3c5d7e9a01     # UUID v4 — généré avec `uuidgen`
status: experimental
description: >
  Détecte l'exécution de PowerShell avec le paramètre -EncodedCommand, technique
  courante d'obfuscation pour dissimuler la charge utile aux journaux et à l'analyse.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Michel-Ange Doubogan
date: 2026/07/19
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027

logsource:
  product: windows
  category: process_creation

detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_enc:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -ec '
      - ' -e '
  filter_legit:
    ParentImage|startswith:
      - 'C:\Program Files\Microsoft Monitoring Agent\'
      - 'C:\Program Files\WindowsApps\'
  condition: selection_img and selection_enc and not filter_legit

falsepositives:
  - Scripts d'administration légitimes (SCCM, agents de monitoring)
  - Certains installeurs
level: high

# Champ custom : le lien détection → réponse. C'est mon fil rouge.
response_playbook: PB-0001
```

**Décomposons, parce que chaque bloc est une question possible :**

| Bloc | Rôle | Le piège |
|---|---|---|
| `id` (UUID) | Identité **stable** de la règle | Le titre change, l'UUID jamais. C'est lui la clé d'upsert dans mon déploiement idempotent — sans lui, renommer une règle en créerait une deuxième |
| `logsource` | Dit au backend **où chercher** | `category: process_creation` se traduit en `EventID: 1` (Sysmon) sur un backend Windows. **Le logsource est ce qui rend Sigma portable** — c'est la couche d'abstraction |
| `selection_img` | Cible le binaire | `OriginalFileName` en plus de `Image` : renommer `powershell.exe` en `svchost.exe` ne contourne pas la règle — l'attribut est dans l'en-tête PE, il survit au renommage. **⚡ Détail d'expert : dis-le.** |
| `filter_legit` | Réduit le bruit | **Sans exclusion, la règle est inutilisable en prod** : SCCM lance du PowerShell encodé toute la journée. Une règle à 200 alertes/jour est une règle désactivée |
| `condition` | La logique booléenne | `not filter_legit` = le pattern d'exclusion standard |
| `falsepositives` | Documentation opérationnelle | **Obligatoire.** L'analyste qui reçoit l'alerte à 3 h doit savoir quoi écarter en premier. Une règle sans `falsepositives`, c'est une règle qu'on n'a pas exploitée |
| `response_playbook` | **Mon extension** | Champ non standard qui lie la détection à la réaction. Sigma l'ignore, mon pipeline le lit. **C'est le fil rouge du projet** |

> **⚡ La question qui vient :** « Ton `-e` va matcher plein de choses, non ? »
> **Réponse :** *« Oui — et c'est volontaire, parce que PowerShell accepte n'importe quel préfixe non ambigu : `-e`, `-en`, `-enc`, `-encod` fonctionnent tous. Si je ne matche que `-EncodedCommand`, je suis contourné par un caractère en moins. Le prix, c'est du bruit — que je paie avec `filter_legit` et que je mesure avec mon test de faux positif. C'est un compromis que j'ai chiffré, pas subi. »*

## 4.2 Les 8 règles

| Fichier | Technique | Source | Playbook |
|---|---|---|---|
| `windows/powershell_encoded_command.yml` | T1059.001 | Sysmon EID 1 | PB-0001 |
| `windows/lsass_memory_access.yml` | T1003.001 | Sysmon EID 10 | PB-0002 |
| `windows/registry_run_key_persistence.yml` | T1547.001 | Sysmon EID 13 | PB-0003 |
| `windows/local_account_creation.yml` | T1136.001 | Security 4720 / EID 1 `net user /add` | PB-0004 |
| `windows/scheduled_task_creation.yml` | T1053.005 | Sysmon EID 1 `schtasks /create` | PB-0003 |
| `windows/eventlog_clearing.yml` | T1070.001 | Security 1102 / `wevtutil cl` | PB-0002 |
| `windows/ingress_tool_transfer.yml` | T1105 | Sysmon EID 1 `certutil -urlcache` | PB-0001 |
| `linux/suspicious_curl_bash.yml` | T1059.004 | auditd execve | PB-0001 |

**Exemple — LSASS (la plus « sexy » à montrer) :**
```yaml
title: Accès mémoire à LSASS (dump de credentials)
id: 2b4c6d8e-1f3a-4b5c-8d7e-9a0b1c2d3e4f
status: experimental
description: Détecte l'ouverture de la mémoire de lsass.exe avec des droits de lecture,
  signature d'un dump de credentials (Mimikatz, procdump, comsvcs.dll).
author: Michel-Ange Doubogan
date: 2026/07/19
tags: [attack.credential-access, attack.t1003.001]
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'          # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
      - '0x1410'
      - '0x143a'          # accès complet — Mimikatz classique
  filter_signed:
    SourceImage|startswith:
      - 'C:\Windows\System32\wbem\'
      - 'C:\Program Files\Windows Defender\'
  condition: selection and not filter_signed
falsepositives:
  - Antivirus et EDR légitimes (scannent LSASS)
  - Outils de diagnostic Microsoft
level: critical
response_playbook: PB-0002
```
> **`GrantedAccess`** est le masque de droits demandé lors de l'ouverture du processus. `0x1010` = lire la mémoire. **La ruse :** on ne détecte pas *l'outil* (Mimikatz peut être renommé, recompilé, obfusqué) — on détecte **le comportement** (« quelqu'un lit la mémoire de LSASS »). Un attaquant peut changer d'outil ; il ne peut pas changer le fait qu'il doit lire LSASS pour en extraire les credentials.
> **⚡ C'est LA phrase qui montre que tu comprends la détection :** *« On détecte le comportement, pas l'outil. L'outil est une variable ; l'objectif de l'attaquant est une constante. »*

## 4.3 Valider et convertir

```bash
# Validation syntaxique
sigma check detections/

# Conversion vers les 3 SIEM cités par CAE
sigma convert -t elasticsearch -p ecs_windows detections/windows/ -o build/elastic.json
sigma convert -t splunk -p sysmon detections/windows/ -o build/splunk.txt
sigma convert -t opensearch -p ecs_windows detections/windows/ -o build/wazuh_queries.json
```
> **⚡ L'argument de portabilité, à sortir tel quel :**
> *« Je convertis vers Elastic, Splunk et OpenSearch depuis la même source. L'offre mentionne Splunk, Elastic et Sentinel — mes détections sont portables sur les trois. Je ne suis pas marié à un SIEM, et si CAE migre, mes règles suivent : je change une ligne dans le pipeline, pas 200 règles à la main. C'est le même raisonnement que pour Terraform vs les clics dans le portail Azure. »*

## 4.4 Le déploiement idempotent — `tools/deploy_rules.py`

```python
#!/usr/bin/env python3
"""Convertit les règles Sigma et les déploie dans Wazuh. Idempotent, par UUID."""
import argparse, hashlib, subprocess, sys
from pathlib import Path
import yaml

WAZUH_RULE_ID_BASE = 100100          # plage 100000+ réservée aux règles custom


def stable_rule_id(sigma_id: str) -> int:
    """UUID Sigma → ID numérique Wazuh, déterministe.
    Même règle = même ID, à travers les exécutions et les machines."""
    h = int(hashlib.sha256(sigma_id.encode()).hexdigest(), 16)
    return WAZUH_RULE_ID_BASE + (h % 800)


def build_wazuh_rules(directory: Path) -> str:
    out = ['<group name="sigma,soc_autopilot,">']
    for path in sorted(directory.rglob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rid = stable_rule_id(rule["id"])
        level = {"low": 5, "medium": 7, "high": 10, "critical": 12}.get(rule.get("level"), 7)
        mitre = [t.split(".", 1)[1].upper() for t in rule.get("tags", [])
                 if t.startswith("attack.t")]
        out.append(f'''
  <rule id="{rid}" level="{level}">
    <if_group>sysmon</if_group>
    <description>{rule["title"]}</description>
    <mitre>{"".join(f"<id>{m}</id>" for m in mitre)}</mitre>
    <options>no_full_log</options>
    <group>sigma_{rule["id"][:8]},playbook_{rule.get("response_playbook","none")},</group>
  </rule>''')
    out.append("\n</group>")
    return "\n".join(out)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--detections", default="detections")
    p.add_argument("--out", default="build/sigma_rules.xml")
    p.add_argument("--check-only", action="store_true")
    a = p.parse_args()

    r = subprocess.run(["sigma", "check", a.detections], capture_output=True, text=True)
    if r.returncode != 0:
        print("❌ Validation Sigma échouée:\n", r.stderr, file=sys.stderr)
        return 1
    print("✅ Toutes les règles Sigma sont valides")

    xml = build_wazuh_rules(Path(a.detections))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(xml, encoding="utf-8")
    print(f"✅ {a.out} généré")

    if a.check_only:
        return 0
    # Déploiement : scp vers /var/ossec/etc/rules/ puis restart manager
    print("→ scp build/sigma_rules.xml soc-lab:/var/ossec/etc/rules/ && restart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

> **`stable_rule_id` est le cœur de l'idempotence du déploiement.**
> *« Je dérive l'ID numérique Wazuh d'un hash de l'UUID Sigma. Résultat : la même règle a toujours le même ID, sur n'importe quelle machine, à n'importe quel moment. Je peux redéployer 50 fois, je n'accumule pas de doublons. Sans ça, chaque déploiement créerait des règles fantômes et les alertes historiques pointeraient vers des IDs qui n'existent plus. Le corollaire, c'est le risque de collision — 800 valeurs possibles, donc ~4 % de collision à 8 règles par le paradoxe des anniversaires. À l'échelle réelle, je passerais à une plage plus large avec détection de collision au build. **C'est une limite connue, elle est dans mon README.** »*
> ⚡ **Reconnaître spontanément la faiblesse mathématique de sa propre solution, avec le chiffre : c'est le genre de réponse qui fait basculer une entrevue.**

## 4.5 Le mapping Sigma → DeTT&CT — `tools/sigma_to_dettect.py`

```python
#!/usr/bin/env python3
"""Génère techniques.yaml pour DeTT&CT à partir des tags ATT&CK des règles Sigma."""
from pathlib import Path
import yaml, sys

techniques = {}
for path in Path("detections").rglob("*.yml"):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    for tag in rule.get("tags", []):
        if not tag.startswith("attack.t"):
            continue
        tid = tag.replace("attack.", "").upper()
        if "." in tid:
            base, sub = tid.split(".", 1)
            tid = f"{base}.{sub.zfill(3)}"
        techniques.setdefault(tid, []).append({
            "detection_name": rule["title"],
            "score": {"low": 2, "medium": 3, "high": 4, "critical": 5}.get(rule.get("level"), 2),
            "location": [f"Wazuh/{path.name}"],
        })

out = {
    "version": 1.2,
    "file_type": "technique-administration",
    "name": "SOC Autopilot",
    "platform": ["Windows", "Linux"],
    "techniques": [
        {"technique_id": tid, "technique_name": "",
         "detection": [{"applicable_to": ["all"], "location": d["location"],
                        "comment": d["detection_name"],
                        "score_logbook": [{"date": "2026-07-19", "score": d["score"],
                                           "comment": "Auto-généré depuis Sigma"}]}
                       for d in dets]}
        for tid, dets in sorted(techniques.items())
    ],
}
Path("build").mkdir(exist_ok=True)
Path("build/techniques.yaml").write_text(yaml.safe_dump(out, sort_keys=False))
print(f"✅ {len(techniques)} techniques couvertes : {sorted(techniques)}")
```

> **⚡ Le point à marteler :** *« Ma carte de couverture n'est jamais périmée, parce qu'elle n'est pas écrite à la main — elle est dérivée de mes règles. La plupart des SOC ont une matrice ATT&CK dans un PowerPoint qui datait déjà le jour où il a été présenté. La mienne se régénère à chaque commit. **La couverture est un produit du code, pas un document.** »*

## 4.6 L'analyse de lacunes — `docs/telemetry-gap-analysis.md`

Rédige une vraie page (elle sera lue) :

```markdown
# Analyse des lacunes de télémétrie

## Méthode
Sources collectées (data_sources.yaml) × techniques détectées (dérivées des tags Sigma)
→ DeTT&CT → couche de gap. Priorisation par (1) prévalence ATT&CK, (2) score sectoriel
issu de threat-intel-api pour le profil gov/ICS.

## Sources collectées
| Source | EID | Qualité | Rétention | Note |
|---|---|---|---|---|
| Sysmon Process Creation | 1 | Élevée | 7 j (labo) | ligne de cmd + parent + hash |
| Sysmon Network | 3 | Élevée | 7 j | par processus |
| Sysmon ProcessAccess | 10 | Élevée | 7 j | LSASS |
| Sysmon Registry | 13 | Moyenne | 7 j | config SwiftOnSecurity filtre agressivement |
| Windows Security | 4624/4688/4720/1102 | Moyenne | 7 j | 4688 sans cmdline (GPO absente) |
| PowerShell Operational | 4103/4104 | **Absente** | — | **GAP** — script block logging non activé |
| DNS Client | 3006 | **Absente** | — | **GAP** |

## Top 5 des lacunes

### 1. PowerShell Script Block Logging (EID 4104) — 🔴 Critique
- **Impact :** T1059.001 partiellement couvert. Je détecte `-enc`, mais pas le contenu
  du script s'il est lancé sans encodage ou via un fichier .ps1.
- **Remédiation :** GPO `Turn on PowerShell Script Block Logging`. Coût nul.
- **Gain :** couverture complète de T1059.001 + T1027 + détection d'obfuscation.

### 2. Sysmon EID 8 (CreateRemoteThread) — 🔴 Critique
- **Impact :** T1055 (Process Injection) invisible — 12 sous-techniques.
- **Remédiation :** décommenter la section dans sysmonconfig.xml.
- **Coût :** volume +~5 %.

### 3. Journalisation DNS — 🟡 Moyen
- **Impact :** T1071.004 (DNS tunneling), T1568 (DGA) invisibles.
- **Remédiation :** activer le journal Microsoft-Windows-DNS-Client/Operational.

### 4. Télémétrie Linux (auditd) — 🟡 Moyen
- **Impact :** une seule règle Linux ; T1053.003, T1543.002 non couverts.

### 5. Journaux d'authentification cloud — 🟢 Faible (labo)
- **Impact :** N/A en labo. En prod : Entra ID sign-in logs pour T1078.

## Ce que je NE couvre pas et pourquoi
Tactiques absentes : Reconnaissance, Resource Development, Impact.
**Raison assumée :** j'ai priorisé la chaîne complète Execution → Persistence →
Credential Access → C2, qui est le chemin critique d'une intrusion typique, plutôt
qu'une couverture large et superficielle. La largeur est dans la roadmap.
```

> **La section « Ce que je NE couvre pas et pourquoi » est celle qui te démarque.**
> N'importe qui liste ce qu'il a fait. Un ingénieur explique ce qu'il n'a **pas** fait et pourquoi c'était la bonne décision. C'est la différence entre montrer et **raisonner**.

**Commits :**
```bash
git commit -m "feat(detections): 8 Sigma rules across execution, persistence, credential access"
git commit -m "feat(tools): idempotent Sigma→Wazuh deployment via stable UUID-derived rule IDs"
git commit -m "feat(tools): auto-generate DeTT&CT technique coverage from Sigma tags"
git commit -m "docs: telemetry gap analysis with prioritised remediation backlog"
```

### ✅ Fin de J4 : `sigma check` vert, 8 règles déployées, une carte ATT&CK générée.

---

# J5 — Lundi 20 juillet : tests d'attaque
### → Fichier 04. C'est la journée la plus importante après J2. Ne la saute pas.

---

# J6 — Mardi 21 juillet : Kubernetes, Terraform, CI/CD

**Durée : 8 h.** Cette journée fait disparaître deux gaps de ta roadmap.

## 6.1 Dockerfile

```dockerfile
# syntax=docker/dockerfile:1.7
# ─── Étage 1 : build ────────────────────────────────────────────────
FROM python:3.12-alpine AS builder
WORKDIR /build
RUN apk add --no-cache gcc musl-dev libffi-dev
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Étage 2 : runtime ──────────────────────────────────────────────
FROM python:3.12-alpine AS runtime

RUN addgroup -g 1001 -S soc && adduser -u 1001 -S soc -G soc

COPY --from=builder /install /usr/local
WORKDIR /app
COPY --chown=soc:soc soc_autopilot/ ./soc_autopilot/
COPY --chown=soc:soc playbooks/ ./playbooks/

USER 1001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
      sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

ENTRYPOINT ["uvicorn", "soc_autopilot.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

> **Chaque ligne est défendable :**
> - **Multi-stage :** `gcc` et `musl-dev` servent à compiler les wheels, puis disparaissent. Image finale ~190 Mo au lieu de ~450 Mo. **Moins de binaires = moins de surface d'attaque = moins de CVE à patcher.** C'est un argument de **sécurité**, pas de performance.
> - **`USER 1001` (numérique, pas `soc`) :** Kubernetes `runAsNonRoot` vérifie l'**UID**. Si tu écris `USER soc`, k8s ne peut pas prouver que ce n'est pas root et **refuse de démarrer le pod**. Détail qui coûte 30 min à qui ne le sait pas.
> - **UID 1001 :** le même que `threat-intel-api`. **Cohérence entre mes projets.**
> - **Alpine :** ~5 Mo de base. Le compromis : `musl` au lieu de `glibc`, ce qui casse certains paquets scientifiques. Ici, aucune dépendance concernée — **j'ai vérifié, ce n'est pas un choix par défaut.**
> - **HEALTHCHECK en Python pur :** pas de `curl` dans l'image → un attaquant qui obtient une exécution n'a pas d'outil de téléchargement sous la main. **Living-off-the-land defense.** ⚡ Ce point-là est rare et impressionne.

## 6.2 Le Helm chart

`charts/soc-autopilot/values.yaml` :
```yaml
replicaCount: 2

image:
  repository: ghcr.io/setounkpe7/soc-autopilot
  tag: "0.3.0"
  pullPolicy: IfNotPresent

securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001
  seccompProfile: { type: RuntimeDefault }

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }

resources:
  requests: { cpu: 100m, memory: 256Mi }
  limits:   { cpu: 500m, memory: 512Mi }

networkPolicy:
  enabled: true
  allowedEgress:
    - { cidr: "192.168.56.10/32", ports: [55000, 9000, 5432] }   # Wazuh, TheHive, PG
    - { cidr: "0.0.0.0/0", ports: [443] }                        # Slack, threat-intel-api

config:
  dryRun: true
  approvalTimeoutSeconds: 900
```

`templates/deployment.yaml` (extrait — le bloc sécurité) :
```yaml
    spec:
      serviceAccountName: {{ include "soc-autopilot.fullname" . }}
      securityContext: {{- toYaml .Values.securityContext | nindent 8 }}
      containers:
        - name: soc-autopilot
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          securityContext: {{- toYaml .Values.containerSecurityContext | nindent 12 }}
          ports: [{ containerPort: 8000, name: http }]
          envFrom:
            - secretRef: { name: {{ include "soc-autopilot.fullname" . }}-secrets }
            - configMapRef: { name: {{ include "soc-autopilot.fullname" . }}-config }
          volumeMounts:
            - { name: playbooks, mountPath: /app/playbooks, readOnly: true }
            - { name: tmp, mountPath: /tmp }
          livenessProbe:
            httpGet: { path: /health, port: http }
            initialDelaySeconds: 15
            periodSeconds: 20
          readinessProbe:
            httpGet: { path: /health, port: http }
            initialDelaySeconds: 5
            periodSeconds: 10
          resources: {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: playbooks
          configMap: { name: {{ include "soc-autopilot.fullname" . }}-playbooks }
        - name: tmp
          emptyDir: {}
```

`templates/networkpolicy.yaml` :
```yaml
{{- if .Values.networkPolicy.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "soc-autopilot.fullname" . }}
spec:
  podSelector:
    matchLabels: {{- include "soc-autopilot.selectorLabels" . | nindent 6 }}
  policyTypes: [Ingress, Egress]
  ingress:
    - from: [{ podSelector: {} }]
      ports: [{ protocol: TCP, port: 8000 }]
  egress:
    - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }}]
      ports: [{ protocol: UDP, port: 53 }]      # DNS
    {{- range .Values.networkPolicy.allowedEgress }}
    - to: [{ ipBlock: { cidr: {{ .cidr | quote }} } }]
      ports: {{- range .ports }}
        - { protocol: TCP, port: {{ . }} }
      {{- end }}
    {{- end }}
{{- end }}
```

> **Explique chaque contrôle par la MENACE qu'il bloque, jamais par la case à cocher :**
> | Contrôle | La menace bloquée |
> |---|---|
> | `readOnlyRootFilesystem: true` | Un attaquant avec exécution ne peut pas déposer de binaire. → d'où le volume `emptyDir` sur `/tmp` : **c'est ça qui casse chez tout le monde**, Python a besoin d'écrire quelque part |
> | `capabilities: drop: ALL` | Ma web app n'a besoin d'aucune capability Linux. Pourquoi lui laisser `NET_RAW` (sniffing) ou `SYS_ADMIN` ? |
> | `allowPrivilegeEscalation: false` | Bloque les binaires setuid → pas d'escalade vers root dans le conteneur |
> | `seccompProfile: RuntimeDefault` | Filtre ~44 syscalls dangereux (`keyctl`, `ptrace`…) — bloque des évasions de conteneur connues |
> | **NetworkPolicy egress explicite** | **Le plus important.** Mon SOAR a les clés du royaume : il peut isoler des machines. Si on le compromet, il ne doit pas pouvoir parler à autre chose que Wazuh, TheHive, PostgreSQL et Slack. **C'est de la limitation de blast radius.** Sans NetworkPolicy, Kubernetes est **flat** : n'importe quel pod parle à n'importe quel pod. **Beaucoup l'ignorent — le dire te classe.** |
> | `resources.limits` | Un playbook en boucle ne doit pas affamer les autres pods du nœud. C'est de la **disponibilité**, et la disponibilité fait partie de la sécurité (le D de CIA/DIC) |

**Valider :**
```bash
helm lint charts/soc-autopilot
helm template charts/soc-autopilot | kubeconform -strict -summary
checkov -d charts/soc-autopilot --framework helm
```

## 6.3 Terraform

`infra/main.tf` :
```hcl
terraform {
  required_version = ">= 1.7"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.31" }
    helm       = { source = "hashicorp/helm",       version = "~> 2.14" }
    random     = { source = "hashicorp/random",     version = "~> 3.6" }
  }
}

provider "kubernetes" { config_path = var.kubeconfig_path }
provider "helm"       { kubernetes { config_path = var.kubeconfig_path } }

resource "kubernetes_namespace" "soc" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"   # PSA — le durcissement natif
      "pod-security.kubernetes.io/audit"   = "restricted"
      "app.kubernetes.io/managed-by"       = "terraform"
    }
  }
}

resource "random_password" "webhook_hmac" {
  length  = 48
  special = false
}

resource "kubernetes_secret" "integrations" {
  metadata {
    name      = "soc-autopilot-secrets"
    namespace = kubernetes_namespace.soc.metadata[0].name
  }
  data = {
    WEBHOOK_HMAC_SECRET = random_password.webhook_hmac.result
    WAZUH_API_PASSWORD  = var.wazuh_api_password
    THEHIVE_API_KEY     = var.thehive_api_key
    SLACK_BOT_TOKEN     = var.slack_bot_token
    DATABASE_URL        = var.database_url
  }
  type = "Opaque"
}

resource "kubernetes_config_map" "playbooks" {
  metadata {
    name      = "soc-autopilot-playbooks"
    namespace = kubernetes_namespace.soc.metadata[0].name
  }
  data = { for f in fileset("${path.module}/../playbooks", "*.yml") :
           f => file("${path.module}/../playbooks/${f}") }
}

resource "helm_release" "soc_autopilot" {
  name       = "soc-autopilot"
  chart      = "${path.module}/../charts/soc-autopilot"
  namespace  = kubernetes_namespace.soc.metadata[0].name
  values     = [file("${path.module}/values.${var.environment}.yaml")]
  depends_on = [kubernetes_secret.integrations, kubernetes_config_map.playbooks]

  set { name = "config.dryRun", value = var.dry_run }
}

output "webhook_hmac_secret" {
  value     = random_password.webhook_hmac.result
  sensitive = true      # jamais dans les logs de CI
}
```

`infra/variables.tf` :
```hcl
variable "kubeconfig_path" { type = string, default = "~/.kube/config" }
variable "namespace"       { type = string, default = "soc-autopilot" }
variable "environment"     { type = string, default = "lab" }
variable "dry_run"         { type = bool,   default = true }

variable "wazuh_api_password" { type = string, sensitive = true }
variable "thehive_api_key"    { type = string, sensitive = true }
variable "slack_bot_token"    { type = string, sensitive = true }
variable "database_url"       { type = string, sensitive = true }
```

```bash
cd infra
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file=lab.tfvars     # lab.tfvars est dans .gitignore !
terraform apply -var-file=lab.tfvars
```

> **Ce que tu défends :**
> - **`random_password` :** le secret HMAC est **généré par Terraform**, il n'existe nulle part en clair, il n'est jamais tapé par un humain. `sensitive = true` l'exclut des logs. **En prod, le state Terraform lui-même contient le secret en clair → backend chiffré Azure Storage avec state locking, et idéalement Vault ou Azure Key Vault en source. C'est une limite connue de mon setup labo, et elle est documentée.** ⚡
> - **Pod Security Admission `restricted` :** au niveau du **namespace**, Kubernetes refuse tout pod qui ne respecte pas les contraintes (non-root, pas de privileged, seccomp…). C'est une **ceinture** au cas où quelqu'un déploierait un pod mal configuré à côté. **Défense en profondeur : le chart est bien configuré, ET le namespace refuserait de toute façon.**
> - **`depends_on` explicite :** Terraform déduit les dépendances, mais pas toujours dans le bon ordre pour les ConfigMap montées. Sans ça, le pod démarre avant que la ConfigMap existe → CrashLoop. **Je l'ai rencontré, je l'ai corrigé.**
> - **Le lien avec ton passé :** *« C'est le même raisonnement que mes Runbooks Azure chez WSP : l'infrastructure est décrite, versionnée, revue en PR, et reproductible. J'ai juste changé de langage — de PowerShell déclaratif à HCL. »*

## 6.4 La CI — `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push: { branches: [main, dev] }
  pull_request: { branches: [main] }

permissions:
  contents: read
  packages: write
  id-token: write        # OBLIGATOIRE pour Cosign keyless (OIDC)

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv tool install ruff && ruff check . && ruff format --check .
      - run: uv tool install mypy && mypy soc_autopilot --strict
      - run: pipx install yamllint && yamllint playbooks/ detections/

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r requirements.txt pytest pytest-asyncio pytest-cov respx
      - run: pytest tests/unit tests/integration --cov=soc_autopilot --cov-fail-under=85

  sigma:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install sigma-cli pysigma-backend-elasticsearch pysigma-backend-splunk pyyaml
      - name: Valider la syntaxe Sigma
        run: sigma check detections/
      - name: Vérifier la portabilité multi-SIEM
        run: |
          sigma convert -t elasticsearch -p ecs_windows detections/windows/ -o /dev/null
          sigma convert -t splunk -p sysmon detections/windows/ -o /dev/null
      - name: Chaque règle DOIT déclarer un playbook de réponse
        run: python tools/check_playbook_links.py
      - name: Tests de détection (vrai positif + faux positif)
        run: pytest tests/detection -v          # ← LE job qui te distingue
      - name: Générer la couverture ATT&CK
        run: python tools/sigma_to_dettect.py

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install bandit && bandit -r soc_autopilot -ll
      - uses: returntocorp/semgrep-action@v1
        with: { config: "p/security-audit p/python .semgrep/" }

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install pip-audit && pip-audit -r requirements.txt
      - name: SBOM CycloneDX
        run: pipx install cyclonedx-bom && cyclonedx-py requirements -i requirements.txt -o sbom.json
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: sbom.json }

  iac:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform -chdir=infra init -backend=false && terraform -chdir=infra validate
      - run: terraform -chdir=infra fmt -check -recursive
      - uses: bridgecrewio/checkov-action@master
        with: { directory: ., framework: terraform,helm,dockerfile }
      - uses: aquasecurity/tfsec-action@v1.0.3
      - run: |
          curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
          helm lint charts/soc-autopilot

  container:
    needs: [lint, test, sast, sca]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hadolint/hadolint-action@v3.1.0
        with: { dockerfile: Dockerfile }
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        id: build
        with:
          push: ${{ github.ref == 'refs/heads/main' }}
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/${{ github.repository }}:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'                      # le build ÉCHOUE s'il y a un CVE HIGH
      - uses: sigstore/cosign-installer@v3
      - if: github.ref == 'refs/heads/main'
        run: cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

> **Les points à défendre :**
> - **`id-token: write`** — Cosign keyless obtient un certificat éphémère de Fulcio via l'identité OIDC de GitHub. **Il n'y a aucune clé privée à protéger, donc aucune clé à voler.** La preuve d'origine est dans un log de transparence public (Rekor). *« Sans signature, rien ne prouve que l'image dans le registre est celle sortie de mon pipeline. Un attaquant qui compromet le registre pousse une image malveillante avec le même tag, et personne ne le voit. »*
> - **`exit-code: 1` sur Trivy** — *« Le scan qui n'échoue pas est un scan décoratif. Ma règle : zéro CRITICAL/HIGH sur main, et si un CVE est un faux positif, je le supprime explicitement avec `.trivyignore` **et une date d'expiration** — pas en désactivant le job. Le risque résiduel est formalisé, comme les 28 risques que j'ai documentés sur RailsGoat. »* ⚡ **Pont direct avec ton portfolio existant.**
> - **`needs: [lint, test, sast, sca]`** — on ne construit pas une image à partir de code qui ne passe pas les tests. **L'ordre du DAG est une décision, pas un hasard.**
> - **`check_playbook_links.py`** — un job qui échoue si une règle Sigma déclare un `response_playbook` inexistant. *« Une détection sans réaction, c'est une alerte de plus dans la file. Mon pipeline refuse le commit. »* ⚡ **Personne n'a ça. Montre ce job.**

`tools/check_playbook_links.py` :
```python
#!/usr/bin/env python3
"""Échoue si une règle Sigma référence un playbook qui n'existe pas."""
import sys
from pathlib import Path
import yaml

playbooks = {yaml.safe_load(p.read_text())["id"] for p in Path("playbooks").glob("*.yml")}
errors = []
for rule_path in Path("detections").rglob("*.yml"):
    rule = yaml.safe_load(rule_path.read_text())
    pb = rule.get("response_playbook")
    if not pb:
        errors.append(f"{rule_path}: aucun response_playbook déclaré")
    elif pb not in playbooks:
        errors.append(f"{rule_path}: playbook inconnu '{pb}' (connus: {sorted(playbooks)})")

if errors:
    print("❌ Liens détection→réponse cassés:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print(f"✅ {len(list(Path('detections').rglob('*.yml')))} règles liées à un playbook valide")
```

## 6.5 Branch protection
GitHub → Settings → Branches → `main` :
- ☑ Require a pull request before merging
- ☑ Require status checks: `lint`, `test`, `sigma`, `sast`, `sca`, `iac`, `container`
- ☑ Require branches to be up to date
- ☑ Do not allow bypassing (**y compris pour toi**)

> *« Je m'applique à moi-même la contrainte que j'appliquerais à une équipe. C'est aussi ce que je faisais chez WSP : branch protection sur main, PR obligatoire depuis dev. »*

**Commits :**
```bash
git commit -m "feat(docker): hardened multi-stage Alpine image, non-root uid 1001"
git commit -m "feat(helm): chart with NetworkPolicy, restricted securityContext, RBAC"
git commit -m "feat(terraform): namespace with PSA restricted, generated HMAC secret, helm release"
git commit -m "ci: 7-job pipeline — lint, test, sigma, sast, sca, iac, signed container"
```

### ✅ Fin de J6 : `terraform apply` → `kubectl get pods -n soc-autopilot` → 2/2 Running. CI verte.

---

# J7 — Mercredi 22 juillet : documentation, démo, répétition

**Durée : 8 h. Ne code presque rien aujourd'hui.**

## 7.1 (2 h) Le threat model — `docs/threat-model.md`

```markdown
# Threat model — SOC Autopilot

## Pourquoi ce document
Mon SOAR a les clés du royaume : il peut isoler un hôte, lire toutes les alertes,
détenir les credentials de Wazuh, TheHive et Slack. C'est un **système d'administration
privilégié**. Je l'ai modélisé comme tel.

## Actifs
| Actif | Valeur | Impact si compromis |
|---|---|---|
| Credentials API Wazuh | Critique | Isolation arbitraire de tout le parc = DoS interne |
| Secret HMAC du webhook | Critique | Forge d'alertes → containment arbitraire |
| Contenu des playbooks | Élevée | Surface d'exécution de code (Jinja2) |
| Audit trail | Élevée | Effacement = perte de la preuve forensique |
| Clé API TheHive | Moyenne | Lecture/écriture des cas d'incident |

## STRIDE
| Menace | Scénario | Contrôle |
|---|---|---|
| **S**poofing | Un attaquant forge une alerte Wazuh et fait isoler un serveur de prod | HMAC-SHA256 + `compare_digest` (temps constant) |
| **T**ampering | Modification d'un playbook pour ajouter une action malveillante | Git + PR obligatoire + branch protection + ConfigMap en lecture seule |
| **R**epudiation | « Ce n'est pas moi qui ai approuvé » | Audit trail insert-only + identité de l'approbateur + version du playbook |
| **I**nfo disclosure | Fuite d'IOC/topologie interne vers un service tiers (VirusTotal) | Filtre des IP RFC1918 avant tout appel externe ; **interrogation VirusTotal par hash uniquement, aucun chemin d'upload de fichier** ; PII scrubbing dans structlog |
| **D**oS | Tempête d'alertes → saturation | Rate limit par IP, timeout par étape, `resources.limits`, idempotence |
| **E**levation | RCE via template Jinja2 dans un playbook | SandboxedEnvironment + règle Semgrep custom en CI + test unitaire d'évasion |

## Contrôles de containment (défense en profondeur)
1. `DRY_RUN=true` par défaut — l'outil est **désarmé** tant qu'on ne l'arme pas explicitement
2. `protected_assets` — liste d'actifs jamais isolés automatiquement, vérifiée **avant** le dry-run
3. Approbation humaine au-dessus du seuil de score
4. **Timeout d'approbation = DENY** (fail-safe, jamais fail-open)
5. Rollback déclaré par action destructive
6. NetworkPolicy egress : le pod ne parle qu'à Wazuh, TheHive, PostgreSQL, Slack

## Risques résiduels acceptés
| # | Risque | Pourquoi accepté | Remédiation prod |
|---|---|---|---|
| R1 | `WAZUH_VERIFY_TLS=false` | Certificat auto-signé de labo | CA interne monté dans le conteneur |
| R2 | Approbations en mémoire (perdues au restart) | Labo mono-instance ; le défaut est *deny* donc l'échec est sûr | Redis avec TTL + notification d'expiration |
| R3 | `BackgroundTasks` perd les tâches si le pod meurt | Acceptable en démo | File durable (Redis/Celery) |
| R4 | State Terraform en local contient le HMAC en clair | Labo | Backend Azure Storage chiffré + Key Vault |
| R5 | Collision possible sur `stable_rule_id` (~4 % à 8 règles) | Périmètre labo | Plage élargie + détection de collision au build |
| R6 | Defender désactivé sur la VM cible | Sinon aucune télémétrie d'attaque | Anneau de test avec exclusions validées |
```

> **Ce document seul te distingue de 95 % des candidats.**
> Et le tableau des **risques résiduels** est ta meilleure carte : *« Je documente ce que je n'ai pas sécurisé et pourquoi. Chez WSP je formalisais les risques résiduels avec un propriétaire et une date de revue — j'ai fait pareil sur RailsGoat, 28 risques formalisés. Un risque non documenté n'est pas un risque accepté, c'est un risque ignoré. »*

## 7.2 (1 h 30) Le README

Ordre imposé — c'est un produit, pas un devoir :
```markdown
# SOC Autopilot
> Detection-as-Code + SOAR. Le triage d'une alerte passe de ~12 min à ~40 s,
> l'humain garde la décision de containment.

[badges CI · coverage · trivy · cosign · licence]

## 🎬 Démo (5 min)  ← lien vidéo, en HAUT
## Le problème        ← le tableau des 12 min
## Architecture       ← le schéma
## Comment ça marche  ← le fil rouge ATT&CK (une technique traverse les 5 composants)
## Quickstart         ← docker compose up, < 5 min
## Anatomie d'un playbook  ← le YAML annoté
## Détections & tests ← le job CI qui rejoue une vraie attaque
## Couverture ATT&CK  ← image Navigator + lien GitHub Pages
## Sécurité de la plateforme ← lien threat model
## Stack
## Limites connues & roadmap   ← ⚡ l'honnêteté = la crédibilité
```

**La section « Limites connues » — écris-la vraiment :**
```markdown
## Limites connues
- Labo mono-nœud : pas de HA, pas de capacity planning.
- Approbations en mémoire : perdues au redémarrage (échec en *deny*, donc sûr).
- `BackgroundTasks` FastAPI : pas de file durable. Redis/Celery en prod.
- Cache VirusTotal en mémoire (perdu au restart) + quota gratuit 4 req/min, 500/j.
  En prod : Redis + clé VT payante.
- 8 règles, 4 tactiques ATT&CK. Reconnaissance/Impact non couverts — choix assumé
  (profondeur > largeur, voir docs/telemetry-gap-analysis.md).
- Pas de MISP, pas de Falco, pas de kube-bench. Roadmap, dans cet ordre.
- Testé contre Atomic Red Team uniquement — pas contre un adversaire adaptatif.
```

## 7.3 (2 h) La vidéo — le livrable le plus rentable de la semaine

**Le recruteur ne clonera pas ton repo. Il regardera 5 minutes.**

**Script minuté :**
| Temps | Contenu | À dire |
|---|---|---|
| 0:00-0:30 | Le problème | « 300 alertes/jour, 12 min chacune, l'analyste coupe les coins. » |
| 0:30-1:00 | Architecture | Le schéma, 20 secondes, pas plus |
| 1:00-1:45 | **L'attaque** | `Invoke-AtomicTest T1059.001` sur victim-win — écran partagé |
| 1:45-2:15 | La détection | Wazuh Dashboard : l'alerte apparaît, tag T1059.001 |
| 2:15-3:15 | **Le playbook** | Logs structurés en direct : decode → enrich → score → case |
| 3:15-3:45 | TheHive | Le cas créé, pré-rempli, observables, tags ATT&CK |
| 3:45-4:15 | **L'approbation** | Slack : « Isoler WS-042 ? » — **et tu ne cliques pas** → timeout → refusé |
| 4:15-4:45 | La CI | Le job `sigma` : tests de détection TP + FP verts |
| 4:45-5:00 | La carte | ATT&CK Navigator, layer généré au commit |

> **Le moment 3:45 est le meilleur de ta vidéo.** Tu montres l'approbation, **tu ne cliques pas**, et tu dis en voix off : *« Je ne réponds pas. Le timeout expire. L'action est refusée, pas approuvée. Fail-safe. »*
> **C'est du théâtre, et c'est le bon théâtre :** tu ne montres pas que ça marche, tu montres que **tu as pensé au cas où ça ne devrait pas marcher**.

**Outils :** OBS Studio (`sudo apt install obs-studio`) ou ScreenToGif. Voix off en français. Sous-titres anglais si tu as le temps.
**Publie sur YouTube en « non répertorié »**, lien dans le README.

## 7.4 (1 h) Rendre le quickstart réel

Un `docker-compose.demo.yml` qui monte **tout** (soc-autopilot + PostgreSQL + un faux webhook), plus un `make demo` qui envoie une alerte pré-enregistrée.
```bash
make demo    # → une exécution complète en 30 s, sans VM, sans Wazuh
```
> **Pourquoi c'est critique :** si un ingénieur CAE veut essayer ton projet et qu'il doit monter Wazuh d'abord, il abandonne. Ton quickstart doit marcher **sur un laptop en 5 minutes**. Ce n'est pas de la complaisance — c'est de la **DX** (developer experience), et un intégrateur qui ne pense pas à ceux qui consomment son outil est un mauvais intégrateur.

## 7.5 (1 h 30) Répétition
**→ Fichier 05.** Chronomètre-toi. À voix haute. En français **et en anglais**.

## 7.6 (30 min) Le dernier commit
```bash
git commit -m "docs: threat model, README, telemetry gap analysis, demo scenario"
git tag -a v0.3.0 -m "Release for CAE interview — 2026-07-23"
git push --tags
```

---

## Fallback : si tu prends du retard

**Coupe dans cet ordre, sans regret :**
1. Le 4ᵉ playbook → 3 suffisent
2. Grafana → `/metrics` suffit
3. La conversion Splunk → garde Elastic + OpenSearch
4. Les règles Linux → tout en Windows
5. Terraform → `helm install` à la main (**mais alors tu perds un gap comblé — c'est le dernier à couper**)

**Ne coupe JAMAIS :**
- Les tests de détection (fichier 04) — c'est le différenciateur
- Le threat model — c'est ce qui te classe
- La vidéo — c'est ce qui sera vu
- Les limites connues — c'est ce qui te rend crédible

> **Un projet à 70 % que tu maîtrises à 100 % bat un projet à 100 % que tu maîtrises à 70 %.**
> Le 23 juillet, ce qu'on évalue, ce n'est pas ton repo. C'est **ta tête**.
