from typing import Any

from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

# ⚠️ SandboxedEnvironment, JAMAIS Environment
_env = SandboxedEnvironment(undefined=StrictUndefined)


def render(template: str, context: dict[str, Any]) -> Any:
    """Rend un template Jinja2 en environnement sandboxé.

    Retourne TOUJOURS la chaîne rendue telle quelle (pas de coercion), pour ne
    jamais corrompre un paramètre : un id d'agent zero-paddé comme "001" doit
    rester "001", pas devenir l'entier 1. La coercion bool/int est réservée à
    `evaluate()`, qui traite des conditions `when:`.
    """
    if not isinstance(template, str) or "{{" not in template:
        return template
    return _env.from_string(template).render(**context)


def _coerce(result: str) -> Any:
    """Coercion des littéraux simples pour les conditions booléennes/numériques."""
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
    rendered = render(expression, context)
    if isinstance(rendered, str):
        rendered = _coerce(rendered)
    return bool(rendered)
