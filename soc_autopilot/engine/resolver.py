from typing import Any

from jinja2 import ChainableUndefined
from jinja2.sandbox import SandboxedEnvironment

# ⚠️ SandboxedEnvironment, JAMAIS Environment
# ChainableUndefined (et non StrictUndefined) : l'enrichissement est best-effort
# (`on_error: continue`). Un enrichissement absent ne doit PAS faire crasher le
# playbook de réponse — `steps.vt.output.worst_verdict` sur une étape en échec
# (output None) rend "" (falsy) au lieu de lever, y compris quand une étape
# critique `on_error: fail` (ex. description d'un cas) interpole ce champ.
#
# CONTREPARTIE assumée : une typo de template ne lève plus, elle rend "". La
# garantie « ne jamais agir silencieusement sur la mauvaise cible » n'est donc
# PLUS assurée par le rendu (`on_error` ne voit pas les erreurs de rendu). Elle
# est rétablie côté executor, qui REFUSE toute étape `destructive:` dont la cible
# rendue est vide (garde-fou "destructive_empty_target").
_env = SandboxedEnvironment(undefined=ChainableUndefined)


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


def _render_item(v: Any, context: dict[str, Any]) -> Any:
    if isinstance(v, str):
        return render(v, context)
    if isinstance(v, dict):
        return render_dict(v, context)
    if isinstance(v, list):
        return [_render_item(i, context) for i in v]
    return v


def render_dict(data: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    # Rend récursivement dicts ET listes-de-dicts : sinon les `boosters` de
    # transform.score (liste de dicts avec `when`) ne seraient jamais résolus.
    return {k: _render_item(v, context) for k, v in data.items()}


def evaluate(expression: str | None, context: dict[str, Any]) -> bool:
    """Évalue une condition `when:`. Absence de condition = True."""
    if expression is None:
        return True
    rendered = render(expression, context)
    if isinstance(rendered, str):
        rendered = _coerce(rendered)
    return bool(rendered)
