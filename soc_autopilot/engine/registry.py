from collections.abc import Awaitable, Callable
from typing import Any

ActionFn = Callable[[dict[str, Any], "ExecutionContext"], Awaitable[Any]]  # noqa: F821
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
