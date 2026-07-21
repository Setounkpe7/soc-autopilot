"""Évaluateur Sigma minimal pour tests hors-ligne.

On n'a pas besoin d'un Elasticsearch en CI pour valider la LOGIQUE d'une règle :
on rejoue la règle brute (avant pipeline Wazuh) contre des événements Sysmon bruts.
"""

from typing import Any


def _get(event: dict, field: str) -> Any:
    """Sysmon met les champs dans EventData. On aplatit."""
    if field in event:
        return event[field]
    return event.get("EventData", {}).get(field)


def _match_value(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    a = str(actual)
    exps = expected if isinstance(expected, list) else [expected]
    for e in exps:
        e = str(e)
        if modifier == "contains" and e.lower() in a.lower():
            return True
        if modifier == "endswith" and a.lower().endswith(e.lower()):
            return True
        if modifier == "startswith" and a.lower().startswith(e.lower()):
            return True
        if modifier is None and a.lower() == e.lower():
            return True
    return False


def _match_selection(event: dict, selection: Any) -> bool:
    # Une liste de dicts = OR entre les dicts
    if isinstance(selection, list):
        return any(_match_selection(event, s) for s in selection)
    # Un dict = AND entre les clés
    for key, expected in selection.items():
        field, _, modifier = key.partition("|")
        modifier = modifier or None
        if not _match_value(_get(event, field), expected, modifier):
            return False
    return True


def evaluate_rule(rule: dict, event: dict) -> bool:
    """Évalue la condition Sigma. Gère 'A and B', 'A and not B', 'A or B'."""
    detection = rule["detection"]
    condition = detection["condition"].strip()

    results = {
        k: _match_selection(event, v) for k, v in detection.items() if k != "condition"
    }

    # Parseur de condition volontairement limité au sous-ensemble utilisé.
    expr = condition
    for name in sorted(results, key=len, reverse=True):
        expr = expr.replace(name, str(results[name]))
    expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")

    # Sécurisé : seuls True/False/and/or/not/parenthèses subsistent après substitution.
    allowed = {"True", "False", "and", "or", "not", "(", ")"}
    tokens = expr.replace("(", " ( ").replace(")", " ) ").split()
    if not set(tokens).issubset(allowed):
        raise ValueError(f"Condition non supportée: {condition} → {expr}")
    return eval(expr)  # noqa: S307 — entrée validée par la whitelist ci-dessus
