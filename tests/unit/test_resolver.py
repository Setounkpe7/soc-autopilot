import pytest
from jinja2.exceptions import SecurityError

from soc_autopilot.engine.resolver import evaluate, render, render_dict


def test_render_simple():
    ctx = {"alert": {"agent": {"name": "WS-042"}}}
    assert render("{{ alert.agent.name }}", ctx) == "WS-042"


def test_evaluate_condition_true():
    assert evaluate("{{ score > 5 }}", {"score": 9}) is True


def test_evaluate_condition_false():
    assert evaluate("{{ score > 5 }}", {"score": 1}) is False


def test_missing_enrichment_is_tolerant():
    """Contrat: l'enrichissement est best-effort (`on_error: continue`). Un champ
    absent — intel/contexte/VT en échec → sortie None — doit rendre "" (falsy)
    au lieu de lever, sinon un enrichissement raté ferait crasher tout le playbook
    de RÉPONSE en aval. Les champs critiques restent gardés par `on_error: fail`.
    (Compromis assumé : StrictUndefined → ChainableUndefined ; les fautes de frappe
    de template ne lèvent plus, mais la structure des playbooks est validée au chargement.)"""
    ctx = {"alert": {"agent": {"name": "WS-042"}}}
    # variable de premier niveau absente
    assert render("{{ alert.agnet.name }}", ctx) == ""
    # chaînage sur un enrichissement en échec (output None) : ne lève pas
    none_ctx = {"steps": {"vt": {"output": None}}}
    assert render("{{ steps.vt.output.worst_verdict }}", none_ctx) == ""
    assert (
        evaluate("{{ steps.vt.output.worst_verdict == 'malicious' }}", none_ctx)
        is False
    )


def test_sandbox_blocks_rce():
    """LE test le plus important du repo : l'évasion du bac à sable échoue."""
    with pytest.raises(SecurityError):
        render("{{ ''.__class__.__mro__[1].__subclasses__() }}", {})


def test_non_template_passthrough():
    assert render("plain", {}) == "plain"
    assert render(42, {}) == 42


def test_render_does_not_coerce_padded_ids():
    """Un id zero-paddé rendu doit rester une chaîne, pas devenir un int."""
    assert render("{{ v }}", {"v": "001"}) == "001"
    assert render("{{ v }}", {"v": "true"}) == "true"


def test_evaluate_still_coerces_numeric_and_bool():
    assert evaluate("{{ v }}", {"v": "true"}) is True
    assert evaluate("{{ n }}", {"n": 0}) is False


def test_render_dict_recurses_into_list_of_dicts():
    """Les boosters (liste de dicts) doivent être rendus, pas laissés bruts."""
    data = {"boosters": [{"when": "{{ flag }}", "points": 2}]}
    out = render_dict(data, {"flag": True})
    assert out["boosters"][0]["when"] == "True"
    assert out["boosters"][0]["points"] == 2
