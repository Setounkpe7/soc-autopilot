import pytest
from jinja2.exceptions import SecurityError, UndefinedError

from soc_autopilot.engine.resolver import evaluate, render


def test_render_simple():
    ctx = {"alert": {"agent": {"name": "WS-042"}}}
    assert render("{{ alert.agent.name }}", ctx) == "WS-042"


def test_evaluate_condition_true():
    assert evaluate("{{ score > 5 }}", {"score": 9}) is True


def test_evaluate_condition_false():
    assert evaluate("{{ score > 5 }}", {"score": 1}) is False


def test_missing_variable_raises():
    ctx = {"alert": {"agent": {"name": "WS-042"}}}
    with pytest.raises(UndefinedError):
        render("{{ alert.agnet.name }}", ctx)


def test_sandbox_blocks_rce():
    """LE test le plus important du repo : l'évasion du bac à sable échoue."""
    with pytest.raises(SecurityError):
        render("{{ ''.__class__.__mro__[1].__subclasses__() }}", {})


def test_non_template_passthrough():
    assert render("plain", {}) == "plain"
    assert render(42, {}) == 42
