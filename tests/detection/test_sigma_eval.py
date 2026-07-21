import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from sigma_eval import evaluate_rule  # noqa: E402


def _rule(condition, **selections):
    return {"detection": {**selections, "condition": condition}}


def test_simple_and():
    rule = _rule("a and b", a={"F|contains": "x"}, b={"F|contains": "y"})
    assert evaluate_rule(rule, {"F": "xy"}) is True
    assert evaluate_rule(rule, {"F": "x"}) is False


def test_and_not():
    rule = _rule("sel and not filt", sel={"F|contains": "x"}, filt={"F|contains": "z"})
    assert evaluate_rule(rule, {"F": "x"}) is True
    assert evaluate_rule(rule, {"F": "xz"}) is False


def test_short_names_that_are_operator_substrings():
    """Noms courts (`no` ⊂ `not`, `a` ⊂ `and`) : le tokenizer ne les corrompt pas."""
    rule = _rule("a and not no", a={"F|contains": "x"}, no={"F|contains": "z"})
    assert evaluate_rule(rule, {"F": "x"}) is True
    assert evaluate_rule(rule, {"F": "xz"}) is False


def test_parentheses_or():
    rule = _rule(
        "(a or b) and not c",
        a={"F|contains": "x"},
        b={"F|contains": "y"},
        c={"F|contains": "z"},
    )
    assert evaluate_rule(rule, {"F": "y"}) is True
    assert evaluate_rule(rule, {"F": "yz"}) is False


def test_unknown_token_raises():
    rule = _rule("a and ghost", a={"F|contains": "x"})
    with pytest.raises(ValueError):
        evaluate_rule(rule, {"F": "x"})


def test_injection_in_condition_raises():
    rule = _rule("__import__", a={"F|contains": "x"})
    with pytest.raises(ValueError):
        evaluate_rule(rule, {"F": "x"})
