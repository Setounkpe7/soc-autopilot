import pytest

from soc_autopilot.engine import registry


def test_register_and_get():
    @registry.action("test.echo")
    async def _echo(params, ctx):
        return params

    assert registry.get_action("test.echo") is _echo
    assert "test.echo" in registry.list_actions()


def test_duplicate_registration_raises():
    @registry.action("test.dup")
    async def _a(params, ctx):
        return None

    with pytest.raises(ValueError):

        @registry.action("test.dup")
        async def _b(params, ctx):
            return None


def test_unknown_action_raises():
    with pytest.raises(KeyError):
        registry.get_action("does.not.exist")
