"""Tests for ToolRegistry permission enforcement."""

import pytest

from sigil import SigilSeal
from sigil_llm_adapter import ToolRegistry


def _make_seal(allowed_tools=None):
    """Helper to create a minimal seal."""
    return SigilSeal(
        node_id="tool_test",
        instruction="test",
        allowed_tools=allowed_tools or [],
        signature="fakesig" * 8,
        signer_key_id="fakekey",
    )


def test_register_adds_tool():
    """register() adds a callable tool to the registry."""
    registry = ToolRegistry()

    @registry.register("my_tool", "A test tool")
    def my_tool():
        return 42

    assert "my_tool" in registry.tools


def test_execute_allowed_tool():
    """execute() runs the tool when seal allows it."""
    registry = ToolRegistry()

    @registry.register("allowed", "Allowed tool")
    def allowed(x=1):
        return x * 2

    seal = _make_seal(allowed_tools=["allowed"])
    result = registry.execute("allowed", seal, x=5)
    assert result == 10


def test_execute_disallowed_tool():
    """execute() raises PermissionError when tool not in seal's allowed list."""
    registry = ToolRegistry()

    @registry.register("blocked", "Blocked tool")
    def blocked():
        return "should not run"

    seal = _make_seal(allowed_tools=["other_tool"])
    with pytest.raises(PermissionError, match="not allowed"):
        registry.execute("blocked", seal)


def test_execute_unknown_tool():
    """execute() raises ValueError for unregistered tool."""
    registry = ToolRegistry()
    seal = _make_seal(allowed_tools=[])
    with pytest.raises(ValueError, match="Unknown tool"):
        registry.execute("nonexistent", seal)


def test_get_available_no_restrictions():
    """get_available() returns all tools if seal has empty allowed_tools."""
    registry = ToolRegistry()

    @registry.register("tool_a", "Tool A")
    def tool_a():
        pass

    @registry.register("tool_b", "Tool B")
    def tool_b():
        pass

    seal = _make_seal(allowed_tools=[])
    available = registry.get_available(seal)
    assert len(available) == 2


def test_get_available_filters_by_seal():
    """get_available() only returns tools in seal's allowed_tools."""
    registry = ToolRegistry()

    @registry.register("tool_a", "Tool A")
    def tool_a():
        pass

    @registry.register("tool_b", "Tool B")
    def tool_b():
        pass

    seal = _make_seal(allowed_tools=["tool_a"])
    available = registry.get_available(seal)
    assert len(available) == 1
    assert available[0]["name"] == "tool_a"


def test_register_preserves_function():
    """register() decorator preserves the original function."""
    registry = ToolRegistry()

    @registry.register("preserved", "Test")
    def my_func():
        return "original"

    assert my_func() == "original"


def test_tool_schema_stored():
    """register() stores the tool schema with name, description, parameters."""
    registry = ToolRegistry()
    params = {"input": "string"}

    @registry.register("schema_test", "A tool with params", parameters=params)
    def schema_tool():
        pass

    schema = registry.tool_schemas["schema_test"]
    assert schema["name"] == "schema_test"
    assert schema["description"] == "A tool with params"
    assert schema["parameters"] == params
