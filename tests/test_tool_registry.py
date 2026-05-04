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
    """execute() raises ValueError for unregistered tool when seal allowlists it."""
    registry = ToolRegistry()
    seal = _make_seal(allowed_tools=["nonexistent"])
    with pytest.raises(ValueError, match="Unknown tool"):
        registry.execute("nonexistent", seal)


def test_get_available_empty_allowlist_returns_nothing():
    """RT-2026-05-01-001: empty allowed_tools means no tools, not all tools."""
    registry = ToolRegistry()

    @registry.register("tool_a", "Tool A")
    def tool_a():
        pass

    @registry.register("tool_b", "Tool B")
    def tool_b():
        pass

    seal = _make_seal(allowed_tools=[])
    available = registry.get_available(seal)
    assert available == []


def test_execute_empty_allowlist_denies_registered_tool():
    """RT-2026-05-01-001: empty allowed_tools must deny execution of any tool."""
    registry = ToolRegistry()

    @registry.register("safe_tool", "Registered tool")
    def safe_tool():
        return "ran"

    seal = _make_seal(allowed_tools=[])
    with pytest.raises(PermissionError, match="not allowed"):
        registry.execute("safe_tool", seal)


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


# --- v1.7: close the capability-bearing-seal bypass on ToolRegistry.execute ---


def _make_capability_seal(tool_name: str = "transfer", capability_id: str = "cap_a1b2c3d4"):
    """Helper for a seal that uses the capability-ID indirection."""
    return SigilSeal(
        node_id="cap_test",
        instruction="test",
        allowed_tools=[tool_name],
        capabilities={capability_id: tool_name},
        signature="fakesig" * 8,
        signer_key_id="fakekey",
    )


def test_execute_refuses_raw_name_on_capability_bearing_seal():
    """Seals with a capabilities map specify the LLM should propose capability_ids,
    not real tool names. ToolRegistry.execute(tool_name, seal) bypasses the
    Validator path that resolves the capability and applies parameter
    constraints + effect class checks + escalation. Refuse it."""
    registry = ToolRegistry()

    @registry.register("transfer", "Transfer money")
    def transfer(**kwargs):
        return "executed"

    seal = _make_capability_seal()
    with pytest.raises(PermissionError, match="capability"):
        registry.execute("transfer", seal)


def test_execute_still_works_on_legacy_seal_without_capabilities():
    """Backwards compat: seals without a capabilities map (simple
    allowed_tools only) keep the existing execute(tool_name, seal) path."""
    registry = ToolRegistry()

    @registry.register("legacy_tool", "No capability indirection")
    def legacy_tool():
        return "ran"

    seal = _make_seal(allowed_tools=["legacy_tool"])
    assert registry.execute("legacy_tool", seal) == "ran"


def test_execute_validated_runs_resolved_tool():
    """execute_validated takes a Validator-produced ToolInvocation with
    resolved_tool already filled in and runs it. This is the supported path
    for capability-bearing seals."""
    from sigil import ToolInvocation

    registry = ToolRegistry()

    @registry.register("transfer", "Transfer money")
    def transfer(amount=0):
        return f"transferred {amount}"

    seal = _make_capability_seal()
    invocation = ToolInvocation(
        capability_id="cap_a1b2c3d4",
        parameters={"amount": 50},
        resolved_tool="transfer",
    )
    result = registry.execute_validated(seal, invocation, amount=50)
    assert result == "transferred 50"


def test_execute_validated_refuses_unresolved_invocation():
    """execute_validated requires resolved_tool to be set — that's the proof
    the invocation came through Validator.validate_invocation."""
    from sigil import ToolInvocation

    registry = ToolRegistry()
    seal = _make_capability_seal()
    bad = ToolInvocation(capability_id="cap_a1b2c3d4", parameters={})  # resolved_tool=None
    with pytest.raises(ValueError, match="resolved_tool"):
        registry.execute_validated(seal, bad)


def test_execute_validated_enforces_capability_match():
    """execute_validated must verify the invocation's capability_id is
    actually in the seal's capabilities map and resolves to the same tool —
    otherwise a forged ToolInvocation could call a different tool than
    advertised."""
    from sigil import ToolInvocation

    registry = ToolRegistry()

    @registry.register("transfer", "Transfer")
    def transfer(**kwargs):
        return "transfer-ran"

    @registry.register("delete_account", "Delete")
    def delete_account(**kwargs):
        return "delete-ran"

    seal = _make_capability_seal(tool_name="transfer", capability_id="cap_a1b2c3d4")
    forged = ToolInvocation(
        capability_id="cap_a1b2c3d4",
        parameters={},
        resolved_tool="delete_account",  # mismatch with seal.capabilities[cap_a1b2c3d4] == "transfer"
    )
    with pytest.raises(PermissionError, match="(?i)capability"):
        registry.execute_validated(seal, forged)
