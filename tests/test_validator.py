"""Tests for the deterministic Validator gate, capability IDs, effect model,
parameter constraints, output schema, and effect escalation."""

import json
import pytest

from sigil import (
    Architect, EffectClass, HumanGate, Keyring, SigilRuntime, SigilSeal,
    ToolInvocation, Validator,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def constrained_architect(keypair):
    """Architect with real keys."""
    return Architect("architect")


@pytest.fixture
def constrained_seal(constrained_architect):
    """A seal with parameter constraints, output schema, and effect model."""
    return constrained_architect.seal(
        node_id="search_node",
        instruction="Search the user's query and return results.",
        allowed_tools=["web_search", "read_file"],
        parameter_constraints={
            "web_search": {
                "query": {"type": "string", "max_length": 200, "pattern": r"^[a-zA-Z0-9 ]+$"},
                "limit": {"type": "int", "min": 1, "max": 10},
            },
            "read_file": {
                "path": {"type": "string", "max_length": 500, "pattern": r"^/data/public/"},
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "results": {"type": "array", "maxItems": 10},
                "summary": {"type": "string", "maxLength": 1000},
            },
            "required": ["results", "summary"],
            "additionalProperties": False,
        },
        allowed_effects=[EffectClass.READ, EffectClass.NETWORK],
        escalate_effects=[EffectClass.NETWORK],
    )


@pytest.fixture
def cap_map(constrained_seal):
    """Convenience: maps tool name -> capability ID for the constrained seal."""
    return {v: k for k, v in constrained_seal.capabilities.items()}


# ---------------------------------------------------------------------------
# EffectClass
# ---------------------------------------------------------------------------

class TestEffectClass:
    def test_high_impact_set(self):
        hi = EffectClass.high_impact()
        assert EffectClass.WRITE in hi
        assert EffectClass.NETWORK in hi
        assert EffectClass.EXEC in hi
        assert EffectClass.PRIVILEGED in hi
        assert EffectClass.READ not in hi

    def test_all_values(self):
        assert set(e.value for e in EffectClass) == {"read", "write", "network", "exec", "privileged"}


# ---------------------------------------------------------------------------
# Capability ID minting
# ---------------------------------------------------------------------------

class TestCapabilityMinting:
    def test_capabilities_created_for_each_tool(self, constrained_seal):
        assert len(constrained_seal.capabilities) == 2
        tools = set(constrained_seal.capabilities.values())
        assert tools == {"web_search", "read_file"}

    def test_capability_ids_are_opaque(self, constrained_seal):
        for cap_id in constrained_seal.capabilities:
            assert cap_id.startswith("cap_")
            assert len(cap_id) == 16  # "cap_" + 12 hex chars

    def test_parameter_constraints_keyed_by_capability_id(self, constrained_seal):
        for cap_id in constrained_seal.parameter_constraints:
            assert cap_id in constrained_seal.capabilities

    def test_constraint_for_missing_tool_raises(self, constrained_architect):
        with pytest.raises(ValueError, match="not in allowed_tools"):
            constrained_architect.seal(
                node_id="bad",
                instruction="test",
                allowed_tools=["web_search"],
                parameter_constraints={
                    "nonexistent_tool": {"x": {"type": "string"}},
                },
            )

    def test_capabilities_in_canonical_payload(self, constrained_seal):
        payload = json.loads(constrained_seal.canonical_payload())
        assert "capabilities" in payload
        assert "parameter_constraints" in payload
        assert "output_schema" in payload
        assert "allowed_effects" in payload


# ---------------------------------------------------------------------------
# Parameter constraint validation
# ---------------------------------------------------------------------------

class TestParameterValidation:
    @pytest.fixture(autouse=True)
    def _register_effects(self):
        Validator.register_tool_effects({
            "web_search": EffectClass.NETWORK,
            "read_file": EffectClass.READ,
        })

    def test_valid_string_param(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "hello world", "limit": 5},
        )
        result = Validator.validate_invocation(constrained_seal, inv)
        assert result.resolved_tool == "web_search"

    def test_string_too_long(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "a" * 201, "limit": 5},
        )
        with pytest.raises(ValueError, match="max_length"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_string_pattern_mismatch(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "DROP TABLE users;", "limit": 5},
        )
        with pytest.raises(ValueError, match="pattern"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_int_below_min(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "test", "limit": 0},
        )
        with pytest.raises(ValueError, match="minimum"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_int_above_max(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "test", "limit": 999},
        )
        with pytest.raises(ValueError, match="maximum"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_wrong_type(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "test", "limit": "five"},
        )
        with pytest.raises(ValueError, match="expected int"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_unexpected_parameter_rejected(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "test", "limit": 5, "injected": "evil"},
        )
        with pytest.raises(ValueError, match="Unexpected parameters"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_path_traversal_blocked(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["read_file"],
            parameters={"path": "/etc/shadow"},
        )
        with pytest.raises(ValueError, match="pattern"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_valid_path(self, constrained_seal, cap_map):
        inv = ToolInvocation(
            capability_id=cap_map["read_file"],
            parameters={"path": "/data/public/report.csv"},
        )
        result = Validator.validate_invocation(constrained_seal, inv)
        assert result.resolved_tool == "read_file"


# ---------------------------------------------------------------------------
# Capability ID resolution
# ---------------------------------------------------------------------------

class TestCapabilityResolution:
    def test_unknown_capability_rejected(self, constrained_seal):
        inv = ToolInvocation(capability_id="cap_doesnotexist", parameters={})
        with pytest.raises(ValueError, match="Unknown capability ID"):
            Validator.validate_invocation(constrained_seal, inv)

    def test_real_tool_name_rejected(self, constrained_seal):
        """LLM cannot use tool names directly — only capability IDs."""
        inv = ToolInvocation(capability_id="web_search", parameters={})
        with pytest.raises(ValueError, match="Unknown capability ID"):
            Validator.validate_invocation(constrained_seal, inv)


# ---------------------------------------------------------------------------
# Effect class enforcement (deny-by-default)
# ---------------------------------------------------------------------------

class TestEffectEnforcement:
    def test_allowed_effect_passes(self, constrained_seal, cap_map):
        Validator.register_tool_effect("web_search", EffectClass.NETWORK)
        Validator.register_tool_effect("read_file", EffectClass.READ)
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "test", "limit": 5},
        )
        result = Validator.validate_invocation(constrained_seal, inv)
        assert result.effect_class == EffectClass.NETWORK

    def test_disallowed_effect_denied(self, constrained_architect, cap_map):
        """A seal that only allows READ should deny WRITE tools."""
        Validator.register_tool_effect("delete_file", EffectClass.WRITE)
        seal = constrained_architect.seal(
            node_id="readonly",
            instruction="Read only",
            allowed_tools=["delete_file"],
            allowed_effects=[EffectClass.READ],
        )
        inv_cap = list(seal.capabilities.keys())[0]
        inv = ToolInvocation(capability_id=inv_cap, parameters={})
        with pytest.raises(PermissionError, match="not permitted"):
            Validator.validate_invocation(seal, inv)

    def test_unregistered_tool_defaults_to_privileged(self, constrained_architect):
        """Unregistered tools get PRIVILEGED effect — denied unless explicitly allowed."""
        seal = constrained_architect.seal(
            node_id="unknown_tool",
            instruction="test",
            allowed_tools=["mystery_tool"],
            allowed_effects=[EffectClass.READ],
        )
        inv_cap = list(seal.capabilities.keys())[0]
        inv = ToolInvocation(capability_id=inv_cap, parameters={})
        with pytest.raises(PermissionError, match="not permitted"):
            Validator.validate_invocation(seal, inv)

    def test_empty_allowed_effects_denies_everything(self, constrained_architect):
        """No allowed_effects = no tool invocations permitted."""
        Validator.register_tool_effect("web_search", EffectClass.NETWORK)
        seal = constrained_architect.seal(
            node_id="no_effects",
            instruction="text only",
            allowed_tools=["web_search"],
            allowed_effects=[],
        )
        inv_cap = list(seal.capabilities.keys())[0]
        inv = ToolInvocation(capability_id=inv_cap, parameters={})
        with pytest.raises(PermissionError, match="not permitted"):
            Validator.validate_invocation(seal, inv)


# ---------------------------------------------------------------------------
# Output schema validation
# ---------------------------------------------------------------------------

class TestOutputSchema:
    def test_valid_output(self, constrained_seal):
        output = {"results": [{"title": "A"}], "summary": "Found one result"}
        Validator.validate_output(constrained_seal, output)

    def test_missing_required_field(self, constrained_seal):
        output = {"results": []}
        with pytest.raises(ValueError, match="missing required"):
            Validator.validate_output(constrained_seal, output)

    def test_extra_field_rejected(self, constrained_seal):
        output = {"results": [], "summary": "ok", "injected": "evil"}
        with pytest.raises(ValueError, match="disallowed extra"):
            Validator.validate_output(constrained_seal, output)

    def test_array_too_many_items(self, constrained_seal):
        output = {"results": list(range(11)), "summary": "ok"}
        with pytest.raises(ValueError, match="maxItems"):
            Validator.validate_output(constrained_seal, output)

    def test_string_too_long(self, constrained_seal):
        output = {"results": [], "summary": "x" * 1001}
        with pytest.raises(ValueError, match="max_length"):
            Validator.validate_output(constrained_seal, output)

    def test_wrong_type(self, constrained_seal):
        output = "not an object"
        with pytest.raises(ValueError, match="must be an object"):
            Validator.validate_output(constrained_seal, output)

    def test_no_schema_is_noop(self, constrained_architect):
        seal = constrained_architect.seal(
            node_id="no_schema", instruction="test", allowed_tools=[],
        )
        Validator.validate_output(seal, {"anything": "goes"})


# ---------------------------------------------------------------------------
# Effect escalation
# ---------------------------------------------------------------------------

class TestEffectEscalation:
    def test_escalation_needed(self, constrained_seal, cap_map):
        Validator.register_tool_effect("web_search", EffectClass.NETWORK)
        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "test", "limit": 5},
        )
        validated = Validator.validate_invocation(constrained_seal, inv)
        assert Validator.check_escalation(constrained_seal, validated) is True

    def test_no_escalation_for_read(self, constrained_seal, cap_map):
        Validator.register_tool_effect("read_file", EffectClass.READ)
        inv = ToolInvocation(
            capability_id=cap_map["read_file"],
            parameters={"path": "/data/public/test.txt"},
        )
        validated = Validator.validate_invocation(constrained_seal, inv)
        assert Validator.check_escalation(constrained_seal, validated) is False


# ---------------------------------------------------------------------------
# SigilSeal serialization with new fields
# ---------------------------------------------------------------------------

class TestSealSerialization:
    def test_round_trip(self, constrained_seal):
        """Seal -> dict -> from_dict preserves new fields."""
        from dataclasses import asdict
        d = asdict(constrained_seal)
        restored = SigilSeal.from_dict(d)
        assert restored.capabilities == constrained_seal.capabilities
        assert restored.parameter_constraints == constrained_seal.parameter_constraints
        assert restored.output_schema == constrained_seal.output_schema
        assert restored.allowed_effects == constrained_seal.allowed_effects
        assert restored.escalate_effects == constrained_seal.escalate_effects

    def test_invalid_effect_class_rejected(self):
        with pytest.raises(ValueError, match="unknown effect class"):
            SigilSeal.from_dict({
                "node_id": "x",
                "instruction": "y",
                "allowed_effects": ["invalid_effect"],
            })

    def test_signature_integrity_with_new_fields(self, constrained_seal, sentinel):
        """Seal signature covers all new fields."""
        valid, msg = sentinel.verify(constrained_seal)
        assert valid

        # Tamper with allowed_effects — signature must break
        constrained_seal.allowed_effects.append("privileged")
        valid, msg = sentinel.verify(constrained_seal)
        assert not valid


# ---------------------------------------------------------------------------
# validate_and_execute integration
# ---------------------------------------------------------------------------

class TestValidateAndExecute:
    def test_full_path(self, keypair, constrained_seal, cap_map):
        Validator.register_tool_effect("web_search", EffectClass.NETWORK)
        Validator.register_tool_effect("read_file", EffectClass.READ)

        # Need operator key for escalation
        Keyring.generate("operator")

        runtime = SigilRuntime("architect")
        runtime.load_seal(constrained_seal)

        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "hello", "limit": 3},
        )
        output = {"results": [{"title": "A"}], "summary": "Found one"}

        result = runtime.validate_and_execute(
            node_id="search_node",
            user_input="search for hello",
            proposed_invocations=[inv],
            llm_output=output,
        )

        assert len(result["validated_invocations"]) == 1
        vi = result["validated_invocations"][0]
        assert vi["resolved_tool"] == "web_search"
        assert vi["effect_class"] == "network"
        # NETWORK is in escalate_effects, so approval should be requested
        assert len(result["escalation_approvals"]) == 1

    def test_bad_invocation_blocks_all(self, keypair, constrained_seal, cap_map):
        Validator.register_tool_effect("web_search", EffectClass.NETWORK)
        runtime = SigilRuntime("architect")
        runtime.load_seal(constrained_seal)

        inv = ToolInvocation(
            capability_id=cap_map["web_search"],
            parameters={"query": "DROP TABLE;", "limit": 5},
        )

        with pytest.raises(ValueError, match="pattern"):
            runtime.validate_and_execute(
                "search_node", "input", proposed_invocations=[inv],
            )

    def test_bad_output_blocks(self, keypair, constrained_seal):
        Validator.register_tool_effect("web_search", EffectClass.NETWORK)
        runtime = SigilRuntime("architect")
        runtime.load_seal(constrained_seal)

        with pytest.raises(ValueError, match="missing required"):
            runtime.validate_and_execute(
                "search_node", "input",
                proposed_invocations=[],
                llm_output={"results": []},  # missing "summary"
            )
