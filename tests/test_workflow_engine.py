"""Tests for WorkflowEngine multi-step orchestration."""

import pytest

from sigil import Architect, SigilRuntime
from sigil_llm_adapter import WorkflowEngine, WorkflowNode


@pytest.fixture
def workflow_setup(keypair):
    """Set up architect, runtime, and engine for workflow tests."""
    architect = Architect("architect")
    runtime = SigilRuntime("architect")
    engine = WorkflowEngine(runtime)

    seal_a = architect.seal(node_id="step_a", instruction="Do step A")
    seal_b = architect.seal(node_id="step_b", instruction="Do step B")

    nodes = {
        "step_a": WorkflowNode(seal=seal_a, transitions={"next": "step_b"}),
        "step_b": WorkflowNode(seal=seal_b, transitions={}),
    }
    return engine, nodes, architect, runtime


def test_register_workflow_valid(workflow_setup):
    """register_workflow succeeds with valid sealed nodes."""
    engine, nodes, _, _ = workflow_setup
    engine.register_workflow("test_wf", nodes)
    assert "test_wf" in engine.workflows


def test_register_workflow_invalid_seal(keypair):
    """register_workflow raises if any seal is invalid."""
    runtime = SigilRuntime("architect")
    engine = WorkflowEngine(runtime)

    bad_seal = WorkflowNode(
        seal=__import__("sigil").SigilSeal(node_id="bad", instruction="unsigned"),
    )
    with pytest.raises(ValueError, match="failed signature"):
        engine.register_workflow("bad_wf", {"bad": bad_seal})


def test_start_creates_state(workflow_setup):
    """start() creates and returns a WorkflowState."""
    engine, nodes, _, _ = workflow_setup
    engine.register_workflow("wf1", nodes)
    state = engine.start("wf1", "step_a", initial_context={"key": "val"})
    assert state.workflow_id == "wf1"
    assert state.current_node == "step_a"
    assert state.context_data == {"key": "val"}


def test_step_returns_context_string(workflow_setup):
    """step() returns a context string containing workflow state."""
    engine, nodes, _, _ = workflow_setup
    engine.register_workflow("wf2", nodes)
    state = engine.start("wf2", "step_a")
    context, next_node = engine.step(state, "user input")
    assert "<SIGIL_TRUST_BOUNDARY>" in context
    assert "WORKFLOW_STATE" in context
    assert "step_a" in context


def test_step_increments_step_count(workflow_setup):
    """step() increments the step_count on the state."""
    engine, nodes, _, _ = workflow_setup
    engine.register_workflow("wf3", nodes)
    state = engine.start("wf3", "step_a")
    assert state.step_count == 0
    engine.step(state, "input")
    assert state.step_count == 1


def test_step_adds_to_history(workflow_setup):
    """step() adds user input to the state history."""
    engine, nodes, _, _ = workflow_setup
    engine.register_workflow("wf4", nodes)
    state = engine.start("wf4", "step_a")
    engine.step(state, "my input")
    assert len(state.history) == 1
    assert state.history[0]["content"] == "my input"
