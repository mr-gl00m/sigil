"""Tests for the minimal stdio MCP trust wrapper."""

import hashlib
import io
import json

import pytest

import sigil_mcp
from sigil import EffectClass, SigilSeal, Validator
from sigil_mcp import MCPTrustWrapper, serve_stdio
from sigil_receipts import ReceiptStore, canonical_json


READ_TOOL = {
    "name": "read_file",
    "description": "Read one file.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}
WRITE_TOOL = {
    "name": "write_file",
    "description": "Write one file.",
    "inputSchema": {"type": "object"},
}


@pytest.fixture
def mcp_seal(architect, monkeypatch):
    monkeypatch.setitem(Validator._tool_effects, "read_file", EffectClass.READ)
    monkeypatch.setitem(Validator._tool_effects, "write_file", EffectClass.WRITE)
    return architect.seal(
        node_id="mcp_agent",
        instruction="Read authorized files.",
        allowed_tools=["read_file"],
        parameter_constraints={
            "read_file": {"path": {"type": "string", "required": True}}
        },
        allowed_effects=[EffectClass.READ],
    )


def _call(name="read_file", arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {"path": "notes.txt"}},
    }


def test_wrapper_rejects_unverified_seal(sentinel):
    forged = SigilSeal(
        node_id="forged_mcp_policy",
        instruction="Authorize an unsigned tool policy.",
        capabilities={"cap_forged": "read_file"},
        allowed_effects=[EffectClass.READ.value],
    )

    with pytest.raises(PermissionError, match="verification"):
        MCPTrustWrapper(forged, [READ_TOOL], lambda name, arguments: {})

    with pytest.raises(PermissionError, match="verification"):
        MCPTrustWrapper(
            forged,
            [READ_TOOL],
            lambda name, arguments: {},
            sentinel=sentinel,
        )


def test_allowed_call_persists_decision_before_dispatch_and_outcome_after(
    mcp_seal, sentinel
):
    def dispatch(name, arguments):
        stored = ReceiptStore.list()
        assert len(stored) == 1
        assert stored[0]["fields"]["receipt_type"] == "decision"
        assert stored[0]["fields"]["decision"] == "allow"
        return {"content": [{"type": "text", "text": "contents"}]}

    wrapper = MCPTrustWrapper(
        mcp_seal, [READ_TOOL, WRITE_TOOL], dispatch, sentinel=sentinel
    )

    response = wrapper.handle(_call())

    assert "result" in response
    receipts = ReceiptStore.list()
    assert [item["fields"]["decision"] for item in receipts] == [
        "allow",
        "succeeded",
    ]
    outcome = response["result"]["_meta"]["poe_receipt"]
    assert outcome["receipt_id"] == receipts[1]["receipt_id"]
    assert response["result"]["_meta"]["poe_decision_receipt_id"] == receipts[0][
        "receipt_id"
    ]
    assert receipts[1]["fields"]["previous_receipt_id"] == receipts[0]["receipt_id"]


def test_unauthorized_call_is_denied_without_dispatch(mcp_seal, sentinel):
    called = False

    def dispatch(name, arguments):
        nonlocal called
        called = True

    wrapper = MCPTrustWrapper(
        mcp_seal, [READ_TOOL, WRITE_TOOL], dispatch, sentinel=sentinel
    )

    response = wrapper.handle(_call("write_file", {"path": "notes.txt"}))

    assert called is False
    assert response["error"]["code"] == -32602
    receipt = response["error"]["data"]["poe_receipt"]
    assert receipt["fields"]["decision"] == "deny"
    assert ReceiptStore.list() == [receipt]


def test_escalated_effect_does_not_dispatch_without_approval(
    architect, sentinel, monkeypatch
):
    monkeypatch.setitem(Validator._tool_effects, "write_file", EffectClass.WRITE)
    seal = architect.seal(
        node_id="mcp_escalation",
        instruction="Write only after human approval.",
        allowed_tools=["write_file"],
        allowed_effects=[EffectClass.WRITE],
        escalate_effects=[EffectClass.WRITE],
    )
    dispatched = False

    def dispatch(name, arguments):
        nonlocal dispatched
        dispatched = True
        return {"ok": True}

    wrapper = MCPTrustWrapper(
        seal,
        [WRITE_TOOL],
        dispatch,
        sentinel=sentinel,
    )

    response = wrapper.handle(_call("write_file", {"path": "notes.txt"}))

    assert dispatched is False
    assert response["error"]["code"] == -32002
    receipt = response["error"]["data"]["poe_receipt"]
    assert receipt["fields"]["decision"] == "deny"
    assert receipt["fields"]["metadata"]["reason"] == "human_approval_required"


def test_tool_failure_emits_terminal_failure_receipt(mcp_seal, sentinel):
    def dispatch(name, arguments):
        raise RuntimeError("backend failed")

    wrapper = MCPTrustWrapper(mcp_seal, [READ_TOOL], dispatch, sentinel=sentinel)

    response = wrapper.handle(_call())

    assert response["error"]["code"] == -32000
    receipts = ReceiptStore.list()
    assert [item["fields"]["decision"] for item in receipts] == ["allow", "failed"]
    assert receipts[1]["fields"]["metadata"] == {"error_type": "RuntimeError"}


def test_noncanonical_result_emits_outcome_unknown(mcp_seal, sentinel):
    wrapper = MCPTrustWrapper(
        mcp_seal,
        [READ_TOOL],
        lambda name, args: {"ratio": 1.5},
        sentinel=sentinel,
    )

    response = wrapper.handle(_call())

    assert response["error"]["code"] == -32003
    receipts = ReceiptStore.list()
    assert [item["fields"]["decision"] for item in receipts] == [
        "allow",
        "outcome_unknown",
    ]
    assert receipts[1]["fields"]["action_id"] == receipts[0]["fields"]["action_id"]
    assert receipts[1]["fields"]["metadata"] == {
        "reason": "noncanonical_tool_result"
    }


def test_tools_list_exposes_only_seal_authorized_tools(mcp_seal, sentinel):
    wrapper = MCPTrustWrapper(
        mcp_seal,
        [READ_TOOL, WRITE_TOOL],
        lambda name, args: {},
        sentinel=sentinel,
    )

    response = wrapper.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )

    assert [tool["name"] for tool in response["result"]["tools"]] == ["read_file"]


def test_receipt_pins_exact_tool_manifest(mcp_seal, sentinel):
    wrapper = MCPTrustWrapper(
        mcp_seal,
        [READ_TOOL],
        lambda name, args: {"ok": True},
        sentinel=sentinel,
    )

    wrapper.handle(_call())

    expected = hashlib.sha256(canonical_json(READ_TOOL)).hexdigest()
    assert all(
        item["fields"]["tool_manifest_hash"] == expected
        for item in ReceiptStore.list()
    )


def test_stdio_transport_round_trip(mcp_seal, sentinel):
    wrapper = MCPTrustWrapper(
        mcp_seal,
        [READ_TOOL],
        lambda name, args: {"ok": True},
        sentinel=sentinel,
    )
    input_stream = io.StringIO(json.dumps(_call()) + "\n")
    output_stream = io.StringIO()

    serve_stdio(wrapper, input_stream, output_stream)

    response = json.loads(output_stream.getvalue())
    assert response["result"]["ok"] is True
    assert "poe_receipt" in response["result"]["_meta"]


def test_stdio_transport_rejects_duplicate_json_keys(mcp_seal, sentinel):
    wrapper = MCPTrustWrapper(
        mcp_seal,
        [READ_TOOL],
        lambda name, args: {"ok": True},
        sentinel=sentinel,
    )
    input_stream = io.StringIO(
        '{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
    )
    output_stream = io.StringIO()

    serve_stdio(wrapper, input_stream, output_stream)

    response = json.loads(output_stream.getvalue())
    assert response["error"]["code"] == -32700


def test_stdio_caps_allocation_before_newline(mcp_seal, sentinel, monkeypatch):
    monkeypatch.setattr(sigil_mcp, "MAX_MESSAGE_BYTES", 64)
    wrapper = MCPTrustWrapper(
        mcp_seal,
        [READ_TOOL],
        lambda name, args: {"ok": True},
        sentinel=sentinel,
    )
    valid = json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        separators=(",", ":"),
    )
    source = io.StringIO("x" * 100 + "\n" + valid + "\n")

    class GuardedStream:
        def __iter__(self):
            raise AssertionError("serve_stdio used unbounded stream iteration")

        def readline(self, size=-1):
            assert 0 < size <= sigil_mcp.MAX_MESSAGE_BYTES + 1
            return source.readline(size)

    output_stream = io.StringIO()

    serve_stdio(wrapper, GuardedStream(), output_stream)

    responses = [json.loads(line) for line in output_stream.getvalue().splitlines()]
    assert responses[0]["error"]["code"] == -32600
    assert responses[1]["id"] == 2
