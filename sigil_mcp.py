#!/usr/bin/env python3
"""Minimal stdio MCP trust wrapper for SIGIL receipt conformance."""

import copy
import hashlib
import json
import sys
from typing import Any, Callable, Dict, IO, List, Optional, Sequence

from sigil import EffectClass, Sentinel, SigilSeal, ToolInvocation, Validator
from sigil_receipts import ReceiptStore, canonical_json


MAX_MESSAGE_BYTES = 1024 * 1024


def _reject_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"Duplicate JSON-RPC key: {key}")
        result[key] = value
    return result


class MCPTrustWrapper:
    """Gate MCP tool calls against one seal and emit portable receipts."""

    def __init__(
        self,
        seal: SigilSeal,
        tool_manifest: Sequence[Dict[str, Any]],
        dispatch: Callable[[str, Dict[str, Any]], Any],
        sentinel: Optional[Sentinel] = None,
    ):
        if sentinel is None:
            raise PermissionError("MCP seal verification requires a Sentinel")
        self._sentinel = sentinel
        self.seal = copy.deepcopy(seal)
        self._verify_seal()
        self.dispatch = dispatch
        self._tools: Dict[str, Dict[str, Any]] = {}
        for item in tool_manifest:
            if not isinstance(item, dict):
                raise ValueError("Each MCP tool manifest entry must be an object")
            name = item.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("Each MCP tool manifest entry needs a name")
            if name in self._tools:
                raise ValueError(f"Duplicate MCP tool name: {name}")
            self._tools[name] = copy.deepcopy(item)

    def _verify_seal(self) -> None:
        valid, _ = self._sentinel.verify(self.seal, refresh_crl=True)
        if not valid:
            raise PermissionError("MCP seal verification failed")

    def _authorized_tool_names(self) -> set:
        return set(self.seal.capabilities.values())

    def _tool_manifest_hash(self, name: str) -> str:
        tool = self._tools.get(name)
        if tool is None:
            return hashlib.sha256(canonical_json({"name": name})).hexdigest()
        return hashlib.sha256(canonical_json(tool)).hexdigest()

    def _capability_for(self, name: str) -> Optional[str]:
        matches = [
            capability_id
            for capability_id, tool_name in self.seal.capabilities.items()
            if tool_name == name
        ]
        if len(matches) > 1:
            raise ValueError(f"MCP tool {name} has ambiguous capability mappings")
        return matches[0] if matches else None

    @staticmethod
    def _error(
        request_id: Any,
        code: int,
        message: str,
        receipt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        error: Dict[str, Any] = {"code": code, "message": message}
        if receipt is not None:
            error["data"] = {"poe_receipt": receipt}
        return {"jsonrpc": "2.0", "id": request_id, "error": error}

    def _emit_denial(
        self,
        name: str,
        arguments: Dict[str, Any],
        capability_id: Optional[str],
        reason: str,
        parent_receipt_id: Optional[str],
    ) -> Dict[str, Any]:
        effect = Validator.get_tool_effect(name)
        return ReceiptStore.emit(
            receipt_type="mcp_call",
            action=name,
            decision="deny",
            effect_class=effect.value,
            arguments=arguments,
            actor_id=self.seal.node_id,
            seal_hash=self.seal.content_hash(),
            capability_id=capability_id,
            policy_hash=self.seal.content_hash(),
            tool_manifest_hash=self._tool_manifest_hash(name),
            parent_receipt_id=parent_receipt_id,
            metadata={"reason": reason},
        )

    def _handle_call(self, request_id: Any, params: Any) -> Dict[str, Any]:
        if not isinstance(params, dict):
            return self._error(request_id, -32602, "tools/call params must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        request_meta = params.get("_meta", {})
        if not isinstance(name, str) or not name:
            return self._error(request_id, -32602, "tools/call name is required")
        if not isinstance(arguments, dict):
            return self._error(request_id, -32602, "tools/call arguments must be an object")
        if not isinstance(request_meta, dict):
            return self._error(request_id, -32602, "tools/call _meta must be an object")
        parent_receipt_id = request_meta.get("poe_parent_receipt_id")
        if parent_receipt_id is not None and not isinstance(parent_receipt_id, str):
            return self._error(
                request_id, -32602, "poe_parent_receipt_id must be a string"
            )
        if parent_receipt_id is not None:
            try:
                ReceiptStore.get(parent_receipt_id)
            except (KeyError, ValueError):
                receipt = self._emit_denial(
                    name, arguments, None, "invalid_delegation_parent", None
                )
                return self._error(
                    request_id, -32602, "Delegation parent is invalid", receipt
                )

        try:
            capability_id = self._capability_for(name)
        except ValueError as exc:
            receipt = self._emit_denial(
                name, arguments, None, "ambiguous_capability", parent_receipt_id
            )
            return self._error(request_id, -32602, str(exc), receipt)
        if capability_id is None or name not in self._tools:
            receipt = self._emit_denial(
                name, arguments, capability_id, "unauthorized_tool", parent_receipt_id
            )
            return self._error(request_id, -32602, "Tool is not authorized", receipt)

        invocation = ToolInvocation(capability_id, copy.deepcopy(arguments))
        try:
            validated = Validator.validate_invocation(self.seal, invocation)
        except (PermissionError, ValueError) as exc:
            receipt = self._emit_denial(
                name,
                arguments,
                capability_id,
                type(exc).__name__,
                parent_receipt_id,
            )
            return self._error(request_id, -32602, "Tool call rejected by policy", receipt)

        if Validator.check_escalation(self.seal, validated):
            receipt = self._emit_denial(
                name,
                arguments,
                capability_id,
                "human_approval_required",
                parent_receipt_id,
            )
            return self._error(
                request_id,
                -32002,
                "Tool call requires human approval",
                receipt,
            )

        effect = validated.effect_class or EffectClass.PRIVILEGED
        decision_receipt = ReceiptStore.emit(
            receipt_type="decision",
            action=name,
            decision="allow",
            effect_class=effect.value,
            arguments=arguments,
            actor_id=self.seal.node_id,
            seal_hash=self.seal.content_hash(),
            capability_id=capability_id,
            policy_hash=self.seal.content_hash(),
            tool_manifest_hash=self._tool_manifest_hash(name),
            parent_receipt_id=parent_receipt_id,
            metadata={"transport": "stdio", "protocol_method": "tools/call"},
        )

        try:
            result = self.dispatch(name, copy.deepcopy(arguments))
        except Exception as exc:
            failure_receipt = ReceiptStore.emit(
                receipt_type="mcp_call",
                action=name,
                decision="failed",
                effect_class=effect.value,
                arguments=arguments,
                output={"error_type": type(exc).__name__},
                action_id=decision_receipt["fields"]["action_id"],
                actor_id=self.seal.node_id,
                seal_hash=self.seal.content_hash(),
                capability_id=capability_id,
                policy_hash=self.seal.content_hash(),
                tool_manifest_hash=self._tool_manifest_hash(name),
                parent_receipt_id=parent_receipt_id,
                metadata={"error_type": type(exc).__name__},
            )
            return self._error(request_id, -32000, "Tool execution failed", failure_receipt)

        try:
            outcome_receipt = ReceiptStore.emit(
                receipt_type="mcp_call",
                action=name,
                decision="succeeded",
                effect_class=effect.value,
                arguments=arguments,
                output=result,
                action_id=decision_receipt["fields"]["action_id"],
                actor_id=self.seal.node_id,
                seal_hash=self.seal.content_hash(),
                capability_id=capability_id,
                policy_hash=self.seal.content_hash(),
                tool_manifest_hash=self._tool_manifest_hash(name),
                parent_receipt_id=parent_receipt_id,
                metadata={"transport": "stdio", "protocol_method": "tools/call"},
            )
        except (TypeError, ValueError):
            unknown_receipt = ReceiptStore.emit(
                receipt_type="mcp_call",
                action=name,
                decision="outcome_unknown",
                effect_class=effect.value,
                arguments=arguments,
                action_id=decision_receipt["fields"]["action_id"],
                actor_id=self.seal.node_id,
                seal_hash=self.seal.content_hash(),
                capability_id=capability_id,
                policy_hash=self.seal.content_hash(),
                tool_manifest_hash=self._tool_manifest_hash(name),
                parent_receipt_id=parent_receipt_id,
                metadata={"reason": "noncanonical_tool_result"},
            )
            return self._error(
                request_id,
                -32003,
                "Tool completed but its result could not be committed",
                unknown_receipt,
            )
        if isinstance(result, dict):
            response_result = copy.deepcopy(result)
        else:
            response_result = {"content": result}
        response_meta = response_result.setdefault("_meta", {})
        if not isinstance(response_meta, dict):
            response_meta = {"upstream_meta": response_meta}
            response_result["_meta"] = response_meta
        response_meta["poe_receipt"] = outcome_receipt
        response_meta["poe_decision_receipt_id"] = decision_receipt["receipt_id"]
        return {"jsonrpc": "2.0", "id": request_id, "result": response_result}

    def handle(self, request: Any) -> Dict[str, Any]:
        """Handle one JSON-RPC request without reading or writing transport state."""
        if not isinstance(request, dict):
            return self._error(None, -32600, "Request must be an object")
        request_id = request.get("id")
        if request.get("jsonrpc") != "2.0":
            return self._error(request_id, -32600, "jsonrpc must be 2.0")
        method = request.get("method")
        if method == "tools/list":
            authorized = self._authorized_tool_names()
            tools: List[Dict[str, Any]] = [
                copy.deepcopy(self._tools[name])
                for name in sorted(self._tools)
                if name in authorized
            ]
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": tools},
            }
        if method == "tools/call":
            try:
                self._verify_seal()
            except PermissionError:
                return self._error(request_id, -32001, "MCP seal is no longer valid")
            return self._handle_call(request_id, request.get("params", {}))
        return self._error(request_id, -32601, "Method not found")


def serve_stdio(
    wrapper: MCPTrustWrapper,
    input_stream: IO[str] = sys.stdin,
    output_stream: IO[str] = sys.stdout,
) -> None:
    """Serve newline-delimited JSON-RPC messages over stdio."""
    while True:
        line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
        if line == "":
            return
        overlong = (
            len(line) > MAX_MESSAGE_BYTES
            or len(line.encode("utf-8")) > MAX_MESSAGE_BYTES
        )
        if overlong:
            while line and not line.endswith("\n"):
                line = input_stream.readline(MAX_MESSAGE_BYTES + 1)
            response = wrapper._error(None, -32600, "Message exceeds the size limit")
        else:
            try:
                request = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
                response = wrapper.handle(request)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                response = wrapper._error(None, -32700, "Parse error")
        output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
        output_stream.flush()
