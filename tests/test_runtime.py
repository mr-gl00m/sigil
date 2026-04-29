"""Tests for SigilRuntime seal lifecycle and replay protection."""

import json
import time

import pytest

import sigil
from sigil import (
    SigilRuntime, Architect, Keyring, SigilSeal, AuditChain,
)


def test_load_seal_valid(runtime, signed_seal):
    """load_seal() returns True for a valid seal."""
    assert runtime.load_seal(signed_seal) is True


def test_load_seal_invalid(runtime):
    """load_seal() returns False for an unsigned seal."""
    seal = SigilSeal(node_id="bad", instruction="test")
    assert runtime.load_seal(seal) is False


def test_execute_returns_correct_structure(runtime, signed_seal):
    """execute() returns dict with instruction, user_input_as_data, etc."""
    runtime.load_seal(signed_seal)
    result = runtime.execute("test_node", "Hello user input")
    assert result["instruction"] == "You are a test assistant."
    assert result["user_input_as_data"] == "Hello user input"
    assert "tool_a" in result["allowed_tools"]
    assert "tool_b" in result["allowed_tools"]
    assert result["nonce"] == signed_seal.nonce


def test_execute_unloaded_node_raises(runtime):
    """execute() raises PermissionError for unloaded node."""
    with pytest.raises(PermissionError, match="not loaded"):
        runtime.execute("nonexistent", "input")


def test_execute_reverifies_seal(architect, runtime):
    """execute() re-verifies the seal at execution time."""
    seal = architect.seal(node_id="reverify", instruction="test")
    runtime.load_seal(seal)
    # Should succeed
    result = runtime.execute("reverify", "input")
    assert result["instruction"] == "test"


def test_execute_revoked_seal_raises(architect, runtime):
    """Seal revoked after load is caught at execution time."""
    seal = architect.seal(node_id="revoked_exec", instruction="test")
    runtime.load_seal(seal)

    # Revoke the seal
    architect.revoke(seal, reason="post_load_revocation")
    # Reset CRL cache timestamp so force reload works
    runtime.sentinel._crl_cache_timestamp = 0

    with pytest.raises(PermissionError, match="re-verification"):
        runtime.execute("revoked_exec", "input")


def test_one_time_seal_executes_once(architect, runtime):
    """One-time seal can be executed exactly once."""
    seal = architect.seal(node_id="one_shot", instruction="test")
    seal.one_time = True
    # Re-sign since we changed one_time
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    runtime.load_seal(seal)
    result = runtime.execute("one_shot", "input")
    assert result["instruction"] == "test"


def test_one_time_seal_replay_raises(architect, runtime):
    """Replaying a one-time seal raises PermissionError."""
    seal = architect.seal(node_id="replay_test", instruction="test")
    seal.one_time = True
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    runtime.load_seal(seal)
    runtime.execute("replay_test", "first")

    with pytest.raises(PermissionError, match="Replay attack"):
        runtime.execute("replay_test", "second")


def test_nonce_file_created(architect, runtime):
    """Executing a one-time seal creates the nonces file."""
    seal = architect.seal(node_id="nonce_file", instruction="test")
    seal.one_time = True
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    runtime.load_seal(seal)
    runtime.execute("nonce_file", "input")

    assert sigil.EXECUTED_NONCES_FILE.exists()
    data = sigil._read_encrypted_state(sigil.EXECUTED_NONCES_FILE)
    nonces = {e["nonce"] for e in data["entries"]}
    assert seal.nonce in nonces


def test_execute_defensive_copy_tools(runtime, signed_seal):
    """execute() returns a defensive copy of allowed_tools."""
    runtime.load_seal(signed_seal)
    result = runtime.execute("test_node", "input")
    result["allowed_tools"].append("evil_tool")
    # Original seal should be unmodified
    assert "evil_tool" not in signed_seal.allowed_tools


def test_execute_defensive_copy_metadata(runtime, signed_seal):
    """execute() returns a defensive copy of metadata."""
    runtime.load_seal(signed_seal)
    result = runtime.execute("test_node", "input")
    result["metadata"]["injected"] = True
    # Original seal should be unmodified
    assert "injected" not in signed_seal.metadata


def test_load_seal_stores_in_dict(runtime, signed_seal):
    """load_seal() stores the seal in loaded_seals dict."""
    runtime.load_seal(signed_seal)
    assert "test_node" in runtime.loaded_seals
    assert runtime.loaded_seals["test_node"] is signed_seal


# --- H-06: Nonce file integrity ---


def test_nonce_logged_to_audit_chain(architect, runtime):
    """Executing a one-time seal logs nonce_reserved to audit chain."""
    seal = architect.seal(node_id="nonce_audit", instruction="test")
    seal.one_time = True
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    runtime.load_seal(seal)
    runtime.execute("nonce_audit", "input")

    content = AuditChain.LOG_FILE.read_text()
    assert "nonce_reserved" in content


def test_nonce_recovery_from_chain(architect, runtime):
    """Nonces are recovered from audit chain if nonce file is deleted."""
    seal = architect.seal(node_id="nonce_recover", instruction="test")
    seal.one_time = True
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    runtime.load_seal(seal)
    runtime.execute("nonce_recover", "input")

    # Delete the nonce file
    if sigil.EXECUTED_NONCES_FILE.exists():
        sigil.EXECUTED_NONCES_FILE.unlink()

    # Create a new runtime — should recover nonces from chain
    runtime2 = SigilRuntime("architect")
    assert seal.nonce in runtime2.executed_nonces


def test_replay_blocked_after_nonce_file_deletion(architect, runtime):
    """Replay is still blocked after nonce file deletion (recovered from chain)."""
    seal = architect.seal(node_id="nonce_replay", instruction="test")
    seal.one_time = True
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    runtime.load_seal(seal)
    runtime.execute("nonce_replay", "first")

    # Delete nonce file
    if sigil.EXECUTED_NONCES_FILE.exists():
        sigil.EXECUTED_NONCES_FILE.unlink()

    # New runtime should recover nonces and block replay
    runtime2 = SigilRuntime("architect")
    runtime2.load_seal(seal)
    with pytest.raises(PermissionError, match="Replay attack"):
        runtime2.execute("nonce_replay", "second")
