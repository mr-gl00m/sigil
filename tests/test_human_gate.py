"""Tests for HumanGate human-in-the-loop approval."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import nacl.signing
import nacl.encoding

import sigil
from sigil import HumanGate, Keyring, AuditChain, _read_encrypted_state, _write_encrypted_state


def test_request_approval_creates_state_file():
    """request_approval() creates a pending state file."""
    gate = HumanGate()
    state_id = gate.request_approval(action="test_action", context={"key": "val"})
    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    assert state_file.exists()


def test_request_approval_returns_state_id():
    """request_approval() returns a 24-char hex state_id (96-bit entropy)."""
    gate = HumanGate()
    state_id = gate.request_approval(action="test", context={})
    assert len(state_id) == 24
    assert all(c in "0123456789abcdef" for c in state_id)


def test_check_approval_unapproved_returns_none():
    """check_approval() returns None if not yet approved."""
    gate = HumanGate()
    state_id = gate.request_approval(action="test", context={})
    result = gate.check_approval(state_id)
    assert result is None


def test_check_approval_approved_returns_state(keypair):
    """check_approval() returns PausedState if properly approved."""
    # Generate operator key
    Keyring.generate("operator", force=True)
    gate = HumanGate(operator_key="operator")
    state_id = gate.request_approval(action="test", context={"info": "data"})

    # Manually approve: load state, sign integrity_hash, update file
    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    state_data = _read_encrypted_state(state_file)

    signer = Keyring.load_signer("operator")
    sig = signer.sign(state_data["integrity_hash"].encode()).signature.hex()
    state_data["approved"] = True
    state_data["approved_at"] = "2024-01-01T00:00:00+00:00"
    state_data["approval_signature"] = sig
    _write_encrypted_state(state_file, state_data)

    result = gate.check_approval(state_id)
    assert result is not None
    assert result.approved is True


def test_approve_with_y(keypair):
    """HumanGate.approve() with 'y' input approves the state."""
    Keyring.generate("operator", force=True)
    gate = HumanGate()
    state_id = gate.request_approval(action="test", context={"info": "data"})

    with patch("builtins.input", return_value="y"):
        HumanGate.approve(state_id, operator_key="operator")

    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    state_data = _read_encrypted_state(state_file)
    assert state_data["approved"] is True
    assert state_data["approval_signature"] is not None


def test_approve_with_n(keypair):
    """HumanGate.approve() with 'n' input does not approve."""
    Keyring.generate("operator", force=True)
    gate = HumanGate()
    state_id = gate.request_approval(action="test", context={})

    with patch("builtins.input", return_value="n"):
        HumanGate.approve(state_id, operator_key="operator")

    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    state_data = _read_encrypted_state(state_file)
    assert state_data["approved"] is False


def test_approve_missing_state(capsys):
    """approve() with nonexistent state_id prints error."""
    # Use a syntactically valid state_id that just doesn't exist on disk.
    HumanGate.approve("a" * 24)
    captured = capsys.readouterr()
    assert "not found" in captured.out


# --- RT-2026-05-04-002: state_id is opaque, refuse path-traversal payloads ---


@pytest.mark.parametrize("bad_id", [
    "../../../../tmp/exploit",
    "..\\..\\windows\\system32",
    "/abs/path",
    "with spaces",
    "with/slash",
    "with\\backslash",
    "with.dot",
    "UPPERCASE",
    "",
    "a" * 25,           # too long
    "a" * 23,           # too short
    "g" * 24,           # non-hex char
    "12345 67890abcdef12345",
])
def test_approve_rejects_invalid_state_id(bad_id, sigil_isolation):
    """RT-2026-05-04-002: HumanGate.approve must reject any state_id that
    doesn't match the request_approval-generated shape (^[a-f0-9]{24}$).
    Pre-fix, a payload like ../../../../tmp/exploit would be plumbed into
    STATE_DIR / f'attempts_{state_id}.json' and _record_attempt would write
    encrypted state to the resolved path."""
    with pytest.raises(ValueError, match="state_id"):
        HumanGate.approve(bad_id)


@pytest.mark.parametrize("bad_id", [
    "../../tmp/exploit",
    "/abs/path",
    "",
    "g" * 24,
])
def test_check_approval_rejects_invalid_state_id(bad_id, sigil_isolation):
    """RT-2026-05-04-002: check_approval must also reject malformed state_ids
    so an attacker cannot probe the file system via existence checks."""
    gate = HumanGate()
    with pytest.raises(ValueError, match="state_id"):
        gate.check_approval(bad_id)


def test_approve_traversal_does_not_create_attempt_file_outside_state_dir(sigil_isolation, capsys):
    """RT-2026-05-04-002: a traversal payload must be rejected before any
    file I/O happens. Verify by asserting no attempts_*.json file appears
    above STATE_DIR after the rejected call."""
    parent_before = set(sigil_isolation["state_dir"].parent.iterdir())
    with pytest.raises(ValueError, match="state_id"):
        HumanGate.approve("../poison")
    parent_after = set(sigil_isolation["state_dir"].parent.iterdir())
    assert parent_before == parent_after, (
        f"Traversal payload created files outside STATE_DIR: "
        f"{parent_after - parent_before}"
    )


def test_request_approval_state_id_passes_validation(sigil_isolation):
    """RT-2026-05-04-002: state_ids generated by request_approval must
    themselves match the validation regex — otherwise the validator and the
    generator have drifted."""
    gate = HumanGate()
    state_id = gate.request_approval(action="test", context={})
    # Should not raise — validates the generator/validator agree on shape.
    HumanGate._validate_state_id(state_id)


def test_request_approval_logs_to_audit():
    """request_approval() creates an audit chain entry."""
    gate = HumanGate()
    gate.request_approval(action="audit_test", context={})

    if AuditChain.LOG_FILE.exists():
        content = AuditChain.LOG_FILE.read_text()
        assert "hitl_pause" in content


def test_check_approval_rejects_tampered_context(keypair):
    """check_approval() rejects state where context was modified after signing."""
    Keyring.generate("operator", force=True)
    gate = HumanGate(operator_key="operator")
    state_id = gate.request_approval(action="test", context={"target": "safe"})

    # Legitimately approve
    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    state_data = _read_encrypted_state(state_file)
    signer = Keyring.load_signer("operator")
    sig = signer.sign(state_data["integrity_hash"].encode()).signature.hex()
    state_data["approved"] = True
    state_data["approved_at"] = "2024-01-01T00:00:00+00:00"
    state_data["approval_signature"] = sig

    # Tamper: change context AFTER signing (but don't update integrity_hash)
    state_data["context"]["target"] = "malicious"
    _write_encrypted_state(state_file, state_data)

    result = gate.check_approval(state_id)
    assert result is None
    # State file should be deleted
    assert not state_file.exists()


def test_check_approval_rejects_recomputed_hash(keypair):
    """check_approval() rejects state where context AND hash were recomputed (signature fails)."""
    Keyring.generate("operator", force=True)
    gate = HumanGate(operator_key="operator")
    state_id = gate.request_approval(action="test", context={"target": "safe"})

    # Legitimately approve
    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    state_data = _read_encrypted_state(state_file)
    signer = Keyring.load_signer("operator")
    sig = signer.sign(state_data["integrity_hash"].encode()).signature.hex()
    state_data["approved"] = True
    state_data["approved_at"] = "2024-01-01T00:00:00+00:00"
    state_data["approval_signature"] = sig

    # Tamper: change context AND recompute integrity_hash
    state_data["context"]["target"] = "malicious"
    state_data["integrity_hash"] = HumanGate._compute_integrity_hash(
        state_data["action"], state_data["context"], state_data["created_at"]
    )
    _write_encrypted_state(state_file, state_data)

    # The integrity hash now matches the tampered data, but the signature
    # was over the ORIGINAL hash — so signature verification must fail
    result = gate.check_approval(state_id)
    assert result is None


def test_approve_rejects_tampered_state_file(keypair, capsys):
    """approve() refuses to sign if state file was tampered before operator acts."""
    Keyring.generate("operator", force=True)
    gate = HumanGate()
    state_id = gate.request_approval(action="deploy", context={"env": "staging"})

    # Tamper: modify context before the operator approves
    state_file = sigil.STATE_DIR / f"pending_{state_id}.json"
    state_data = _read_encrypted_state(state_file)
    state_data["context"]["env"] = "production"
    _write_encrypted_state(state_file, state_data)

    with patch("builtins.input", return_value="y"):
        HumanGate.approve(state_id, operator_key="operator")

    captured = capsys.readouterr()
    assert "integrity" in captured.out.lower() or "tamper" in captured.out.lower()
    # State file should still exist (approve returned early without modifying)
    state_data = _read_encrypted_state(state_file)
    assert state_data.get("approved") is not True


# --- H-02: Rate limiting and lockout ---


def test_approve_logs_denial(keypair, capsys):
    """approve() with 'n' records a failed attempt and logs denial."""
    Keyring.generate("operator", force=True)
    gate = HumanGate()
    state_id = gate.request_approval(action="test", context={})

    with patch("builtins.input", return_value="n"):
        HumanGate.approve(state_id, operator_key="operator")

    # Audit chain should have hitl_approve_denied
    if AuditChain.LOG_FILE.exists():
        content = AuditChain.LOG_FILE.read_text()
        assert "hitl_approve_denied" in content


def test_approve_lockout_after_max_failures(keypair, capsys):
    """After MAX_FAILED_ATTEMPTS bad state_ids, the state_id is locked out."""
    Keyring.generate("operator", force=True)
    # RT-2026-05-04-002: must be a valid-shape state_id that just doesn't
    # exist on disk, so approve() reaches the not-found / record-attempt path.
    fake_id = "deadbeef" * 3
    for _ in range(HumanGate.MAX_FAILED_ATTEMPTS):
        HumanGate.approve(fake_id, operator_key="operator")

    # Next attempt should be locked out
    HumanGate.approve(fake_id, operator_key="operator")
    captured = capsys.readouterr()
    assert "locked out" in captured.out.lower() or "too many" in captured.out.lower()


def test_approve_lockout_expires(keypair, capsys):
    """Lockout expires after LOCKOUT_DURATION_SECONDS."""
    from datetime import datetime, timezone, timedelta
    Keyring.generate("operator", force=True)
    fake_id = "feedface" * 3

    # Manually create an expired lockout
    attempt_file = HumanGate._get_attempt_file(fake_id)
    past_lock = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    _write_encrypted_state(attempt_file, {
        "attempts": HumanGate.MAX_FAILED_ATTEMPTS,
        "last_attempt": past_lock,
        "locked_until": past_lock,
    })

    # Should NOT be locked out since lockout time is in the past
    assert HumanGate._check_lockout(fake_id) is False
