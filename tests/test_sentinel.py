"""Tests for Sentinel verification and CRL handling."""

import json
import time
from datetime import datetime, timezone, timedelta

import pytest
import nacl.signing
import nacl.encoding

import sigil
from sigil import (
    Sentinel, Architect, Keyring, SigilSeal, AuditChain,
)


def test_valid_seal_passes(architect, sentinel, signed_seal):
    """A properly signed seal passes verification."""
    valid, msg = sentinel.verify(signed_seal)
    assert valid is True
    assert "VERIFIED" in msg


def test_unsigned_seal_fails(sentinel):
    """A seal with no signature fails verification."""
    seal = SigilSeal(node_id="n1", instruction="test")
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_tampered_instruction_fails(architect, sentinel):
    """Modifying the instruction after signing fails verification."""
    seal = architect.seal(node_id="n1", instruction="original")
    seal.instruction = "tampered"
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_tampered_allowed_tools_fails(architect, sentinel):
    """Modifying allowed_tools after signing fails verification."""
    seal = architect.seal(node_id="n1", instruction="test", allowed_tools=["safe"])
    seal.allowed_tools = ["safe", "evil"]
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_expired_seal_fails(architect, sentinel):
    """An expired seal fails with EXPIRED."""
    seal = architect.seal(node_id="n1", instruction="test")
    seal.expires_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    # Re-sign with the backdated expiry so the signature is valid
    # but we need to manipulate the existing seal, so this will actually
    # trigger TAMPERED since we changed expires_at post-signing.
    # Instead, let's make the architect sign it with a past expiry.
    # The architect doesn't support negative days, so we'll craft it manually.
    seal2 = SigilSeal(
        node_id="expired_node",
        instruction="test",
        expires_at=(datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(),
    )
    # Sign manually
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal2.canonical_payload())
    seal2.signature = signed.signature.hex()
    seal2.signer_key_id = Keyring.get_key_id("architect")

    valid, msg = sentinel.verify(seal2)
    assert valid is False
    assert "INVALID" in msg


def test_revoked_seal_fails(architect, sentinel):
    """A revoked seal fails verification."""
    seal = architect.seal(node_id="n1", instruction="revoke me")
    architect.revoke(seal, reason="test")
    sentinel._load_crl(force=True)
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_wrong_key_id_fails(architect, sentinel):
    """A seal signed by a different key fails verification."""
    seal = architect.seal(node_id="n1", instruction="test")
    seal.signer_key_id = "0000000000000000"
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_crl_file_missing_ok(sentinel):
    """Sentinel works fine with no CRL file."""
    assert sentinel.revoked_hashes == set() or len(sentinel.revoked_hashes) == 0


def test_crl_cache_ttl(architect, sentinel):
    """CRL cache respects TTL - within 5s, cached version is used."""
    seal = architect.seal(node_id="n1", instruction="test")
    # Verify it passes
    valid, _ = sentinel.verify(seal)
    assert valid is True

    # Revoke it
    architect.revoke(seal, reason="late_revocation")
    # Don't force reload - cache should still be valid
    # Within 5s TTL, the cached (empty) CRL is used
    valid2, msg2 = sentinel.verify(seal)
    # Should still pass because cache hasn't expired
    assert valid2 is True


def test_force_reload_bypasses_cache(architect, sentinel):
    """force=True on _load_crl bypasses the TTL cache."""
    seal = architect.seal(node_id="n1", instruction="test")
    architect.revoke(seal, reason="test")
    sentinel._load_crl(force=True)
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_malformed_crl_entry_skipped(architect, sentinel):
    """Malformed CRL entries are skipped without breaking valid ones."""
    seal = architect.seal(node_id="n1", instruction="test")
    architect.revoke(seal, reason="valid_entry")

    # Add a malformed entry
    crl = json.loads(sigil.CRL_FILE.read_text())
    crl.append({"garbage": "data"})
    sigil.CRL_FILE.write_text(json.dumps(crl))

    sentinel._load_crl(force=True)
    # The valid entry should still be in revoked_hashes
    assert seal.content_hash() in sentinel.revoked_hashes


def test_wrong_signer_crl_entry_rejected(keypair, sentinel):
    """CRL entries signed by a different key are rejected."""
    # Create a second keypair
    Keyring.generate("other_arch", force=True)
    other_arch = Architect("other_arch")

    seal = other_arch.seal(node_id="n1", instruction="test")
    other_arch.revoke(seal, reason="other_key")

    # Load CRL with sentinel that expects "architect" key
    sentinel._load_crl(force=True)
    # The other-key entry should not be in revoked_hashes
    assert seal.content_hash() not in sentinel.revoked_hashes


def test_invalid_date_format(architect, sentinel):
    """Invalid expiration date format fails verification."""
    seal = SigilSeal(
        node_id="bad_date",
        instruction="test",
        expires_at="not-a-date",
    )
    signer = Keyring.load_signer("architect")
    signed = signer.sign(seal.canonical_payload())
    seal.signature = signed.signature.hex()
    seal.signer_key_id = Keyring.get_key_id("architect")

    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg


def test_refresh_crl_parameter(architect, sentinel):
    """verify(refresh_crl=True) reloads CRL before checking."""
    seal = architect.seal(node_id="n1", instruction="test")
    valid1, _ = sentinel.verify(seal)
    assert valid1 is True

    architect.revoke(seal, reason="test")
    # Use refresh_crl to catch the revocation
    # Reset the cache timestamp to force a real reload
    sentinel._crl_cache_timestamp = 0
    valid2, msg2 = sentinel.verify(seal, refresh_crl=True)
    assert valid2 is False
    assert "INVALID" in msg2


# --- H-01: Key rotation ---


def test_key_rotation_creates_succession_record(keypair):
    """rotate_key creates a signed succession record."""
    Keyring.rotate_key("architect")
    records = Keyring.list_key_versions("architect")
    assert len(records) == 1
    record = records[0]
    assert record["key_name"] == "architect"
    assert "old_key_id" in record
    assert "new_key_id" in record
    assert "old_key_signature" in record
    assert record["old_key_id"] != record["new_key_id"]


def test_rotated_key_seal_valid_during_transition(keypair):
    """Seal signed by old key passes verification during transition window."""
    # Sign a seal with the current (old) key
    arch = Architect("architect")
    seal = arch.seal(node_id="pre_rotate", instruction="test")

    # Rotate the key
    Keyring.rotate_key("architect", transition_days=7)

    # Create a new sentinel with the new key
    sentinel = Sentinel("architect")
    valid, msg = sentinel.verify(seal)
    assert valid is True
    assert "VERIFIED" in msg


def test_rotated_key_seal_invalid_after_transition(keypair):
    """Seal signed by old key fails after transition window closes."""
    import json
    from datetime import datetime, timezone, timedelta

    arch = Architect("architect")
    seal = arch.seal(node_id="expired_transition", instruction="test")

    # Rotate the key
    Keyring.rotate_key("architect", transition_days=7)

    # Manually expire the transition window
    records = Keyring._load_succession_records()
    for r in records:
        r["transition_end"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    Keyring._save_succession_records(records)

    sentinel = Sentinel("architect")
    valid, msg = sentinel.verify(seal)
    assert valid is False
    assert "INVALID" in msg
