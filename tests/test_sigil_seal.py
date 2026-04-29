"""Tests for SigilSeal pure functions."""

import json
import hashlib
from datetime import datetime, timezone

from sigil import SigilSeal


def test_canonical_payload_deterministic():
    """Same inputs produce identical canonical payloads."""
    seal = SigilSeal(node_id="n1", instruction="test", nonce="fixed", created_at="2024-01-01T00:00:00")
    assert seal.canonical_payload() == seal.canonical_payload()


def test_canonical_payload_sorts_allowed_tools():
    """allowed_tools are sorted in canonical payload for determinism."""
    seal = SigilSeal(node_id="n1", instruction="test", nonce="fixed",
                     created_at="2024-01-01T00:00:00", allowed_tools=["z_tool", "a_tool"])
    payload = json.loads(seal.canonical_payload())
    assert payload["allowed_tools"] == ["a_tool", "z_tool"]


def test_content_hash_is_sha256():
    """content_hash returns SHA-256 hex of the canonical payload."""
    seal = SigilSeal(node_id="n1", instruction="test", nonce="fixed", created_at="2024-01-01T00:00:00")
    expected = hashlib.sha256(seal.canonical_payload()).hexdigest()
    assert seal.content_hash() == expected


def test_default_version_is_1_0():
    """Default version is SIGIL-specific '1.0'."""
    seal = SigilSeal(node_id="n1", instruction="test")
    assert seal.version == "1.0"


def test_nonce_auto_generated():
    """Nonce is auto-generated and 16 characters."""
    seal = SigilSeal(node_id="n1", instruction="test")
    assert len(seal.nonce) == 16
    assert all(c in "0123456789abcdef" for c in seal.nonce)


def test_created_at_auto_generated_iso():
    """created_at is auto-generated as ISO format UTC."""
    seal = SigilSeal(node_id="n1", instruction="test")
    # Should parse without error
    dt = datetime.fromisoformat(seal.created_at.replace("Z", "+00:00"))
    assert dt.tzinfo is not None


def test_default_one_time_is_false():
    """one_time defaults to False."""
    seal = SigilSeal(node_id="n1", instruction="test")
    assert seal.one_time is False


def test_seal_fields_from_kwargs():
    """SigilSeal constructed from kwargs has correct fields."""
    seal = SigilSeal(
        node_id="my_node",
        instruction="Do something",
        allowed_tools=["tool1"],
        metadata={"key": "val"},
    )
    assert seal.node_id == "my_node"
    assert seal.instruction == "Do something"
    assert seal.allowed_tools == ["tool1"]
    assert seal.metadata == {"key": "val"}
    assert seal.signature is None
    assert seal.signer_key_id is None
