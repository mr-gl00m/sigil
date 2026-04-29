"""Tests for AuditChain Merkle-linked logging."""

import json
import hashlib

import nacl.signing
import nacl.encoding

import sigil
from sigil import AuditChain, KEYS_DIR


def test_first_entry_links_to_genesis():
    """First log entry has prev_hash == 'GENESIS'."""
    AuditChain.log("test_event", {"key": "value"})
    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[0])
    assert entry["prev_hash"] == "GENESIS"


def test_second_entry_links_to_first():
    """Second entry's prev_hash matches first entry's entry_hash."""
    AuditChain.log("event_1", {"seq": 1})
    AuditChain.log("event_2", {"seq": 2})
    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert second["prev_hash"] == first["entry_hash"]


def test_verify_chain_valid():
    """verify_chain() passes on an untampered chain."""
    AuditChain.log("a", {"x": 1})
    AuditChain.log("b", {"x": 2})
    AuditChain.log("c", {"x": 3})
    valid, msg = AuditChain.verify_chain()
    assert valid is True
    assert "3 entries" in msg


def test_verify_chain_tampered_data():
    """Modifying an entry's data is detected."""
    AuditChain.log("a", {"x": 1})
    AuditChain.log("b", {"x": 2})

    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[0])
    entry["data"]["x"] = 999  # Tamper
    lines[0] = json.dumps(entry)
    AuditChain.LOG_FILE.write_text("\n".join(lines) + "\n")

    valid, msg = AuditChain.verify_chain()
    assert valid is False
    assert "tampered" in msg.lower()


def test_verify_chain_broken_link():
    """Breaking the prev_hash link is detected."""
    AuditChain.log("a", {"x": 1})
    AuditChain.log("b", {"x": 2})

    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[1])
    entry["prev_hash"] = "0000000000000000"
    lines[1] = json.dumps(entry)
    AuditChain.LOG_FILE.write_text("\n".join(lines) + "\n")

    valid, msg = AuditChain.verify_chain()
    assert valid is False
    assert "broken" in msg.lower() or "tampered" in msg.lower()


def test_verify_chain_empty_log():
    """verify_chain on empty log returns True."""
    AuditChain.LOG_FILE.write_text("")
    valid, msg = AuditChain.verify_chain()
    assert valid is True


def test_verify_chain_missing_log():
    """verify_chain with no log file returns True."""
    if AuditChain.LOG_FILE.exists():
        AuditChain.LOG_FILE.unlink()
    valid, msg = AuditChain.verify_chain()
    assert valid is True
    assert "No audit log" in msg


def test_log_creates_file():
    """log() creates the chain file if it doesn't exist."""
    if AuditChain.LOG_FILE.exists():
        AuditChain.LOG_FILE.unlink()
    AuditChain.log("creation_test", {"created": True})
    assert AuditChain.LOG_FILE.exists()


def test_entry_has_entry_hash():
    """Each entry includes an entry_hash field."""
    AuditChain.log("hash_test", {"data": "test"})
    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[-1])
    assert "entry_hash" in entry
    assert len(entry["entry_hash"]) == 64  # Full SHA256 (64 hex chars)


def test_entry_hash_is_64_chars():
    """entry_hash is exactly 64 hex characters (full SHA-256)."""
    AuditChain.log("len_test", {"x": 1})
    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[-1])
    assert len(entry["entry_hash"]) == 64
    assert all(c in "0123456789abcdef" for c in entry["entry_hash"])


def test_entry_has_signature():
    """New entries include signature and signer_key_id fields."""
    AuditChain.log("sig_test", {"data": "test"})
    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[-1])
    assert "signature" in entry
    assert "signer_key_id" in entry
    assert len(entry["signature"]) == 128  # Ed25519 signature is 64 bytes = 128 hex
    assert len(entry["signer_key_id"]) == 16


def test_verify_chain_detects_forged_signature():
    """verify_chain() detects a garbage signature."""
    AuditChain.log("a", {"x": 1})

    lines = AuditChain.LOG_FILE.read_text().strip().split("\n")
    entry = json.loads(lines[0])
    entry["signature"] = "ab" * 64  # Garbage 64-byte signature
    lines[0] = json.dumps(entry)
    AuditChain.LOG_FILE.write_text("\n".join(lines) + "\n")

    valid, msg = AuditChain.verify_chain()
    assert valid is False
    assert "invalid signature" in msg.lower()


def test_verify_chain_strict_rejects_unsigned():
    """strict mode rejects entries that lack a signature."""
    # Write a legacy unsigned entry directly
    entry = {
        "timestamp": "2024-01-01T00:00:00+00:00",
        "event": "legacy_event",
        "data": {"x": 1},
        "prev_hash": "GENESIS"
    }
    entry_hash = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()
    ).hexdigest()
    entry["entry_hash"] = entry_hash
    AuditChain.LOG_FILE.write_text(json.dumps(entry) + "\n")

    # Non-strict should pass
    valid, msg = AuditChain.verify_chain(strict=False)
    assert valid is True
    assert "1 unsigned" in msg

    # Strict should fail
    valid, msg = AuditChain.verify_chain(strict=True)
    assert valid is False
    assert "unsigned" in msg.lower()


def test_system_key_auto_generated():
    """_system.key and _system.pub are auto-created on first log()."""
    key_path = sigil.KEYS_DIR / "_system.key"
    pub_path = sigil.KEYS_DIR / "_system.pub"
    assert not key_path.exists()
    assert not pub_path.exists()

    AuditChain.log("auto_gen_test", {"test": True})

    assert key_path.exists()
    assert pub_path.exists()


def test_verify_chain_signed_chain_valid():
    """A fully signed chain passes verification."""
    AuditChain.log("event_1", {"seq": 1})
    AuditChain.log("event_2", {"seq": 2})
    AuditChain.log("event_3", {"seq": 3})

    valid, msg = AuditChain.verify_chain()
    assert valid is True
    assert "3 entries" in msg
    # All entries are signed, so no "unsigned" in the message
    assert "unsigned" not in msg


# --- M-01: Robust _get_last_entry ---


def test_get_last_entry_single_line():
    """_get_last_entry works with a file containing exactly one entry."""
    AuditChain.log("single", {"x": 1})
    entry = AuditChain._get_last_entry()
    assert entry is not None
    assert entry["event"] == "single"


def test_get_last_entry_no_trailing_newline():
    """_get_last_entry works when file lacks a trailing newline."""
    AuditChain.log("entry_a", {"x": 1})
    # Strip trailing newline
    content = AuditChain.LOG_FILE.read_text().rstrip('\n')
    AuditChain.LOG_FILE.write_text(content)
    entry = AuditChain._get_last_entry()
    assert entry is not None
    assert entry["event"] == "entry_a"


# --- L-05: Streaming verify_chain ---


def test_verify_chain_streams_large_file():
    """verify_chain works correctly on many entries (streaming mode)."""
    for i in range(120):
        AuditChain.log(f"event_{i}", {"seq": i})
    valid, msg = AuditChain.verify_chain()
    assert valid is True
    assert "120 entries" in msg
