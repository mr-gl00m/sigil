"""Tests for Architect signing and revocation."""

import json
from datetime import datetime, timezone

import sigil
from sigil import Architect, Keyring, SigilSeal


def test_seal_creates_signed_seal(architect):
    """seal() returns a SigilSeal with a signature."""
    seal = architect.seal(node_id="n1", instruction="Do stuff")
    assert seal.signature is not None
    assert len(seal.signature) > 0


def test_seal_has_valid_signature(architect, sentinel):
    """Seal produced by Architect verifies with Sentinel."""
    seal = architect.seal(node_id="n1", instruction="Do stuff")
    valid, msg = sentinel.verify(seal)
    assert valid is True
    assert "VERIFIED" in msg


def test_seal_with_expiry(architect):
    """seal(expires_in_days=N) sets expires_at."""
    seal = architect.seal(node_id="n1", instruction="test", expires_in_days=30)
    assert seal.expires_at is not None
    expires = datetime.fromisoformat(seal.expires_at.replace("Z", "+00:00"))
    assert expires > datetime.now(timezone.utc)


def test_seal_without_expiry(architect):
    """seal() with no expiry has None expires_at."""
    seal = architect.seal(node_id="n1", instruction="test")
    assert seal.expires_at is None


def test_seal_populates_signer_key_id(architect):
    """seal() sets signer_key_id to the architect's key ID."""
    seal = architect.seal(node_id="n1", instruction="test")
    assert seal.signer_key_id == architect.key_id


def test_seal_preserves_metadata(architect):
    """seal() preserves metadata dict."""
    meta = {"author": "test", "version": "1.0"}
    seal = architect.seal(node_id="n1", instruction="test", metadata=meta)
    assert seal.metadata == meta


def test_revoke_adds_to_crl(architect):
    """revoke() creates/appends to the CRL file."""
    seal = architect.seal(node_id="n1", instruction="revoke me")
    architect.revoke(seal, reason="test_revocation")
    assert sigil.CRL_FILE.exists()
    crl = json.loads(sigil.CRL_FILE.read_text())
    assert len(crl) == 1
    assert crl[0]["hash"] == seal.content_hash()
    assert crl[0]["reason"] == "test_revocation"


def test_revoke_creates_signed_crl_entry(architect, sentinel):
    """CRL entry has a valid signature from the architect."""
    seal = architect.seal(node_id="n1", instruction="test")
    architect.revoke(seal, reason="signed_revocation")
    crl = json.loads(sigil.CRL_FILE.read_text())
    entry = crl[0]
    assert "signature" in entry
    assert "signer_key_id" in entry
    assert entry["signer_key_id"] == architect.key_id
