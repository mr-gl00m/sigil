"""Tests for Keyring key generation and loading."""

import json
import os
import base64
import hashlib
import pytest

import nacl.signing
import nacl.encoding

import sigil
from sigil import Keyring


def test_generate_creates_files():
    """generate() creates .key and .pub files."""
    priv, pub = Keyring.generate("test_key")
    assert priv.exists()
    assert pub.exists()


def test_generate_existing_raises():
    """generate() raises FileExistsError if key already exists."""
    Keyring.generate("dup_key")
    with pytest.raises(FileExistsError):
        Keyring.generate("dup_key")


def test_generate_force_overwrites():
    """generate(force=True) overwrites existing key."""
    _, pub1 = Keyring.generate("force_key")
    old_bytes = pub1.read_bytes()
    _, pub2 = Keyring.generate("force_key", force=True)
    # New key should (almost certainly) differ
    assert pub2.read_bytes() != old_bytes


def test_load_signer_from_disk():
    """load_signer() loads private key from disk."""
    Keyring.generate("signer_test")
    sk = Keyring.load_signer("signer_test")
    assert isinstance(sk, nacl.signing.SigningKey)


def test_load_signer_from_env(monkeypatch):
    """load_signer() loads from SIGIL_KEY_{NAME} env var."""
    sk = nacl.signing.SigningKey.generate()
    hex_key = sk.encode(encoder=nacl.encoding.HexEncoder).decode()
    monkeypatch.setenv("SIGIL_KEY_ENVTEST", hex_key)
    loaded = Keyring.load_signer("envtest")
    assert loaded.encode(encoder=nacl.encoding.HexEncoder) == sk.encode(encoder=nacl.encoding.HexEncoder)


def test_load_signer_missing_raises():
    """load_signer() raises FileNotFoundError for missing key."""
    with pytest.raises(FileNotFoundError):
        Keyring.load_signer("nonexistent")


def test_load_verifier_from_disk():
    """load_verifier() loads public key from disk."""
    Keyring.generate("ver_test")
    vk = Keyring.load_verifier("ver_test")
    assert isinstance(vk, nacl.signing.VerifyKey)


def test_load_verifier_from_env(monkeypatch):
    """load_verifier() loads from SIGIL_PUB_{NAME} env var."""
    sk = nacl.signing.SigningKey.generate()
    vk = sk.verify_key
    hex_pub = vk.encode(encoder=nacl.encoding.HexEncoder).decode()
    monkeypatch.setenv("SIGIL_PUB_ENVPUB", hex_pub)
    loaded = Keyring.load_verifier("envpub")
    assert loaded.encode(encoder=nacl.encoding.HexEncoder) == vk.encode(encoder=nacl.encoding.HexEncoder)


def test_load_verifier_missing_raises():
    """load_verifier() raises FileNotFoundError for missing key."""
    with pytest.raises(FileNotFoundError):
        Keyring.load_verifier("nonexistent")


def test_get_key_id_returns_16_hex():
    """get_key_id() returns a 16-char hex fingerprint."""
    Keyring.generate("id_test")
    key_id = Keyring.get_key_id("id_test")
    assert len(key_id) == 16
    assert all(c in "0123456789abcdef" for c in key_id)


def test_get_key_id_from_env(monkeypatch):
    """get_key_id() works with env-provided public key."""
    monkeypatch.setenv("SIGIL_PUB_ENVID", "aa" * 32)
    key_id = Keyring.get_key_id("envid")
    expected = hashlib.sha256(("aa" * 32).encode()).hexdigest()[:16]
    assert key_id == expected


def test_export_public_returns_base64():
    """export_public() returns base64-encoded public key."""
    Keyring.generate("export_test")
    exported = Keyring.export_public("export_test")
    # Should be valid base64
    decoded = base64.b64decode(exported)
    assert len(decoded) > 0


# --- Encrypted key tests (C-02) ---


def test_generate_encrypted_key():
    """generate() with passphrase produces a version 2 JSON envelope."""
    priv, pub = Keyring.generate("enc_test", passphrase="testpass123")
    file_data = priv.read_bytes()
    envelope = json.loads(file_data)
    assert envelope["version"] == 2
    assert envelope["kdf"] == "argon2id"
    assert "salt" in envelope
    assert "encrypted" in envelope
    # Public key should still be plain hex
    assert pub.exists()
    vk = nacl.signing.VerifyKey(pub.read_bytes(), encoder=nacl.encoding.HexEncoder)
    assert vk is not None


def test_load_encrypted_signer():
    """load_signer() with correct passphrase succeeds."""
    Keyring.generate("enc_load", passphrase="mypassword")
    sk = Keyring.load_signer("enc_load", passphrase="mypassword")
    assert isinstance(sk, nacl.signing.SigningKey)


def test_load_encrypted_wrong_passphrase():
    """load_signer() with wrong passphrase raises ValueError."""
    Keyring.generate("enc_wrong", passphrase="correctpass")
    with pytest.raises(ValueError, match="Wrong passphrase"):
        Keyring.load_signer("enc_wrong", passphrase="wrongpass")


def test_load_encrypted_no_passphrase():
    """load_signer() without passphrase on encrypted key raises ValueError."""
    Keyring.generate("enc_nopw", passphrase="securepass")
    with pytest.raises(ValueError, match="encrypted.*[Pp]assphrase"):
        Keyring.load_signer("enc_nopw")


def test_load_plaintext_ignores_passphrase():
    """load_signer() on a plaintext key ignores passphrase parameter."""
    Keyring.generate("plain_pw")
    sk = Keyring.load_signer("plain_pw", passphrase="ignoredpass")
    assert isinstance(sk, nacl.signing.SigningKey)


def test_migrate_key_encrypts():
    """migrate_key() converts a plaintext key to encrypted format in place."""
    Keyring.generate("mig_test")
    key_path = sigil.KEYS_DIR / "mig_test.key"

    # Should be plaintext initially
    assert not Keyring._is_encrypted_key(key_path.read_bytes())

    Keyring.migrate_key("mig_test", "migratepass")

    # Should be encrypted now
    assert Keyring._is_encrypted_key(key_path.read_bytes())

    # Should be loadable with passphrase
    sk = Keyring.load_signer("mig_test", passphrase="migratepass")
    assert isinstance(sk, nacl.signing.SigningKey)


def test_migrate_already_encrypted_raises():
    """migrate_key() on an already-encrypted key raises ValueError."""
    Keyring.generate("mig_dup", passphrase="firstpass")
    with pytest.raises(ValueError, match="already encrypted"):
        Keyring.migrate_key("mig_dup", "secondpass")


def test_encrypted_key_roundtrip_signing():
    """Sign+verify cycle works with an encrypted key."""
    Keyring.generate("enc_rt", passphrase="roundtrip")
    sk = Keyring.load_signer("enc_rt", passphrase="roundtrip")
    vk = Keyring.load_verifier("enc_rt")

    message = b"test message for signing"
    signed = sk.sign(message)
    # Should not raise
    vk.verify(signed)


# --- Key permission checks (L-02) ---


def test_key_permission_check_on_load():
    """_check_key_permissions is called during load_signer."""
    from unittest.mock import patch
    Keyring.generate("perm_test")
    with patch.object(Keyring, '_check_key_permissions') as mock_check:
        Keyring.load_signer("perm_test")
        assert mock_check.called


def test_key_permission_check_verifier_on_load():
    """_check_key_permissions is called during load_verifier."""
    from unittest.mock import patch
    Keyring.generate("perm_ver")
    with patch.object(Keyring, '_check_key_permissions') as mock_check:
        Keyring.load_verifier("perm_ver")
        assert mock_check.called
