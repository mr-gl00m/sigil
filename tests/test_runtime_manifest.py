"""Tests for signed runtime software manifests and decision binding."""

import hashlib
import json

import nacl.encoding
import nacl.signing

import sigil
from sigil import (
    AuditChain,
    EffectClass,
    RuntimeManifest,
    SigilSeal,
    ToolInvocation,
    Validator,
)


def _system_verify_key() -> nacl.signing.VerifyKey:
    return nacl.signing.VerifyKey(
        (sigil.KEYS_DIR / "_system.pub").read_bytes(),
        encoder=nacl.encoding.HexEncoder,
    )


def test_runtime_manifest_measures_required_sources():
    manifest = RuntimeManifest.current()

    assert set(manifest["files"]) == set(RuntimeManifest.SOURCE_FILES)
    assert manifest["missing_files"] == []
    for name, digest in manifest["files"].items():
        expected = hashlib.sha256(
            (RuntimeManifest.SOURCE_ROOT / name).read_bytes()
        ).hexdigest()
        assert digest == expected
    assert manifest["runtime_version"] == sigil.__version__
    assert "_system" in manifest["active_key_ids"]


def test_runtime_manifest_includes_every_active_public_key():
    extra_key = sigil.KEYS_DIR / "operator.pub"
    extra_key.write_text("ab" * 32, encoding="ascii")

    manifest = RuntimeManifest.current()

    assert manifest["active_key_ids"]["operator"] == hashlib.sha256(
        extra_key.read_bytes()
    ).hexdigest()[:16]


def test_runtime_manifest_signature_verifies_and_snapshot_is_written():
    manifest = RuntimeManifest.current()

    valid, message = RuntimeManifest.verify(manifest, _system_verify_key())

    assert valid is True, message
    snapshot = (
        sigil.STATE_DIR
        / "runtime_manifests"
        / f"{manifest['manifest_hash']}.json"
    )
    assert json.loads(snapshot.read_text()) == manifest


def test_runtime_manifest_rejects_tampered_measurement():
    manifest = RuntimeManifest.current()
    manifest["files"]["sigil.py"] = "0" * 64

    valid, message = RuntimeManifest.verify(manifest, _system_verify_key())

    assert valid is False
    assert "hash mismatch" in message.lower()


def test_runtime_manifest_rejects_unknown_envelope_fields():
    manifest = RuntimeManifest.current()
    manifest["unsigned_claim"] = "accepted"

    valid, message = RuntimeManifest.verify(manifest, _system_verify_key())

    assert valid is False
    assert "envelope" in message.lower()


def test_audit_entries_bind_to_runtime_manifest():
    AuditChain.log("manifest_bound", {"value": 1})

    entry = json.loads(AuditChain.LOG_FILE.read_text().strip())
    manifest_path = (
        sigil.STATE_DIR
        / "runtime_manifests"
        / f"{entry['manifest_hash']}.json"
    )
    manifest = json.loads(manifest_path.read_text())
    assert entry["manifest_hash"] == manifest["manifest_hash"]
    assert RuntimeManifest.verify(manifest, _system_verify_key())[0] is True


def test_validator_result_binds_to_runtime_manifest(monkeypatch):
    monkeypatch.setitem(Validator._tool_effects, "read_file", EffectClass.READ)
    seal = SigilSeal(
        node_id="manifest_validator",
        instruction="Read one file.",
        capabilities={"cap_read": "read_file"},
        allowed_effects=["read"],
    )
    invocation = ToolInvocation("cap_read", {})

    validated = Validator.validate_invocation(seal, invocation)

    assert validated.runtime_manifest_hash == RuntimeManifest.current()["manifest_hash"]
