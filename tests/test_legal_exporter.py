"""Tests for LegalExporter discovery packages."""

import json
import hashlib
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import nacl.encoding
import nacl.signing
import pytest

import sigil
from sigil_audit_proxy import LegalExporter, AuditProxy, AuditRecord
from sigil_receipts import ReceiptStore, verify_disclosure


def _add_sample_records(proxy, count=3):
    """Add sample audit records to the proxy."""
    for i in range(count):
        record = AuditRecord(
            request_id=f"legal_{i}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            provider="anthropic",
            model="claude",
            latency_ms=100.0,
            time_to_first_byte_ms=None,
            input_tokens=10,
            output_tokens=20,
            total_tokens=30,
            estimated_cost_usd=0.001,
            request_hash="h",
            response_fingerprint="f",
            status_code=200,
            success=True,
        )
        proxy._store_record(record)


def test_create_discovery_package_creates_zip(audit_proxy, tmp_path):
    """create_discovery_package produces a .zip file."""
    _add_sample_records(audit_proxy)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="TEST-001",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )
    assert zip_path.exists()
    assert zip_path.suffix == ".zip"


def test_zip_contains_records_json(audit_proxy, tmp_path):
    """Discovery zip contains records.json."""
    _add_sample_records(audit_proxy)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="TEST-002",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        assert "records.json" in names


def test_zip_contains_manifest(audit_proxy, tmp_path):
    """Discovery zip contains sha256_manifest.json."""
    _add_sample_records(audit_proxy)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="TEST-003",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert "sha256_manifest.json" in zf.namelist()
        assert "manifest_signature.json" in zf.namelist()


def test_discovery_manifest_signature_verifies(audit_proxy, tmp_path):
    """The discovery manifest is bound to the system Ed25519 key."""
    _add_sample_records(audit_proxy)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)
    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="TEST-SIGNED",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )

    with zipfile.ZipFile(zip_path, "r") as zf:
        manifest_bytes = zf.read("sha256_manifest.json")
        envelope = json.loads(zf.read("manifest_signature.json"))

    assert envelope["manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    assert envelope["signed_file"] == "sha256_manifest.json"
    verify_key = nacl.signing.VerifyKey(
        (sigil.KEYS_DIR / "_system.pub").read_bytes(),
        encoder=nacl.encoding.HexEncoder,
    )
    verify_key.verify(manifest_bytes, bytes.fromhex(envelope["signature"]))


def test_manifest_is_signed_by_the_system_evidence_key(audit_proxy, tmp_path):
    """The manifest must carry a detached signature from the system key."""
    _add_sample_records(audit_proxy)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="SIGNED-001",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )

    with zipfile.ZipFile(zip_path, "r") as zf:
        manifest_bytes = zf.read("sha256_manifest.json")
        receipt = json.loads(zf.read("manifest_signature.json"))

    public_bytes = (sigil.KEYS_DIR / "_system.pub").read_bytes()
    verifier = nacl.signing.VerifyKey(
        public_bytes,
        encoder=nacl.encoding.HexEncoder,
    )
    verifier.verify(manifest_bytes, bytes.fromhex(receipt["signature"]))
    assert receipt["signer_key_id"] == hashlib.sha256(public_bytes).hexdigest()[:16]
    assert receipt["manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()


def test_zip_contains_chain_of_custody(audit_proxy, tmp_path):
    """Discovery zip contains chain_of_custody.txt."""
    _add_sample_records(audit_proxy)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="TEST-004",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )
    with zipfile.ZipFile(zip_path, "r") as zf:
        assert "chain_of_custody.txt" in zf.namelist()
        content = zf.read("chain_of_custody.txt").decode()
        assert "TEST-004" in content


def test_discovery_package_contains_verifiable_selective_receipts(
    audit_proxy, tmp_path
):
    """Legal exports disclose selected receipt fields with public proof material."""
    receipt = ReceiptStore.emit(
        receipt_type="action",
        action="read_file",
        decision="allow",
        effect_class="read",
        arguments={"path": "private.txt"},
        capability_id="cap_read",
    )
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="DISCLOSE-001",
        proxy=audit_proxy,
        output_dir=tmp_path,
        disclosure_fields=(
            "action",
            "decision",
            "manifest_hash",
            "previous_receipt_id",
        ),
    )

    with zipfile.ZipFile(zip_path, "r") as zf:
        bundle = json.loads(zf.read("receipt_disclosures.json"))
    assert len(bundle["disclosures"]) == 1
    disclosure = bundle["disclosures"][0]
    assert disclosure["receipt_id"] == receipt["receipt_id"]
    assert set(disclosure["disclosed"]) == {
        "action",
        "decision",
        "manifest_hash",
        "previous_receipt_id",
    }
    assert "arguments_hash" not in disclosure["disclosed"]
    verify_key = nacl.signing.VerifyKey(
        bundle["trust_bundle"]["receipt_public_key"].encode("ascii"),
        encoder=nacl.encoding.HexEncoder,
    )
    manifest_hash = disclosure["disclosed"]["manifest_hash"]["value"]
    assert manifest_hash in bundle["runtime_manifests"]
    system_key = nacl.signing.VerifyKey(
        bundle["trust_bundle"]["system_public_key"].encode("ascii"),
        encoder=nacl.encoding.HexEncoder,
    )
    assert verify_disclosure(
        disclosure,
        verify_key,
        bundle["runtime_manifests"][manifest_hash],
        system_key,
    )[0] is True


def test_discovery_package_requires_receipt_chain_links(audit_proxy, tmp_path):
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    with pytest.raises(ValueError, match="previous_receipt_id"):
        LegalExporter.create_discovery_package(
            time_range=(start, end),
            case_id="TEST-MISSING-LINK",
            proxy=audit_proxy,
            output_dir=tmp_path,
            disclosure_fields=("manifest_hash",),
        )


def test_discovery_package_reredacts_leaked_preview(audit_proxy, tmp_path):
    """RT-2026-05-29-001: records captured under older redaction logic may
    carry a secret in their preview fields. The discovery bundle is the
    highest-consequence sink (handed to a court/regulator), so it re-redacts
    record previews before writing records.json instead of trusting that
    capture-time redaction was complete."""
    record = AuditRecord(
        request_id="leak_0",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        provider="anthropic",
        model="claude",
        latency_ms=100.0,
        time_to_first_byte_ms=None,
        input_tokens=10,
        output_tokens=20,
        total_tokens=30,
        estimated_cost_usd=0.001,
        request_hash="h",
        response_fingerprint="f",
        status_code=200,
        success=True,
        response_preview="Authorization: Bearer sk-HISTORICAL-LEAK-987654321",
    )
    audit_proxy._store_record(record)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    zip_path = LegalExporter.create_discovery_package(
        time_range=(start, end),
        case_id="LEAK-001",
        proxy=audit_proxy,
        output_dir=tmp_path,
    )
    with zipfile.ZipFile(zip_path, "r") as zf:
        records_json = zf.read("records.json").decode()
    assert "sk-HISTORICAL-LEAK-987654321" not in records_json, (
        "discovery bundle leaked a secret from a record preview"
    )
    assert "[REDACTED]" in records_json


def test_hash_file(tmp_path):
    """_hash_file returns consistent SHA256."""
    import hashlib
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    result = LegalExporter._hash_file(test_file)
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert result == expected
