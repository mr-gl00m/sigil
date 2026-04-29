"""Tests for LegalExporter discovery packages."""

import json
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from sigil_audit_proxy import LegalExporter, AuditProxy, AuditRecord


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


def test_hash_file(tmp_path):
    """_hash_file returns consistent SHA256."""
    import hashlib
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    result = LegalExporter._hash_file(test_file)
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert result == expected
