"""Round-trip tests for the standalone SIGIL receipt verifier."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

import sigil
from sigil_receipts import ReceiptStore
from sigil_verify import VerificationError, _load_path, _verify_chain


VERIFIER = Path(__file__).resolve().parents[1] / "sigil_verify.py"


def _emit(action_id: str = "external_action"):
    return ReceiptStore.emit(
        receipt_type="action",
        action="read_file",
        decision="allow",
        effect_class="read",
        arguments={"path": "evidence.txt"},
        action_id=action_id,
        capability_id="cap_read",
    )


def _run(input_path: Path):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            str(input_path),
            "--receipt-key",
            str(sigil.KEYS_DIR / "_receipt.pub"),
            "--system-key",
            str(sigil.KEYS_DIR / "_system.pub"),
            "--manifest",
            str(sigil.STATE_DIR / "runtime_manifests"),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _run_without_keys(input_path: Path):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            str(input_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_standalone_verifier_round_trips_full_receipt(tmp_path):
    receipt = _emit()
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))

    result = _run(path)

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["valid"] is True
    assert report["receipt_ids"] == [receipt["receipt_id"]]
    assert report["assurance_profile"] == "software_manifest"


def test_standalone_verifier_checks_chain_and_delegation(tmp_path):
    parent = ReceiptStore.emit(
        receipt_type="delegation",
        action="delegate",
        decision="allow",
        effect_class="read",
        arguments={"scope": "files"},
        action_id="parent",
    )
    child = ReceiptStore.emit(
        receipt_type="action",
        action="read_file",
        decision="allow",
        effect_class="read",
        arguments={"path": "evidence.txt"},
        action_id="child",
        parent_receipt_id=parent["receipt_id"],
    )
    path = tmp_path / "chain.json"
    path.write_text(json.dumps([parent, child]))

    result = _run(path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["kind"] == "receipt_chain"


def test_standalone_verifier_round_trips_disclosure(tmp_path):
    receipt = _emit()
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["action", "decision", "manifest_hash"]
    )
    path = tmp_path / "disclosure.json"
    path.write_text(json.dumps(disclosure))

    result = _run(path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["kind"] == "disclosure"


def test_standalone_verifier_accepts_disclosure_without_manifest_claim(tmp_path):
    receipt = _emit()
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["action", "decision"]
    )
    path = tmp_path / "disclosure_without_manifest.json"
    path.write_text(json.dumps(disclosure))

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            str(path),
            "--receipt-key",
            str(sigil.KEYS_DIR / "_receipt.pub"),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["valid"] is True
    assert report["kind"] == "disclosure"
    assert report["assurance_profile"] is None
    assert "runtime_manifest_signature" not in report["verified_components"]
    assert "runtime_manifest_binding" in report["unverified_components"]


def test_standalone_disclosure_manifest_claim_requires_system_key(tmp_path):
    receipt = _emit()
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["action", "manifest_hash"]
    )
    path = tmp_path / "disclosure_with_manifest.json"
    path.write_text(json.dumps(disclosure))

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            str(path),
            "--receipt-key",
            str(sigil.KEYS_DIR / "_receipt.pub"),
            "--manifest",
            str(sigil.STATE_DIR / "runtime_manifests"),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["valid"] is False
    assert report["error"] == "system public key is required"


def test_legal_bundle_rejects_embedded_unpinned_keys(tmp_path):
    receipt = _emit()
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["action", "decision", "manifest_hash"]
    )
    manifest_hash = receipt["fields"]["manifest_hash"]
    manifest_path = (
        sigil.STATE_DIR / "runtime_manifests" / f"{manifest_hash}.json"
    )
    bundle = {
        "schema_id": "sigil.legal_receipt_bundle",
        "schema_version": "0.1",
        "case_id": "forged-self-anchor",
        "disclosures": [disclosure],
        "runtime_manifests": {
            manifest_hash: json.loads(manifest_path.read_text())
        },
        "trust_bundle": ReceiptStore.trust_bundle(),
    }
    path = tmp_path / "legal_bundle.json"
    path.write_text(json.dumps(bundle))

    result = _run_without_keys(path)

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["valid"] is False
    assert "required" in report["error"].lower()


def test_legal_bundle_rejects_omitted_chain_links(tmp_path):
    first = _emit("legal_first")
    second = _emit("legal_second")
    disclosures = [
        ReceiptStore.reveal(
            receipt["receipt_id"], ["action", "decision", "manifest_hash"]
        )
        for receipt in (first, second)
    ]
    manifest_hash = first["fields"]["manifest_hash"]
    manifest_path = (
        sigil.STATE_DIR / "runtime_manifests" / f"{manifest_hash}.json"
    )
    bundle = {
        "schema_id": "sigil.legal_receipt_bundle",
        "schema_version": "0.1",
        "case_id": "missing-chain-links",
        "disclosures": disclosures,
        "runtime_manifests": {
            manifest_hash: json.loads(manifest_path.read_text())
        },
        "trust_bundle": ReceiptStore.trust_bundle(),
    }
    path = tmp_path / "missing_links.json"
    path.write_text(json.dumps(bundle))

    result = _run(path)

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["valid"] is False
    assert "previous_receipt_id" in report["error"]


def test_legal_bundle_rejects_extra_envelope_fields(tmp_path):
    receipt = _emit("legal_envelope")
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["manifest_hash", "previous_receipt_id"]
    )
    manifest_hash = receipt["fields"]["manifest_hash"]
    manifest_path = (
        sigil.STATE_DIR / "runtime_manifests" / f"{manifest_hash}.json"
    )
    bundle = {
        "schema_id": "sigil.legal_receipt_bundle",
        "schema_version": "0.1",
        "case_id": "extra-envelope-field",
        "disclosures": [disclosure],
        "runtime_manifests": {
            manifest_hash: json.loads(manifest_path.read_text())
        },
        "trust_bundle": ReceiptStore.trust_bundle(),
        "unsigned_claim": "verified",
    }
    path = tmp_path / "extra_envelope.json"
    path.write_text(json.dumps(bundle))

    result = _run(path)

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["valid"] is False
    assert "envelope" in report["error"].lower()


def test_standalone_verifier_rejects_broken_chain(tmp_path):
    first = _emit("first")
    second = _emit("second")
    path = tmp_path / "broken.json"
    path.write_text(json.dumps([second, first]))

    result = _run(path)

    assert result.returncode == 1
    assert json.loads(result.stdout)["valid"] is False


def test_standalone_verifier_explicitly_rejects_self_parent():
    receipt_id = "ab" * 32
    receipt = {
        "receipt_id": receipt_id,
        "fields": {
            "previous_receipt_id": None,
            "parent_receipt_id": receipt_id,
            "delegation_depth": 1,
        },
    }

    with pytest.raises(VerificationError, match="self-parent"):
        _verify_chain([receipt])


def test_verifier_bounds_reads_before_allocation(tmp_path, monkeypatch):
    path = tmp_path / "bounded.json"
    path.write_text('{"schema_id":"test"}', encoding="utf-8")

    def reject_unbounded_read(self):
        raise AssertionError("verifier used Path.read_bytes")

    monkeypatch.setattr(Path, "read_bytes", reject_unbounded_read)

    assert _load_path(path) == {"schema_id": "test"}


def test_verifier_source_does_not_import_producer_modules():
    source = VERIFIER.read_text()

    assert "import sigil\n" not in source
    assert "from sigil" not in source
    assert "sigil_receipts" not in source
