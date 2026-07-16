"""Tests for portable action receipts, chaining, and disclosure proofs."""

import copy
import json

import nacl.encoding
import nacl.signing
import pytest

import sigil
from sigil_receipts import (
    ReceiptStore,
    verify_disclosure,
    verify_receipt,
)


def _verify_key(name: str) -> nacl.signing.VerifyKey:
    return nacl.signing.VerifyKey(
        (sigil.KEYS_DIR / f"{name}.pub").read_bytes(),
        encoder=nacl.encoding.HexEncoder,
    )


def _manifest_for(receipt):
    manifest_hash = receipt["fields"]["manifest_hash"]
    path = sigil.STATE_DIR / "runtime_manifests" / f"{manifest_hash}.json"
    return json.loads(path.read_text())


def _emit(**overrides):
    values = {
        "receipt_type": "action",
        "action": "read_file",
        "decision": "allow",
        "effect_class": "read",
        "arguments": {"path": "notes.txt"},
        "actor_id": "agent.test",
        "capability_id": "cap_read",
    }
    values.update(overrides)
    return ReceiptStore.emit(**values)


def test_receipt_round_trip_verifies_with_manifest_binding():
    receipt = _emit()

    valid, message = verify_receipt(
        receipt,
        _verify_key("_receipt"),
        _manifest_for(receipt),
        _verify_key("_system"),
    )

    assert valid is True, message
    assert receipt["fields"]["assurance_profile"] == "software_manifest"
    assert receipt["fields"]["output_hash"] is None


def test_receipt_verification_requires_runtime_manifest_binding():
    receipt = _emit()

    valid, message = verify_receipt(receipt, _verify_key("_receipt"))

    assert valid is False
    assert "manifest" in message.lower()


def test_receipt_signer_is_separate_from_audit_system_signer():
    receipt = _emit()

    assert receipt["signer_key_id"] != _manifest_for(receipt)["signer_key_id"]
    assert (sigil.KEYS_DIR / "_receipt.key").read_bytes() != (
        sigil.KEYS_DIR / "_system.key"
    ).read_bytes()


def test_tampered_receipt_field_is_rejected():
    receipt = _emit()
    tampered = copy.deepcopy(receipt)
    tampered["fields"]["action"] = "write_file"

    valid, message = verify_receipt(tampered, _verify_key("_receipt"))

    assert valid is False
    assert "merkle root mismatch" in message.lower()


def test_receipt_store_links_each_append():
    first = _emit(action_id="action_a")
    second = _emit(action_id="action_b")

    assert first["fields"]["previous_receipt_id"] is None
    assert second["fields"]["previous_receipt_id"] == first["receipt_id"]
    assert [item["receipt_id"] for item in ReceiptStore.list()] == [
        first["receipt_id"],
        second["receipt_id"],
    ]


def test_delegated_receipt_binds_parent_and_depth():
    parent = _emit(receipt_type="delegation", action="delegate")
    child = _emit(
        parent_receipt_id=parent["receipt_id"],
        action_id="delegated_action",
    )

    assert child["fields"]["parent_receipt_id"] == parent["receipt_id"]
    assert child["fields"]["delegation_depth"] == 1


def test_missing_delegation_parent_is_rejected():
    with pytest.raises(ValueError, match="parent does not exist"):
        _emit(parent_receipt_id="ab" * 32)


def test_selective_disclosure_round_trip_and_tamper_rejection():
    receipt = _emit()
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["action", "decision", "manifest_hash"]
    )

    valid, message = verify_disclosure(disclosure, _verify_key("_receipt"))

    assert valid is False
    assert "manifest" in message.lower()

    valid, message = verify_disclosure(
        disclosure,
        _verify_key("_receipt"),
        _manifest_for(receipt),
        _verify_key("_system"),
    )

    assert valid is True, message
    assert set(disclosure["disclosed"]) == {"action", "decision", "manifest_hash"}
    assert "arguments_hash" not in disclosure["disclosed"]

    tampered = copy.deepcopy(disclosure)
    tampered["disclosed"]["decision"]["value"] = "deny"
    assert verify_disclosure(tampered, _verify_key("_receipt"))[0] is False


def test_disclosure_explicitly_rejects_self_parent():
    receipt = _emit()
    disclosure = ReceiptStore.reveal(receipt["receipt_id"], ["parent_receipt_id"])
    disclosure["disclosed"]["parent_receipt_id"]["value"] = receipt["receipt_id"]

    valid, message = verify_disclosure(disclosure, _verify_key("_receipt"))

    assert valid is False
    assert "self-parent" in message.lower()


def test_disclosure_rejects_extra_envelope_fields():
    receipt = _emit()
    disclosure = ReceiptStore.reveal(
        receipt["receipt_id"], ["manifest_hash"]
    )
    disclosure["unsigned_claim"] = "verified"

    valid, message = verify_disclosure(
        disclosure,
        _verify_key("_receipt"),
        _manifest_for(receipt),
        _verify_key("_system"),
    )

    assert valid is False
    assert "envelope" in message.lower()


def test_receipt_rejects_floating_point_metadata():
    with pytest.raises(ValueError, match="Floating-point"):
        _emit(metadata={"latency_ms": 1.5})


def test_trust_bundle_contains_both_public_keys():
    bundle = ReceiptStore.trust_bundle()

    assert bundle["receipt_public_key"] == (
        sigil.KEYS_DIR / "_receipt.pub"
    ).read_text().strip()
    assert bundle["system_public_key"] == (
        sigil.KEYS_DIR / "_system.pub"
    ).read_text().strip()


def test_append_fails_closed_when_stored_receipt_was_tampered():
    receipt = _emit()
    tampered = copy.deepcopy(receipt)
    tampered["fields"]["decision"] = "deny"
    ReceiptStore.path().write_text(json.dumps(tampered) + "\n")

    with pytest.raises(RuntimeError, match="Stored receipt 0 is invalid"):
        _emit(action_id="must_not_append")

    assert len(ReceiptStore.path().read_text().strip().splitlines()) == 1


def test_receipt_store_rejects_duplicate_json_keys():
    receipt = _emit()
    encoded = json.dumps(receipt, separators=(",", ":"))
    duplicated = encoded.replace(
        "{", '{"schema_id":"duplicate",', 1
    )
    ReceiptStore.path().write_text(duplicated + "\n")

    with pytest.raises(ValueError, match="Duplicate JSON key"):
        ReceiptStore.list()
