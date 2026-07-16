#!/usr/bin/env python3
"""Portable SIGIL action receipts and selective-disclosure proofs."""

import copy
import hashlib
import json
import math
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import nacl.encoding
import nacl.signing
from nacl.exceptions import BadSignatureError

import sigil


RECEIPT_SCHEMA_ID = "sigil.proof_of_execution.receipt"
DISCLOSURE_SCHEMA_ID = "sigil.proof_of_execution.disclosure"
SCHEMA_VERSION = "0.1"
ASSURANCE_PROFILE = "software_manifest"
LEAF_DOMAIN = b"sigil-receipt-leaf-v0.1\x00"
NODE_DOMAIN = b"sigil-receipt-node-v0.1\x00"
ID_DOMAIN = b"sigil-receipt-id-v0.1\x00"
SIGNATURE_DOMAIN = b"sigil-receipt-signature-v0.1\x00"
MAX_RECEIPT_BYTES = 1024 * 1024

RECEIPT_TYPES = {"action", "decision", "outcome", "delegation", "mcp_call"}
DECISIONS = {
    "allow",
    "deny",
    "ask",
    "approve",
    "succeeded",
    "failed",
    "timed_out",
    "cancelled",
    "outcome_unknown",
}
EFFECT_CLASSES = {"read", "write", "network", "exec", "privileged"}
FIELD_NAMES = {
    "receipt_type",
    "issued_at",
    "action_id",
    "actor_id",
    "seal_hash",
    "action",
    "decision",
    "capability_id",
    "effect_class",
    "arguments_hash",
    "output_hash",
    "evidence_hashes",
    "policy_hash",
    "tool_manifest_hash",
    "manifest_hash",
    "assurance_profile",
    "previous_receipt_id",
    "parent_receipt_id",
    "delegation_depth",
    "metadata",
}
TOP_LEVEL_NAMES = {
    "schema_id",
    "schema_version",
    "receipt_id",
    "fields",
    "salts",
    "merkle_root",
    "signer_key_id",
    "signature",
}
DISCLOSURE_TOP_LEVEL_NAMES = {
    "schema_id",
    "schema_version",
    "receipt_id",
    "merkle_root",
    "signer_key_id",
    "signature",
    "disclosed",
}


def _reject_duplicate_keys(items: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"Duplicate JSON key in receipt store: {key}")
        result[key] = value
    return result


def _reject_noncanonical(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("Canonical JSON nesting exceeds 64 levels")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"Non-finite number at {path}")
        raise ValueError(f"Floating-point value at {path} is not canonical")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_noncanonical(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"Non-string object key at {path}")
            _reject_noncanonical(item, f"{path}.{key}", depth + 1)
        return
    raise ValueError(f"Unsupported canonical JSON type at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Serialize the closed v0.1 canonical JSON subset."""
    _reject_noncanonical(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _validate_hex(value: Any, length: int, field_name: str) -> None:
    if not isinstance(value, str) or len(value) != length:
        raise ValueError(f"{field_name} must contain {length} hexadecimal characters")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not hexadecimal") from exc


def _leaf_hash(name: str, value: Any, salt_hex: str) -> bytes:
    _validate_hex(salt_hex, 32, f"salt for {name}")
    return hashlib.sha256(
        LEAF_DOMAIN
        + name.encode("utf-8")
        + b"\x00"
        + bytes.fromhex(salt_hex)
        + b"\x00"
        + canonical_json(value)
    ).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def _merkle_levels(fields: Dict[str, Any], salts: Dict[str, str]) -> List[List[bytes]]:
    if not fields:
        raise ValueError("A receipt must contain committed fields")
    if set(fields) != set(salts):
        raise ValueError("Receipt fields and salts must have identical keys")
    level = [_leaf_hash(name, fields[name], salts[name]) for name in sorted(fields)]
    levels = [level]
    while len(level) > 1:
        working = level if len(level) % 2 == 0 else level + [level[-1]]
        level = [
            _node_hash(working[index], working[index + 1])
            for index in range(0, len(working), 2)
        ]
        levels.append(level)
    return levels


def merkle_root(fields: Dict[str, Any], salts: Dict[str, str]) -> str:
    return _merkle_levels(fields, salts)[-1][0].hex()


def _receipt_id(root_hex: str) -> str:
    _validate_hex(root_hex, 64, "merkle_root")
    return hashlib.sha256(ID_DOMAIN + bytes.fromhex(root_hex)).hexdigest()


def _signature_message(receipt: Dict[str, Any]) -> bytes:
    envelope = {
        "schema_id": receipt["schema_id"],
        "schema_version": receipt["schema_version"],
        "receipt_id": receipt["receipt_id"],
        "merkle_root": receipt["merkle_root"],
    }
    return SIGNATURE_DOMAIN + canonical_json(envelope)


def _key_id(verify_key: nacl.signing.VerifyKey) -> str:
    encoded = verify_key.encode(encoder=nacl.encoding.HexEncoder)
    return hashlib.sha256(encoded).hexdigest()[:16]


class ReceiptSigner:
    """Dedicated local Ed25519 signer for proof-of-execution receipts."""

    _lock = threading.Lock()

    @staticmethod
    def _paths() -> tuple[Path, Path]:
        return sigil.KEYS_DIR / "_receipt.key", sigil.KEYS_DIR / "_receipt.pub"

    @classmethod
    def load(cls) -> tuple[nacl.signing.SigningKey, str]:
        with cls._lock:
            key_path, pub_path = cls._paths()
            if not key_path.exists() and pub_path.exists():
                raise RuntimeError("Receipt private key is missing while its public key exists")
            if key_path.exists():
                signer = nacl.signing.SigningKey(
                    key_path.read_bytes(), encoder=nacl.encoding.HexEncoder
                )
            else:
                signer = nacl.signing.SigningKey.generate()
                sigil._atomic_write_bytes(
                    key_path,
                    signer.encode(encoder=nacl.encoding.HexEncoder),
                    mode=0o600,
                )
            expected_public = signer.verify_key.encode(encoder=nacl.encoding.HexEncoder)
            if pub_path.exists() and pub_path.read_bytes() != expected_public:
                raise RuntimeError("Receipt public key does not match its private key")
            if not pub_path.exists():
                sigil._atomic_write_bytes(pub_path, expected_public, mode=0o644)
            return signer, _key_id(signer.verify_key)


class ReceiptStore:
    """Append-only receipt store with signing and disclosure support."""

    @staticmethod
    def path() -> Path:
        return sigil.AUDIT_DIR / "receipts.jsonl"

    @classmethod
    def _load_unlocked(cls) -> List[Dict[str, Any]]:
        path = cls.path()
        if not path.exists():
            return []
        receipts: List[Dict[str, Any]] = []
        with open(path, "rb") as handle:
            for line_number, raw in enumerate(handle, 1):
                if len(raw) > MAX_RECEIPT_BYTES:
                    raise ValueError(f"Receipt line {line_number} exceeds the size limit")
                if not raw.strip():
                    continue
                receipts.append(json.loads(raw, object_pairs_hook=_reject_duplicate_keys))
        return receipts

    @staticmethod
    def _validate_existing(
        receipts: Sequence[Dict[str, Any]],
        verify_key: nacl.signing.VerifyKey,
    ) -> None:
        try:
            system_verify_key = nacl.signing.VerifyKey(
                (sigil.KEYS_DIR / "_system.pub").read_bytes(),
                encoder=nacl.encoding.HexEncoder,
            )
        except (FileNotFoundError, TypeError, ValueError) as exc:
            raise RuntimeError("Runtime manifest system key is missing or invalid") from exc
        previous: Optional[str] = None
        seen: Dict[str, Dict[str, Any]] = {}
        for index, receipt in enumerate(receipts):
            try:
                fields = receipt["fields"]
                manifest = sigil.RuntimeManifest.load(fields["manifest_hash"])
            except (FileNotFoundError, KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Stored receipt {index} has invalid manifest binding"
                ) from exc
            valid, message = verify_receipt(
                receipt,
                verify_key,
                manifest,
                system_verify_key,
            )
            if not valid:
                raise RuntimeError(f"Stored receipt {index} is invalid: {message}")
            if fields["previous_receipt_id"] != previous:
                raise RuntimeError(f"Stored receipt chain is broken at index {index}")
            parent_id = fields["parent_receipt_id"]
            if parent_id is not None:
                parent = seen.get(parent_id)
                if parent is None:
                    raise RuntimeError(
                        f"Stored delegation parent is missing at index {index}"
                    )
                if fields["delegation_depth"] != (
                    parent["fields"]["delegation_depth"] + 1
                ):
                    raise RuntimeError(
                        f"Stored delegation depth is invalid at index {index}"
                    )
            seen[receipt["receipt_id"]] = receipt
            previous = receipt["receipt_id"]

    @classmethod
    def list(cls) -> List[Dict[str, Any]]:
        with sigil.FileLock(cls.path()):
            receipts = cls._load_unlocked()
            if receipts:
                pub_path = sigil.KEYS_DIR / "_receipt.pub"
                if not pub_path.exists():
                    raise RuntimeError("Receipt public key is missing")
                verify_key = nacl.signing.VerifyKey(
                    pub_path.read_bytes(), encoder=nacl.encoding.HexEncoder
                )
                cls._validate_existing(receipts, verify_key)
            return copy.deepcopy(receipts)

    @classmethod
    def get(cls, receipt_id: str) -> Dict[str, Any]:
        _validate_hex(receipt_id, 64, "receipt_id")
        for receipt in cls.list():
            if receipt.get("receipt_id") == receipt_id:
                return receipt
        raise KeyError(f"Receipt {receipt_id} was not found")

    @classmethod
    def emit(
        cls,
        *,
        receipt_type: str,
        action: str,
        decision: str,
        effect_class: str,
        arguments: Any,
        output: Any = None,
        action_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        seal_hash: Optional[str] = None,
        capability_id: Optional[str] = None,
        evidence_hashes: Optional[Sequence[str]] = None,
        policy_hash: Optional[str] = None,
        tool_manifest_hash: Optional[str] = None,
        parent_receipt_id: Optional[str] = None,
        delegation_depth: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if receipt_type not in RECEIPT_TYPES:
            raise ValueError(f"Unsupported receipt_type: {receipt_type}")
        if decision not in DECISIONS:
            raise ValueError(f"Unsupported decision: {decision}")
        if effect_class not in EFFECT_CLASSES:
            raise ValueError(f"Unsupported effect_class: {effect_class}")
        if not isinstance(action, str) or not action:
            raise ValueError("action must be a non-empty string")
        hashes = list(evidence_hashes or [])
        for index, digest in enumerate(hashes):
            _validate_hex(digest, 64, f"evidence_hashes[{index}]")
        for name, digest in (
            ("seal_hash", seal_hash),
            ("policy_hash", policy_hash),
            ("tool_manifest_hash", tool_manifest_hash),
        ):
            if digest is not None:
                _validate_hex(digest, 64, name)

        signer, signer_key_id = ReceiptSigner.load()
        manifest = sigil.RuntimeManifest.current()
        path = cls.path()
        with sigil.FileLock(path):
            receipts = cls._load_unlocked()
            cls._validate_existing(receipts, signer.verify_key)
            previous_receipt_id = receipts[-1]["receipt_id"] if receipts else None
            parent = None
            if parent_receipt_id is not None:
                _validate_hex(parent_receipt_id, 64, "parent_receipt_id")
                parent = next(
                    (
                        item
                        for item in receipts
                        if item.get("receipt_id") == parent_receipt_id
                    ),
                    None,
                )
                if parent is None:
                    raise ValueError("Delegation parent does not exist in this receipt store")
                expected_depth = parent["fields"]["delegation_depth"] + 1
            else:
                expected_depth = 0
            if delegation_depth is not None and delegation_depth != expected_depth:
                raise ValueError("delegation_depth does not match the parent relation")

            fields: Dict[str, Any] = {
                "receipt_type": receipt_type,
                "issued_at": datetime.now(timezone.utc).isoformat(),
                "action_id": action_id or os.urandom(16).hex(),
                "actor_id": actor_id,
                "seal_hash": seal_hash,
                "action": action,
                "decision": decision,
                "capability_id": capability_id,
                "effect_class": effect_class,
                "arguments_hash": _sha256_value(arguments),
                "output_hash": None if output is None else _sha256_value(output),
                "evidence_hashes": hashes,
                "policy_hash": policy_hash,
                "tool_manifest_hash": tool_manifest_hash,
                "manifest_hash": manifest["manifest_hash"],
                "assurance_profile": ASSURANCE_PROFILE,
                "previous_receipt_id": previous_receipt_id,
                "parent_receipt_id": parent_receipt_id,
                "delegation_depth": expected_depth,
                "metadata": copy.deepcopy(metadata or {}),
            }
            _validate_fields(fields)
            salts = {name: os.urandom(16).hex() for name in fields}
            root = merkle_root(fields, salts)
            receipt: Dict[str, Any] = {
                "schema_id": RECEIPT_SCHEMA_ID,
                "schema_version": SCHEMA_VERSION,
                "receipt_id": _receipt_id(root),
                "fields": fields,
                "salts": salts,
                "merkle_root": root,
                "signer_key_id": signer_key_id,
            }
            receipt["signature"] = signer.sign(
                _signature_message(receipt)
            ).signature.hex()
            encoded = canonical_json(receipt)
            if len(encoded) > MAX_RECEIPT_BYTES:
                raise ValueError("Receipt exceeds the size limit")
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "ab") as handle:
                handle.write(encoded + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                path.chmod(0o600)
            except (OSError, NotImplementedError):
                pass
            return copy.deepcopy(receipt)

    @classmethod
    def reveal(cls, receipt_id: str, fields: Sequence[str]) -> Dict[str, Any]:
        receipt = cls.get(receipt_id)
        selected = list(dict.fromkeys(fields))
        if not selected:
            raise ValueError("At least one field must be disclosed")
        unknown = set(selected) - set(receipt["fields"])
        if unknown:
            raise ValueError(f"Unknown disclosure fields: {sorted(unknown)}")
        names = sorted(receipt["fields"])
        levels = _merkle_levels(receipt["fields"], receipt["salts"])
        disclosed: Dict[str, Any] = {}
        for name in selected:
            index = names.index(name)
            path: List[Dict[str, str]] = []
            for level in levels[:-1]:
                working = level if len(level) % 2 == 0 else level + [level[-1]]
                sibling_index = index - 1 if index % 2 else index + 1
                path.append(
                    {
                        "side": "left" if sibling_index < index else "right",
                        "hash": working[sibling_index].hex(),
                    }
                )
                index //= 2
            disclosed[name] = {
                "value": copy.deepcopy(receipt["fields"][name]),
                "salt": receipt["salts"][name],
                "path": path,
            }
        return {
            "schema_id": DISCLOSURE_SCHEMA_ID,
            "schema_version": SCHEMA_VERSION,
            "receipt_id": receipt["receipt_id"],
            "merkle_root": receipt["merkle_root"],
            "signer_key_id": receipt["signer_key_id"],
            "signature": receipt["signature"],
            "disclosed": disclosed,
        }

    @staticmethod
    def trust_bundle() -> Dict[str, Any]:
        ReceiptSigner.load()
        sigil.AuditChain._get_system_signer()
        return {
            "schema_id": "sigil.trust_bundle",
            "schema_version": SCHEMA_VERSION,
            "receipt_public_key": (sigil.KEYS_DIR / "_receipt.pub").read_text().strip(),
            "system_public_key": (sigil.KEYS_DIR / "_system.pub").read_text().strip(),
        }


def _validate_fields(fields: Any) -> None:
    if not isinstance(fields, dict) or set(fields) != FIELD_NAMES:
        raise ValueError("Receipt committed field set does not match schema v0.1")
    for name in (
        "receipt_type",
        "issued_at",
        "action_id",
        "action",
        "decision",
        "effect_class",
        "arguments_hash",
        "manifest_hash",
        "assurance_profile",
    ):
        if not isinstance(fields[name], str) or not fields[name]:
            raise ValueError(f"{name} must be a non-empty string")
    if fields["receipt_type"] not in RECEIPT_TYPES:
        raise ValueError("receipt_type is invalid")
    if fields["decision"] not in DECISIONS:
        raise ValueError("decision is invalid")
    if fields["effect_class"] not in EFFECT_CLASSES:
        raise ValueError("effect_class is invalid")
    if fields["assurance_profile"] != ASSURANCE_PROFILE:
        raise ValueError("assurance_profile is invalid")
    for name in (
        "arguments_hash",
        "manifest_hash",
        "seal_hash",
        "output_hash",
        "policy_hash",
        "tool_manifest_hash",
        "previous_receipt_id",
        "parent_receipt_id",
    ):
        if fields[name] is not None:
            _validate_hex(fields[name], 64, name)
    if not isinstance(fields["evidence_hashes"], list):
        raise ValueError("evidence_hashes must be an array")
    for index, digest in enumerate(fields["evidence_hashes"]):
        _validate_hex(digest, 64, f"evidence_hashes[{index}]")
    if not isinstance(fields["delegation_depth"], int) or isinstance(
        fields["delegation_depth"], bool
    ):
        raise ValueError("delegation_depth must be an integer")
    if fields["delegation_depth"] < 0:
        raise ValueError("delegation_depth cannot be negative")
    if fields["parent_receipt_id"] is None and fields["delegation_depth"] != 0:
        raise ValueError("Root receipts must have delegation_depth zero")
    if fields["parent_receipt_id"] is not None and fields["delegation_depth"] == 0:
        raise ValueError("Delegated receipts must have positive delegation_depth")
    for name in ("actor_id", "capability_id"):
        if fields[name] is not None and not isinstance(fields[name], str):
            raise ValueError(f"{name} must be a string or null")
    if not isinstance(fields["metadata"], dict):
        raise ValueError("metadata must be an object")
    try:
        parsed = datetime.fromisoformat(fields["issued_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("issued_at is not a valid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("issued_at must include a timezone")
    _reject_noncanonical(fields)


def verify_receipt(
    receipt: Dict[str, Any],
    verify_key: nacl.signing.VerifyKey,
    manifest: Optional[Dict[str, Any]] = None,
    system_verify_key: Optional[nacl.signing.VerifyKey] = None,
) -> tuple[bool, str]:
    """Verify a full receipt and its required runtime manifest binding."""
    try:
        if not isinstance(receipt, dict) or set(receipt) != TOP_LEVEL_NAMES:
            return False, "Receipt envelope does not match schema v0.1"
        if receipt["schema_id"] != RECEIPT_SCHEMA_ID:
            return False, "Receipt schema_id is unsupported"
        if receipt["schema_version"] != SCHEMA_VERSION:
            return False, "Receipt schema_version is unsupported"
        _validate_fields(receipt["fields"])
        root = merkle_root(receipt["fields"], receipt["salts"])
        if root != receipt["merkle_root"]:
            return False, "Receipt Merkle root mismatch"
        if _receipt_id(root) != receipt["receipt_id"]:
            return False, "Receipt ID mismatch"
        if _key_id(verify_key) != receipt["signer_key_id"]:
            return False, "Receipt signer key ID mismatch"
        verify_key.verify(
            _signature_message(receipt), bytes.fromhex(receipt["signature"])
        )
        if manifest is None or system_verify_key is None:
            return False, "Manifest and system verify key are required"
        valid, message = sigil.RuntimeManifest.verify(manifest, system_verify_key)
        if not valid:
            return False, message
        if receipt["fields"]["manifest_hash"] != manifest["manifest_hash"]:
            return False, "Receipt runtime manifest binding mismatch"
    except (BadSignatureError, KeyError, TypeError, ValueError):
        return False, "Receipt signature or structure is invalid"
    return True, "Receipt valid"


def verify_disclosure(
    disclosure: Dict[str, Any],
    verify_key: nacl.signing.VerifyKey,
    manifest: Optional[Dict[str, Any]] = None,
    system_verify_key: Optional[nacl.signing.VerifyKey] = None,
) -> tuple[bool, str]:
    """Verify inclusion proofs, signature, and any disclosed runtime binding."""
    try:
        if not isinstance(disclosure, dict) or set(disclosure) != DISCLOSURE_TOP_LEVEL_NAMES:
            return False, "Disclosure envelope does not match schema v0.1"
        if disclosure.get("schema_id") != DISCLOSURE_SCHEMA_ID:
            return False, "Disclosure schema_id is unsupported"
        if disclosure.get("schema_version") != SCHEMA_VERSION:
            return False, "Disclosure schema_version is unsupported"
        root_hex = disclosure["merkle_root"]
        if _receipt_id(root_hex) != disclosure["receipt_id"]:
            return False, "Disclosure receipt ID mismatch"
        if _key_id(verify_key) != disclosure["signer_key_id"]:
            return False, "Disclosure signer key ID mismatch"
        signed_envelope = {
            "schema_id": RECEIPT_SCHEMA_ID,
            "schema_version": SCHEMA_VERSION,
            "receipt_id": disclosure["receipt_id"],
            "merkle_root": root_hex,
        }
        verify_key.verify(
            SIGNATURE_DOMAIN + canonical_json(signed_envelope),
            bytes.fromhex(disclosure["signature"]),
        )
        disclosed = disclosure["disclosed"]
        if not isinstance(disclosed, dict) or not disclosed:
            return False, "Disclosure contains no fields"
        parent_proof = disclosed.get("parent_receipt_id")
        if (
            isinstance(parent_proof, dict)
            and parent_proof.get("value") == disclosure["receipt_id"]
        ):
            return False, "Disclosure contains a self-parent delegation"
        for name, proof in disclosed.items():
            current = _leaf_hash(name, proof["value"], proof["salt"])
            for step in proof["path"]:
                sibling = bytes.fromhex(step["hash"])
                if len(sibling) != 32:
                    return False, f"Disclosure path for {name} has an invalid hash"
                if step["side"] == "left":
                    current = _node_hash(sibling, current)
                elif step["side"] == "right":
                    current = _node_hash(current, sibling)
                else:
                    return False, f"Disclosure path for {name} has an invalid side"
            if current.hex() != root_hex:
                return False, f"Disclosure proof failed for {name}"
        manifest_proof = disclosed.get("manifest_hash")
        if manifest_proof is not None:
            if manifest is None or system_verify_key is None:
                return False, "Manifest and system verify key are required"
            valid, message = sigil.RuntimeManifest.verify(manifest, system_verify_key)
            if not valid:
                return False, message
            if manifest_proof["value"] != manifest["manifest_hash"]:
                return False, "Disclosure runtime manifest binding mismatch"
    except (BadSignatureError, KeyError, TypeError, ValueError):
        return False, "Disclosure signature or structure is invalid"
    return True, "Disclosure valid"
