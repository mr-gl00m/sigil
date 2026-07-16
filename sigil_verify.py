#!/usr/bin/env python3
"""Independent verifier for SIGIL v0.1 receipts and disclosures."""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import nacl.encoding
import nacl.signing
from nacl.exceptions import BadSignatureError


RECEIPT_SCHEMA_ID = "sigil.proof_of_execution.receipt"
DISCLOSURE_SCHEMA_ID = "sigil.proof_of_execution.disclosure"
MANIFEST_SCHEMA_ID = "sigil.runtime_manifest"
LEGAL_BUNDLE_SCHEMA_ID = "sigil.legal_receipt_bundle"
SCHEMA_VERSION = "0.1"
LEAF_DOMAIN = b"sigil-receipt-leaf-v0.1\x00"
NODE_DOMAIN = b"sigil-receipt-node-v0.1\x00"
ID_DOMAIN = b"sigil-receipt-id-v0.1\x00"
SIGNATURE_DOMAIN = b"sigil-receipt-signature-v0.1\x00"
MANIFEST_SIGNATURE_DOMAIN = b"sigil-runtime-manifest-v0.1\x00"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_FILES = 256
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
RECEIPT_TOP_LEVEL = {
    "schema_id",
    "schema_version",
    "receipt_id",
    "fields",
    "salts",
    "merkle_root",
    "signer_key_id",
    "signature",
}
DISCLOSURE_TOP_LEVEL = {
    "schema_id",
    "schema_version",
    "receipt_id",
    "merkle_root",
    "signer_key_id",
    "signature",
    "disclosed",
}
LEGAL_BUNDLE_TOP_LEVEL = {
    "schema_id",
    "schema_version",
    "case_id",
    "disclosures",
    "runtime_manifests",
    "trust_bundle",
}
RECEIPT_FIELDS = {
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
MANIFEST_PAYLOAD_FIELDS = (
    "schema_id",
    "schema_version",
    "runtime_version",
    "files",
    "missing_files",
    "active_key_ids",
)
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


class VerificationError(ValueError):
    """Raised for any invalid or incomplete verification input."""


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(raw: bytes) -> Any:
    if len(raw) > MAX_INPUT_BYTES:
        raise VerificationError("Input exceeds the 16 MiB size limit")
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VerificationError(f"Invalid JSON: {exc}") from exc


def _load_path(path: Path) -> Any:
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise VerificationError("Input exceeds the 16 MiB size limit")
    try:
        return _load_json_bytes(raw)
    except VerificationError as original:
        items = []
        for line_number, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                items.append(_load_json_bytes(line))
            except VerificationError as exc:
                raise VerificationError(
                    f"Invalid JSONL at line {line_number}: {exc}"
                ) from original
        if not items:
            raise original
        return items


def _reject_float(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > 64:
        raise VerificationError("Canonical JSON nesting exceeds 64 levels")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise VerificationError(f"Floating-point value at {path} is not canonical")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_float(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VerificationError(f"Non-string object key at {path}")
            _reject_float(item, f"{path}.{key}", depth + 1)
        return
    raise VerificationError(f"Unsupported JSON type at {path}: {type(value).__name__}")


def _canonical(value: Any) -> bytes:
    _reject_float(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hex_bytes(value: Any, chars: int, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != chars:
        raise VerificationError(f"{name} must contain {chars} hexadecimal characters")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise VerificationError(f"{name} is not hexadecimal") from exc
    if len(decoded) * 2 != chars:
        raise VerificationError(f"{name} has an invalid length")
    return decoded


def _key_id(verify_key: nacl.signing.VerifyKey) -> str:
    public_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
    return hashlib.sha256(public_hex).hexdigest()[:16]


def _load_verify_key(value: Optional[str], name: str) -> nacl.signing.VerifyKey:
    if value is None:
        raise VerificationError(f"{name} is required")
    candidate = Path(value)
    try:
        raw = candidate.read_bytes() if candidate.is_file() else value.encode("ascii")
        return nacl.signing.VerifyKey(raw.strip(), encoder=nacl.encoding.HexEncoder)
    except (OSError, TypeError, ValueError) as exc:
        raise VerificationError(f"{name} is invalid") from exc


def _leaf(name: str, value: Any, salt_hex: str) -> bytes:
    salt = _hex_bytes(salt_hex, 32, f"salt for {name}")
    return hashlib.sha256(
        LEAF_DOMAIN
        + name.encode("utf-8")
        + b"\x00"
        + salt
        + b"\x00"
        + _canonical(value)
    ).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def _root(fields: Dict[str, Any], salts: Dict[str, str]) -> str:
    if not fields or set(fields) != set(salts):
        raise VerificationError("Receipt fields and salts are empty or mismatched")
    level = [_leaf(name, fields[name], salts[name]) for name in sorted(fields)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[index], level[index + 1]) for index in range(0, len(level), 2)]
    return level[0].hex()


def _receipt_id(root_hex: str) -> str:
    return hashlib.sha256(ID_DOMAIN + _hex_bytes(root_hex, 64, "merkle_root")).hexdigest()


def _signature_message(receipt: Dict[str, Any]) -> bytes:
    envelope = {
        "schema_id": receipt["schema_id"],
        "schema_version": receipt["schema_version"],
        "receipt_id": receipt["receipt_id"],
        "merkle_root": receipt["merkle_root"],
    }
    return SIGNATURE_DOMAIN + _canonical(envelope)


def _validate_receipt_fields(fields: Any) -> None:
    if not isinstance(fields, dict) or set(fields) != RECEIPT_FIELDS:
        raise VerificationError("Receipt committed field set does not match schema v0.1")
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
            raise VerificationError(f"{name} must be a non-empty string")
    if fields["receipt_type"] not in RECEIPT_TYPES:
        raise VerificationError("receipt_type is invalid")
    if fields["decision"] not in DECISIONS:
        raise VerificationError("decision is invalid")
    if fields["effect_class"] not in EFFECT_CLASSES:
        raise VerificationError("effect_class is invalid")
    if fields["assurance_profile"] != "software_manifest":
        raise VerificationError("Receipt assurance profile is unsupported")
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
            _hex_bytes(fields[name], 64, name)
    evidence_hashes = fields["evidence_hashes"]
    if not isinstance(evidence_hashes, list):
        raise VerificationError("evidence_hashes must be an array")
    for index, digest in enumerate(evidence_hashes):
        _hex_bytes(digest, 64, f"evidence_hashes[{index}]")
    depth = fields["delegation_depth"]
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0:
        raise VerificationError("delegation_depth must be a non-negative integer")
    if fields["parent_receipt_id"] is None and depth != 0:
        raise VerificationError("Root receipt delegation depth must be zero")
    if fields["parent_receipt_id"] is not None and depth == 0:
        raise VerificationError("Delegated receipt depth must be positive")
    for name in ("actor_id", "capability_id"):
        if fields[name] is not None and not isinstance(fields[name], str):
            raise VerificationError(f"{name} must be a string or null")
    if not isinstance(fields["metadata"], dict):
        raise VerificationError("metadata must be an object")
    try:
        issued_at = datetime.fromisoformat(fields["issued_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError("issued_at is not a valid RFC 3339 timestamp") from exc
    if issued_at.tzinfo is None:
        raise VerificationError("issued_at must include a timezone")
    _reject_float(fields)


def _validate_disclosed_value(name: str, value: Any) -> None:
    if name in {
        "arguments_hash",
        "manifest_hash",
        "seal_hash",
        "output_hash",
        "policy_hash",
        "tool_manifest_hash",
        "previous_receipt_id",
        "parent_receipt_id",
    }:
        if value is not None:
            _hex_bytes(value, 64, name)
    elif name == "receipt_type" and value not in RECEIPT_TYPES:
        raise VerificationError("Disclosed receipt_type is invalid")
    elif name == "decision" and value not in DECISIONS:
        raise VerificationError("Disclosed decision is invalid")
    elif name == "effect_class" and value not in EFFECT_CLASSES:
        raise VerificationError("Disclosed effect_class is invalid")
    elif name == "assurance_profile" and value != "software_manifest":
        raise VerificationError("Disclosed assurance_profile is invalid")
    elif name == "delegation_depth":
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise VerificationError("Disclosed delegation_depth is invalid")
    elif name == "metadata" and not isinstance(value, dict):
        raise VerificationError("Disclosed metadata is invalid")
    _reject_float(value)


def verify_manifest(
    manifest: Dict[str, Any], verify_key: nacl.signing.VerifyKey
) -> str:
    expected_names = set(MANIFEST_PAYLOAD_FIELDS) | {
        "manifest_hash",
        "signer_key_id",
        "signature",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_names:
        raise VerificationError("Runtime manifest envelope does not match schema v0.1")
    if manifest.get("schema_id") != MANIFEST_SCHEMA_ID:
        raise VerificationError("Runtime manifest schema_id is unsupported")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("Runtime manifest schema_version is unsupported")
    try:
        payload = {name: manifest[name] for name in MANIFEST_PAYLOAD_FIELDS}
    except KeyError as exc:
        raise VerificationError(f"Runtime manifest field is missing: {exc}") from exc
    manifest_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    if manifest.get("manifest_hash") != manifest_hash:
        raise VerificationError("Runtime manifest hash mismatch")
    if manifest.get("signer_key_id") != _key_id(verify_key):
        raise VerificationError("Runtime manifest signer key ID mismatch")
    try:
        signature = _hex_bytes(manifest.get("signature"), 128, "manifest signature")
        verify_key.verify(
            MANIFEST_SIGNATURE_DOMAIN + manifest_hash.encode("ascii"), signature
        )
    except BadSignatureError as exc:
        raise VerificationError("Runtime manifest signature invalid") from exc
    return manifest_hash


def verify_receipt(receipt: Dict[str, Any], verify_key: nacl.signing.VerifyKey) -> str:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_TOP_LEVEL:
        raise VerificationError("Receipt envelope does not match schema v0.1")
    if receipt["schema_id"] != RECEIPT_SCHEMA_ID:
        raise VerificationError("Receipt schema_id is unsupported")
    if receipt["schema_version"] != SCHEMA_VERSION:
        raise VerificationError("Receipt schema_version is unsupported")
    fields = receipt["fields"]
    _validate_receipt_fields(fields)
    root = _root(fields, receipt["salts"])
    if receipt["merkle_root"] != root:
        raise VerificationError("Receipt Merkle root mismatch")
    receipt_id = _receipt_id(root)
    if receipt["receipt_id"] != receipt_id:
        raise VerificationError("Receipt ID mismatch")
    if receipt["signer_key_id"] != _key_id(verify_key):
        raise VerificationError("Receipt signer key ID mismatch")
    try:
        signature = _hex_bytes(receipt["signature"], 128, "receipt signature")
        verify_key.verify(_signature_message(receipt), signature)
    except BadSignatureError as exc:
        raise VerificationError("Receipt signature invalid") from exc
    return receipt_id


def verify_disclosure(
    disclosure: Dict[str, Any], verify_key: nacl.signing.VerifyKey
) -> str:
    if not isinstance(disclosure, dict) or set(disclosure) != DISCLOSURE_TOP_LEVEL:
        raise VerificationError("Disclosure envelope does not match schema v0.1")
    if disclosure.get("schema_id") != DISCLOSURE_SCHEMA_ID:
        raise VerificationError("Disclosure schema_id is unsupported")
    if disclosure.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("Disclosure schema_version is unsupported")
    root_hex = disclosure.get("merkle_root")
    receipt_id = _receipt_id(root_hex)
    if disclosure.get("receipt_id") != receipt_id:
        raise VerificationError("Disclosure receipt ID mismatch")
    if disclosure.get("signer_key_id") != _key_id(verify_key):
        raise VerificationError("Disclosure signer key ID mismatch")
    envelope = {
        "schema_id": RECEIPT_SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "merkle_root": root_hex,
    }
    try:
        signature = _hex_bytes(disclosure.get("signature"), 128, "receipt signature")
        verify_key.verify(SIGNATURE_DOMAIN + _canonical(envelope), signature)
    except BadSignatureError as exc:
        raise VerificationError("Disclosure receipt signature invalid") from exc
    disclosed = disclosure.get("disclosed")
    if not isinstance(disclosed, dict) or not disclosed:
        raise VerificationError("Disclosure contains no fields")
    for name, proof in disclosed.items():
        if name not in RECEIPT_FIELDS:
            raise VerificationError(f"Disclosure field is unknown: {name}")
        _validate_disclosed_value(name, proof["value"])
        current = _leaf(name, proof["value"], proof["salt"])
        for step in proof["path"]:
            sibling = _hex_bytes(step["hash"], 64, f"proof hash for {name}")
            if step["side"] == "left":
                current = _node(sibling, current)
            elif step["side"] == "right":
                current = _node(current, sibling)
            else:
                raise VerificationError(f"Disclosure side is invalid for {name}")
        if current.hex() != root_hex:
            raise VerificationError(f"Disclosure proof failed for {name}")
    return receipt_id


def _load_manifests(path_value: Optional[str]) -> Dict[str, Dict[str, Any]]:
    if path_value is None:
        return {}
    path = Path(path_value)
    candidates = sorted(path.glob("*.json")) if path.is_dir() else [path]
    if len(candidates) > MAX_MANIFEST_FILES:
        raise VerificationError("Runtime manifest file count exceeds the limit")
    manifests: Dict[str, Dict[str, Any]] = {}
    total_bytes = 0
    for candidate in candidates:
        total_bytes += candidate.stat().st_size
        if total_bytes > MAX_MANIFEST_BYTES:
            raise VerificationError("Runtime manifest bytes exceed the aggregate limit")
        data = _load_path(candidate)
        if isinstance(data, dict) and data.get("schema_id") == MANIFEST_SCHEMA_ID:
            manifests[data.get("manifest_hash", "")] = data
    return manifests


def _verify_chain(receipts: List[Dict[str, Any]]) -> None:
    previous: Optional[str] = None
    seen: Dict[str, Dict[str, Any]] = {}
    for index, receipt in enumerate(receipts):
        fields = receipt["fields"]
        if fields.get("previous_receipt_id") != previous:
            raise VerificationError(f"Receipt chain link failed at index {index}")
        parent_id = fields.get("parent_receipt_id")
        depth = fields.get("delegation_depth")
        if parent_id is None:
            if depth != 0:
                raise VerificationError(f"Root delegation depth failed at index {index}")
        else:
            if parent_id == receipt["receipt_id"]:
                raise VerificationError(f"Receipt self-parent failed at index {index}")
            parent = seen.get(parent_id)
            if parent is None:
                raise VerificationError(f"Delegation parent is missing at index {index}")
            if depth != parent["fields"].get("delegation_depth") + 1:
                raise VerificationError(f"Delegation depth failed at index {index}")
        seen[receipt["receipt_id"]] = receipt
        previous = receipt["receipt_id"]


def _verify_manifest_binding(
    manifest_hash: Any,
    manifests: Dict[str, Dict[str, Any]],
    system_key: nacl.signing.VerifyKey,
) -> None:
    if not isinstance(manifest_hash, str) or manifest_hash not in manifests:
        raise VerificationError("Matching runtime manifest is missing")
    verified_hash = verify_manifest(manifests[manifest_hash], system_key)
    if verified_hash != manifest_hash:
        raise VerificationError("Runtime manifest binding mismatch")


def verify_document(
    document: Any,
    receipt_key_value: Optional[str],
    system_key_value: Optional[str],
    manifests: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if isinstance(document, dict) and document.get("schema_id") == LEGAL_BUNDLE_SCHEMA_ID:
        if set(document) != LEGAL_BUNDLE_TOP_LEVEL:
            raise VerificationError("Legal receipt bundle envelope does not match schema v0.1")
        if document.get("schema_version") != SCHEMA_VERSION:
            raise VerificationError("Legal receipt bundle schema_version is unsupported")
        manifests = {**document.get("runtime_manifests", {}), **manifests}
        receipt_key = _load_verify_key(receipt_key_value, "receipt public key")
        system_key = _load_verify_key(system_key_value, "system public key")
        disclosures = document.get("disclosures")
        if not isinstance(disclosures, list) or not disclosures:
            raise VerificationError("Legal receipt bundle contains no disclosures")
        receipt_ids = []
        disclosed_previous: Optional[str] = None
        first = True
        for disclosure in disclosures:
            receipt_ids.append(verify_disclosure(disclosure, receipt_key))
            fields = disclosure["disclosed"]
            manifest_proof = fields.get("manifest_hash")
            if manifest_proof is None:
                raise VerificationError("Disclosure omits manifest_hash")
            _verify_manifest_binding(manifest_proof["value"], manifests, system_key)
            previous_proof = fields.get("previous_receipt_id")
            if previous_proof is None:
                raise VerificationError("Disclosure omits previous_receipt_id")
            previous_value = previous_proof["value"]
            if not first and previous_value != disclosed_previous:
                raise VerificationError("Disclosed receipt chain link failed")
            disclosed_previous = disclosure["receipt_id"]
            first = False
        return {
            "valid": True,
            "kind": "legal_receipt_bundle",
            "receipt_ids": receipt_ids,
            "assurance_profile": "software_manifest",
            "verified_components": [
                "receipt_signatures",
                "merkle_disclosures",
                "runtime_manifest_signatures",
                "disclosed_chain_links",
            ],
            "unverified_components": [
                "hardware_isolation",
                "model_inference",
                "tool_result_correctness",
                "wall_clock_authority",
                "freshness",
                "revocation_state",
                "semantic_delegation_intent",
            ],
            "trust_anchor": "caller_supplied",
        }

    receipt_key = _load_verify_key(receipt_key_value, "receipt public key")
    if isinstance(document, list):
        receipts = document
    elif isinstance(document, dict) and document.get("schema_id") == RECEIPT_SCHEMA_ID:
        receipts = [document]
    elif isinstance(document, dict) and document.get("schema_id") == DISCLOSURE_SCHEMA_ID:
        receipt_id = verify_disclosure(document, receipt_key)
        proof = document["disclosed"].get("manifest_hash")
        verified_components = [
            "receipt_signature",
            "merkle_disclosure",
        ]
        unverified_components = [
            "hidden_receipt_fields",
            "hardware_isolation",
            "model_inference",
            "tool_result_correctness",
            "wall_clock_authority",
            "freshness",
            "revocation_state",
            "semantic_delegation_intent",
        ]
        assurance_profile: Optional[str] = None
        if proof is not None:
            system_key = _load_verify_key(system_key_value, "system public key")
            _verify_manifest_binding(proof["value"], manifests, system_key)
            verified_components.append("runtime_manifest_signature")
            assurance_profile = "software_manifest"
        else:
            unverified_components.insert(1, "runtime_manifest_binding")
        return {
            "valid": True,
            "kind": "disclosure",
            "receipt_ids": [receipt_id],
            "assurance_profile": assurance_profile,
            "verified_components": verified_components,
            "unverified_components": unverified_components,
            "trust_anchor": "caller_supplied",
        }
    else:
        raise VerificationError("Input schema is unsupported")

    system_key = _load_verify_key(system_key_value, "system public key")
    receipt_ids = []
    for receipt in receipts:
        receipt_ids.append(verify_receipt(receipt, receipt_key))
        _verify_manifest_binding(
            receipt["fields"].get("manifest_hash"), manifests, system_key
        )
    _verify_chain(receipts)
    return {
        "valid": True,
        "kind": "receipt_chain" if len(receipts) > 1 else "receipt",
        "receipt_ids": receipt_ids,
        "assurance_profile": "software_manifest",
        "verified_components": [
            "receipt_signatures",
            "merkle_commitments",
            "runtime_manifest_signatures",
            "receipt_chain",
            "delegation_links",
        ],
        "unverified_components": [
            "hardware_isolation",
            "model_inference",
            "tool_result_correctness",
            "wall_clock_authority",
            "freshness",
            "revocation_state",
            "semantic_delegation_intent",
        ],
        "trust_anchor": "caller_supplied",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigil-verify",
        description="Verify SIGIL v0.1 receipts without importing producer modules.",
    )
    parser.add_argument("input", help="Receipt, disclosure, legal bundle, or receipt JSONL")
    parser.add_argument("--receipt-key", help="Pinned receipt public key path or hexadecimal key")
    parser.add_argument("--system-key", help="Pinned system public key path or hexadecimal key")
    parser.add_argument("--manifest", help="Runtime manifest JSON file or snapshot directory")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        document = _load_path(Path(args.input))
        manifests = _load_manifests(args.manifest)
        result = verify_document(
            document, args.receipt_key, args.system_key, manifests
        )
    except (OSError, VerificationError, KeyError, TypeError, ValueError) as exc:
        result = {"valid": False, "error": str(exc)}
        if args.json:
            print(json.dumps(result, sort_keys=True))
        else:
            print(f"FAIL: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        ids = ", ".join(result["receipt_ids"])
        print(f"OK: {result['kind']} verified: {ids}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
