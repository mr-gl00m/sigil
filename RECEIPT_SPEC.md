# SIGIL Proof-of-Execution Receipt Specification

Version: 0.1

Status: implementation contract

## 1. Scope

This document defines SIGIL's portable software proof-of-execution receipt, signed runtime
manifest, receipt chain, delegation link, and selective-disclosure proof. The format is local
first, framework neutral, and verifiable without access to the producing process or private
keys.

The v0.1 assurance profile is `software_manifest`. It proves that a holder of the receipt key
signed a field commitment bound to a signed measurement of the SIGIL source files and active
public keys. Its claim boundary excludes hardware isolation, model inference correctness, tool
result correctness, wall-clock authority, freshness, revocation state, and semantic intent
transitivity across delegation hops.

The existing Python `IntegrityReceipt` remains a prompt-conditioning canary. It is outside this
schema and must not be described as an action receipt.

## 2. Cryptographic suite

| Purpose | Primitive |
|---|---|
| Content digest | SHA-256 |
| Merkle leaf and node digest | SHA-256 with domain separation |
| Runtime manifest signature | Ed25519 system key |
| Action receipt signature | Ed25519 receipt key |
| Random field salt | 16 bytes from the operating system CSPRNG |

Prompt seals, audit entries, and action receipts use separate keys. Runtime manifests use the
audit system key because the active execution plan extends that existing system-key path. A
verifier trusts keys through an out-of-band public-key pin or trust bundle policy. A public key
carried beside a receipt provides portability, not identity by itself.

## 3. Canonical JSON

Canonical JSON uses UTF-8 with these rules:

1. Object keys are strings and are sorted in ascending Unicode code point order.
2. Arrays retain their declared order.
3. No insignificant whitespace is emitted.
4. Strings use JSON escaping and retain their Unicode content.
5. Only null, booleans, strings, integers, arrays, and objects are accepted in signed values.
6. Floating-point values, NaN, and infinities are rejected. A decimal quantity is represented
   as a string when exact cross-language form matters.

The Python reference form is:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
```

Any implementation must recursively reject floating-point values before serialization.

## 4. Runtime manifest

A runtime manifest has this shape:

```json
{
  "schema_id": "sigil.runtime_manifest",
  "schema_version": "0.1",
  "runtime_version": "1.9.0",
  "files": {
    "pyproject.toml": "<sha256>",
    "sigil.py": "<sha256>",
    "sigil_audit_proxy.py": "<sha256>",
    "sigil_llm_adapter.py": "<sha256>",
    "sigil_mcp.py": "<sha256>",
    "sigil_receipts.py": "<sha256>",
    "sigil_verify.py": "<sha256>"
  },
  "missing_files": [],
  "active_key_ids": {
    "_system": "<16 hex characters>",
    "_receipt": "<16 hex characters>"
  },
  "manifest_hash": "<sha256>",
  "signer_key_id": "<16 hex characters>",
  "signature": "<Ed25519 signature as 128 hex characters>"
}
```

`active_key_ids` contains every active `*.pub` file in the producer's SIGIL key directory,
sorted by filename. Each value is the first 16 hexadecimal characters of SHA-256 over the
public key file bytes. The example shows the two keys present in a minimal receipt-only
installation; deployments may include architect, operator, and rotated public keys.

`manifest_hash` is SHA-256 over canonical JSON containing every field above except
`manifest_hash`, `signer_key_id`, and `signature`. The signature message is:

```text
UTF8("sigil-runtime-manifest-v0.1\0") || ASCII(manifest_hash)
```

The producer stores immutable manifest snapshots by hash. Each audit entry and action receipt
carries the applicable `manifest_hash`.

## 5. Full action receipt

### 5.1 Envelope

```json
{
  "schema_id": "sigil.proof_of_execution.receipt",
  "schema_version": "0.1",
  "receipt_id": "<sha256>",
  "fields": { "<field name>": "<field value>" },
  "salts": { "<field name>": "<32 hex characters>" },
  "merkle_root": "<sha256>",
  "signer_key_id": "<16 hex characters>",
  "signature": "<Ed25519 signature as 128 hex characters>"
}
```

`fields` and `salts` have identical key sets. Unknown top-level fields are rejected. Receipt
field extensions require a new schema version.

### 5.2 Required committed fields

| Field | Type | Meaning |
|---|---|---|
| `receipt_type` | string | `action`, `decision`, `outcome`, `delegation`, or `mcp_call` |
| `issued_at` | string | UTC RFC 3339 timestamp |
| `action_id` | string | Stable identifier for the attempted action |
| `actor_id` | string or null | Agent or workflow identity within the producer's policy domain |
| `seal_hash` | string or null | SHA-256 digest of the governing SIGIL seal |
| `action` | string | Stable action or tool name |
| `decision` | string | `allow`, `deny`, `ask`, `approve`, `succeeded`, `failed`, `timed_out`, `cancelled`, or `outcome_unknown` |
| `capability_id` | string or null | Capability resolved by the deterministic gate |
| `effect_class` | string | `read`, `write`, `network`, `exec`, or `privileged` |
| `arguments_hash` | string | SHA-256 digest of canonical action arguments |
| `output_hash` | string or null | SHA-256 digest of canonical output when an output exists |
| `evidence_hashes` | array of strings | Digests of evidence used for the action or decision |
| `policy_hash` | string or null | Digest of the applicable policy bundle or seal policy fields |
| `tool_manifest_hash` | string or null | Digest of the exact tool definition used for dispatch |
| `manifest_hash` | string | Signed runtime manifest digest |
| `assurance_profile` | string | `software_manifest` for v0.1 |
| `previous_receipt_id` | string or null | Prior receipt in the producer's append-only linear receipt chain |
| `parent_receipt_id` | string or null | Receipt that delegated authority to this action |
| `delegation_depth` | integer | Zero for a root action, otherwise parent depth plus one |
| `metadata` | object | Redacted, non-secret outcome metadata |

Raw prompts, credentials, arguments, tool results, and retrieved documents are excluded. Their
canonical SHA-256 digests belong in the receipt. `metadata` must pass the same secret-redaction
policy used by the audit proxy before signing.

### 5.3 Merkle construction

Field names are sorted by ascending Unicode code point order. For field name `N`, salt `S`, and
canonical field value `V`, compute:

```text
leaf = SHA256(
  UTF8("sigil-receipt-leaf-v0.1\0") ||
  UTF8(N) || 0x00 || HEX-DECODE(S) || 0x00 || CANONICAL-JSON(V)
)
```

For each adjacent pair of raw 32-byte digests `L` and `R`, compute:

```text
node = SHA256(UTF8("sigil-receipt-node-v0.1\0") || L || R)
```

When a level has an odd count, duplicate its final digest as `R`. Repeat until one root remains.
Receipts with zero fields are invalid.

`receipt_id` is:

```text
SHA256(UTF8("sigil-receipt-id-v0.1\0") || HEX-DECODE(merkle_root))
```

The receipt signature message is:

```text
UTF8("sigil-receipt-signature-v0.1\0") ||
CANONICAL-JSON({
  "schema_id": schema_id,
  "schema_version": schema_version,
  "receipt_id": receipt_id,
  "merkle_root": merkle_root
})
```

## 6. Chain and delegation rules

The receipt store serializes append operations under an exclusive file lock and fsyncs each
record before returning it to a caller.

1. The first stored receipt has `previous_receipt_id: null`.
2. Each later receipt names the immediately preceding stored receipt.
3. A root action has `parent_receipt_id: null` and `delegation_depth: 0`.
4. A delegated action names an existing parent and sets depth to parent depth plus one.
5. A missing parent, depth mismatch, or self-parent is invalid.
6. v0.1 records the delegation relation and its provenance. Capability subset enforcement,
   freshness, revocation, and semantic intent preservation remain the caller's policy
   responsibility and must run before emission.

The linear link detects omission and reordering within one store. The parent link forms the
delegation tree across logical actions. It does not create transitive authority or prove that an
intermediate agent preserved the delegator's natural-language intent.

## 7. Selective disclosure

A disclosure bundle has this shape:

```json
{
  "schema_id": "sigil.proof_of_execution.disclosure",
  "schema_version": "0.1",
  "receipt_id": "<sha256>",
  "merkle_root": "<sha256>",
  "signer_key_id": "<16 hex characters>",
  "signature": "<receipt signature>",
  "disclosed": {
    "manifest_hash": {
      "value": "<sha256>",
      "salt": "<32 hex characters>",
      "path": [
        {"side": "right", "hash": "<sha256>"}
      ]
    }
  }
}
```

For each disclosed field, the verifier recomputes its salted leaf, folds the sibling path in
order, compares the result to `merkle_root`, derives `receipt_id`, and verifies the receipt
signature. `side` states the sibling's position relative to the current digest.

A disclosure containing `manifest_hash` must include or reference the matching signed runtime
manifest and must be verified against a pinned system public key. Omitted fields make no claim.
A valid inclusion proof says that the producer committed to the disclosed value; it says nothing
about hidden values.

SIGIL legal receipt bundles use a stricter application profile. Every disclosure in that bundle
must reveal `manifest_hash` and `previous_receipt_id` so the verifier can prove runtime binding and
adjacent chain links.

## 8. Verification algorithm

A full receipt verifier performs these checks in order:

1. Parse JSON with duplicate-key rejection and size limits.
2. Match `schema_id` and `schema_version` exactly.
3. Reject unknown top-level fields, missing required fields, invalid types, floats, and malformed
   hexadecimal values.
4. Recompute every salted leaf and the Merkle root.
5. Recompute `receipt_id`.
6. Match `signer_key_id` to the pinned receipt public key.
7. Verify the Ed25519 receipt signature.
8. Verify the signed runtime manifest with the pinned system public key.
9. Match `fields.manifest_hash` to the verified runtime manifest.
10. When a sequence is supplied, verify every `previous_receipt_id` link.
11. When parents are supplied, verify parent existence and exact delegation depth.

Any failed check returns a nonzero result. Machine-readable verification output reports the
assurance profile, verified components, unverified components, receipt ID, and failure reason.

## 9. MCP reference binding

The reference MCP wrapper resolves each `tools/call` name to a capability in a verified seal,
runs the existing deterministic effect gate, and emits a `mcp_call` receipt. The receipt binds
the canonical request arguments, canonical result, runtime manifest, capability, effect class,
and parent receipt when supplied. A denied or failed call receives a signed receipt before the
wrapper returns its error response.

For future CrabMeat adoption, use `poe_receipt`, `receipt_signer`, and `proof_manifest` in code
and configuration. Existing lowercase `sigil` names in CrabMeat retain their input-normalization
meaning. This vocabulary prevents the two trust boundaries from sharing one overloaded name.

## 10. Compatibility

Readers reject unsupported major or minor schema versions. Additive fields require a new schema
version because the allowed top-level and committed field sets are closed in v0.1. The receipt
ID, salts, signature domains, and canonicalization rules never change within one schema version.
