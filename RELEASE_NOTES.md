# SIGIL 1.7.0

Cryptographic proof-of-conditioning per request, embedding-based uncertainty checks, and 26 red-team findings closed across three remediation rounds.

## Highlights

- **`IntegrityReceipt` — HMAC proof-of-conditioning per request.** SIGIL embeds an HMAC canary in the prompt context that the model is asked to echo. The canary is derived from a domain-separated subkey of the system signing key plus a per-request nonce and the seal hash. SIGIL recomputes the HMAC and verifies the response carried a valid receipt. A model that bypassed `IRONCLAD_CONTEXT` cannot fabricate a matching canary because it doesn't hold the key. Closest thing to a soundness check on whether the model actually conditioned on the seal in this specific request.
- **Embedding-based `UncertaintyGate` replaces Jaccard.** The old similarity metric passed "Yes, transfer the funds" and "No, don't transfer the funds" as consistent because they share most stop-word-stripped tokens. Cosine on Ollama embeddings (`nomic-embed-text` by default) catches the semantic flip. Hard dep on a reachable Ollama instance; fails closed on `EmbeddingError`.
- **26 red-team findings closed.** Three rounds: RT-2026-05-01 (10 findings), RT-2026-05-04 (8 findings), RT-2026-05-04B (8 findings + 2 info-deferred). Hardening across atomic-write coverage, SSRF allowlists, secret redaction in audit logs, key separation in the HMAC-receipt path, deny-by-default tool allowlists, and path-traversal prevention.

## What's changed

### Added

- `IntegrityReceipt` — HMAC-based proof-of-conditioning per request. `embed(seal)` and `verify(seal, context, response)` for callers; `AuditProxy.audited_request` auto-verifies and populates `AuditRecord.integrity_receipt_verified`.
- `EmbeddingClient` — Ollama embeddings client backing the new `UncertaintyGate`. Honors `OLLAMA_ALLOW_REMOTE`, `verify_tls`, `ca_bundle`. Per-call audit-chain entries.
- `_PerSealAnomalyTracker` — rolling-window statistical anomaly detection per `SigilSeal.node_id`. Fires `*_OUTLIER_FOR_SEAL` reasons when a record is ≥3σ off the seal's own baseline. LRU cap 1000, env override `SIGIL_PER_SEAL_TRACKER_MAX`.
- `ToolRegistry.execute_validated(seal, invocation)` — supported dispatch path for capability-bearing seals. Re-verifies `seal.capabilities[capability_id]` matches `invocation.resolved_tool` before running.
- `requirements-lock.txt` for reproducible installs.
- Operator knobs: `OLLAMA_ALLOW_REMOTE`, `SIGIL_PROMPT_BUNDLE_MAX_BYTES`, `SIGIL_NORMALIZE_MAX_BYTES`, `SIGIL_PER_SEAL_TRACKER_MAX`, `OLLAMA_TIMEOUT_SECONDS`. New kwargs: `verify_tls` / `ca_bundle` on `EmbeddingClient` and `OllamaAdapter`, `verify` / `node_id` / `seal` / `prompt_context` on `AuditProxy.audited_request`, `stream_capture_cap` on `AuditProxy`.

### Changed (breaking)

Six breaking changes within the 1.x series. All have explicit migration paths in the migration section below.

- `InputNormalizer.normalize` now redacts encoded payloads instead of decoding them into the prompt. Redaction markers like `[REDACTED-BASE64-{hash}]` replace the encoded slice; the original + decoded form are logged to AuditChain. The model never sees the decoded payload.
- `ToolRegistry.execute(tool_name, seal)` refuses capability-bearing seals. Use the validator path (`SigilRuntime.validate_and_execute` → `ToolRegistry.execute_validated`).
- `UncertaintyGate` similarity metric switched from Jaccard to embedding cosine. Default threshold 0.6 → 0.7. Requires Ollama unless an `embedding_client=` is injected.
- `HumanGate.approve` / `check_approval` reject `state_id` values that don't match `^[a-f0-9]{24}$`. Closes a path-traversal vector.
- `AuditChain.verify_chain` fails closed when signed entries exist but the system pubkey is missing or unreadable.
- Empty `SigilSeal.allowed_tools` now denies all tools instead of permitting all (matches `allowed_effects` deny-by-default semantics).

### Changed (non-breaking)

- `OllamaAdapter` refuses non-localhost `base_url` unless `OLLAMA_ALLOW_REMOTE=1` or `allow_remote=True`. Each opt-in is logged to AuditChain.
- `AuditProxy.audited_request` enforces an explicit `(scheme, host)` allowlist before `httpx.post`.
- Every state-writing path uses atomic writes (tmp + fsync + rename): keys, encrypted state, CRL, pending approvals, succession records, pin file, archive copies, system keypair bootstrap, pricing signature, audit exports, CLI sign output, compliance report.
- `IntegrityReceipt` canary widened to 128 bits; HMAC key now a domain-separated SHA-256 subkey of the signing key (not the raw bytes).
- `AuditRecord.response_preview` is now redacted, including JSON-quoted `"key": "value"` forms.
- Streaming response capture bounded at 256 KiB; CLI prompt-bundle reads at 4 MiB; `InputNormalizer` input at 1 MiB.
- `TRUST_PREAMBLE` reframed from threat-language to advisory; Validator named explicitly as the authoritative gate.

### Fixed

- Power-loss safety on every state-writing path.
- DoS prevention via input-size caps on every external boundary.
- `InputNormalizer` no longer over-redacts non-decoding base64/hex slices — legitimate hashes survive.
- `EmbeddingClient` honors operator TLS settings; writes audit-chain entries on every embed call.
- `AuditRecord.integrity_receipt_verified` auto-populated when `seal` + `prompt_context` are passed.
- `AuditProxy.audited_request` honors the calling adapter's `verify_tls` / `ca_bundle` choice.
- Streaming request bodies redacted before audit log persistence.
- Telemetry exception handling no longer swallows specific failures.

### Security

- New `IntegrityReceipt` HMAC primitive (see Highlights).
- Path-traversal closed in `HumanGate`.
- SSRF allowlist on `AuditProxy` outbound HTTP.
- All outbound HTTP egress writes audit-chain entries.
- `AuditChain.verify_chain` fails closed on missing pubkey.
- Tool allowlist deny-by-default.
- `OllamaAdapter` localhost-only by default.
- Streaming + non-streaming request and response previews both redacted.
- `TRUST_PREAMBLE` overclaim removed.

## Migration from v1.6.1

Six breaking changes; full before/after examples in `CHANGELOG.md` under the `Migration from 1.6.1` section. The short list:

1. **`InputNormalizer.normalize` returns redaction markers, not decoded text.** Read decoded forms from the audit chain (`input_payload_redacted` events) if you need them.
2. **Capability-bearing seals require the validator path.** `ToolRegistry.execute(tool_name, seal)` raises `PermissionError` when `seal.capabilities` is non-empty. Use `SigilRuntime.validate_and_execute` and `ToolRegistry.execute_validated`.
3. **`UncertaintyGate` requires Ollama** with an embedding model loaded (default `nomic-embed-text`). No silent fallback.
4. **State IDs must be 24-character hex.** Use what `request_approval` returns; arbitrary strings raise `ValueError`.
5. **`AuditChain.verify_chain` fails closed on missing system pubkey.** Restore `_system.pub` or regenerate; don't read the False return as a tampering event without that check.
6. **Empty `allowed_tools` denies, doesn't permit.** Audit existing seals — an empty list was probably unintentional. List allowed tools explicitly.

**Full changelog:** https://github.com/mr-gl00m/sigil/compare/v1.6.1...v1.7.0
