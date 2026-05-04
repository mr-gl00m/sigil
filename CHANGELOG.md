# Changelog

All notable changes to SIGIL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.7.0] - 2026-05-04

### Highlights

- **Cryptographic proof-of-conditioning per request.** New `IntegrityReceipt` primitive embeds an HMAC canary in the prompt context that the model is instructed to echo. SIGIL recomputes the HMAC against the system signing key and verifies the response carried a valid receipt. A model that bypassed `IRONCLAD_CONTEXT` cannot fabricate a matching canary because it doesn't hold the key. This is the closest thing to a soundness check on whether the model actually conditioned on the seal.
- **Embedding-based `UncertaintyGate` replaces Jaccard word-overlap.** The old similarity metric passed "Yes, transfer the funds" and "No, don't transfer the funds" as consistent because they share most stop-word-stripped tokens. Cosine on Ollama embeddings (`nomic-embed-text` by default) catches the semantic flip. Hard dep on a reachable Ollama instance; fails closed on `EmbeddingError`.
- **26 red-team findings closed across three remediation rounds.** Hardening across atomic-write coverage, SSRF allowlists, secret redaction in audit logs, key separation in the HMAC-receipt path, deny-by-default tool allowlists, path-traversal prevention in the human-gate, and a dozen smaller items.

### Added

- `IntegrityReceipt` class — HMAC-based proof-of-conditioning per request. `embed(seal) -> (nonce, canary, block_string)` and `verify(seal, context, response) -> (bool, reason)`.
- `EmbeddingClient` class — thin Ollama `/api/embeddings` client backing the new `UncertaintyGate`. Honors `OLLAMA_ALLOW_REMOTE`, `verify_tls`, `ca_bundle`, and writes per-call audit-chain entries.
- `_PerSealAnomalyTracker` — rolling-window statistical anomaly detection per `SigilSeal.node_id`. Fires `*_OUTLIER_FOR_SEAL` reasons when a record is ≥3σ off the seal's own baseline.
- `ToolRegistry.execute_validated(seal, invocation)` — supported dispatch path for capability-bearing seals. Re-verifies that `seal.capabilities[capability_id]` matches `invocation.resolved_tool` before running.
- `requirements-lock.txt` — pinned application install lockfile for reproducible builds.
- `node_id` and `integrity_receipt_verified` fields on `AuditRecord`.
- New operator knobs (env var or kwarg, see README): `OLLAMA_ALLOW_REMOTE`, `SIGIL_PROMPT_BUNDLE_MAX_BYTES`, `SIGIL_NORMALIZE_MAX_BYTES`, `SIGIL_PER_SEAL_TRACKER_MAX`, `OLLAMA_TIMEOUT_SECONDS`, `verify_tls` / `ca_bundle` on `EmbeddingClient`, `verify` / `node_id` / `seal` / `prompt_context` on `AuditProxy.audited_request`, `allow_remote` / `verify_tls` / `ca_bundle` on `OllamaAdapter`, `stream_capture_cap` on `AuditProxy`.

### Changed

- **Breaking: `InputNormalizer.normalize` now redacts encoded payloads instead of decoding them into the prompt.** Previously, detected base64 / hex / ROT13 / URL / UTF-7 payloads were decoded and returned with a `[DECODED_PAYLOAD]` prefix — that did the attacker's first-stage work. The new behavior replaces each encoded slice with `[REDACTED-BASE64-{hash}]`-style markers and logs the original + decoded form to `AuditChain` (`input_payload_redacted` event). The model never sees the decoded payload. Callers that depended on `normalize()` returning decoded text will see a redaction marker instead. Slices that don't decode as printable UTF-8 (binary hashes, file signatures) are preserved.
- **Breaking: `ToolRegistry.execute(tool_name, seal)` refuses capability-bearing seals.** A seal with non-empty `capabilities` map now rejects the raw-tool-name path with `PermissionError`. Use `SigilRuntime.validate_and_execute` → `ToolRegistry.execute_validated(seal, invocation)`. Legacy seals (no `capabilities` map) keep working unchanged.
- **Breaking: `UncertaintyGate` similarity metric switched from Jaccard to embedding cosine.** Default `consistency_threshold` raised 0.6 → 0.7 to match the cosine scale. Constructing the gate requires a reachable Ollama instance unless an `embedding_client=` is injected (tests). Fails closed with `EmbeddingError` rather than silently falling back.
- **Breaking: `HumanGate.approve` and `check_approval` reject `state_id` values that don't match `^[a-f0-9]{24}$`** (the shape `request_approval` produces). Closes a path-traversal where `state_id="../tmp/foo"` could write encrypted state outside `STATE_DIR`.
- **Breaking: `AuditChain.verify_chain` fails closed when signed entries exist but `_system.pub` is missing or unreadable.** Earlier versions skipped signature enforcement and reported success.
- **Breaking: empty `SigilSeal.allowed_tools` denies all tools.** Previously treated as "all tools allowed" — inverted to match `allowed_effects` deny-by-default semantics.
- **`OllamaAdapter` refuses non-localhost `base_url` unless `OLLAMA_ALLOW_REMOTE=1` env var or `allow_remote=True` constructor arg is set.** Each remote opt-in is logged to `AuditChain` for forensic traceability.
- `AuditProxy.audited_request` enforces an explicit `(scheme, host)` allowlist for outbound HTTP — refuses URLs outside the four documented provider hosts before `httpx.post`.
- Every state-writing path uses atomic writes (tmp file + `fsync` + `os.replace`): keys, encrypted state, CRL, pending approvals, succession records, key pin file, archive copies, system keypair bootstrap, pricing signature, audit exports, CLI sign output, compliance report.
- `IntegrityReceipt` canary widened from 64-bit to 128-bit truncation (16 → 32 hex characters).
- `IntegrityReceipt` HMAC key is now a domain-separated subkey derived via SHA-256, not the raw Ed25519 signing-key bytes.
- `AuditRecord.response_preview` is now redacted (request side already was; v1.7 closes the asymmetry on both string-level and structural-dict-walk paths). The redaction regex catches JSON-quoted `"key": "value"` shapes that the v1.6.1 regex missed.
- `_PerSealAnomalyTracker` enforces an LRU cap of 1000 distinct `node_id` values by default. `SIGIL_PER_SEAL_TRACKER_MAX` widens.
- Streaming response capture bounded at 256 KiB by default (`stream_capture_cap`). Larger responses still yield to the caller chunk-by-chunk; only the audit-record preview is truncated with a `[STREAM TRUNCATED AT N BYTES; TOTAL M]` marker.
- CLI prompt-bundle reads capped at 4 MiB (`SIGIL_PROMPT_BUNDLE_MAX_BYTES`).
- `InputNormalizer.normalize` short-circuits oversized inputs at 1 MiB before the recursive scan (`SIGIL_NORMALIZE_MAX_BYTES`).
- `TRUST_PREAMBLE` reframed from threat-language ("severe punishment," "immutable law") to advisory framing that explicitly names the `Validator` gate as authoritative. The README claim of "structural resistance to injection" was an overclaim that the v1.7 docs walk back. Per the new framing: SIGIL mediates effects under the assumption the model may be jailbroken at the attention level. Cite: Srivastava & Panda, *Attention Is Where You Attack* (2026).
- Telemetry exception handling narrowed: `except Exception:` only at recursion-prone sites (where re-entering `AuditChain.log` would loop). Other security-telemetry paths catch the specific exceptions (`OSError`, `RuntimeError`, `ValueError`) and surface to a module logger.

### Migration from 1.6.1

Six breaking changes with explicit migration paths:

**1. `InputNormalizer.normalize` returns redaction markers, not decoded text.**

```python
# v1.6.1
text, warnings = InputNormalizer.normalize(b64_payload)
assert "ignore previous instructions" in text  # decoded into output

# v1.7.0
text, warnings = InputNormalizer.normalize(b64_payload)
assert "ignore previous instructions" not in text  # redacted
assert "[REDACTED-BASE64-" in text                  # marker present
# Decoded form is in AuditChain "input_payload_redacted" entry
```

If you relied on the decoded form for downstream processing, read it from the audit chain via `AuditChain` queries on the `input_payload_redacted` event.

**2. Capability-bearing seals must use the validator path.**

```python
# v1.6.1
result = tools.execute("transfer_money", seal, amount=100)

# v1.7.0 — for seals with seal.capabilities populated
result = runtime.validate_and_execute(node_id, user_input, [proposed_invocation])
for inv in result["validated_invocations"]:
    tools.execute_validated(seal, ToolInvocation(**inv), **inv["parameters"])

# Legacy seals (empty seal.capabilities) — no change required
result = tools.execute("legacy_tool", seal)  # still works
```

**3. `UncertaintyGate` requires a reachable Ollama instance.**

```python
# v1.7.0 default — requires Ollama at http://localhost:11434 with
# nomic-embed-text loaded.
gate = UncertaintyGate(adapter, k_samples=3)

# Override the embedding model or URL:
gate = UncertaintyGate(
    adapter,
    embedding_url="http://localhost:11434",
    embedding_model="bge-small-en",
)

# Tests can inject a fake client to skip Ollama:
gate = UncertaintyGate(adapter, embedding_client=fake_client)
```

If you cannot run Ollama, `UncertaintyGate` is not currently usable — opt out at the architecture level rather than running a known-broken Jaccard implementation. The v1.6.1 behavior is gone.

**4. State IDs must be 24-character hex.**

```python
# v1.6.1 — accepted any string
HumanGate.approve("any_arbitrary_string")

# v1.7.0 — must match request_approval shape
HumanGate.approve("a1b2c3d4e5f6a1b2c3d4e5f6")  # 24 hex chars
HumanGate.approve("../tmp/exploit")           # raises ValueError
```

If you have callers that synthesized state_ids with non-hex characters, they need to use the value `request_approval` returns.

**5. `AuditChain.verify_chain` fails closed on missing system pubkey.**

If your tooling depended on `verify_chain()` succeeding when `_system.pub` was missing or unreadable, the new behavior returns `(False, "Entry N has signature but system public key is missing or unreadable")`. Restore the pubkey file or regenerate it; do not interpret the False return as a tampering event without that check.

**6. Empty `allowed_tools` denies, doesn't permit.**

```python
# v1.6.1 — empty list meant "all tools allowed"
seal = SigilSeal(node_id="x", instruction="...", allowed_tools=[])
tools.execute("any_tool", seal)  # ran

# v1.7.0 — empty list denies everything
tools.execute("any_tool", seal)  # raises PermissionError
```

Audit your existing seals: an empty `allowed_tools` was probably unintentional. If you needed "all tools," list them explicitly.

### Fixed

- Power-loss safety on every state-writing path (RT-2026-05-01-003 + RT-2026-05-04-001 + B-001 + B-006 sweep): keys, encrypted state, CRL, pending approvals, succession records, pin file, archive copies, system keypair bootstrap, pricing signature, audit exports, CLI sign output, compliance report.
- DoS prevention: CLI prompt bundles capped at 4 MiB, streaming capture at 256 KiB, `InputNormalizer` input at 1 MiB, per-seal anomaly tracker memory at 1000 LRU entries.
- `InputNormalizer` no longer over-redacts non-decoding base64/hex slices — legitimate hashes and signatures survive when an attack payload is detected nearby.
- `EmbeddingClient.embed` writes per-call audit-chain entries (host, model, text length, SHA-256 of text — never raw text).
- `EmbeddingClient` honors `verify_tls` / `ca_bundle` for internal-CA-signed Ollama deployments.
- `AuditRecord.integrity_receipt_verified` is auto-populated by `AuditProxy.audited_request` when `seal` and `prompt_context` are passed (closes the v1.7 plumbing gap).
- `AuditProxy.audited_request` honors the calling adapter's `verify_tls` / `ca_bundle` setting on the audited path (previously dropped silently).
- Streaming request bodies redacted before audit log persistence (closes the asymmetry where the non-streaming path was already redacted).
- Telemetry exception handling no longer swallows specific failures: narrowed catches surface the actual error to a module logger instead of silently passing.

### Security

- New cryptographic primitive: `IntegrityReceipt` HMAC proof-of-conditioning per request. Domain-separated subkey derivation prevents key reuse across audit-chain signing and integrity-receipt verification.
- Path-traversal closed in `HumanGate.approve` / `check_approval`.
- SSRF allowlist on `AuditProxy.audited_request` / `audited_stream_generator`. URLs outside the four documented provider hosts (api.anthropic.com, api.openai.com, generativelanguage.googleapis.com, localhost for Ollama) refused before `httpx.post`.
- All outbound HTTP egress (including new `EmbeddingClient`) writes audit-chain entries.
- `AuditChain.verify_chain` fails closed on missing/unreadable system pubkey.
- Tool allowlist deny-by-default (empty `allowed_tools` denies all).
- `OllamaAdapter` refuses non-localhost `base_url` unless explicitly opted in.
- Streaming + non-streaming request and response previews are now both redacted, including JSON-quoted forms.
- `TRUST_PREAMBLE` overclaim removed: no more "severe punishment" framing; the Validator is named explicitly as the authoritative gate.

### Internal

- 40 commits in range. 26 red-team findings closed. Test count 310 → 411 (+101 regression tests). One test-fixture cleanup (`3ba3981`) tightened the per-seal isolation assertion to `TOKEN_COUNT_OUTLIER_FOR_SEAL` after `time.perf_counter()` variance turned out to fire `LATENCY_MS_OUTLIER_FOR_SEAL` in CI; latency-noise threshold tracked in `.red_team/followups.md`. Three full red-team audit + remediation cycles: RT-2026-05-01 (10 findings closed), RT-2026-05-04 (8 findings closed), RT-2026-05-04B (8 findings closed, 2 info-deferred).

## [1.6.1] - 2026-04-28

> **Note on versioning.** The previous version on the GitHub remote is `v1.6.0`. Local working-tree development continued from `v1.5.0`, and the changes documented in the [1.5.0] entry below are included in `v1.6.1` as well. The `v1.6.0` release on GitHub does not have a corresponding entry in this CHANGELOG yet — its release notes live on the GitHub Releases page and will be reconciled into this file when the local working tree is fetched against the remote.

### License migration: CC0 → MIT

The repo previously carried a CC0 LICENSE file but described itself as MIT in the pitch documents — a contradiction that read as legal carelessness on first contact. Settling on MIT and propagating it across every reference: `LICENSE`, README badge, README footer, `CONTRIBUTING.md`, source-file headers in `sigil.py` / `sigil_audit_proxy.py` / `sigil_llm_adapter.py`, the demo banner, and historical release-notes footers. Existing CC0 grants for code published under prior tags remain valid for what was distributed at the time.

### Documentation honesty

- The pitch-bundle documents (`paper-sigil_2026-04-17/00_SIGIL_Pitch.md`, `01_SIGIL_Overview.md`, `02_SIGIL_Whitepaper.md`) previously described "five rounds of independent security review" and "two independent red team assessments." Reframed every instance as "structured red-team review, self-conducted by the author using adversarial prompting against frontier LLMs (Claude, GPT-4, Gemini)." The 88-findings figure stands; the implication of external auditing did not.
- Added a hyperlink citation to the [Claude Mythos Preview announcement](https://red.anthropic.com/2026/mythos-preview/) on every `Mythos` reference in the pitch documents so readers can verify the claim.

### Project hygiene

- **`SECURITY.md`** added with a responsible-disclosure process, contact email, and response-time targets.
- **`pyproject.toml`** added — `pip install sigil-security` will work after the first PyPI upload. Optional dependency groups: `[llm]` for `httpx` + `python-dotenv`, `[tokens]` for `tiktoken`, `[all]` for both, `[dev]` for the test suite.
- **GitHub Actions CI** added at `.github/workflows/ci.yml` — runs pytest on Python 3.10/3.11/3.12 across Ubuntu and Windows, plus a `python -m build` + `twine check` pass on every push and PR. README now carries a CI status badge.
- **`_cli_entry()`** added to `sigil.py` so the `sigil` console script (registered in `pyproject.toml`) reproduces the existing `__main__` dispatch (no-args → demo, args → cli).
- **Project website** added at `docs/index.html` (single-file HTML, no JS, no external dependencies, dark theme matching the project ethos). `docs/.nojekyll` opts out of Jekyll so the custom HTML renders as-is. To deploy: GitHub repo → Settings → Pages → Source: "Deploy from a branch" → Branch: `main` / `/docs`. Custom domain (e.g. `sigil.security`, `sigil-project.org`) goes in the same settings page once registered. Site content adapted from the Document 1 overview, with install instructions, the seven design commitments, the limitations section, and the same self-conducted-review honesty as the pitch documents.

### Changed

- `CHANGELOG.md` comparison URLs corrected from the stale `mr-gl00m/sigil` GitHub handle to the current `mr-gl00m/sigil`.
- README's "no attribution required, fork it sell it" footer (CC0 language) replaced with MIT-correct phrasing that names the license-notice preservation requirement.

---

## [1.5.0] - 2026-04-02

### Security Hardening via Leaked Codebase Cross-Reference

A security analysis of a recently leaked agentic AI codebase cataloged 14 vulnerability classes (SEC-01 through SEC-14). We cross-referenced every finding against SIGIL's attack surface — 4 required patches, 8 were already mitigated, 2 were not applicable.

Full analysis in [report.md](report.md). Detailed release notes in [RELEASE_NOTES_v1.5.0.md](release/RELEASE_NOTES_v1.5.0.md).

#### Fixed (CRITICAL severity)

- **Encrypted State Files at Rest** — HumanGate state files (`pending_*.json`, `attempts_*.json`, `executed_nonces.json`) now encrypted with XSalsa20-Poly1305 using a key derived from the system signing key. Files set to `0o600` permissions. Legacy plaintext files auto-migrated on first read. (SEC-01)
- **Embedded Encoding Payload Detection** — `InputNormalizer` Base64/Hex patterns no longer use anchored regexes. Two-phase detection: whole-string fast path plus `finditer()`-based embedded payload scanning catches encoded payloads within natural language. Recursive normalization handles multi-layer (Matryoshka) encodings. (SEC-12)

#### Fixed (HIGH severity)

- **FileLock on State File Writes** — `HumanGate._record_attempt()`, `request_approval()`, and `approve()` now wrapped in `FileLock` blocks, preventing concurrent-write corruption of lockout counters and approval signatures. (SEC-10)
- **Bounded Audit Proxy Queue** — `AuditProxy._log_queue` set to `maxsize=1000` with `put_nowait()` and stderr warning on overflow. Prevents unbounded memory growth under high load or flooding attacks. (SEC-04)

#### Fixed (MEDIUM severity)

- **File Permissions on Sensitive Files** — `_write_encrypted_state()` and `AuditChain.log()` now call `chmod(0o600)` after writes. Gracefully handles Windows via `try/except (OSError, NotImplementedError)`. (SEC-01)

### Test Results

310 tests across 23 modules (310 passed, 2 skipped). Test suite updated for encrypted state helpers and `_state_key_cache` isolation.

---

## [1.4.0] - 2026-04-01

### Deterministic Validator Gate

Prior SIGIL releases hardened the _audit and forensic_ layer — signing prompts, verifying chains, detecting encoding attacks. But the core execution path still relied on LLM cooperation: the model decided which tools to call and with what arguments, and SIGIL could only log what happened afterward.

v1.4.0 introduces a **deterministic validator gate** that sits between LLM output and tool execution. The LLM can no longer name tools directly. It emits opaque capability IDs, and the Validator — running ordinary code, not AI — resolves, constrains, and authorizes every invocation before the executor sees it. This is the architectural change SIGIL needed to move from _"we'll catch it in the audit"_ to _"it can't happen."_

Motivation and architectural analysis documented in [RELEASE_NOTES_v1.4.0.md](release/RELEASE_NOTES_v1.4.0.md).

### Added

- **`EffectClass` enum** — Five effect classes (`READ`, `WRITE`, `NETWORK`, `EXEC`, `PRIVILEGED`) for deny-by-default capability enforcement. `high_impact()` classmethod identifies classes that may require escalation.
- **Capability ID minting** — `Architect.seal()` mints opaque capability IDs (`cap_{sha256(node_id:tool_name:nonce)[:12]}`) for each allowed tool. The LLM never sees real tool names; only the Validator can resolve IDs back to tools.
- **Seal-level parameter constraints** — `SigilSeal.parameter_constraints` defines per-capability JSON-Schema-subset constraints (type, min, max, minLength, maxLength, pattern, enum). Constraints are signature-covered — tampering invalidates the seal.
- **Seal-level output schema** — `SigilSeal.output_schema` defines the expected structure of LLM output (JSON Schema subset: type, properties, required, additionalProperties, maxItems, items). Also signature-covered.
- **Seal-level effect declarations** — `SigilSeal.allowed_effects` and `SigilSeal.escalate_effects` declare which effect classes a workflow step permits, and which require human gate approval even after validation.
- **`Validator` class** — Deterministic validation engine (~200 lines) with:
  - `validate_invocation()` — resolves capability ID → tool name, validates parameters against constraints, checks effect class against allowed list
  - `validate_output()` — validates LLM output structure against output schema
  - `check_escalation()` — determines if an invocation's effect class requires human gate approval
  - `register_tool_effect()` / `get_tool_effect()` — effect class registry (unregistered tools default to `PRIVILEGED`)
- **`ToolInvocation` dataclass** — Structured representation of a proposed tool call: `capability_id`, `parameters`, `resolved_tool` (filled by validation), `effect_class` (filled by validation).
- **`SigilRuntime.validate_and_execute()`** — Mandatory gate method that chains seal verification → invocation validation → output validation → effect escalation. Returns validated invocations with resolved tools, escalation approvals, and output validation status.
- **37 new tests** in `tests/test_validator.py` covering: effect class behavior, capability ID minting, parameter validation (type/range/length/pattern/enum), capability resolution, effect enforcement, output schema validation, effect escalation, seal serialization round-trips, and the full validate-and-execute pipeline.

### Changed

- **`SigilSeal` dataclass** — Extended with 5 new fields: `capabilities`, `parameter_constraints`, `output_schema`, `allowed_effects`, `escalate_effects`. All fields included in `canonical_payload()` (signature-covered).
- **`Architect.seal()`** — Accepts new parameters for constraints, output schema, and effect declarations. Mints capability IDs and re-keys constraint dicts from tool names to capability IDs.
- **`SigilSeal.from_dict()`** — Validates all new fields on deserialization, including effect class value validation against the `EffectClass` enum.
- **`SigilRuntime.execute()` return dict** — Now includes `capabilities`, `parameter_constraints`, `output_schema`, `allowed_effects`, and `escalate_effects` alongside existing fields.

### Test Results

310 tests across 23 modules (310 passed, 2 skipped). 37 new tests covering all validator functionality.

---

## [1.3.0] - 2026-03-02

### Complete Red Team Remediation

A third-round red team assessment identified 20 findings. The 3 CRITICAL findings (C-01, C-02, C-03) were fixed in v1.2.0. This release resolves the remaining 17 findings (6 HIGH, 6 MEDIUM, 5 LOW), closing every known security issue.

Full details in [RED_TEAM_REPORT.md](RED_TEAM_REPORT.md).

#### Fixed (HIGH severity)

- **H-01: Key Rotation Mechanism** — `Keyring.rotate_key()` generates versioned keypairs with cryptographically signed succession records. Old keys remain valid during a configurable transition window. `Sentinel.verify()` checks succession records automatically.
- **H-02: Rate Limiting on HumanGate** — Approval attempts are now rate-limited with lockout after 5 failures (5-minute cooldown). All attempts logged to audit chain.
- **H-03: Header Redaction** — `AuditProxy` automatically redacts `Authorization`, `X-API-Key`, `Cookie`, and other sensitive headers. Custom redaction patterns supported via regex. Body content scrubbed for embedded credentials.
- **H-05: Encoding Detectors** — `InputNormalizer` now detects UTF-7, Punycode (`xn--` domains), and leetspeak (`1gn0r3 1nstruct10ns`) attack encodings in addition to existing Base64/ROT13/Hex/URL coverage.
- **H-06: Nonce File Integrity** — Nonce reservations logged to audit chain. On nonce file deletion/corruption, nonces are recovered from chain entries, preventing replay attacks even after file tampering.

#### Fixed (MEDIUM severity)

- **M-01: Robust `_get_last_entry()`** — Fallback now reads all content and takes last non-empty line, handling single-line files and missing trailing newlines.
- **M-02: TLS Certificate Verification** — All LLM adapters accept `verify_tls` and `ca_bundle` parameters. Disabling TLS verification logs a warning to the audit chain.
- **M-03: Pricing Data Integrity** — `pricing.json` can be cryptographically signed via `CostCalculator.sign_pricing()`. Tampered pricing files fall back to built-in defaults.
- **M-04: Improved Loyalty Analysis** — Negative compliance markers ("I cannot", "I refuse", etc.) now suppress false `CRITICAL_LOYALTY_FAILURE` alerts. Expanded contradiction phrase detection. Configurable phrase lists.
- **M-06: FileLock Timeout** — File locking uses non-blocking acquisition with exponential backoff (10ms–200ms). Configurable timeout (default 10s) prevents indefinite deadlocks.

#### Fixed (LOW severity)

- **L-02: Key File Permissions** — `Keyring` warns via audit chain when private key files have overly permissive Unix permissions (group/other readable).
- **L-03: Provenance Hardening** — `CodeProvenance` uses structural salt derived from class names and verifies required classes/methods exist at runtime. Violations logged to audit chain.
- **L-05: Streaming Chain Verification** — `verify_chain()` processes entries line-by-line instead of loading the entire file into memory, supporting chains with millions of entries.

### Test Results

275 tests across 22 modules (273 passed, 2 skipped). 35 new tests covering all remediated findings.

---

## [1.2.0] - 2026-02-27

### Critical Security Hardening

Addressed the 3 CRITICAL findings from the Round 3 red team assessment.

#### Fixed

- **C-01: Signed Audit Chain** — Every audit chain entry is now cryptographically signed with an auto-generated system key. Entries include `signature` and `signer_key_id` fields. `verify_chain()` validates signatures in strict mode.
- **C-02: Encrypted Key Storage** — Private keys are encrypted at rest using passphrase-derived keys (Argon2id + XSalsa20-Poly1305 via PyNaCl). Unencrypted keys auto-upgraded on first load.
- **C-03: HumanGate Integrity Binding** — Approval signatures now bind to the specific seal content hash, preventing approval reuse across different seals.

---

## [1.1.0] - 2026-02-17

### Security Remediation

Two structured red-team passes (53 findings total) — distinct adversarial prompt regimens against separate frontier models, self-conducted by the author — revealed code that contradicted SIGIL's own promises. Every finding was addressed immediately. Full details in [SECURITY_REMEDIATION_REPORT.md](SECURITY_REMEDIATION_REPORT.md).

#### Fixed (Tier 1 — Code contradicted its promises)
- `ClaudeAdapter` and `OpenAIAdapter` now actually read `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` env vars before falling back to disk files (C-05).
- `expires_in_days=0` now correctly creates an immediately-expiring seal instead of an immortal one; negative values raise `ValueError` (H-01).
- `WorkflowEngine` now has `process_response()` to parse `<TRANSITION>` and `<CONTEXT_UPDATE>` tags and advance state (H-08).
- `UncertaintyGate` now passes `self.temperature` to `llm.complete()` for diverse sampling (I-10).
- Conversation history messages are now HTML-entity escaped to prevent injection via history (M-04).
- Tool descriptions and parameter schemas are now HTML-entity escaped before context inclusion (M-05).

#### Fixed (Tier 2 — Security hazards)
- Gemini API key is now passed via `x-goog-api-key` header instead of URL query parameter, preventing key leakage into audit logs (C-01).
- `FileLock` now defaults to `strict=True`: lock acquisition failures raise instead of silently continuing (C-02).
- Key names validated against `^[a-zA-Z0-9_-]+$` to prevent path traversal in all Keyring methods (C-03).
- `sys.exit(1)` on missing pynacl replaced with `raise ImportError(...)` (C-04).
- `LegalExporter.create_discovery_package()` validates `case_id` against path traversal (RT-02).
- Environment-variable key usage now logged to audit chain for visibility (RT-01).
- CRL reads and writes are now protected by `FileLock` (RT-07).

#### Fixed (Tier 3 — Robustness)
- Nonce entries now include timestamps and are pruned after 90 days to prevent unbounded file growth (H-02).
- `canonical_payload()` uses `copy.deepcopy(self.metadata)` (H-05).
- `verify_chain()` no longer mutates entries in-place during verification (H-06).
- `verify_chain()` wraps JSON parsing per-line in try/except with reason reporting (RT-08).
- Removed duplicate `import queue` (H-03).
- `ClaudeAdapter` and `OpenAIAdapter` accept `model` as constructor parameter (M-03).
- `AuditProxy._records` uses `collections.deque(maxlen=10000)` instead of unbounded list (M-07/RT-05).
- Streaming audit success check changed from `== 200` to `200 <= status_code < 300` (M-08).
- `os.system()` in compare_contexts.py replaced with `subprocess.run()` (M-01).
- Directory creation moved from import-time to lazy `_ensure_dirs()` (M-10).
- Deprecated `asyncio.get_event_loop().run_until_complete()` replaced with `asyncio.run()` in tests (M-06).
- `get_key_id()` handles `FileNotFoundError` with clear message; `export_public()` checks env vars first (L-05/L-06).

#### Changed (Tier 4 — Documentation honesty)
- README: Removed "Attack failed" / "zero tag breakout risk" language.
- README: Added Limitations section acknowledging XML boundaries are advisory, not structural.
- README: Updated provider table with configurable model names.

### Added
- CRL entries are now signed and verified with the architect key; invalid or unsigned revocations are ignored for tamper-evidence.
- AuditProxy gained a canary runner to detect backend model swaps via IntegrityCheck and logs results to the AuditChain.
- Political/lobbyist buzzword detector adds `POLITICAL_INJECTION_DETECTED` alerts when refusals match a curated phrase list.
- Tiktoken-backed token accounting with heuristic fallback for providers; adapters accept proxy injection for DRY audited calls.
- URL-encoding detection added to InputNormalizer to catch `%3C`-style payloads.
- compare_contexts now writes context_unsafe.txt and context_sigil.txt for side-by-side diffing.
- Pricing is now loaded from .sigil/config/pricing.json with auto-created defaults to avoid hardcoded rates.
- Anomaly scores (0-10) are attached to each audit record, weighting encoded inputs, high cost, latency, and alert signals.
- LegalExporter builds tamper-evident legal discovery bundles with manifest + chain-of-custody notes.
- Executive dashboard CLI (`python sigil.py dashboard`) summarizes cost, top prompts, alerts, and chain health.
- Compliance report generator (`python sigil.py compliance --standard soc2|gdpr|hipaa|iso27001`) produces evidence markdown.
- README documents pricing config, political detector example, canary runner, and legal discovery export; install instructions now include tiktoken.

### Changed
- FileLock now opens in append mode to avoid accidental truncation if misconfigured.
- One-time seal replay protection now atomically reserves nonces under a file lock to prevent races.
- Audit logging uses a background queue with FileLock on disk writes to avoid inflating API latency.
- Adapters (Claude/OpenAI/Gemini/Ollama) accept an AuditProxy and reuse a shared audited call path instead of duplicating request logic; Ollama timeout is configurable via env.
- README now frames SIGIL as a flight recorder (forensic audit) rather than a force field.

### Fixed
- CRL cache loading now validates signatures and logs invalid entries instead of trusting unsigned data.
- Loyalty detection flags CRITICAL_LOYALTY_FAILURE/LOYALTY_RISK when user instructions contradict signed context and the model complies.

---

## [1.0.0] - 2026-01-16

### Initial Public Release

SIGIL (Sovereign Integrity & Governance Interface Layer) - Open-source cryptographic prompt security for LLMs.

### Features

#### Core Security
- **Ed25519 Digital Signatures** - Cryptographically sign and verify LLM prompts
- **Seal Revocation** - Certificate Revocation List (CRL) for compromised seals
- **Time-Bounded Signatures** - Auto-expiring seals with configurable TTL
- **Replay Protection** - Nonce-based one-time seal execution
- **Merkle-Linked Audit Chain** - Tamper-evident logging with chain verification

#### Data Governance
- **Classification Decorators** (`@vow`) - Runtime data handling enforcement
- **Automatic Redaction/Hashing** - PII/PHI/PCI data protection
- **Human-in-the-Loop** - File-based approval gates (no dashboard required)
- **Tool Permission Enforcement** - Restrict LLM access to approved functions

#### LLM Integration
- **Context Architecture** - Structural isolation of user input from system instructions
- **Input Normalization** - Detects and decodes Base64/ROT13/Hex encoded attacks
- **XML Tag Escape** - Prevents injection via tag breakout
- **Multi-Provider Support** - Adapters for Claude, GPT, Gemini, Ollama

#### Platform Features
- **Cross-Platform** - Windows, macOS, Linux support
- **Zero External Dependencies** - Runs entirely locally, no servers required
- **Environment-Based Key Management** - Container-friendly (Docker/Kubernetes)
- **CLI Tools** - Key generation, signing, verification, approval workflows

---

## How to Release (For Maintainers)

### Creating a Release

1. **Update version** in `sigil.py` (`__version__`) and `CHANGELOG.md`
2. **Commit changes**:
   ```bash
   git add .
   git commit -m "Release vX.Y.Z"
   ```

3. **Create and push tag**:
   ```bash
   git tag -a vX.Y.Z -m "SIGIL vX.Y.Z - Description"
   git push origin main
   git push origin vX.Y.Z
   ```

4. **Create GitHub Release**:
   - Go to: Releases > New release
   - Select tag: `vX.Y.Z`
   - Title: `SIGIL vX.Y.Z — Description`
   - Description: Copy from CHANGELOG.md or release/RELEASE_NOTES.md
   - Click "Publish release"

### Versioning Guidelines

SIGIL follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes to API
- **MINOR** (0.X.0): New features, backward compatible
- **PATCH** (0.0.X): Bug fixes, backward compatible

[Unreleased]: https://github.com/mr-gl00m/sigil/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/mr-gl00m/sigil/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/mr-gl00m/sigil/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/mr-gl00m/sigil/releases/tag/v1.6.0
[1.5.0]: https://github.com/mr-gl00m/sigil/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/mr-gl00m/sigil/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/mr-gl00m/sigil/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mr-gl00m/sigil/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mr-gl00m/sigil/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mr-gl00m/sigil/releases/tag/v1.0.0
