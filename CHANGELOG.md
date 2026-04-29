# Changelog

All notable changes to SIGIL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/mr-gl00m/sigil/compare/v1.6.1...HEAD
[1.6.1]: https://github.com/mr-gl00m/sigil/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/mr-gl00m/sigil/releases/tag/v1.6.0
[1.5.0]: https://github.com/mr-gl00m/sigil/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/mr-gl00m/sigil/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/mr-gl00m/sigil/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mr-gl00m/sigil/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mr-gl00m/sigil/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mr-gl00m/sigil/releases/tag/v1.0.0
