# SIGIL 1.8.0

Security-hardening release. Seven RT-2026-05-29 findings closed — four of them caller-visible behavior changes. No new features, no new dependencies, suite green.

## Highlights

- **Redaction stops leaking unlabeled and multi-token credentials.** `_redact_body` now catches `Bearer <token>` forms and bare provider tokens (`sk-…`, `gh[pousr]_…`, `AIza…`) that the previous label-anchored regex missed. Audit logs that previously preserved a secret after a space or without a `key:` prefix no longer do.
- **`conversation_history` is normalized, not just escaped.** An encoded payload (base64 / hex / ROT13) planted in conversation history used to bypass the `InputNormalizer` pass that live user input gets. History now goes through the same normalization.
- **Oversize input is scanned, not waved through.** Input above `SIGIL_NORMALIZE_MAX_BYTES` used to short-circuit and return verbatim — a free smuggling path past the cap. It is now truncated to the cap and scanned; the dropped tail can't reach the model.
- **A corrupt CRL fails closed.** A garbled `revoked.json` previously crashed seal verification with a raw traceback. It now rejects every seal with `CRL_UNREADABLE` and logs the parse error. Deliberately fails closed — the obvious "treat it as empty" fix would have silently un-revoked every seal.

## What's changed

### Security

- Redaction catches space-separated and unlabeled credential values (RT-2026-05-29-001).
- `conversation_history` runs through `InputNormalizer` instead of HTML-escape only (RT-2026-05-29-002).
- Oversize input truncated-then-scanned instead of passed through (RT-2026-05-29-003).
- Corrupt `revoked.json` fails closed with `CRL_UNREADABLE` instead of crashing or un-revoking (RT-2026-05-29-004).
- `keygen --force` warns, requires typing the key name, and archives the old keypair before overwriting (RT-2026-05-29-007).

### Changed

- `_redact_body` redacts more aggressively; over-redaction (lost log detail) is the deliberate safe-side trade.
- `InputNormalizer.normalize` no longer returns oversize input verbatim. `build_context` is unaffected.
- Dependency ranges gained upper bounds: `pynacl>=1.5,<2`, `httpx>=0.25,<1`, `python-dotenv>=1.0,<2`, `tiktoken>=0.7,<1`, `pytest>=7.0,<10`. Locked versions all satisfy them; `requirements-lock.txt` stays the reproducible-install source of truth.

### Fixed

- Stale `SECURITY_ALERT` wording corrected — it described the pre-v1.7 decode-into-prompt model; the normalizer redacts, not decodes (RT-2026-05-29-008).

### Deferred

- Audit-log rotation for `chain.jsonl` / `audit_records.jsonl` (RT-2026-05-29-005). Tamper-evidence-preserving rotation is a design item, scheduled for a v1.8.1+ round.

## Migration from v1.7.0

Four caller-visible changes; full before/after in `CHANGELOG.md` under `Migration from 1.7.0`. The short list:

1. **`InputNormalizer.normalize` truncates oversize input.** Direct callers that relied on oversize passthrough now get output truncated to `SIGIL_NORMALIZE_MAX_BYTES`. `build_context` callers are unaffected.
2. **Audit-log redaction is more aggressive.** Expect more redaction spans if you parse `response_preview` or request bodies, including context adjacent to a credential on the same line.
3. **`keygen --force` is interactive on an existing key.** Non-interactive clobber scripts now block on a confirmation prompt — use `Keyring.generate(force=True)` for unattended overwrite. The old key is archived either way.
4. **Pinned dependency upper bounds.** A required newer major of any dependency is no longer permitted by `pyproject.toml`; override in your own environment if you accept the risk.

**Full changelog:** https://github.com/mr-gl00m/sigil/compare/v1.7.0...v1.8.0
