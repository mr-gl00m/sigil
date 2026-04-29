# SIGIL Security Hardening Report
## Informed by Leaked Agentic AI Codebase Analysis

**Date:** 2026-04-02
**Scope:** Cross-referencing vulnerabilities cataloged in a recently leaked agentic AI codebase's security analysis against SIGIL's attack surface, then applying targeted patches to `sigil.py`, `sigil_llm_adapter.py`, `sigil_audit_proxy.py`, and their test suites.

**Test Results Post-Patch:** 310 passed, 2 skipped, 0 failures.

---

## 1. Background: The Leaked Codebase and Why It Matters

In early 2026, a reverse-engineered reimplementation of a major commercial AI coding agent was leaked publicly — comprising ~8,000 lines of Rust across 9 crates and ~2,000 lines of Python across 66 files. Its security analysis document catalogs 14 distinct vulnerability classes (SEC-01 through SEC-14), ranging from CRITICAL to LOW severity.

SIGIL (Sovereign Integrity & Governance Interface Layer) sits at a different point in the LLM security stack — it provides cryptographic prompt signing, audit chains, human-in-the-loop approval gates, and input normalization. However, the two systems share several overlapping threat surfaces:

- **State file storage** -- both persist sensitive operational state to disk
- **Input processing** -- both handle untrusted text that may contain encoded payloads
- **Audit logging** -- both maintain records that need tamper-evidence and availability guarantees
- **Concurrent access** -- both must handle multi-process file access safely
- **Trust boundaries** -- both gate actions through permission hierarchies

The leaked codebase analysis served as a forcing function to audit SIGIL against real-world vulnerability patterns found in production-adjacent agentic infrastructure.

---

## 2. Vulnerability Cross-Reference Matrix

The table below maps each leaked codebase finding to its SIGIL analog, the status before patching, and what was done.

| Ref ID | Source Issue | SIGIL Analog | Pre-Patch Status | Patch Applied |
|---|---|---|---|---|
| **SEC-01** | Unencrypted session storage | State files (`pending_*.json`, `attempts_*.json`, `executed_nonces.json`) stored as plaintext JSON | **VULNERABLE** | Encrypted with XSalsa20-Poly1305 |
| **SEC-02** | No output filtering for secrets | AuditProxy body/header redaction | Already mitigated | N/A (existing `_redact_headers()` and `_redact_body()`) |
| **SEC-03** | Hook script injection | External command execution | Not applicable | N/A (SIGIL executes no external commands) |
| **SEC-04** | No rate limiting | AuditProxy queue, HumanGate lockout | Partially mitigated | Bounded queue to `maxsize=1000` |
| **SEC-05** | Sequential session IDs | State IDs use `os.urandom(32)` | Already mitigated | N/A (96-bit entropy state IDs) |
| **SEC-06** | Binary trust gate | EffectClass-based granular permissions | Already mitigated | N/A (5 distinct effect classes) |
| **SEC-07** | File path traversal | Key name validation | Already mitigated | N/A (regex-validated key names) |
| **SEC-08** | DangerFullAccess as default | Deny-by-default capability model | Already mitigated | N/A |
| **SEC-09** | OAuth token storage | Private key encryption | Already mitigated | N/A (Argon2id + XSalsa20-Poly1305) |
| **SEC-10** | Concurrent session file writes | FileLock coverage | **VULNERABLE** | Added FileLock to 3 unprotected write sites |
| **SEC-11** | Recursive JSON stack overflow | JSON parsing | Already mitigated | N/A (uses Python stdlib `json`) |
| **SEC-12** | No input sanitization for prompts | InputNormalizer encoding detection | **VULNERABLE** | Fixed anchored patterns, added `finditer()` |
| **SEC-13** | No audit trail | AuditChain with Merkle linking | Already mitigated | Added `chmod 0o600` to log file |
| **SEC-14** | Token budget estimation | Not applicable to SIGIL | N/A | N/A |

**Result:** 4 vulnerabilities patched, 8 already mitigated, 2 not applicable.

---

## 3. Detailed Patch Descriptions

### 3.1 CRITICAL: Encrypted State Files at Rest

**Source parallel:** SEC-01 (Unencrypted Session Storage)

**Problem:** SIGIL's HumanGate stores pending approval state, lockout tracking, and nonce history as plaintext JSON files under `.sigil/state/`. These files contain:
- **Approval context** -- the full `action` and `context` dict passed to `request_approval()`, which may include sensitive operational parameters
- **Lockout state** -- attempt counts and timing that an attacker could reset to bypass rate limiting
- **Nonce history** -- the full set of executed one-time nonces, which if known, could inform replay attack strategies

Any process with filesystem read access could extract this data. On shared systems or in containerized environments with mounted volumes, this is a direct information leak.

**Solution:** Two new module-level functions in `sigil.py`:

```python
def _write_encrypted_state(path: Path, data: dict) -> None:
    """Encrypt dict as JSON using XSalsa20-Poly1305, set 0o600 permissions."""
    key = _get_state_encryption_key()
    box = nacl.secret.SecretBox(key)
    plaintext = json.dumps(data, indent=2).encode()
    ciphertext = box.encrypt(plaintext)
    path.write_bytes(ciphertext)
    path.chmod(0o600)

def _read_encrypted_state(path: Path) -> dict:
    """Decrypt state file. Falls back to plaintext JSON for migration."""
    raw = path.read_bytes()
    try:
        key = _get_state_encryption_key()
        box = nacl.secret.SecretBox(key)
        return json.loads(box.decrypt(raw).decode())
    except CryptoError:
        return json.loads(raw.decode())  # Legacy plaintext fallback
```

The encryption key is derived by hashing the system signing key (already present for AuditChain signatures) through SHA-256, producing a 32-byte key suitable for NaCl's SecretBox. This avoids introducing a new key management surface -- the system key is auto-generated on first use and is machine-local.

**Migration:** The `_read_encrypted_state()` function attempts decryption first, then falls back to plaintext JSON parsing. This means existing `.sigil/state/` files from pre-patch installations will be read correctly and re-encrypted on next write. No manual migration step is required.

**Files changed:**
- `sigil.py`: Added `_get_state_encryption_key()`, `_write_encrypted_state()`, `_read_encrypted_state()`. Updated `HumanGate._record_attempt()`, `HumanGate._check_lockout()`, `HumanGate.request_approval()`, `HumanGate.approve()`, `HumanGate.check_approval()`, `SigilRuntime._reserve_nonce()`, `SigilRuntime.__init__()`.
- `tests/test_human_gate.py`: Updated all state file reads/writes to use encrypted helpers.
- `tests/test_runtime.py`: Updated nonce file verification to use `_read_encrypted_state()`.
- `tests/conftest.py`: Added `_state_key_cache` reset to per-test isolation fixture.

---

### 3.2 CRITICAL: Embedded Encoding Payload Detection

**Source parallel:** SEC-12 (No Input Sanitization for Prompt Content)

**Problem:** SIGIL's `InputNormalizer` is specifically designed to defeat "Mismatched Generalization" attacks where malicious instructions are encoded (Base64, Hex, ROT13, URL, UTF-7) to bypass safety filters. However, the Base64 and Hex detection patterns used anchored regexes:

```python
# BEFORE (vulnerable)
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=]{20,}$')
HEX_PATTERN = re.compile(r'^(?:0x)?[0-9a-fA-F]{20,}$')
```

These only match when the **entire string** is an encoded payload. An attacker embedding a payload within natural language completely bypasses detection:

```
"Hey, can you process this data: aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM= thanks!"
```

The Base64 portion (`aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=`) decodes to `"ignore all previous instructions"` but the anchored pattern never fires because the full string contains spaces and non-base64 characters.

**Solution:** Removed anchors and restructured the detection methods to use a two-phase approach:

1. **Whole-string fast path** -- if the entire input looks like pure base64/hex (using private `_BASE64_FULL` / `_HEX_FULL` anchored patterns), decode it directly. This preserves the original behavior for inputs that are entirely encoded.

2. **Embedded payload scan** -- use `finditer()` on the unanchored pattern to locate encoded subsequences within natural language. Each candidate is individually validated (base64 decoding with `validate=True`, hex with even-length and UTF-8 checks). On first successful decode, the encoded portion is replaced inline with its decoded form and the detection flag is raised.

```python
# AFTER (secure)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')  # No anchors
HEX_PATTERN = re.compile(r'(?:0x)?[0-9a-fA-F]{20,}')       # No anchors
```

The `normalize()` method's recursive loop then re-processes the decoded text, catching Matryoshka (multi-layer) encodings even when the outer layer was embedded.

**LLM interaction impact:** This directly hardens the prompt injection surface. When SIGIL's `ContextArchitect` builds the structured context for an LLM call, user input passes through `InputNormalizer.normalize()`. Without this fix, an attacker could smuggle encoded instructions past the normalizer and into the `<user_input>` section of the prompt, where the LLM would decode and follow them. With the fix, embedded payloads are decoded *before* the LLM sees them, allowing downstream safety filters and the structural isolation layer to evaluate the actual content.

**Files changed:**
- `sigil_llm_adapter.py`: Updated `BASE64_PATTERN`, `HEX_PATTERN` (removed anchors), added `_BASE64_FULL`, `_HEX_FULL` (private anchored versions). Rewrote `detect_and_decode_base64()` and `detect_hex_encoding()` with two-phase detection.

---

### 3.3 HIGH: FileLock on State File Writes

**Source parallel:** SEC-10 (Concurrent Session File Writes)

**Problem:** Three state file write operations in `HumanGate` lacked `FileLock` protection:

| Location | Risk |
|---|---|
| `_record_attempt()` -- writes `attempts_{state_id}.json` | Two concurrent approval denials could corrupt the attempt counter, allowing an attacker to reset the lockout state |
| `request_approval()` -- writes `pending_{state_id}.json` | Unlikely race (state IDs are unique), but defense-in-depth |
| `approve()` -- rewrites state with approval signature | Two operators approving the same state concurrently could produce a corrupt file |

**Solution:** Wrapped all three writes in `with FileLock(file):` blocks. SIGIL's `FileLock` uses platform-appropriate locking (`fcntl.flock` on Unix, `msvcrt.locking` on Windows) with exponential backoff and configurable timeout.

**Files changed:**
- `sigil.py`: Added `FileLock` to `_record_attempt()`, `request_approval()`, and `approve()`.

---

### 3.4 HIGH: Bounded Audit Proxy Queue

**Source parallel:** SEC-04 (No Rate Limiting or Abuse Prevention)

**Problem:** `AuditProxy._log_queue` was initialized as `queue.Queue()` with no size limit. While the in-memory record buffer was bounded (`collections.deque(maxlen=10000)`), the queue feeding the background log-writer thread could grow without bound. In a scenario where audit records are produced faster than the worker can write them to disk (e.g., during high-frequency LLM API calls or a deliberate flooding attack), memory usage grows linearly and unboundedly.

**Solution:** Set `maxsize=1000` on the queue and switched the producer from blocking `put()` to `put_nowait()` with a stderr warning on full:

```python
self._log_queue: queue.Queue[AuditRecord] = queue.Queue(maxsize=1000)

# In _store_record():
try:
    self._log_queue.put_nowait(record)
except queue.Full:
    print("[SIGIL WARN] Audit log queue full (1000). Record dropped.", file=sys.stderr)
```

The record is still added to the bounded `_records` deque (for in-memory query), so the data is not lost for the current session -- only the persistent disk write is skipped under extreme load. The stderr warning ensures operators are aware of the condition.

**Files changed:**
- `sigil_audit_proxy.py`: Changed `Queue()` to `Queue(maxsize=1000)`, changed `put()` to `put_nowait()` with `queue.Full` handling.

---

### 3.5 MEDIUM: File Permissions on Sensitive Files

**Source parallel:** SEC-01 (recommendation to set explicit file permissions)

**Problem:** State files and audit logs were created with default filesystem permissions, meaning on multi-user Unix systems they could be world-readable.

**Solution:**
- `_write_encrypted_state()` calls `path.chmod(0o600)` after every write, restricting access to the file owner.
- Added `chmod(0o600)` to `AuditChain.log()` after appending to the chain file.
- Both are wrapped in `try/except (OSError, NotImplementedError)` to gracefully handle Windows (which doesn't support Unix permission semantics).

**Files changed:**
- `sigil.py`: `_write_encrypted_state()` and `AuditChain.log()`.

---

## 4. How These Changes Improve LLM Interaction Security

SIGIL sits at three critical points in the LLM interaction pipeline:

```
User Input ──> [InputNormalizer] ──> [ContextArchitect] ──> LLM API
                     ^                      |
                     |                      v
                [Patch 3.2]          [AuditProxy] ──> [AuditChain]
              Encoding bypass              |               |
              now blocked            [Patch 3.4]     [Patch 3.5]
                                    Queue bounded    Permissions set
                     
HumanGate ──> [State Files] ──> Operator Approval ──> Seal Execution
                    |
              [Patch 3.1]     [Patch 3.3]
            Encrypted at rest  File-locked
```

### 4.1 Pre-LLM: Input Normalization (Patch 3.2)

The InputNormalizer is the first line of defense against prompt injection. LLMs are trained to follow instructions, and attackers exploit this by encoding malicious instructions in formats that bypass text-based safety filters but are decoded by the LLM's own capabilities.

The embedded encoding fix closes a specific attack vector where an attacker wraps a payload in base64 or hex and embeds it within an otherwise innocent-looking prompt. Before this patch, SIGIL's normalizer would pass the encoded payload through to the LLM unchanged. The LLM, seeing base64, might decode and follow it -- or the encoded bytes might match internal token patterns that trigger unintended behavior.

With `finditer()`-based scanning, SIGIL now detects and decodes these embedded payloads *before* the LLM processes them, allowing the structural isolation layer (`ContextArchitect`) and any downstream filters to evaluate the actual decoded content.

### 4.2 During LLM Interaction: Audit Integrity (Patches 3.4, 3.5)

The AuditProxy sits between the application and LLM providers, logging every request and response. If the audit pipeline fails silently under load (unbounded queue growth leading to OOM), the system loses its tamper-evident record of what was sent to and received from the LLM. This is particularly dangerous in compliance-sensitive deployments where audit gaps could mask unauthorized data exfiltration or model manipulation.

The bounded queue ensures the audit pipeline degrades gracefully under load (dropping disk writes while preserving in-memory records) rather than failing catastrophically.

### 4.3 Post-LLM: Approval Gate Integrity (Patches 3.1, 3.3)

When an LLM-driven workflow hits a `PAUSE` governance action, SIGIL's HumanGate creates a pending approval state that a human operator must sign. If an attacker can read the plaintext state file, they learn:
- What action is pending (potential information leak about workflow logic)
- The approval context (may contain sensitive parameters)
- The integrity hash (which, combined with knowledge of the signing scheme, could inform forgery attempts)

Encrypting state files at rest ensures that even with filesystem access, the approval context remains confidential. The FileLock additions prevent concurrent-write corruption of lockout state, which could otherwise be exploited to bypass rate limiting on the approval mechanism.

---

## 5. What Was Already Strong

The leaked codebase analysis also highlighted areas where SIGIL was already ahead of the curve:

| Source Weakness | SIGIL's Existing Defense |
|---|---|
| SEC-05: Sequential session IDs | 96-bit entropy state IDs from `os.urandom(32)` |
| SEC-06: Binary trust gate | Five-class `EffectClass` enum with per-seal granular controls |
| SEC-09: Plaintext OAuth tokens | Private keys encrypted with Argon2id + XSalsa20-Poly1305 |
| SEC-13: No audit trail | Merkle-linked, signed AuditChain with chain verification |
| SEC-03: Hook script injection | No external command execution surface |
| SEC-11: Recursive JSON parser | Uses Python stdlib `json` module |
| SEC-07: Path traversal | Regex-validated key names (`^[a-zA-Z0-9_-]+$`) |

These preexisting defenses reflect SIGIL's security-first design philosophy established through four rounds of remediation (v1.1.0 through v1.4.0).

---

## 6. Architectural Lessons from the Comparison

Beyond the specific patches, several architectural observations emerge from cross-referencing the two codebases:

### 6.1 The Trust Surface Is the Storage Surface

The leaked codebase's SEC-01 (unencrypted sessions) and SIGIL's plaintext state files share a root cause: **any system that persists state to disk has an implicit trust boundary at the filesystem**. The fix isn't just encryption -- it's recognizing that state persistence *is* a security operation, not a convenience feature.

SIGIL already had this principle right for cryptographic keys (encrypted with passphrase). The gap was that non-key state files (approvals, nonces, lockout data) were treated as less sensitive. The analysis made clear that *any* operational state is a potential information leak or manipulation target.

### 6.2 Anchored Patterns Are a False Sense of Security

The `^...$` pattern on encoding detection is a subtle and common bug. It's the input validation equivalent of checking the front door while leaving the windows open. The leaked codebase's security analysis didn't explicitly call out this pattern, but its SEC-12 (prompt injection) finding highlights the broader principle: **input sanitization must account for the actual input distribution, not just the clean case**.

The fix (scanning with `finditer()` instead of matching with `^...$`) is small in code terms but large in security terms. It transforms the normalizer from "catches pure-encoded inputs" to "catches encoded payloads wherever they appear."

### 6.3 Queue Bounds Are a Reliability Primitive

The unbounded `queue.Queue()` in AuditProxy is a classic production failure mode. In testing, queues are always small. In production under load (or under attack), unbounded queues become the weakest link. The source codebase's SEC-04 (rate limiting) is the broader category; the specific instance here is that **any producer-consumer pipeline needs a bound on the buffer between them**.

The `put_nowait()` + stderr warning approach is borrowed directly from SIGIL's MEMORY.md note about `AuditProxy._log_queue` having `maxsize=1000` -- this was already a documented design intent that hadn't been implemented in the code.

---

## 7. Test Impact

All patches were verified against SIGIL's full test suite:

```
310 passed, 2 skipped, 0 failures (16.37s)
```

Test modifications:
- `tests/test_human_gate.py`: All 12 HumanGate tests updated to use `_read_encrypted_state()` / `_write_encrypted_state()` instead of direct `json.loads(path.read_text())` / `path.write_text(json.dumps(...))`. Tests that simulate tampering (modifying context after signing) now tamper through the encrypted write path, which correctly exercises the integrity check on the encrypted-then-decrypted data.
- `tests/test_runtime.py`: `test_nonce_file_created` updated to verify nonce file contents through `_read_encrypted_state()`.
- `tests/conftest.py`: Added `_state_key_cache` reset to the per-test isolation fixture, ensuring each test derives its own encryption key from its own test-scoped system key.

---

## 8. Summary

| Patch | Severity | Source Ref | SIGIL Files | Lines Changed |
|---|---|---|---|---|
| Encrypted state files | CRITICAL | SEC-01 | `sigil.py`, `conftest.py`, `test_human_gate.py`, `test_runtime.py` | +67 new, ~30 modified |
| Embedded encoding detection | CRITICAL | SEC-12 | `sigil_llm_adapter.py` | +40 new, ~20 modified |
| FileLock on state writes | HIGH | SEC-10 | `sigil.py` | +6 modified |
| Bounded audit queue | HIGH | SEC-04 | `sigil_audit_proxy.py` | +4 modified |
| File permissions | MEDIUM | SEC-01 | `sigil.py` | +4 new |

Total: 5 patches addressing 4 vulnerability classes, 0 test regressions.
