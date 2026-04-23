# Known Limitations & Remediation Paths

Developer-facing companion to the README's "Known Limitations" section. Each item here covers: what the current design does, why it's shaped that way, and what an addressable remediation would look like if we decide to build it.

This is a roadmap document, not a commitment. Items are ordered by how tractable they are, not how urgent.

---

## 1. Horizontal Scaling vs. Local File Locks

### Current state

SIGIL's state lives on the local filesystem:

- `.sigil/audit.log` — append-only signed Merkle chain
- `.sigil/nonces/` — replay-prevention nonce store
- `.sigil/approvals/` — HumanGate pending/approved state
- `.sigil/keys/` — key material

Concurrency control is `fcntl` on POSIX, `msvcrt` on Windows, via the `FileLock` class in `sigil.py`. This is correct and efficient for a single host. It breaks cleanly and non-obviously if you point 50 containers at a shared EFS mount.

### Why it's this way

Single-host was the design target. Zero external dependencies is a core SIGIL value — "trust mathematics, not our server." A local file is auditable by a human with `less`; a Redis cluster is not.

### The remediation

Break the problem into four sub-problems. They need different solutions.

**a. The signed audit chain** — the hard one. Each entry signs over the previous hash, which is a *single-writer invariant by design*. You cannot parallelize appends without forking the chain. Two viable approaches:

- **Per-node chains keyed by `key_id`.** Each container gets its own system key and writes its own chain. Verification becomes "verify N independent chains." You lose global ordering across the fleet. Acceptable when "this node's history is intact and signed" is a sufficient guarantee.
- **DB-backed chain with serializable isolation.** The chain becomes a Postgres table (`prev_hash`, `entry_hash`, `sig`, `key_id`, `ts`). Appending does `SELECT ... FOR UPDATE` on the head row per `key_id`, then inserts. The DB enforces single-writer via row locks instead of file locks. Reads and verification parallelize trivially.

The DB approach is the right default for enterprise. It preserves the cryptographic invariant and scales to thousands of writes per second on commodity Postgres — more than any realistic SIGIL deployment.

**b. Nonces.** Trivial. Redis `SET key NX EX ttl`, or a DB table with a unique constraint. The current in-memory-set + file-scan logic becomes a backend call. No design change.

**c. HumanGate approvals.** Trivial. It's a work queue with a state machine. DB table or Redis pub/sub. The `pending_*.json` files are already a poor man's version of this.

**d. `FileLock`.** Deleted. Replaced by DB transactions for the chain, Redis or DB for everything else. `FileLock` is only load-bearing because the backend is a filesystem.

### Implementation shape

Define a `StateBackend` interface at the `AuditChain` / `Keyring` / `HumanGate` layer. Two implementations:

- `LocalFileBackend` — current behavior, default.
- `DistributedBackend` — Postgres for the chain, Redis for nonces and lock leases.

Backend selected via config / env var. All existing tests run against `LocalFileBackend`; a new integration suite runs the same contract against `DistributedBackend` using testcontainers.

### Estimated scope

Real feature: ~1-2k lines plus a contract test suite. The chokepoints (`AuditChain.log`, `FileLock`, `HumanGate.*`, nonce reservation) already exist. This is architecture work, not a rewrite.

### Non-goals

- Not trying to support multi-master writes to a single chain. That's not a solvable problem without giving up the signed-sequence invariant.
- Not trying to make `LocalFileBackend` work on NFS. If you need shared storage, use `DistributedBackend`.

---

## 2. XML Trust Boundaries Are Advisory

### Current state

`ContextArchitect` wraps user input in `<USER_DATA>` tags and HTML-escapes `<` and `>`. The LLM is instructed via the sealed preamble to treat `<USER_DATA>` content as untrusted data, not commands.

### Why it's this way

This is the strongest primitive available when the substrate (an LLM) doesn't have isolation semantics. Every alternative has the same fundamental limitation — models parse semantic tokens, not tagged regions.

### The remediation

This is the one genuinely bounded item. You can't make semantic isolation deterministic because LLMs don't have isolation primitives. What you *can* do is stack defenses so the attacker has to clear multiple independent bars.

- **Structured output / tool-call mode.** Force the LLM to emit JSON matching a schema, or to express its action through a tool call. The attack surface collapses to "produce a valid schema value that happens to be malicious" — much narrower than "produce any output."
- **Output classifier pass.** Cheap second model checks "did the response follow the sealed instruction?" Not perfect, but catches obvious hijacks.
- **Upstream guardrails.** Prompt Guard, Lakera, Constitutional classifiers, or similar. SIGIL already has `InputNormalizer`; this is additional defensive layers before the model sees anything.
- **Canonical framing.** Treat LLM output as untrusted regardless of whether the input was sealed. Post-process, validate, never pipe directly into privileged operations.

### Estimated scope

These are additive features, not a redesign:

- Structured output helpers: small (~100 lines, mostly prompt engineering and schema plumbing).
- Output classifier: moderate (new `OutputGate` class, similar shape to `UncertaintyGate`).
- Guardrail integrations: per-provider, each its own adapter.

The honest framing in the README and SECURITY docs is the most important part. This section exists so a developer evaluating SIGIL for a high-stakes deployment knows the model's output should be treated as untrusted.

---

## 3. System Key Stored Unencrypted on Disk

### Current state

`Keyring._get_system_signer()` at `sigil.py:1948` loads the Ed25519 signing key from `.sigil/keys/_system.key`, generating it on first use. File mode is `0o600`. The key is hex-encoded, unencrypted at rest.

If an attacker achieves RCE or LFI on the host, they can read the key and forge audit entries. The signed chain still verifies — they just signed the malicious entries themselves.

### Why it's this way

Zero external dependencies at install time. Local-first operation. A brand-new SIGIL install has no cloud account, no KMS, no Vault cluster — it just works.

### The remediation

The architecture already has the chokepoint. `_get_system_signer()` returns `(SigningKey, key_id)`. Abstract this into a `Signer` interface:

```python
class Signer(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    @property
    def key_id(self) -> str: ...
    @property
    def verify_key(self) -> bytes: ...
```

Implementations:

- `LocalFileSigner` — current behavior, default.
- `KMSSigner` — AWS KMS asymmetric key. `sign(payload)` calls `kms.Sign`. Key never leaves AWS.
- `VaultSigner` — HashiCorp Transit engine. Same shape.
- `HSMSigner` — PKCS#11 for hardware modules.

Signing becomes a remote call, but it happens once per logged event — not in a hot loop. Verification stays local (public key only).

### Caveats worth stating honestly

KMS raises *cost-to-exfiltrate*. It does not stop an attacker with RCE from signing malicious entries *while the process is running* — they just ask KMS to sign on their behalf. Real mitigations against active compromise:

- **Short-rotation ephemeral leaf keys.** Container holds a leaf key good for N minutes, signed by a KMS-anchored parent. Blast radius is bounded to the compromise window.
- **Per-container keys.** If a container is compromised, revoke its key and invalidate its chain. The rest of the fleet is unaffected.

These layer on top of `KMSSigner`, not instead of it.

### Estimated scope

- `Signer` interface + `LocalFileSigner` refactor: small, couple hundred lines plus tests.
- `KMSSigner`: small, mostly boto3 plumbing.
- `VaultSigner`, `HSMSigner`: one adapter each. Each is self-contained.

Ephemeral leaf rotation is a separate feature on top, larger in scope.

---

## 4. UncertaintyGate Latency and Cost

### Current state

`UncertaintyGate` at `sigil_llm_adapter.py:1067` generates `k_samples=3` responses and checks for semantic consistency. The samples are generated **sequentially** (`for _ in range(self.k_samples): self.llm.complete(...)`). Token cost is structurally 3x; wall-clock latency is structurally 3x.

### Why it's this way

Self-consistency voting requires multiple samples by definition. The 3x cost is the algorithm, not an implementation artifact.

### The remediation

One free win and several mitigations.

**The free win: parallelize.** Sequential samples are an implementation artifact, not an algorithmic requirement. Replace the for-loop with `asyncio.gather` or a thread pool. Wall-clock latency drops to roughly 1x the slowest sample. Token cost stays at 3x.

Rough sketch:

```python
# sigil_llm_adapter.py ~ line 1197
with ThreadPoolExecutor(max_workers=self.k_samples) as pool:
    futures = [
        pool.submit(self.llm.complete, context, max_tokens, temperature=self.temperature)
        for _ in range(self.k_samples)
    ]
    responses = []
    for f in futures:
        try:
            responses.append(f.result())
        except Exception as e:
            AuditChain.log("uncertainty_generation_error", {"error": str(e)})
```

Roughly a 20-line change. Preserves existing behavior, audit logging, and error handling.

**Mitigations beyond parallelization:**

- **Cheaper consistency model.** Use Haiku (or equivalent small model) for the samples; switch to Sonnet/Opus only when consistent. You're checking for divergence, not producing the final answer. Meaningful cost reduction on paired deployments.
- **Adaptive `k_samples`.** Start with 2, add a 3rd only if the first two disagree. Most stable queries resolve at k=2. Worst case matches current behavior.
- **Semantic cache.** Identical prompts within a TTL skip resampling. Trivial for deterministic workflows, useless for anything with variable context.

### Estimated scope

- Parallelization: ~20 lines, plus verifying the existing test suite still passes.
- Adaptive `k_samples`: ~50 lines, new config knob.
- Cheaper consistency model: mostly documentation — show the pattern in the docstring, let users pair adapters themselves.
- Semantic cache: moderate — new class, needs eviction policy and a test suite.

The 3x token cost is structural. If you want self-consistency voting, you pay for samples. Don't invent a cheaper voting algorithm that isn't voting.

---

## Prioritization notes

If we pick this back up, the order I'd tackle these in:

1. **UncertaintyGate parallelization** — smallest possible change, immediate win, no risk.
2. **`Signer` interface + `KMSSigner`** — modest size, high value for anyone running SIGIL in AWS, architecturally clean.
3. **`StateBackend` interface + `DistributedBackend`** — biggest change, biggest enterprise unlock, also the one that most affects SIGIL's identity. Worth discussing whether it ships as a core feature or a separate package.
4. **Output gate / structured output helpers** — additive, low-risk, improves the XML-boundary story without overstating what's possible.

Item 4 (XML boundaries) is worth working on continuously but never "done" — it's defense-in-depth layering, not a solvable problem.

---

## What this document is not

- Not a commitment to ship any of these.
- Not a security roadmap — see `SECURITY.md` and the red-team reports for that.
- Not exhaustive. New limitations surface during real deployments; add them here when we find them.
