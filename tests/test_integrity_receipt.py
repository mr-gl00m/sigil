"""Tests for IntegrityReceipt — the HMAC-based proof-of-conditioning primitive.

v1.7 marquee feature. The receipt closes the gap between "the seal was
verified before the call" and "the model actually conditioned on the
seal during the call." Each request mints a per-request canary derived
from HMAC(system_key, nonce ‖ seal_hash); the model is instructed to
echo the bracketed canary token in its response; the Validator
recomputes the HMAC and matches.

The model can't forge a valid canary without the system key, so a
matching receipt is cryptographic evidence the model saw the real seal
in the real request — not a memorized response, not a tampered prompt.
"""

import re

import pytest

from sigil import Architect, AuditChain, Keyring
from sigil_llm_adapter import ContextArchitect, IntegrityReceipt


@pytest.fixture
def architect_seal(sigil_isolation):
    """Create a real signed seal for receipt tests."""
    Keyring.generate("architect")
    architect = Architect("architect")
    seal = architect.seal(
        node_id="receipt_test",
        instruction="Be helpful within the rules.",
        allowed_tools=[],
    )
    return seal


# --- Generation --------------------------------------------------------------


def test_build_context_embeds_integrity_receipt_block(architect_seal):
    """build_context emits a SIGIL_INTEGRITY_RECEIPT block alongside
    IRONCLAD_CONTEXT, carrying both the per-request nonce and the
    HMAC-derived canary token the model is expected to echo."""
    ctx = ContextArchitect.build_context(architect_seal, "hi")
    assert "<SIGIL_INTEGRITY_RECEIPT" in ctx
    assert "[INTEGRITY-RECEIPT:" in ctx
    # The block must include a nonce attribute so verify can reconstruct
    # the HMAC input.
    assert re.search(r'<SIGIL_INTEGRITY_RECEIPT nonce="[a-f0-9]+">', ctx)


def test_integrity_receipt_uses_per_request_nonce(architect_seal):
    """Two builds for the same seal must produce different nonces and
    therefore different canary tokens — otherwise an attacker could
    capture one canary and replay it indefinitely."""
    ctx_a = ContextArchitect.build_context(architect_seal, "hi")
    ctx_b = ContextArchitect.build_context(architect_seal, "hi")
    canary_a = re.search(r"\[INTEGRITY-RECEIPT: ([a-f0-9]+)\]", ctx_a).group(1)
    canary_b = re.search(r"\[INTEGRITY-RECEIPT: ([a-f0-9]+)\]", ctx_b).group(1)
    assert canary_a != canary_b


def test_build_context_can_disable_integrity_receipt(architect_seal):
    """integrity_receipt=False skips the block — opt-out for callers
    that don't want the receipt overhead or the extra prompt real
    estate. v1.7 default is on. The TRUST_PREAMBLE still mentions the
    receipt format in its operational notes (so the model knows what to
    do when the block is present), but no actual canary block with a
    populated hex nonce is emitted, and IntegrityReceipt.verify reports
    no receipt block found."""
    ctx = ContextArchitect.build_context(architect_seal, "hi", integrity_receipt=False)
    # The receipt-block regex must not match (vs. the documentation
    # mention in the preamble which uses literal "..." placeholders).
    verified, reason = IntegrityReceipt.verify(architect_seal, ctx, "any response")
    assert verified is False
    assert "no_receipt_block" in reason.lower()


# --- Verification ------------------------------------------------------------


def test_verify_succeeds_when_response_echoes_canary(architect_seal):
    """A response that contains the [INTEGRITY-RECEIPT: <canary>] token
    verbatim verifies cleanly."""
    ctx = ContextArchitect.build_context(architect_seal, "hi")
    canary = re.search(r"\[INTEGRITY-RECEIPT: ([a-f0-9]+)\]", ctx).group(1)
    response = (
        f"Sure, here's the answer. [INTEGRITY-RECEIPT: {canary}] "
        f"And here's some more text."
    )
    verified, reason = IntegrityReceipt.verify(architect_seal, ctx, response)
    assert verified is True, f"verify rejected legitimate receipt: {reason}"


def test_verify_fails_when_response_omits_canary(architect_seal):
    """A response with no receipt token at all fails closed."""
    ctx = ContextArchitect.build_context(architect_seal, "hi")
    response = "Sure, here's the answer with no receipt token at all."
    verified, reason = IntegrityReceipt.verify(architect_seal, ctx, response)
    assert verified is False
    assert "missing" in reason.lower()


def test_verify_fails_on_wrong_canary(architect_seal):
    """A response that contains a receipt token with the wrong canary
    fails closed — this is the case where something tampered with the
    prompt mid-flight or the model is confabulating."""
    ctx = ContextArchitect.build_context(architect_seal, "hi")
    response = "Here's my answer. [INTEGRITY-RECEIPT: deadbeef00000000]"
    verified, reason = IntegrityReceipt.verify(architect_seal, ctx, response)
    assert verified is False
    assert "mismatch" in reason.lower() or "wrong" in reason.lower()


def test_verify_fails_when_context_has_no_receipt_block():
    """If the prompt context never had a receipt block, verify cannot
    proceed — no nonce to recompute the HMAC against."""
    seal = Architect.__new__(Architect)  # empty seal placeholder; only
    # the verify path reads the context, not the seal, for this case.
    response = "doesn't matter, no context-side receipt"
    verified, reason = IntegrityReceipt.verify(seal, "no-receipt-here", response)
    assert verified is False
    assert "no_receipt" in reason.lower() or "no_nonce" in reason.lower()


# --- Cryptographic guarantees ------------------------------------------------


def test_canary_changes_when_seal_hash_changes(architect_seal, sigil_isolation):
    """Two seals with different content but the same nonce must yield
    different canaries — the HMAC must bind the seal-hash, not just the
    nonce. Otherwise a canary captured from one seal could be replayed
    against another."""
    # Force a known nonce so we can compare cleanly.
    nonce = "0123456789abcdef0123456789abcdef"
    canary_a = IntegrityReceipt._compute_canary(architect_seal, nonce)

    # A different seal with a different instruction.
    architect = Architect("architect")
    seal_b = architect.seal(
        node_id="receipt_test_b",
        instruction="Different instruction text.",
        allowed_tools=[],
    )
    canary_b = IntegrityReceipt._compute_canary(seal_b, nonce)
    assert canary_a != canary_b, (
        "canary did not change when seal content changed — HMAC binding broken"
    )


def test_canary_changes_when_nonce_changes(architect_seal):
    """Different nonces with the same seal must yield different canaries.
    Confirms the per-request property of the HMAC."""
    canary_a = IntegrityReceipt._compute_canary(architect_seal, "a" * 32)
    canary_b = IntegrityReceipt._compute_canary(architect_seal, "b" * 32)
    assert canary_a != canary_b


def test_attacker_without_system_key_cannot_forge_canary(architect_seal, sigil_isolation):
    """An attacker who can read the prompt context but doesn't have
    _system.key cannot compute a matching canary. Simulated by
    rotating the system key — the canary in the captured prompt is no
    longer valid against the new key."""
    import sigil

    # Build a context with the original system key.
    ctx = ContextArchitect.build_context(architect_seal, "hi")
    canary_old = re.search(r"\[INTEGRITY-RECEIPT: ([a-f0-9]+)\]", ctx).group(1)
    response = f"Echo: [INTEGRITY-RECEIPT: {canary_old}]"

    # Replace the system signer with a fresh one. (Deletion + reset of
    # the cached signer simulates "attacker captured the old context but
    # doesn't have the actual system key bytes".)
    sigil.AuditChain._system_signer = None
    sigil.AuditChain._system_key_id = None
    (sigil_isolation["keys_dir"] / "_system.key").unlink(missing_ok=True)
    (sigil_isolation["keys_dir"] / "_system.pub").unlink(missing_ok=True)
    # Force re-bootstrap with a new signer.
    sigil.AuditChain._get_system_signer()

    # The captured response now fails verification: the new system key
    # produces a different HMAC.
    verified, reason = IntegrityReceipt.verify(architect_seal, ctx, response)
    assert verified is False
    assert "mismatch" in reason.lower() or "wrong" in reason.lower()


# --- AuditRecord integration -------------------------------------------------


def test_audit_record_has_integrity_receipt_field():
    """AuditRecord exposes integrity_receipt_verified for callers that
    plumb the seal+context through AuditProxy.audited_request."""
    from sigil_audit_proxy import AuditRecord
    rec = AuditRecord(
        request_id="r1", timestamp_utc="2026-05-04T00:00:00Z", provider="anthropic",
        model="claude-test", latency_ms=10.0, time_to_first_byte_ms=None,
        input_tokens=1, output_tokens=1, total_tokens=2,
        estimated_cost_usd=0.0, request_hash="h", response_fingerprint="f",
        status_code=200, success=True,
    )
    assert hasattr(rec, "integrity_receipt_verified")
    assert rec.integrity_receipt_verified is None  # default — receipt not used


# --- RT-2026-05-04B-001: HMAC key separation ---


def test_hmac_key_is_not_signer_bytes_directly(architect_seal, sigil_isolation):
    """RT-2026-05-04B-001: the HMAC key used by _compute_canary must be
    derived from the system signing key, not the raw bytes themselves.
    Reusing one cryptographic secret for two unrelated primitives
    (Ed25519 sign + HMAC-SHA256) violates key separation. The fix
    derives an HMAC subkey via SHA-256(domain_separator || signer_bytes);
    we verify by recomputing the canary with the raw bytes and asserting
    it does NOT match the production canary."""
    import hmac as _hmac_mod
    import hashlib as _hashlib_mod
    from sigil import AuditChain

    signer, _ = AuditChain._get_system_signer()
    nonce = "0123456789abcdef0123456789abcdef"

    # What the production code computes.
    production = IntegrityReceipt._compute_canary(architect_seal, nonce)

    # What it would compute under the broken key-reuse pattern.
    seal_hash = architect_seal.content_hash()
    raw_key_canary = _hmac_mod.new(
        signer.encode(),
        nonce.encode("ascii") + seal_hash.encode("ascii"),
        _hashlib_mod.sha256,
    ).hexdigest()[:len(production)]

    assert production != raw_key_canary, (
        "_compute_canary appears to use signer.encode() directly as the "
        "HMAC key — RT-2026-05-04B-001 fix did not land. Expected the "
        "HMAC key to be a derived subkey, but the canary matches the "
        "raw-key form."
    )


# --- RT-2026-05-04B-002: 128-bit truncation ---


def test_canary_is_128_bit_truncation(architect_seal):
    """RT-2026-05-04B-002: canary should be 32 hex characters (128 bits).
    The earlier 16-char (64-bit) truncation was sufficient against
    random collisions but left less margin for any future oracle-style
    API. 128 bits matches modern cryptographic recommendations."""
    nonce = "0123456789abcdef0123456789abcdef"
    canary = IntegrityReceipt._compute_canary(architect_seal, nonce)
    assert len(canary) == 32, (
        f"expected 32-char (128-bit) canary, got {len(canary)} chars: {canary!r}"
    )
    assert all(c in "0123456789abcdef" for c in canary), (
        f"canary has non-hex characters: {canary!r}"
    )
