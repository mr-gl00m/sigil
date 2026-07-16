"""Tests for IntegrityCheck model canary verification."""

import hashlib
from unittest.mock import MagicMock

from sigil_audit_proxy import IntegrityCheck
from sigil_llm_adapter import LLMAdapter


def test_expected_hash_matches_sha256_sigil():
    """EXPECTED_HASH is exactly sha256('SIGIL').hexdigest() (provenance marker)."""
    expected = hashlib.sha256(b"SIGIL").hexdigest()
    assert IntegrityCheck.EXPECTED_HASH == expected


def test_verify_uses_randomized_challenge():
    """verify_model_capability sends a unique challenge each time."""
    calls = []

    def capture_complete(prompt, max_tokens=128):
        calls.append(prompt)
        import re
        match = re.search(r"SIGIL-CANARY-[a-f0-9]{32}", prompt)
        return match.group(0) if match else "unknown"

    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete.side_effect = capture_complete

    result1 = IntegrityCheck.verify_model_capability(adapter)
    result2 = IntegrityCheck.verify_model_capability(adapter)

    # Both should pass
    assert result1 is True
    assert result2 is True
    # Challenges should be different each time
    assert calls[0] != calls[1]


def test_verify_with_wrong_response():
    """verify_model_capability returns False when model returns wrong hash."""
    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete.return_value = "I don't know the hash, sorry."
    assert IntegrityCheck.verify_model_capability(adapter) is False


def test_verify_accepts_exact_opaque_token_echo_without_hash_computation():
    def echo_canary(prompt, max_tokens=128):
        import re
        match = re.search(r"SIGIL-CANARY-[a-f0-9]{32}", prompt)
        return match.group(0) if match else "missing"

    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete.side_effect = echo_canary

    assert IntegrityCheck.verify_model_capability(adapter) is True


def test_verify_allows_fast_exact_echo():
    def instant_correct(prompt, max_tokens=128):
        import re
        match = re.search(r"SIGIL-CANARY-[a-f0-9]{32}", prompt)
        return match.group(0) if match else "unknown"

    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete.side_effect = instant_correct
    assert IntegrityCheck.verify_model_capability(adapter) is True
