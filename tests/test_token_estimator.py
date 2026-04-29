"""Tests for TokenEstimator token counting."""

from sigil_audit_proxy import TokenEstimator


def test_estimate_tokens_returns_positive():
    """Non-empty text returns positive token count."""
    count = TokenEstimator.estimate_tokens("Hello, this is a test string.")
    assert count > 0


def test_estimate_tokens_empty_returns_zero():
    """Empty string returns 0 tokens."""
    assert TokenEstimator.estimate_tokens("") == 0


def test_estimate_tokens_heuristic_ratio(monkeypatch):
    """Heuristic estimation is roughly 1 token per 4 characters."""
    # Force heuristic path by disabling tiktoken
    monkeypatch.setattr("sigil_audit_proxy.tiktoken", None)
    text = "a" * 400
    count = TokenEstimator.estimate_tokens(text, model="nonexistent-model-xyz")
    # With 4 chars/token heuristic, 400 chars ~= 100 tokens
    assert 80 <= count <= 120


def test_estimate_from_messages_sums():
    """estimate_from_messages sums tokens across messages."""
    messages = [
        {"role": "user", "content": "Hello world"},
        {"role": "assistant", "content": "Hi there friend"},
    ]
    total = TokenEstimator.estimate_from_messages(messages)
    assert total > 0
    # Should be roughly sum of individual estimates
    individual = sum(TokenEstimator.estimate_tokens(m["content"]) for m in messages)
    assert total == individual


def test_estimate_from_messages_list_content():
    """estimate_from_messages handles list-type content (multimodal)."""
    messages = [
        {"role": "user", "content": [{"text": "Hello world"}, {"text": "More text"}]},
    ]
    total = TokenEstimator.estimate_from_messages(messages)
    assert total > 0


def test_estimate_from_messages_empty():
    """Empty messages list returns 0."""
    assert TokenEstimator.estimate_from_messages([]) == 0


def test_chars_per_token_constant():
    """CHARS_PER_TOKEN fallback constant is 4.0."""
    assert TokenEstimator.CHARS_PER_TOKEN == 4.0


def test_estimate_tokens_minimum_one():
    """Non-empty text returns at least 1 token."""
    assert TokenEstimator.estimate_tokens("a") >= 1
