"""Tests for LLM adapters with mocked httpx."""

import os
from unittest.mock import MagicMock, patch

import pytest

from sigil_llm_adapter import (
    LLMAdapter, ClaudeAdapter, OpenAIAdapter, GeminiAdapter, OllamaAdapter,
)


def test_claude_adapter_complete(mock_httpx):
    """ClaudeAdapter.complete() returns text from mocked response."""
    mock_post, mock_resp = mock_httpx
    mock_resp.json.return_value = {"content": [{"text": "Claude says hello"}]}
    adapter = ClaudeAdapter(api_key="test-key")
    result = adapter.complete("Hello")
    assert result == "Claude says hello"
    mock_post.assert_called_once()


def test_openai_adapter_complete(mock_httpx):
    """OpenAIAdapter.complete() returns text from mocked response."""
    mock_post, mock_resp = mock_httpx
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "GPT says hello"}}]
    }
    adapter = OpenAIAdapter(api_key="test-key")
    result = adapter.complete("Hello")
    assert result == "GPT says hello"


def test_gemini_adapter_complete(mock_httpx):
    """GeminiAdapter.complete() returns text from mocked response."""
    mock_post, mock_resp = mock_httpx
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "Gemini says hello"}]}}]
    }
    adapter = GeminiAdapter(api_key="test-key")
    result = adapter.complete("Hello")
    assert result == "Gemini says hello"


def test_ollama_adapter_complete(mock_httpx):
    """OllamaAdapter.complete() returns text from mocked response."""
    mock_post, mock_resp = mock_httpx
    mock_resp.json.return_value = {"response": "Ollama says hello"}
    adapter = OllamaAdapter()
    result = adapter.complete("Hello")
    assert result == "Ollama says hello"


def test_claude_no_key_raises():
    """ClaudeAdapter without API key raises ValueError."""
    adapter = ClaudeAdapter(api_key=None)
    adapter.api_key = None  # Force no key
    with pytest.raises(ValueError, match="No API key"):
        adapter.complete("test")


def test_openai_no_key_raises():
    """OpenAIAdapter without API key raises ValueError."""
    adapter = OpenAIAdapter(api_key=None)
    if adapter.api_key is None:
        with pytest.raises(ValueError, match="No API key"):
            adapter.complete("test")


def test_gemini_no_key_raises():
    """GeminiAdapter without API key raises ValueError."""
    adapter = GeminiAdapter(api_key=None)
    if adapter.api_key is None:
        with pytest.raises(ValueError, match="No API key"):
            adapter.complete("test")


def test_base_adapter_raises():
    """LLMAdapter.complete() raises NotImplementedError."""
    adapter = LLMAdapter()
    with pytest.raises(NotImplementedError):
        adapter.complete("test")


def test_claude_with_proxy(mock_httpx):
    """ClaudeAdapter with proxy uses _audited_call."""
    mock_proxy = MagicMock()
    mock_proxy.audited_request.return_value = (
        {"content": [{"text": "audited"}]},
        MagicMock(),
    )
    mock_proxy._extract_response_text.return_value = "audited"

    adapter = ClaudeAdapter(api_key="test-key", proxy=mock_proxy)
    result = adapter.complete("Hello")
    assert result == "audited"
    mock_proxy.audited_request.assert_called_once()


def test_ollama_timeout_from_env(monkeypatch):
    """OllamaAdapter reads timeout from OLLAMA_TIMEOUT_SECONDS env."""
    monkeypatch.setenv("OLLAMA_TIMEOUT_SECONDS", "30")
    adapter = OllamaAdapter()
    assert adapter.timeout == 30.0


# --- M-02: TLS certificate verification ---


def test_adapter_verify_tls_default_true():
    """Default verify_tls is True for all adapters."""
    adapter = LLMAdapter()
    assert adapter.verify_tls is True

    claude = ClaudeAdapter(api_key="test")
    assert claude.verify_tls is True

    openai = OpenAIAdapter(api_key="test")
    assert openai.verify_tls is True


def test_adapter_verify_tls_false_warns():
    """Setting verify_tls=False logs a warning to audit chain."""
    from sigil import AuditChain
    adapter = ClaudeAdapter(api_key="test", verify_tls=False)
    assert adapter.verify_tls is False

    if AuditChain.LOG_FILE.exists():
        content = AuditChain.LOG_FILE.read_text()
        assert "tls_verification_disabled" in content


def test_adapter_ca_bundle_parameter():
    """ca_bundle parameter is accepted and stored."""
    adapter = ClaudeAdapter(api_key="test", ca_bundle="/path/to/ca.pem")
    assert adapter.ca_bundle == "/path/to/ca.pem"


# --- RT-2026-05-01-006: Ollama remote opt-in gate ---


def test_ollama_localhost_default_works(monkeypatch):
    """Default localhost base_url is always allowed."""
    monkeypatch.delenv("OLLAMA_ALLOW_REMOTE", raising=False)
    OllamaAdapter()  # default base_url is http://localhost:11434
    OllamaAdapter(base_url="http://127.0.0.1:11434")
    OllamaAdapter(base_url="http://[::1]:11434")


@pytest.mark.parametrize("remote_url", [
    "http://192.168.1.50:11434",       # private LAN
    "http://10.0.0.5:11434",           # RFC1918
    "http://ollama.example.com:11434", # public DNS
])
def test_ollama_remote_blocked_without_optin(monkeypatch, remote_url):
    """RT-2026-05-01-006: remote Ollama hosts must require an explicit opt-in."""
    monkeypatch.delenv("OLLAMA_ALLOW_REMOTE", raising=False)
    with pytest.raises(ValueError, match="OLLAMA_ALLOW_REMOTE"):
        OllamaAdapter(base_url=remote_url)


def test_ollama_remote_allowed_with_optin(monkeypatch):
    """OLLAMA_ALLOW_REMOTE=1 permits a remote host (operator opt-in)."""
    monkeypatch.setenv("OLLAMA_ALLOW_REMOTE", "1")
    OllamaAdapter(base_url="http://ollama.example.com:11434")


def test_ollama_remote_allowed_with_constructor_flag(monkeypatch):
    """allow_remote=True permits a remote host without the env var."""
    monkeypatch.delenv("OLLAMA_ALLOW_REMOTE", raising=False)
    OllamaAdapter(base_url="http://ollama.example.com:11434", allow_remote=True)
