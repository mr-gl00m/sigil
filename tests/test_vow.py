"""Tests for the vow() governance decorator."""

import hashlib
import asyncio
from typing import Any, Callable, Coroutine, cast

import pytest

from sigil import (
    vow, Classification, Regulation, GovernanceAction,
    AuditChain,
)


def test_allow_passes_through():
    """GovernanceAction.ALLOW returns the function result unchanged."""
    @vow(action=GovernanceAction.ALLOW)
    def get_data():
        return "sensitive data"

    assert get_data() == "sensitive data"


def test_redact_string_full():
    """REDACT with keep_visible=0 returns '[REDACTED]'."""
    @vow(action=GovernanceAction.REDACT)
    def get_email():
        return "user@example.com"

    assert get_email() == "[REDACTED]"


def test_redact_string_partial():
    """REDACT with keep_visible shows first N chars then mask."""
    @vow(action=GovernanceAction.REDACT, keep_visible=3, mask_char="*")
    def get_phone():
        return "+1-555-123-4567"

    result = cast(str, get_phone())
    assert result.startswith("+1-")
    assert "*" in result
    assert len(result) == len("+1-555-123-4567")


def test_redact_dict():
    """REDACT on dict redacts all string values."""
    @vow(action=GovernanceAction.REDACT)
    def get_record():
        return {"name": "Alice", "email": "alice@test.com"}

    result = get_record()
    assert isinstance(result, dict)
    assert result["name"] == "[REDACTED]"
    assert result["email"] == "[REDACTED]"


def test_hash_returns_sha256():
    """HASH returns sha256 hex of the string result."""
    @vow(action=GovernanceAction.HASH)
    def get_secret():
        return "my_secret"

    result = get_secret()
    expected = hashlib.sha256("my_secret".encode()).hexdigest()
    assert result == expected


def test_deny_raises_permission_error():
    """DENY raises PermissionError before executing."""
    @vow(action=GovernanceAction.DENY, classification=Classification.RESTRICTED)
    def get_restricted():
        return "should never run"

    with pytest.raises(PermissionError, match="Access denied"):
        get_restricted()


def test_pause_returns_paused_string():
    """PAUSE returns a SIGIL_PAUSED message with state ID."""
    @vow(action=GovernanceAction.PAUSE)
    def do_transfer():
        return "transferred"

    result = cast(str, do_transfer())
    assert "SIGIL_PAUSED" in result
    assert "Approval Pending" in result


def test_async_allow():
    """ALLOW works on async functions."""
    @vow(action=GovernanceAction.ALLOW)
    async def async_data():
        return "async result"

    async_data_fn = cast(Callable[[], Coroutine[Any, Any, str]], async_data)
    result = asyncio.run(async_data_fn())
    assert result == "async result"


def test_async_redact():
    """REDACT works on async functions."""
    @vow(action=GovernanceAction.REDACT)
    async def async_email():
        return "user@example.com"

    async_email_fn = cast(Callable[[], Coroutine[Any, Any, str]], async_email)
    result = asyncio.run(async_email_fn())
    assert result == "[REDACTED]"


def test_async_deny():
    """DENY works on async functions."""
    @vow(action=GovernanceAction.DENY)
    async def async_restricted():
        return "restricted"

    async_restricted_fn = cast(Callable[[], Coroutine[Any, Any, str]], async_restricted)
    with pytest.raises(PermissionError):
        asyncio.run(async_restricted_fn())


def test_decorated_preserves_name():
    """Decorated function preserves __name__ via @wraps."""
    @vow(action=GovernanceAction.ALLOW)
    def my_function():
        return "test"

    assert my_function.__name__ == "my_function"


def test_sigil_vow_attribute():
    """Decorated functions have _sigil_vow attribute."""
    @vow(
        classification=Classification.CONFIDENTIAL,
        regulation=Regulation.PII,
        action=GovernanceAction.REDACT,
    )
    def annotated():
        return "data"

    annotated_any = cast(Any, annotated)
    assert hasattr(annotated_any, "_sigil_vow")
    assert annotated_any._sigil_vow["classification"] == Classification.CONFIDENTIAL
    assert annotated_any._sigil_vow["regulation"] == Regulation.PII
    assert annotated_any._sigil_vow["action"] == GovernanceAction.REDACT
