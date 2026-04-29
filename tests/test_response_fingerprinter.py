"""Tests for ResponseFingerprinter SHA256 fingerprinting."""

import hashlib

from sigil_audit_proxy import ResponseFingerprinter


def test_fingerprint_is_sha256():
    """fingerprint() returns the SHA256 hex digest."""
    content = "Hello, world!"
    expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert ResponseFingerprinter.fingerprint(content) == expected


def test_fingerprint_deterministic():
    """Same content always produces the same fingerprint."""
    content = "Test content for fingerprinting"
    fp1 = ResponseFingerprinter.fingerprint(content)
    fp2 = ResponseFingerprinter.fingerprint(content)
    assert fp1 == fp2


def test_fingerprint_different_content_differs():
    """Different content produces different fingerprints."""
    fp1 = ResponseFingerprinter.fingerprint("content A")
    fp2 = ResponseFingerprinter.fingerprint("content B")
    assert fp1 != fp2


def test_fingerprint_normalized_ignores_case():
    """Normalized fingerprint treats 'Hello' and 'hello' the same."""
    fp1 = ResponseFingerprinter.fingerprint_normalized("Hello World")
    fp2 = ResponseFingerprinter.fingerprint_normalized("hello world")
    assert fp1 == fp2


def test_fingerprint_normalized_ignores_whitespace():
    """Normalized fingerprint collapses extra whitespace."""
    fp1 = ResponseFingerprinter.fingerprint_normalized("hello   world")
    fp2 = ResponseFingerprinter.fingerprint_normalized("hello world")
    assert fp1 == fp2
