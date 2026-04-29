"""
Code-theft canary tests.

These verify that SIGIL-specific fingerprints exist in the codebase.
If someone wraps SIGIL verbatim as a SaaS product, running these tests
against their service proves provenance.
"""

import hashlib
import json
from pathlib import Path

import pytest

from sigil import (
    SigilSeal, Classification, GovernanceAction, AuditChain,
    CodeProvenance,
)
from sigil_llm_adapter import ContextArchitect
from sigil_audit_proxy import IntegrityCheck

_ADVERSARIAL_CONFIG = Path(__file__).parent.parent / "sigil_adversarial_config.json"
_HAS_ADVERSARIAL_CONFIG = _ADVERSARIAL_CONFIG.exists()


def test_trust_preamble_contains_sigil_identity():
    """ContextArchitect.TRUST_PREAMBLE contains SIGIL identity markers."""
    preamble = ContextArchitect.TRUST_PREAMBLE
    assert "SIGIL" in preamble
    assert "Sovereign Integrity & Governance Interface Layer" in preamble


def test_seal_version_format():
    """SigilSeal default version is '1.0' (SIGIL-specific schema)."""
    seal = SigilSeal(node_id="canary", instruction="test")
    assert seal.version == "1.0"


def test_canary_hash_constant():
    """IntegrityCheck.EXPECTED_HASH == sha256('SIGIL').hexdigest()."""
    expected = hashlib.sha256(b"SIGIL").hexdigest()
    assert IntegrityCheck.EXPECTED_HASH == expected


@pytest.mark.skipif(not _HAS_ADVERSARIAL_CONFIG, reason="adversarial config not present (local-only file)")
def test_adversarial_config_glass_shard_watermark():
    """sigil_adversarial_config.json contains 'v1.0_GLASS_SHARD' version marker."""
    config = json.loads(_ADVERSARIAL_CONFIG.read_text())
    assert config["meta"]["file_version"] == "v1.0_GLASS_SHARD"


@pytest.mark.skipif(not _HAS_ADVERSARIAL_CONFIG, reason="adversarial config not present (local-only file)")
def test_canary_trap_tokens_present():
    """Adversarial config contains unique canary trap tokens."""
    config = json.loads(_ADVERSARIAL_CONFIG.read_text())
    tokens = [t["payload"] for t in config["canary_traps"]["tokens"]]
    payloads = " ".join(tokens)
    assert "::SIGIL_VOW_OF_SILENCE_7X9Y2Z::" in payloads
    assert "::XENON_FALLS_88::" in payloads


def test_governance_enum_sigil_specific_values():
    """GovernanceAction and Classification enums have SIGIL-specific values."""
    ga_values = {e.name for e in GovernanceAction}
    assert ga_values == {"ALLOW", "REDACT", "HASH", "DENY", "PAUSE"}

    cl_values = {e.name for e in Classification}
    assert cl_values == {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}


def test_audit_chain_entry_format_fingerprint():
    """AuditChain entries use SIGIL-specific field names and GENESIS root."""
    AuditChain.log("canary_test", {"marker": True})
    content = AuditChain.LOG_FILE.read_text().strip()
    entry = json.loads(content.split("\n")[0])

    # SIGIL-specific field names
    assert "prev_hash" in entry
    assert "entry_hash" in entry
    assert "event" in entry
    # GENESIS is the chain root
    assert entry["prev_hash"] == "GENESIS"


def test_context_architect_xml_tag_fingerprint():
    """build_context output contains SIGIL-specific XML tags."""
    seal = SigilSeal(
        node_id="fingerprint_test",
        instruction="test",
        signature="a" * 64,
        signer_key_id="k" * 16,
    )
    ctx = ContextArchitect.build_context(seal, "hello")
    assert "<SIGIL_TRUST_BOUNDARY>" in ctx
    assert "<IRONCLAD_CONTEXT" in ctx
    assert "<USER_DATA" in ctx


# --- L-03: Provenance hardening ---


def test_provenance_structural_check():
    """verify_structural() returns all True for an intact codebase."""
    checks = CodeProvenance.verify_structural()
    assert all(checks.values()), f"Failed checks: {[k for k, v in checks.items() if not v]}"


def test_provenance_salt_uses_class_names():
    """Provenance salt is derived from class names."""
    import hashlib
    expected = hashlib.sha256(
        f"{SigilSeal.__name__}:{AuditChain.__name__}:Sentinel".encode()
    ).hexdigest()[:16]
    assert CodeProvenance._PROVENANCE_SALT == expected
