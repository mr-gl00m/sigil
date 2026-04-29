"""
SIGIL Test Suite - conftest.py

Per-test file isolation via monkeypatched paths.
Shared fixtures for real Ed25519 crypto, architects, sentinels, and runtime.
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def sigil_isolation(tmp_path, monkeypatch):
    """
    Autouse fixture: every test gets its own isolated .sigil/ directory.
    Monkeypatches ALL module-level Path variables to prevent test pollution
    and avoid touching the real .sigil/ directory.
    """
    sigil_dir = tmp_path / ".sigil"
    keys_dir = sigil_dir / "keys"
    state_dir = sigil_dir / "state"
    audit_dir = sigil_dir / "audit"
    crl_file = sigil_dir / "revoked.json"
    executed_nonces_file = state_dir / "executed_nonces.json"
    log_file = audit_dir / "chain.jsonl"
    audit_log_dir = audit_dir / "proxy_logs"
    config_dir = sigil_dir / "config"

    for d in [sigil_dir, keys_dir, state_dir, audit_dir, audit_log_dir, config_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Monkeypatch sigil module
    import sigil
    monkeypatch.setattr(sigil, "SIGIL_DIR", sigil_dir)
    monkeypatch.setattr(sigil, "KEYS_DIR", keys_dir)
    monkeypatch.setattr(sigil, "STATE_DIR", state_dir)
    monkeypatch.setattr(sigil, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(sigil, "CRL_FILE", crl_file)
    monkeypatch.setattr(sigil, "EXECUTED_NONCES_FILE", executed_nonces_file)
    monkeypatch.setattr(sigil.AuditChain, "LOG_FILE", log_file)
    # Reset _dirs_ensured so each test re-initializes directories
    monkeypatch.setattr(sigil, "_dirs_ensured", False)
    # Reset state encryption key cache so each test derives its own key
    monkeypatch.setattr(sigil, "_state_key_cache", None)
    # Reset system signer so each test gets its own audit signing key (C-01)
    monkeypatch.setattr(sigil.AuditChain, "_system_signer", None)
    monkeypatch.setattr(sigil.AuditChain, "_system_key_id", None)

    # Monkeypatch sigil_audit_proxy module
    import sigil_audit_proxy
    monkeypatch.setattr(sigil_audit_proxy, "AUDIT_LOG_DIR", audit_log_dir)
    monkeypatch.setattr(sigil_audit_proxy, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(sigil_audit_proxy, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(sigil_audit_proxy, "SIGIL_DIR", sigil_dir)
    # Reset pricing cache so each test starts fresh
    monkeypatch.setattr(sigil_audit_proxy.CostCalculator, "_PRICING_CACHE", None)
    monkeypatch.setattr(sigil_audit_proxy.CostCalculator, "_PRICING_CACHE_TIME", 0.0)
    # Reset token estimator encoding cache
    monkeypatch.setattr(sigil_audit_proxy.TokenEstimator, "_ENCODINGS", {})

    # Clear any ENV keys that might interfere
    for key in list(os.environ.keys()):
        if key.startswith("SIGIL_KEY_") or key.startswith("SIGIL_PUB_"):
            monkeypatch.delenv(key, raising=False)

    return {
        "sigil_dir": sigil_dir,
        "keys_dir": keys_dir,
        "state_dir": state_dir,
        "audit_dir": audit_dir,
        "crl_file": crl_file,
        "log_file": log_file,
        "audit_log_dir": audit_log_dir,
        "config_dir": config_dir,
        "tmp_path": tmp_path,
    }


@pytest.fixture
def keypair(sigil_isolation):
    """Generate a real Ed25519 keypair in the isolated keys directory."""
    from sigil import Keyring
    priv_path, pub_path = Keyring.generate("architect")
    return priv_path, pub_path


@pytest.fixture
def architect(keypair):
    """Create an Architect with real keys."""
    from sigil import Architect
    return Architect("architect")


@pytest.fixture
def signed_seal(architect):
    """Create a signed seal for testing."""
    return architect.seal(
        node_id="test_node",
        instruction="You are a test assistant.",
        allowed_tools=["tool_a", "tool_b"],
        metadata={"test": True},
    )


@pytest.fixture
def sentinel(keypair):
    """Create a Sentinel with the matching public key."""
    from sigil import Sentinel
    return Sentinel("architect")


@pytest.fixture
def runtime(keypair):
    """Create a SigilRuntime with the matching key."""
    from sigil import SigilRuntime
    return SigilRuntime("architect")


@pytest.fixture
def audit_proxy(sigil_isolation):
    """Create an AuditProxy with file logging in the isolated directory."""
    from sigil_audit_proxy import AuditProxy
    proxy = AuditProxy(log_to_chain=False, log_to_file=True)
    yield proxy
    proxy.shutdown(wait=True)


@pytest.fixture
def mock_httpx():
    """Mock httpx.post for adapter tests."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "content": [{"text": "Test response"}],
        "usage": {"input_tokens": 10, "output_tokens": 20},
    }

    with patch("httpx.post", return_value=mock_response) as mock_post:
        yield mock_post, mock_response
