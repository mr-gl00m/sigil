"""Tests for CostCalculator pricing logic."""

import json

import sigil_audit_proxy
from sigil_audit_proxy import CostCalculator


def test_anthropic_default_pricing():
    """Anthropic default rates produce expected cost."""
    cost = CostCalculator.calculate("anthropic", "unknown-model", 1000, 1000)
    # input: 1000/1000 * 0.003 = 0.003, output: 1000/1000 * 0.015 = 0.015
    assert cost == 0.018


def test_openai_default_pricing():
    """OpenAI default rates produce expected cost."""
    cost = CostCalculator.calculate("openai", "unknown-model", 1000, 1000)
    # input: 0.01, output: 0.03
    assert cost == 0.04


def test_google_default_pricing():
    """Google default rates produce expected cost."""
    cost = CostCalculator.calculate("google", "unknown-model", 1000, 1000)
    # input: 0.00125, output: 0.005
    assert cost == 0.00625


def test_ollama_is_free():
    """Ollama default pricing is $0."""
    cost = CostCalculator.calculate("ollama", "llama2", 5000, 5000)
    assert cost == 0.0


def test_unknown_provider_uses_openai():
    """Unknown provider falls back to OpenAI rates."""
    cost = CostCalculator.calculate("some_random_provider", "model", 1000, 1000)
    openai_cost = CostCalculator.calculate("openai", "model", 1000, 1000)
    assert cost == openai_cost


def test_zero_tokens_zero_cost():
    """Zero tokens produce zero cost."""
    cost = CostCalculator.calculate("anthropic", "claude", 0, 0)
    assert cost == 0.0


def test_calculate_returns_float():
    """calculate() returns a float."""
    cost = CostCalculator.calculate("anthropic", "claude", 100, 100)
    assert isinstance(cost, float)


def test_custom_pricing_from_file():
    """Custom pricing loaded from pricing.json overrides defaults."""
    custom = {
        "anthropic": {"default": {"input": 0.1, "output": 0.2}},
    }
    pricing_path = sigil_audit_proxy.CONFIG_DIR / "pricing.json"
    pricing_path.write_text(json.dumps(custom))
    # Reset cache to force reload
    CostCalculator._PRICING_CACHE = None

    cost = CostCalculator.calculate("anthropic", "model", 1000, 1000)
    # input: 1000/1000 * 0.1 = 0.1, output: 1000/1000 * 0.2 = 0.2
    assert cost == 0.3


# --- M-03: Pricing data integrity ---


def test_unsigned_pricing_accepted_with_warning():
    """Pricing without a .sig file loads fine (backward compatible)."""
    custom = {"anthropic": {"default": {"input": 0.05, "output": 0.1}}}
    pricing_path = sigil_audit_proxy.CONFIG_DIR / "pricing.json"
    pricing_path.write_text(json.dumps(custom))
    # Ensure no .sig file
    sig_path = pricing_path.with_suffix('.sig')
    if sig_path.exists():
        sig_path.unlink()
    CostCalculator._PRICING_CACHE = None

    cost = CostCalculator.calculate("anthropic", "model", 1000, 1000)
    # Should use custom pricing
    assert cost == 0.15


def test_signed_pricing_verified(keypair):
    """Signed pricing.json is loaded and verified."""
    custom = {"anthropic": {"default": {"input": 0.07, "output": 0.14}}}
    pricing_path = sigil_audit_proxy.CONFIG_DIR / "pricing.json"
    pricing_path.write_text(json.dumps(custom))
    CostCalculator._PRICING_CACHE = None

    # Sign it
    CostCalculator.sign_pricing("architect")
    sig_path = pricing_path.with_suffix('.sig')
    assert sig_path.exists()

    # Force reload and verify
    CostCalculator._PRICING_CACHE = None
    cost = CostCalculator.calculate("anthropic", "model", 1000, 1000)
    assert cost == 0.21


def test_tampered_pricing_rejected(keypair):
    """Modified pricing after signing falls back to defaults."""
    custom = {"anthropic": {"default": {"input": 0.07, "output": 0.14}}}
    pricing_path = sigil_audit_proxy.CONFIG_DIR / "pricing.json"
    pricing_path.write_text(json.dumps(custom))
    CostCalculator._PRICING_CACHE = None

    # Sign it
    CostCalculator.sign_pricing("architect")

    # Tamper with the pricing file
    tampered = {"anthropic": {"default": {"input": 999.0, "output": 999.0}}}
    pricing_path.write_text(json.dumps(tampered))

    CostCalculator._PRICING_CACHE = None
    cost = CostCalculator.calculate("anthropic", "model", 1000, 1000)
    # Should fall back to defaults (0.003 + 0.015 = 0.018)
    assert cost == CostCalculator._DEFAULT["anthropic"]["default"]["input"] + CostCalculator._DEFAULT["anthropic"]["default"]["output"]
